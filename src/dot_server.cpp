#include "mw/dot_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstring>
#include <format>
#include <mutex>
#include <span>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mw/block_list.hpp"
#include "mw/dns_message.hpp"
#include "mw/dot_framer.hpp"
#include "mw/logger.hpp"

namespace mw {
    namespace {

        constexpr uint64_t kListenTag         = 0;
        constexpr uint64_t kWakeTag           = 1;
        constexpr uint64_t kFirstConnectionId = 2;
        constexpr int kTickMs                 = 100; // how often idle connections are looked for
        constexpr std::size_t kReadChunk      = 16 * 1024;
        constexpr Ms kAcceptBackoff{ 100 }; // after running out of file descriptors

        struct Peer {
            std::string address;
            uint16_t port = 0;
        };

        // a dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d; they are reported as plain IPv4
        Peer peer_of(const sockaddr_storage& ss) {
            char text[INET6_ADDRSTRLEN] = {};
            if (ss.ss_family == AF_INET) {
                const auto& in = reinterpret_cast<const sockaddr_in&>(ss);
                inet_ntop(AF_INET, &in.sin_addr, text, sizeof text);
                return { text, ntohs(in.sin_port) };
            }
            const auto& in6 = reinterpret_cast<const sockaddr_in6&>(ss);
            if (IN6_IS_ADDR_V4MAPPED(&in6.sin6_addr)) {
                inet_ntop(AF_INET, &in6.sin6_addr.s6_addr[12], text, sizeof text);
            } else {
                inet_ntop(AF_INET6, &in6.sin6_addr, text, sizeof text);
            }
            return { text, ntohs(in6.sin6_port) };
        }

        // SO_LINGER 0 turns close() into a TCP reset, so nothing lingers for a dropped client
        void reset_and_close(int fd) {
            const linger no_linger{ 1, 0 };
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &no_linger, sizeof no_linger);
            close(fd);
        }

        // answers handed back by middleware callbacks, which may run on any thread (even inside submit()).
        // the callbacks share ownership, so a late callback after stop() still has a valid eventfd to poke
        struct Mailbox {
            int wake_fd = -1;
            std::mutex mutex;
            std::vector<std::pair<uint64_t, std::vector<std::byte>>> replies;

            ~Mailbox() {
                if (wake_fd >= 0) {
                    close(wake_fd);
                }
            }

            void post(uint64_t connection, std::vector<std::byte> wire) {
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    replies.emplace_back(connection, std::move(wire));
                }
                wake();
            }

            void wake() {
                const uint64_t one = 1;
                (void)!write(wake_fd, &one, sizeof one);
            }

            std::vector<std::pair<uint64_t, std::vector<std::byte>>> take() {
                uint64_t count = 0;
                (void)!read(wake_fd, &count, sizeof count);
                std::lock_guard<std::mutex> lock(mutex);
                return std::exchange(replies, {});
            }
        };

        enum class Ending {
            None,
            Close,
            CloseNotify,
            Reset
        };

        struct Connection {
            uint64_t id = 0;
            int fd      = -1;
            SSL* ssl    = nullptr;
            Peer peer;
            std::string source; // what max_connections_per_source counts: BlockList::key_for(peer.address)
            bool handshaken = false;
            DotFramer framer;
            std::vector<std::byte> unsent; // framed answers waiting for the socket
            std::size_t pending = 0;       // queries the middleware has not answered yet
            TimePoint last_active;         // accept, handshake done, a whole message in, or an answer out
            TimePoint last_sent;           // while unsent is not empty: when bytes last went out
            uint32_t interest      = 0;
            bool wants_write_event = false; // some TLS call returned WANT_WRITE
            bool write_wants_read  = false; // SSL_write needs to read first
            Ending ending          = Ending::None;

            ~Connection() { SSL_free(ssl); }
        };

    } // namespace

    struct DotServer::Impl {
        DotServerOptions opts;
        SSL_CTX* ctx;
        const Admission& admission;
        Middleware& middleware;

        int listen_fd                    = -1;
        int epoll_fd                     = -1;
        uint16_t bound_port              = 0;
        std::shared_ptr<Mailbox> mailbox = std::make_shared<Mailbox>();
        std::unordered_map<uint64_t, std::unique_ptr<Connection>> connections;
        std::unordered_map<std::string, std::size_t> per_source; // open connections per Connection::source
        uint64_t next_id = kFirstConnectionId;
        TimePoint accept_paused_until{};
        TimePoint next_idle_scan{};
        Ms grace{ 0 }; // set by stop() before stopping, read by the I/O thread after it
        std::atomic<bool> stopping{ false };
        std::atomic<std::size_t> count{ 0 };
        std::thread thread;

        Impl(DotServerOptions o, SSL_CTX* c, const Admission& a, Middleware& m) : opts(std::move(o)), ctx(c), admission(a), middleware(m) {}

        std::expected<void, std::string> open();
        void run();
        void accept_all(TimePoint now);
        void service(Connection& c, TimePoint now);
        void handshake(Connection& c, TimePoint now);
        void read_frames(Connection& c, TimePoint now);
        void handle_message(Connection& c, std::span<const std::byte> message, TimePoint now);
        void queue_reply(Connection& c, const std::vector<std::byte>& wire, TimePoint now);
        void flush(Connection& c, TimePoint now);
        void update_interest(Connection& c);
        void deliver_replies(TimePoint now);
        void close_idle(TimePoint now);
        void stop_accepting();
        bool drained(TimePoint now, TimePoint deadline);
        void finish(uint64_t id);
        void close_fds();
    };

    std::expected<void, std::string> DotServer::Impl::open() {
        // a client closing mid-write must not kill the process
        std::signal(SIGPIPE, SIG_IGN);

        const bool v6 = opts.host.find(':') != std::string::npos;
        sockaddr_storage addr{};
        socklen_t addr_len = 0;
        if (v6) {
            auto& in6       = reinterpret_cast<sockaddr_in6&>(addr);
            in6.sin6_family = AF_INET6;
            in6.sin6_port   = htons(opts.port);
            if (inet_pton(AF_INET6, opts.host.c_str(), &in6.sin6_addr) != 1) {
                return std::unexpected(std::format("listen host '{}' is not an IPv6 address", opts.host));
            }
            addr_len = sizeof in6;
        } else {
            auto& in      = reinterpret_cast<sockaddr_in&>(addr);
            in.sin_family = AF_INET;
            in.sin_port   = htons(opts.port);
            if (inet_pton(AF_INET, opts.host.c_str(), &in.sin_addr) != 1) {
                return std::unexpected(std::format("listen host '{}' is not an IPv4 address", opts.host));
            }
            addr_len = sizeof in;
        }

        const auto fail = [this](std::string_view what) {
            const std::string message = std::format("{} on {}:{}: {}", what, opts.host, opts.port, std::strerror(errno));
            close_fds();
            return std::unexpected(message);
        };

        listen_fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listen_fd < 0) {
            return fail("cannot create the listening socket");
        }
        const int one  = 1;
        const int zero = 0;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (v6) {
            setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero); // [::] takes IPv4 too
        }
        if (bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), addr_len) != 0) {
            return fail("cannot bind");
        }
        if (listen(listen_fd, SOMAXCONN) != 0) {
            return fail("cannot listen");
        }
        sockaddr_storage bound{};
        socklen_t bound_len = sizeof bound;
        getsockname(listen_fd, reinterpret_cast<sockaddr*>(&bound), &bound_len);
        bound_port = peer_of(bound).port;

        epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        // kept across stop() and start(): late callbacks from the last run may still hold the mailbox
        if (mailbox->wake_fd < 0) {
            mailbox->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        }
        if (epoll_fd < 0 || mailbox->wake_fd < 0) {
            return fail("cannot create epoll/eventfd");
        }
        epoll_event listen_event{ EPOLLIN, { .u64 = kListenTag } };
        epoll_event wake_event{ EPOLLIN, { .u64 = kWakeTag } };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &listen_event) != 0 || epoll_ctl(epoll_fd, EPOLL_CTL_ADD, mailbox->wake_fd, &wake_event) != 0) {
            return fail("cannot register with epoll");
        }
        return {};
    }

    void DotServer::Impl::close_fds() {
        if (listen_fd >= 0) {
            close(listen_fd);
            listen_fd = -1;
        }
        if (epoll_fd >= 0) {
            close(epoll_fd);
            epoll_fd = -1;
        }
    }

    void DotServer::Impl::run() {
        std::array<epoll_event, 64> events;
        TimePoint drain_deadline{};
        while (true) {
            const int n = epoll_wait(epoll_fd, events.data(), static_cast<int>(events.size()), kTickMs);
            if (n < 0 && errno != EINTR) {
                error("epoll_wait failed: {}", std::strerror(errno));
                break;
            }
            const TimePoint now = SteadyClock::now();
            for (int i = 0; i < n; ++i) {
                const uint64_t tag = events[i].data.u64;
                if (tag == kListenTag) {
                    accept_all(now);
                    continue;
                }
                if (tag == kWakeTag) {
                    deliver_replies(now);
                    continue;
                }
                const auto it = connections.find(tag);
                if (it == connections.end()) {
                    continue; // closed earlier in this batch
                }
                Connection& c = *it->second;
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    c.ending = Ending::Close;
                } else {
                    service(c, now);
                }
                if (c.ending != Ending::None) {
                    finish(c.id);
                } else {
                    update_interest(c);
                }
            }
            if (now >= next_idle_scan) {
                close_idle(now);
                next_idle_scan = now + Ms(kTickMs);
            }
            if (accept_paused_until != TimePoint{} && now >= accept_paused_until) {
                accept_paused_until = {};
                epoll_event listen_event{ EPOLLIN, { .u64 = kListenTag } };
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, listen_fd, &listen_event);
            }
            if (stopping.load()) {
                if (drain_deadline == TimePoint{}) {
                    stop_accepting();
                    drain_deadline = now + grace;
                }
                if (drained(now, drain_deadline)) {
                    break;
                }
            }
        }

        std::vector<uint64_t> ids;
        for (const auto& [id, c] : connections) {
            ids.push_back(id);
        }
        for (uint64_t id : ids) {
            connections.at(id)->ending = Ending::CloseNotify;
            finish(id);
        }
    }

    void DotServer::Impl::accept_all(TimePoint now) {
        while (true) {
            sockaddr_storage ss{};
            socklen_t len = sizeof ss;
            const int fd  = accept4(listen_fd, reinterpret_cast<sockaddr*>(&ss), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno == EINTR || errno == ECONNABORTED) {
                    continue;
                }
                if (errno == EMFILE || errno == ENFILE) {
                    // the listening socket stays readable, so stop watching it for a moment instead of spinning
                    warn("out of file descriptors, pausing accept() for {} ms", kAcceptBackoff.count());
                    epoll_event none{ 0, { .u64 = kListenTag } };
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, listen_fd, &none);
                    accept_paused_until = now + kAcceptBackoff;
                }
                return; // EAGAIN: nothing more to accept
            }

            Peer peer = peer_of(ss);
            if (middleware.is_blocked(peer.address)) {
                debug("dropping blocked source {} before the TLS handshake", peer.address);
                reset_and_close(fd);
                continue;
            }
            if (connections.size() >= opts.max_connections) {
                debug("max_connections ({}) reached, closing {}", opts.max_connections, peer.address);
                close(fd);
                continue;
            }
            // without this one host could hold every slot and lock everyone else out
            std::string source = BlockList::key_for(peer.address).value_or(peer.address);
            if (const auto it = per_source.find(source); opts.max_connections_per_source > 0 && it != per_source.end() &&
                                                         it->second >= opts.max_connections_per_source) {
                debug("max_connections_per_source ({}) reached, closing {}", opts.max_connections_per_source, peer.address);
                close(fd);
                continue;
            }

            const int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one); // answers are small and latency matters
            SSL* ssl = SSL_new(ctx);
            if (!ssl || SSL_set_fd(ssl, fd) != 1) {
                SSL_free(ssl);
                close(fd);
                continue;
            }
            auto c         = std::make_unique<Connection>();
            c->id          = next_id++;
            c->fd          = fd;
            c->ssl         = ssl;
            c->peer        = std::move(peer);
            c->source      = std::move(source);
            c->last_active = now;
            c->interest    = EPOLLIN;
            epoll_event event{ EPOLLIN, { .u64 = c->id } };
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
                close(fd);
                continue;
            }
            ++per_source[c->source];
            connections.emplace(c->id, std::move(c));
            count.store(connections.size());
        }
    }

    void DotServer::Impl::service(Connection& c, TimePoint now) {
        c.wants_write_event = false;
        c.write_wants_read  = false;
        if (!c.handshaken) {
            handshake(c, now);
            if (!c.handshaken || c.ending != Ending::None) {
                return;
            }
        }
        read_frames(c, now);
        if (c.ending == Ending::None) {
            flush(c, now);
        }
    }

    void DotServer::Impl::handshake(Connection& c, TimePoint now) {
        ERR_clear_error();
        const int r = SSL_accept(c.ssl);
        if (r == 1) {
            c.handshaken  = true;
            c.last_active = now;
            return;
        }
        const int err = SSL_get_error(c.ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            return;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            c.wants_write_event = true;
            return;
        }
        // a client that just goes away (a TCP health check, a port scan, one that rejects our certificate with
        // an alert) gets no strike; one that sends something that isn't TLS, or TLS we won't speak, does
        const int reason   = err == SSL_ERROR_SSL ? ERR_GET_REASON(ERR_peek_error()) : 0;
        const bool gave_up = err == SSL_ERROR_SYSCALL || err == SSL_ERROR_ZERO_RETURN || reason == SSL_R_UNEXPECTED_EOF_WHILE_READING ||
                             reason >= SSL_AD_REASON_OFFSET;
        debug("TLS handshake with {} failed: {}", c.peer.address, openssl_errors());
        if (!gave_up) {
            middleware.report_abuse(c.peer.address);
        }
        c.ending = Ending::Close;
    }

    void DotServer::Impl::read_frames(Connection& c, TimePoint now) {
        std::array<std::byte, kReadChunk> buf;
        while (true) {
            // answer what is already buffered first, as long as the pipeline has room
            while (c.ending == Ending::None && c.pending < opts.max_pending_per_connection) {
                std::vector<std::byte> message;
                const FrameStatus status = c.framer.next(message);
                if (status == FrameStatus::NeedMoreData) {
                    break;
                }
                if (status == FrameStatus::Invalid) {
                    debug("invalid DoT frame from {}", c.peer.address);
                    middleware.report_abuse(c.peer.address);
                    c.ending = Ending::Close;
                    return;
                }
                c.last_active = now; // only whole messages count, so trickling bytes can't hold a connection open
                handle_message(c, message, now);
            }
            if (c.ending != Ending::None || c.pending >= opts.max_pending_per_connection) {
                return; // paused: update_interest stops watching for input until answers go out
            }

            ERR_clear_error();
            const int n = SSL_read(c.ssl, buf.data(), static_cast<int>(buf.size()));
            if (n > 0) {
                c.framer.feed(std::span<const std::byte>(buf.data(), static_cast<std::size_t>(n)));
                continue;
            }
            const int err = SSL_get_error(c.ssl, n);
            if (err == SSL_ERROR_WANT_READ) {
                return;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                c.wants_write_event = true;
                return;
            }
            // SSL_ERROR_ZERO_RETURN is the client's clean close; anything else is a broken connection
            c.ending = Ending::Close;
            return;
        }
    }

    void DotServer::Impl::handle_message(Connection& c, std::span<const std::byte> message, TimePoint now) {
        // the source may have been blocked since it connected
        if (middleware.is_blocked(c.peer.address)) {
            debug("dropping {}: blocked mid-connection", c.peer.address);
            c.ending = Ending::Reset;
            return;
        }

        auto parsed = parse_query(message);
        if (!parsed) {
            const ParseError& e = parsed.error();
            auto reply          = encode_parse_error(e);
            if (!reply) {
                middleware.report_abuse(c.peer.address); // no ID to reply to, or not a query at all
                c.ending = Ending::Close;
                return;
            }
            if (!e.bad_edns_version && e.rcode == Rcode::FormErr) {
                middleware.report_abuse(c.peer.address);
            }
            queue_reply(c, *reply, now);
            return;
        }

        if (admission.refuses(*parsed)) {
            queue_reply(c, encode_response(*parsed, error_result(Rcode::Refused)), now);
            return;
        }

        ++c.pending;
        // the query is copied in: the answer is encoded on whichever thread delivers it
        middleware.submit(parsed->name, parsed->type, ClientInfo{ c.peer.address, c.peer.port, Transport::Dot },
                          [mailbox = mailbox, id = c.id, query = *parsed](ResolveResult result) { mailbox->post(id, encode_response(query, result)); });
    }

    void DotServer::Impl::queue_reply(Connection& c, const std::vector<std::byte>& wire, TimePoint now) {
        const auto framed = frame(wire);
        if (!framed) {
            return; // the encoder never produces more than 65535 bytes
        }
        if (c.unsent.empty()) {
            c.last_sent = now; // the stall clock starts when something is first left waiting
        }
        c.unsent.insert(c.unsent.end(), framed->begin(), framed->end());
        if (c.unsent.size() > opts.max_unsent_bytes) {
            debug("{} is not reading its answers, closing", c.peer.address);
            c.ending = Ending::Close;
        }
    }

    void DotServer::Impl::flush(Connection& c, TimePoint now) {
        while (!c.unsent.empty()) {
            ERR_clear_error();
            const int length = static_cast<int>(std::min<std::size_t>(c.unsent.size(), INT_MAX));
            const int n      = SSL_write(c.ssl, c.unsent.data(), length);
            if (n > 0) {
                c.unsent.erase(c.unsent.begin(), c.unsent.begin() + n);
                c.last_active = now;
                c.last_sent   = now;
                continue;
            }
            const int err = SSL_get_error(c.ssl, n);
            if (err == SSL_ERROR_WANT_WRITE) {
                c.wants_write_event = true;
                return;
            }
            if (err == SSL_ERROR_WANT_READ) {
                c.write_wants_read = true;
                return;
            }
            c.ending = Ending::Close;
            return;
        }
    }

    void DotServer::Impl::update_interest(Connection& c) {
        const bool paused = c.handshaken && c.pending >= opts.max_pending_per_connection;
        uint32_t want     = 0;
        if (!paused || c.write_wants_read) {
            want |= EPOLLIN;
        }
        if (c.wants_write_event) {
            want |= EPOLLOUT;
        }
        if (want != c.interest) {
            epoll_event event{ want, { .u64 = c.id } };
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, c.fd, &event);
            c.interest = want;
        }
    }

    void DotServer::Impl::deliver_replies(TimePoint now) {
        std::vector<uint64_t> touched;
        for (auto& [id, wire] : mailbox->take()) {
            const auto it = connections.find(id);
            if (it == connections.end()) {
                continue; // the client left before its answer came back
            }
            Connection& c = *it->second;
            if (c.pending > 0) {
                --c.pending;
            }
            queue_reply(c, wire, now);
            if (std::find(touched.begin(), touched.end(), id) == touched.end()) {
                touched.push_back(id);
            }
        }
        for (uint64_t id : touched) {
            Connection& c = *connections.at(id);
            if (c.ending == Ending::None) {
                service(c, now); // sends the answers, and resumes reading if the pipeline was full
            }
            if (c.ending != Ending::None) {
                finish(id);
            } else {
                update_interest(c);
            }
        }
    }

    void DotServer::Impl::close_idle(TimePoint now) {
        std::vector<std::pair<uint64_t, Ending>> expired;
        for (const auto& [id, c] : connections) {
            if (!c->unsent.empty()) {
                // answers are waiting but the client hasn't read any of them for a whole timeout
                if (now - c->last_sent >= opts.idle_timeout) {
                    expired.emplace_back(id, Ending::Reset);
                }
            } else if (c->pending == 0 && now - c->last_active >= opts.idle_timeout) {
                expired.emplace_back(id, Ending::CloseNotify);
            }
        }
        for (const auto& [id, ending] : expired) {
            Connection& c = *connections.at(id);
            if (ending == Ending::Reset) {
                debug("{} stopped reading its answers, resetting", c.peer.address);
            } else {
                debug("closing idle connection from {}", c.peer.address);
            }
            c.ending = ending;
            finish(id);
        }
    }

    // new clients are refused by the kernel from here on, instead of waiting in the backlog
    void DotServer::Impl::stop_accepting() {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, listen_fd, nullptr);
        close(listen_fd);
        listen_fd           = -1;
        accept_paused_until = {};
    }

    // closes the connections with nothing left to answer or send; true once none are left or the grace period is over
    bool DotServer::Impl::drained(TimePoint now, TimePoint deadline) {
        std::vector<uint64_t> done;
        for (const auto& [id, c] : connections) {
            if (c->pending == 0 && c->unsent.empty()) {
                done.push_back(id);
            }
        }
        for (uint64_t id : done) {
            connections.at(id)->ending = Ending::CloseNotify;
            finish(id);
        }
        return connections.empty() || now >= deadline;
    }

    void DotServer::Impl::finish(uint64_t id) {
        const auto it = connections.find(id);
        if (it == connections.end()) {
            return;
        }
        Connection& c = *it->second;
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c.fd, nullptr);
        if (c.ending == Ending::Reset) {
            reset_and_close(c.fd);
        } else {
            if (c.ending == Ending::CloseNotify && c.handshaken) {
                ERR_clear_error();
                SSL_shutdown(c.ssl); // one non-blocking attempt; the client may already be gone
            }
            close(c.fd);
        }
        if (const auto s = per_source.find(c.source); s != per_source.end() && --s->second == 0) {
            per_source.erase(s);
        }
        connections.erase(it);
        count.store(connections.size());
    }

    DotServerOptions dot_server_options(const Config& cfg) {
        DotServerOptions opts;
        opts.host                       = cfg.listen.host;
        opts.port                       = cfg.listen.port;
        opts.max_connections            = cfg.max_connections;
        opts.max_connections_per_source = cfg.max_connections_per_source;
        opts.idle_timeout               = cfg.idle_timeout;
        return opts;
    }

    DotServer::DotServer(DotServerOptions options, const TlsContext& tls, const Admission& admission, Middleware& middleware)
        : impl_(std::make_unique<Impl>(std::move(options), tls.get(), admission, middleware)) {}

    DotServer::~DotServer() {
        stop();
    }

    std::expected<void, std::string> DotServer::start() {
        if (impl_->thread.joinable()) {
            return {};
        }
        if (auto opened = impl_->open(); !opened) {
            return opened;
        }
        impl_->thread = std::thread([this] { impl_->run(); });
        info("DNS over TLS listening on {}:{}", impl_->opts.host, impl_->bound_port);
        return {};
    }

    void DotServer::stop(Ms grace) {
        if (!impl_->thread.joinable()) {
            return;
        }
        impl_->grace = grace;
        impl_->stopping.store(true);
        impl_->mailbox->wake();
        impl_->thread.join();
        impl_->close_fds();
        impl_->stopping.store(false); // so start() can run it again
    }

    uint16_t DotServer::port() const noexcept {
        return impl_->bound_port;
    }

    std::size_t DotServer::connection_count() const noexcept {
        return impl_->count.load();
    }

} // namespace mw
