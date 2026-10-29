#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <format>
#include <mutex>
#include <random>
#include <span>
#include <vector>

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "backend/Upstream.hpp"
#include "utils.hpp"

namespace backend {
    namespace {
        using Clock = std::chrono::steady_clock;

        class Socket : utils::immovable {
        private:
            int fd;

        public:
            explicit Socket(int fd) : fd(fd) {}
            ~Socket() {
                if (fd >= 0) ::close(fd);
            }
            int get() const noexcept { return fd; }
        };

        socklen_t to_sockaddr(const Endpoint& server, sockaddr_storage& out) {
            std::memset(&out, 0, sizeof(out));
            if (auto ipv4 = server.address.to_ipv4()) {
                auto* addr       = reinterpret_cast<sockaddr_in*>(&out);
                addr->sin_family = AF_INET;
                addr->sin_port   = htons(server.port);
                addr->sin_addr   = *ipv4;
                return sizeof(sockaddr_in);
            }
            auto* addr        = reinterpret_cast<sockaddr_in6*>(&out);
            addr->sin6_family = AF_INET6;
            addr->sin6_port   = htons(server.port);
            addr->sin6_addr   = *server.address.to_ipv6();
            return sizeof(sockaddr_in6);
        }

        bool retryable(int err) {
            return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
        }

        // true once fd is ready for events (or has an error the next call will report), false at the deadline
        bool wait_for(int fd, short events, Clock::time_point deadline) {
            while (true) {
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
                if (left <= 0) return false;
                pollfd p{ fd, events, 0 };
                const int n = ::poll(&p, 1, static_cast<int>(left));
                if (n > 0) return true;
                if (n == 0 || errno != EINTR) return false;
            }
        }

        uint16_t random_id() {
            thread_local std::mt19937 rng{ std::random_device{}() };
            return static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 0xFFFF)(rng));
        }

        struct Question {
            uint16_t id;
            const types::DomainName& name;
            types::RecordType type;
            types::RecordClass rclass;

            bool answered_by(const types::DnsResponse& response) const {
                return response.id == id && response.has_question && response.question == name && response.qtype == type && response.qclass == rclass;
            }
        };

        std::optional<types::DnsResponse> over_udp(const sockaddr_storage& addr, socklen_t addr_len, std::span<const std::byte> query, const Question& question,
                                                   Clock::time_point deadline) {
            Socket sock(::socket(addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (sock.get() < 0) return std::nullopt;
            // connected: the kernel drops datagrams from anyone else, and reports port unreachable as ECONNREFUSED
            if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) return std::nullopt;
            if (::send(sock.get(), query.data(), query.size(), 0) != static_cast<ssize_t>(query.size())) return std::nullopt;

            std::vector<std::byte> buffer(65535);
            while (wait_for(sock.get(), POLLIN, deadline)) {
                const ssize_t n = ::recv(sock.get(), buffer.data(), buffer.size(), 0);
                if (n < 0) {
                    if (retryable(errno)) continue;
                    return std::nullopt;
                }
                auto response = types::parse_response(std::span(buffer.data(), static_cast<std::size_t>(n)));
                if (response && question.answered_by(*response)) return response;
                // anything else may be a spoofing attempt: keep waiting for the real answer
            }
            return std::nullopt;
        }

        // connects the non-blocking stream socket fd, waiting until the deadline at most
        bool connect_stream(int fd, const sockaddr_storage& addr, socklen_t addr_len, Clock::time_point deadline) {
            if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), addr_len) == 0) return true;
            if (errno != EINPROGRESS) return false;
            if (!wait_for(fd, POLLOUT, deadline)) return false;
            int err       = 0;
            socklen_t len = sizeof(err);
            return ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0;
        }

        // RFC 1035 section 4.2.2: every message on a stream is prefixed with its two byte length
        std::vector<std::byte> frame(std::span<const std::byte> message) {
            std::vector<std::byte> framed;
            framed.reserve(message.size() + 2);
            framed.push_back(static_cast<std::byte>(message.size() >> 8));
            framed.push_back(static_cast<std::byte>(message.size() & 0xFF));
            framed.insert(framed.end(), message.begin(), message.end());
            return framed;
        }

        std::size_t frame_length(const std::array<std::byte, 2>& prefix) {
            return std::to_integer<std::size_t>(prefix[0]) << 8 | std::to_integer<std::size_t>(prefix[1]);
        }

        bool send_all(int fd, std::span<const std::byte> data, Clock::time_point deadline) {
            while (!data.empty()) {
                if (!wait_for(fd, POLLOUT, deadline)) return false;
                const ssize_t n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
                if (n < 0) {
                    if (retryable(errno)) continue;
                    return false;
                }
                data = data.subspan(static_cast<std::size_t>(n));
            }
            return true;
        }

        bool recv_all(int fd, std::span<std::byte> out, Clock::time_point deadline) {
            while (!out.empty()) {
                if (!wait_for(fd, POLLIN, deadline)) return false;
                const ssize_t n = ::recv(fd, out.data(), out.size(), 0);
                if (n == 0) return false;
                if (n < 0) {
                    if (retryable(errno)) continue;
                    return false;
                }
                out = out.subspan(static_cast<std::size_t>(n));
            }
            return true;
        }

        std::optional<types::DnsResponse> over_tcp(const sockaddr_storage& addr, socklen_t addr_len, std::span<const std::byte> query, const Question& question,
                                                   Clock::time_point deadline) {
            Socket sock(::socket(addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (sock.get() < 0) return std::nullopt;
            if (!connect_stream(sock.get(), addr, addr_len, deadline)) return std::nullopt;
            if (!send_all(sock.get(), frame(query), deadline)) return std::nullopt;

            std::array<std::byte, 2> length_bytes;
            if (!recv_all(sock.get(), length_bytes, deadline)) return std::nullopt;
            std::vector<std::byte> buffer(frame_length(length_bytes));
            if (!recv_all(sock.get(), buffer, deadline)) return std::nullopt;

            auto response = types::parse_response(buffer);
            if (!response || response->truncated || !question.answered_by(*response)) return std::nullopt;
            return response;
        }

        // ---- DNS-over-TLS ----

        // kept connections older than this are closed rather than reused: servers drop idle clients after a while
        constexpr auto kIdleLifetime = std::chrono::seconds(10);
        constexpr std::size_t kMaxIdle = 64;

        std::string name_text(const X509_NAME* name) {
            if (!name) return {};
            BIO* bio = BIO_new(BIO_s_mem());
            if (!bio) return {};
            X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
            char* data     = nullptr;
            const long len = BIO_get_mem_data(bio, &data);
            std::string out(data, static_cast<std::size_t>(std::max(0L, len)));
            BIO_free(bio);
            return out;
        }

        std::string time_text(const ASN1_TIME* time) {
            if (!time) return {};
            BIO* bio = BIO_new(BIO_s_mem());
            if (!bio) return {};
            ASN1_TIME_print(bio, time);
            char* data     = nullptr;
            const long len = BIO_get_mem_data(bio, &data);
            std::string out(data, static_cast<std::size_t>(std::max(0L, len)));
            BIO_free(bio);
            return out;
        }

        std::string ssl_error_text() {
            const unsigned long err = ERR_peek_last_error();
            ERR_clear_error();
            if (err == 0) return {};
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            return buf;
        }

        // after an SSL call returned ret: waits for what OpenSSL needs from the socket. false on a real error or at the deadline
        bool ssl_wait(SSL* ssl, int fd, int ret, Clock::time_point deadline) {
            switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_WANT_READ: return wait_for(fd, POLLIN, deadline);
            case SSL_ERROR_WANT_WRITE: return wait_for(fd, POLLOUT, deadline);
            default: return false;
            }
        }
    } // namespace

    struct TlsClient::Connection : utils::immovable {
        int fd   = -1;
        SSL* ssl = nullptr;
        std::string key; // which server, and for which name: only reused for the same pair
        Clock::time_point idle_since;
        bool healthy = false; // handshake done and no error since: a close_notify may be sent

        ~Connection() {
            if (ssl) {
                // a polite close_notify if the socket takes it right away, never a wait
                if (healthy) SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            if (fd >= 0) ::close(fd);
        }

        bool write_all(std::span<const std::byte> data, Clock::time_point deadline) {
            while (!data.empty()) {
                ERR_clear_error();
                std::size_t written = 0;
                const int ret       = SSL_write_ex(ssl, data.data(), data.size(), &written);
                if (ret == 1) {
                    data = data.subspan(written);
                    continue;
                }
                if (!ssl_wait(ssl, fd, ret, deadline)) return healthy = false;
            }
            return true;
        }

        enum class Read { Ok, Closed, Failed };

        // Closed: the server hung up before sending anything, as it does to connections it considers idle
        Read read_exact(std::span<std::byte> out, Clock::time_point deadline) {
            bool got_any = false;
            while (!out.empty()) {
                ERR_clear_error();
                std::size_t n = 0;
                const int ret = SSL_read_ex(ssl, out.data(), out.size(), &n);
                if (ret == 1) {
                    got_any = true;
                    out     = out.subspan(n);
                    continue;
                }
                const int err = SSL_get_error(ssl, ret);
                if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                    healthy = false;
                    return got_any ? Read::Failed : Read::Closed;
                }
                if (!ssl_wait(ssl, fd, ret, deadline)) {
                    healthy = false;
                    return Read::Failed;
                }
            }
            return Read::Ok;
        }
    };

    struct TlsClient::State {
        mutable std::mutex mutex;
        SSL_CTX* ctx = nullptr; // set once by configure, then only read
        Stats stats;
        std::vector<std::unique_ptr<Connection>> idle; // oldest first

        ~State() {
            idle.clear();
            if (ctx) SSL_CTX_free(ctx);
        }

        SSL_CTX* context() const {
            std::lock_guard lock(mutex);
            return ctx;
        }

        // a kept connection to key, if one is still usable
        std::unique_ptr<Connection> take(const std::string& key) {
            std::lock_guard lock(mutex);
            const auto now = Clock::now();
            std::erase_if(idle, [&](const auto& c) { return now - c->idle_since > kIdleLifetime; });
            for (auto it = idle.end(); it != idle.begin();) {
                --it;
                if ((*it)->key != key) continue;
                auto conn = std::move(*it);
                idle.erase(it);
                // readable while idle means the server closed it (or sent an alert): not worth trying
                pollfd p{ conn->fd, POLLIN, 0 };
                if (::poll(&p, 1, 0) != 0) return nullptr;
                return conn;
            }
            return nullptr;
        }

        void keep(std::unique_ptr<Connection> conn) {
            conn->idle_since = Clock::now();
            std::lock_guard lock(mutex);
            idle.push_back(std::move(conn));
            if (idle.size() > kMaxIdle) idle.erase(idle.begin());
        }

        template <typename F>
        void update(F f) {
            std::lock_guard lock(mutex);
            f(stats);
        }
    };

    TlsClient::TlsClient() : state(std::make_unique<State>()) {}
    TlsClient::~TlsClient() = default;

    std::expected<void, std::string> TlsClient::configure(const std::filesystem::path& ca_file) {
        std::lock_guard lock(state->mutex);
        if (state->ctx) return std::unexpected("TLS client is already configured");

        ERR_clear_error();
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return std::unexpected("cannot create a TLS context: " + ssl_error_text());
        // RFC 8310's strict privacy profile: TLS 1.2 at least, the certificate checked, no fallback
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        const bool loaded = ca_file.empty() ? SSL_CTX_set_default_verify_paths(ctx) == 1
                                            : SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), nullptr) == 1;
        if (!loaded) {
            const std::string why = ssl_error_text();
            SSL_CTX_free(ctx);
            if (ca_file.empty()) return std::unexpected("cannot load the system's trusted CAs: " + why);
            return std::unexpected(std::format("cannot load CA file '{}': {}", ca_file.string(), why));
        }
        // OpenSSL writes with write(), not send(MSG_NOSIGNAL): a server that hung up must not kill the process
        std::signal(SIGPIPE, SIG_IGN);
        state->ctx = ctx;
        return {};
    }

    bool TlsClient::configured() const {
        return state->context() != nullptr;
    }

    TlsClient::Stats TlsClient::stats() const {
        std::lock_guard lock(state->mutex);
        return state->stats;
    }

    std::unique_ptr<TlsClient::Connection> TlsClient::connect(const Endpoint& server, TimePoint deadline, Probe& out) {
        out.peer   = endpoint_label(server);
        auto fail  = [&](std::string why) {
            out.error = std::move(why);
            state->update([](Stats& s) { s.failed++; });
            return nullptr;
        };
        SSL_CTX* ctx = state->context();
        if (!ctx) return fail("TLS client not configured");

        const auto started = Clock::now();
        sockaddr_storage addr;
        const socklen_t addr_len = to_sockaddr(server, addr);
        auto conn                = std::make_unique<Connection>();
        conn->fd                 = ::socket(addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (conn->fd < 0) return fail(std::format("socket: {}", std::strerror(errno)));
        if (!connect_stream(conn->fd, addr, addr_len, deadline)) return fail("could not connect");
        out.connected = true;

        ERR_clear_error();
        conn->ssl = SSL_new(ctx);
        if (!conn->ssl || SSL_set_fd(conn->ssl, conn->fd) != 1) return fail("SSL_new: " + ssl_error_text());
        SSL_set_hostflags(conn->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (!server.tls_name.empty()) {
            // the name goes out as SNI too, so a server with several certificates picks the right one
            if (SSL_set_tlsext_host_name(conn->ssl, server.tls_name.c_str()) != 1 || SSL_set1_host(conn->ssl, server.tls_name.c_str()) != 1)
                return fail("bad certificate name '" + server.tls_name + "'");
        }
        else if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(conn->ssl), std::string(server.address).c_str()) != 1) {
            return fail("cannot check the certificate against " + std::string(server.address));
        }

        int ret;
        bool timed_out = false;
        while (ERR_clear_error(), (ret = SSL_connect(conn->ssl)) != 1) {
            if (!ssl_wait(conn->ssl, conn->fd, ret, deadline)) {
                timed_out = Clock::now() >= deadline;
                break;
            }
        }

        // what the server presented, even when it was refused: OpenSSL only records the peer certificate once it
        // passed, but the chain as received is kept either way, the server's own certificate first
        const STACK_OF(X509)* chain = SSL_get_peer_cert_chain(conn->ssl);
        if (const X509* cert = chain && sk_X509_num(chain) > 0 ? sk_X509_value(chain, 0) : nullptr) {
            out.subject   = name_text(X509_get_subject_name(cert));
            out.issuer    = name_text(X509_get_issuer_name(cert));
            out.not_after = time_text(X509_get0_notAfter(cert));
        }

        const long verify = SSL_get_verify_result(conn->ssl);
        if (ret != 1 && verify != X509_V_OK) {
            out.error = std::format("certificate rejected: {}", X509_verify_cert_error_string(verify));
            ERR_clear_error();
            state->update([&](Stats& s) {
                s.rejected++;
                s.last_rejected_peer = out.peer;
                s.last_rejection     = out.error;
            });
            return nullptr;
        }
        if (ret != 1) {
            const std::string why = ssl_error_text();
            return fail(timed_out ? "TLS handshake timed out" : why.empty() ? "TLS handshake failed" : "TLS handshake failed: " + why);
        }
        // SSL_VERIFY_PEER makes the handshake fail on a bad certificate; this is belt and braces
        if (verify != X509_V_OK || out.subject.empty()) return fail("TLS handshake finished without a verified certificate");

        conn->healthy    = true;
        out.verified     = true;
        out.protocol     = SSL_get_version(conn->ssl);
        out.cipher       = SSL_get_cipher_name(conn->ssl);
        out.handshake_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
        conn->key        = out.peer;
        state->update([&](Stats& s) {
            s.handshakes++;
            s.last_peer    = out.peer;
            s.last_subject = out.subject;
            s.last_issuer  = out.issuer;
        });
        return conn;
    }

    TlsClient::Probe TlsClient::probe(const Endpoint& server, std::chrono::milliseconds timeout) {
        Probe out;
        connect(server, Clock::now() + timeout, out);
        return out;
    }

    std::optional<types::DnsResponse> TlsClient::exchange(const Endpoint& server, std::span<const std::byte> query,
                                                          const std::function<bool(const types::DnsResponse&)>& matches, TimePoint deadline) {
        enum class Outcome { Answered, Stale, Failed };
        std::optional<types::DnsResponse> response;
        // one query on one connection. Stale: the server had already closed it, a new one may do better
        auto ask = [&](Connection& conn) {
            if (!conn.write_all(frame(query), deadline)) return Outcome::Stale;
            std::array<std::byte, 2> length_bytes;
            switch (conn.read_exact(length_bytes, deadline)) {
            case Connection::Read::Ok: break;
            case Connection::Read::Closed: return Outcome::Stale;
            case Connection::Read::Failed: return Outcome::Failed;
            }
            std::vector<std::byte> buffer(frame_length(length_bytes));
            if (conn.read_exact(buffer, deadline) != Connection::Read::Ok) return Outcome::Failed;
            response = types::parse_response(buffer);
            // a stream carries only our questions: anything else means the connection can't be trusted
            if (!response || response->truncated || !matches(*response)) {
                response.reset();
                return Outcome::Failed;
            }
            return Outcome::Answered;
        };
        auto answered = [&](std::unique_ptr<Connection> conn, bool reused) {
            state->keep(std::move(conn));
            state->update([&](Stats& s) {
                s.queries++;
                if (reused) s.reused++;
            });
            return std::move(response);
        };
        auto failed = [&] {
            state->update([](Stats& s) { s.failed++; });
            return std::nullopt;
        };

        if (auto kept = state->take(endpoint_label(server))) {
            const auto outcome = ask(*kept);
            if (outcome == Outcome::Answered) return answered(std::move(kept), true);
            if (outcome == Outcome::Failed) return failed();
        }
        Probe handshake;
        auto conn = connect(server, deadline, handshake);
        if (!conn) return std::nullopt; // connect counted it
        if (ask(*conn) != Outcome::Answered) return failed();
        return answered(std::move(conn), false);
    }

    std::string endpoint_label(const Endpoint& server) {
        const std::string ip = server.address;
        std::string out      = server.address.is_ipv6() ? std::format("[{}]:{}", ip, server.port) : std::format("{}:{}", ip, server.port);
        if (!server.tls_name.empty()) out += " (" + server.tls_name + ")";
        return out;
    }

    std::optional<types::DnsResponse> query_server(const Endpoint& server, const types::DomainName& name, const types::RecordType type,
                                                   const types::RecordClass rclass, const bool recursion_desired, const std::chrono::milliseconds timeout) {
        const Question question{ random_id(), name, type, rclass };
        // padding only helps where the query is encrypted: it hides the name's length from the upstream hop
        const auto query = types::encode_query(question.id, name, type, rclass, recursion_desired, server.tls ? types::kQueryPaddingBlock : 0);
        if (server.tls)
            return server.tls->exchange(server, query, [&](const types::DnsResponse& r) { return question.answered_by(r); }, Clock::now() + timeout);

        sockaddr_storage addr;
        const socklen_t addr_len = to_sockaddr(server, addr);
        auto response            = over_udp(addr, addr_len, query, question, Clock::now() + timeout);
        if (!response || !response->truncated) return response;
        // the server is up and has more to say than fits in a datagram
        return over_tcp(addr, addr_len, query, question, Clock::now() + timeout);
    }
} // namespace backend
