#include "mw/dot_server.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"
#include "support/temp_dir.hpp"
#include "support/tls_cert.hpp"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

    using mw::test::eventually;
    using mw::test::FakeResolver;

    constexpr uint16_t kTypeA     = 1;
    constexpr uint16_t kTypeHttps = 65;

    void put16(std::vector<std::byte>& out, uint16_t v) {
        out.push_back(static_cast<std::byte>(v >> 8));
        out.push_back(static_cast<std::byte>(v & 0xFF));
    }

    uint16_t get16(const std::vector<std::byte>& wire, std::size_t at) {
        return static_cast<uint16_t>(std::to_integer<uint16_t>(wire.at(at)) << 8 | std::to_integer<uint16_t>(wire.at(at + 1)));
    }

    // a standard query: RD set, one question, class IN, optionally an OPT record with the given version
    std::vector<std::byte> query(uint16_t id, const std::string& name, uint16_t type = kTypeA, int edns_version = -1) {
        std::vector<std::byte> out;
        put16(out, id);
        put16(out, 0x0100);
        put16(out, 1);
        put16(out, 0);
        put16(out, 0);
        put16(out, edns_version >= 0 ? 1 : 0);
        std::size_t start = 0;
        while (start < name.size()) {
            const auto dot          = name.find('.', start);
            const std::string label = name.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
            out.push_back(static_cast<std::byte>(label.size()));
            for (char c : label) {
                out.push_back(static_cast<std::byte>(c));
            }
            if (dot == std::string::npos) {
                break;
            }
            start = dot + 1;
        }
        out.push_back(std::byte{ 0 });
        put16(out, type);
        put16(out, 1);
        if (edns_version >= 0) {
            out.push_back(std::byte{ 0 });
            put16(out, 41);
            put16(out, 1232);
            out.push_back(std::byte{ 0 });
            out.push_back(static_cast<std::byte>(edns_version));
            put16(out, 0);
            put16(out, 0);
        }
        return out;
    }

    uint16_t rcode_of(const std::vector<std::byte>& reply) {
        return get16(reply, 2) & 0xF;
    }

    class DotClient {
    public:
        explicit DotClient(uint16_t port, int max_version = TLS1_3_VERSION) {
            ctx_ = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(ctx_, max_version);
            fd_ = socket(AF_INET, SOCK_STREAM, 0);
            const timeval timeout{ 2, 0 };
            setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
            setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            connected_ = connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0;
            ssl_       = SSL_new(ctx_);
            SSL_set_fd(ssl_, fd_);
            handshake_ok_ = connected_ && SSL_connect(ssl_) == 1;
        }

        ~DotClient() {
            SSL_free(ssl_);
            close(fd_);
            SSL_CTX_free(ctx_);
        }

        bool connected() const { return connected_; }
        bool handshake_ok() const { return handshake_ok_; }

        bool send(const std::vector<std::byte>& message) {
            std::vector<std::byte> framed;
            put16(framed, static_cast<uint16_t>(message.size()));
            framed.insert(framed.end(), message.begin(), message.end());
            return send_raw(framed);
        }

        bool send_raw(const std::vector<std::byte>& bytes) {
            return SSL_write(ssl_, bytes.data(), static_cast<int>(bytes.size())) == static_cast<int>(bytes.size());
        }

        // one framed answer; nullopt when the server closed the connection (or 2 s passed)
        std::optional<std::vector<std::byte>> receive() {
            std::vector<std::byte> length(2);
            if (!read_exactly(length)) {
                return std::nullopt;
            }
            std::vector<std::byte> message(get16(length, 0));
            if (!read_exactly(message)) {
                return std::nullopt;
            }
            return message;
        }

    private:
        bool read_exactly(std::vector<std::byte>& out) {
            std::size_t got = 0;
            while (got < out.size()) {
                const int n = SSL_read(ssl_, out.data() + got, static_cast<int>(out.size() - got));
                if (n <= 0) {
                    return false;
                }
                got += static_cast<std::size_t>(n);
            }
            return true;
        }

        SSL_CTX* ctx_      = nullptr;
        SSL* ssl_          = nullptr;
        int fd_            = -1;
        bool connected_    = false;
        bool handshake_ok_ = false;
    };

    mw::Config middleware_config() {
        mw::Config cfg;
        cfg.mode           = mw::Mode::Recursive;
        cfg.workers        = 2;
        cfg.queue_capacity = 64;
        cfg.log_level      = mw::LogLevel::Error;
        return cfg;
    }

    mw::DotServerOptions server_options() {
        mw::DotServerOptions opts;
        opts.host = "127.0.0.1";
        opts.port = 0;
        return opts;
    }

    // a running server on 127.0.0.1 with a fresh certificate and a fake resolver behind it
    struct Harness {
        support::TempDir dir;
        std::shared_ptr<FakeResolver::State> state = std::make_shared<FakeResolver::State>();
        std::optional<mw::TlsContext> tls;
        mw::Admission admission;
        std::unique_ptr<mw::Middleware> middleware;
        std::unique_ptr<mw::DotServer> server;

        explicit Harness(mw::Config cfg = middleware_config(), mw::DotServerOptions opts = server_options(), const std::string& blocked = "") {
            const auto cert = mw::test::make_test_cert(dir);
            auto context    = mw::TlsContext::create(cert.cert, cert.key);
            if (!context) {
                throw std::runtime_error(context.error());
            }
            tls.emplace(std::move(*context));
            auto parsed = mw::Admission::parse(blocked);
            if (!parsed) {
                throw std::runtime_error(parsed.error());
            }
            admission  = std::move(*parsed);
            middleware = std::make_unique<mw::Middleware>(cfg, FakeResolver::factory(state));
            middleware->start();
            server = std::make_unique<mw::DotServer>(opts, *tls, admission, *middleware);
            if (auto started = server->start(); !started) {
                throw std::runtime_error(started.error());
            }
        }

        ~Harness() {
            server->stop();
            middleware->stop(mw::Ms(500));
        }

        uint16_t port() const { return server->port(); }
    };

} // namespace

TEST(DotServer, AnswersAQuery) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send(query(0x1111, "example.com")));
    const auto reply = client.receive();
    ASSERT_TRUE(reply.has_value());
    EXPECT_SHOW_EQ(get16(*reply, 0), 0x1111);
    EXPECT_SHOW_EQ_AS("QR bit", (get16(*reply, 2) & 0x8000) != 0, true);
    EXPECT_SHOW_EQ(rcode_of(*reply), 0);
    EXPECT_SHOW_EQ_AS("answer count", get16(*reply, 6), 1);
}

TEST(DotServer, PipelinedQueriesAreAllAnswered) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    for (uint16_t id = 1; id <= 5; ++id) {
        ASSERT_TRUE(client.send(query(id, "q" + std::to_string(id) + ".example")));
    }
    std::set<uint16_t> ids;
    for (int i = 0; i < 5; ++i) {
        const auto reply = client.receive();
        ASSERT_TRUE(reply.has_value());
        ids.insert(get16(*reply, 0));
    }
    EXPECT_SHOW_EQ(ids, (std::set<uint16_t>{ 1, 2, 3, 4, 5 }));
}

TEST(DotServer, MalformedQueryGetsFormErrAndTheConnectionStays) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    auto broken = query(0x2222, "example.com");
    broken[5]   = std::byte{ 2 }; // two questions
    ASSERT_TRUE(client.send(broken));
    const auto formerr = client.receive();
    ASSERT_TRUE(formerr.has_value());
    EXPECT_SHOW_EQ(get16(*formerr, 0), 0x2222);
    EXPECT_SHOW_EQ(rcode_of(*formerr), 1);

    ASSERT_TRUE(client.send(query(0x2223, "example.com")));
    const auto answer = client.receive();
    ASSERT_TRUE(answer.has_value());
    EXPECT_SHOW_EQ(rcode_of(*answer), 0);
}

TEST(DotServer, UnsupportedTypeIsNotImp) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send(query(0x3333, "example.com", kTypeHttps)));
    const auto reply = client.receive();
    ASSERT_TRUE(reply.has_value());
    EXPECT_SHOW_EQ(rcode_of(*reply), 4);
}

TEST(DotServer, BadEdnsVersionGetsBadVers) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send(query(0x4444, "example.com", kTypeA, 1)));
    const auto reply = client.receive();
    ASSERT_TRUE(reply.has_value());
    EXPECT_SHOW_EQ(get16(*reply, 0), 0x4444);
    EXPECT_SHOW_EQ_AS("additional count (OPT)", get16(*reply, 10), 1);
    EXPECT_SHOW_EQ_AS("extended rcode byte (16 >> 4)", std::to_integer<int>(reply->at(12 + 5)), 1);
}

TEST(DotServer, UnreadableMessageClosesTheConnection) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send({ std::byte{ 1 }, std::byte{ 2 }, std::byte{ 3 } }));
    EXPECT_SHOW_EQ_AS("closed", client.receive().has_value(), false);
}

TEST(DotServer, ZeroLengthFrameClosesTheConnection) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send_raw({ std::byte{ 0 }, std::byte{ 0 } }));
    EXPECT_SHOW_EQ_AS("closed", client.receive().has_value(), false);
}

TEST(DotServer, BlockedDomainIsRefusedAndTheConnectionStays) {
    Harness h(middleware_config(), server_options(), "ads.example\n");
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send(query(0x5555, "x.ads.example")));
    const auto refused = client.receive();
    ASSERT_TRUE(refused.has_value());
    EXPECT_SHOW_EQ(rcode_of(*refused), 5);
    EXPECT_SHOW_EQ_AS("question echoed", get16(*refused, 4), 1);
    EXPECT_SHOW_EQ_AS("resolver never asked", h.state->calls.load(), 0);

    ASSERT_TRUE(client.send(query(0x5556, "example.com")));
    const auto answer = client.receive();
    ASSERT_TRUE(answer.has_value());
    EXPECT_SHOW_EQ(rcode_of(*answer), 0);
    EXPECT_SHOW_EQ_AS("no strike for a policy hit", h.middleware->is_blocked("127.0.0.1"), false);
}

TEST(DotServer, BlockedSourceIsDroppedBeforeTheHandshake) {
    auto cfg                   = middleware_config();
    cfg.block_protocol_strikes = 1;
    Harness h(cfg);
    h.middleware->report_abuse("127.0.0.1");

    DotClient client(h.port());
    EXPECT_SHOW_EQ_AS("TCP connect still works", client.connected(), true);
    EXPECT_SHOW_EQ(client.handshake_ok(), false);
    EXPECT_SHOW_EQ(h.server->connection_count(), 0u);
}

TEST(DotServer, FormErrStrikesBlockTheSource) {
    auto cfg                   = middleware_config();
    cfg.block_protocol_strikes = 2;
    Harness h(cfg);
    {
        DotClient client(h.port());
        ASSERT_TRUE(client.handshake_ok());
        auto broken = query(0x6666, "example.com");
        broken[5]   = std::byte{ 2 };
        for (int i = 0; i < 2; ++i) {
            ASSERT_TRUE(client.send(broken));
            ASSERT_TRUE(client.receive().has_value());
        }
        EXPECT_SHOW_EQ(h.middleware->is_blocked("127.0.0.1"), true);
        ASSERT_TRUE(client.send(query(0x6667, "example.com")));
        EXPECT_SHOW_EQ_AS("blocked mid-connection: dropped", client.receive().has_value(), false);
    }
    DotClient again(h.port());
    EXPECT_SHOW_EQ_AS("new connection", again.handshake_ok(), false);
}

TEST(DotServer, Tls12ClientIsRejected) {
    Harness h;
    DotClient client(h.port(), TLS1_2_VERSION);
    EXPECT_SHOW_EQ(client.handshake_ok(), false);
}

TEST(DotServer, IdleConnectionIsClosed) {
    auto opts         = server_options();
    opts.idle_timeout = mw::Ms(300);
    Harness h(middleware_config(), opts);
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    const auto start = std::chrono::steady_clock::now();
    EXPECT_SHOW_EQ_AS("closed", client.receive().has_value(), false);
    const auto waited = std::chrono::duration_cast<mw::Ms>(std::chrono::steady_clock::now() - start).count();
    EXPECT_GE(waited, 250);
    EXPECT_LE(waited, 1500);
}

TEST(DotServer, OutstandingQueryKeepsTheConnectionOpen) {
    auto opts         = server_options();
    opts.idle_timeout = mw::Ms(300);
    Harness h(middleware_config(), opts);
    h.state->close_gate();
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(client.send(query(0x7777, "slow.example")));
    std::this_thread::sleep_for(std::chrono::milliseconds(700));
    h.state->open_gate();
    const auto reply = client.receive();
    ASSERT_TRUE(reply.has_value());
    EXPECT_SHOW_EQ(get16(*reply, 0), 0x7777);
}

TEST(DotServer, MaxConnectionsClosesExtraClients) {
    auto opts            = server_options();
    opts.max_connections = 1;
    Harness h(middleware_config(), opts);
    DotClient first(h.port());
    ASSERT_TRUE(first.handshake_ok());
    DotClient second(h.port());
    EXPECT_SHOW_EQ(second.handshake_ok(), false);
    EXPECT_SHOW_EQ(h.server->connection_count(), 1u);
}

TEST(DotServer, FullPipelinePausesReading) {
    auto opts                       = server_options();
    opts.max_pending_per_connection = 2;
    Harness h(middleware_config(), opts);
    h.state->close_gate();
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    for (uint16_t id = 1; id <= 5; ++id) {
        ASSERT_TRUE(client.send(query(id, "p" + std::to_string(id) + ".example")));
    }
    ASSERT_TRUE(eventually([&] { return h.middleware->metrics_snapshot().received == 2; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_SHOW_EQ_AS("submitted while 2 are outstanding", h.middleware->metrics_snapshot().received, 2u);

    h.state->open_gate();
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(client.receive().has_value());
    }
    EXPECT_SHOW_EQ(h.middleware->metrics_snapshot().received, 5u);
}

TEST(DotServer, StopClosesConnections) {
    Harness h;
    DotClient client(h.port());
    ASSERT_TRUE(client.handshake_ok());
    ASSERT_TRUE(eventually([&] { return h.server->connection_count() == 1; }));
    h.server->stop();
    EXPECT_SHOW_EQ(h.server->connection_count(), 0u);
    EXPECT_SHOW_EQ_AS("closed", client.receive().has_value(), false);
}
