#ifndef TESTS_SUPPORT_FAKE_DOT_SERVER_HPP
#define TESTS_SUPPORT_FAKE_DOT_SERVER_HPP

// A DNS-over-TLS server on 127.0.0.1 for the upstream tests: the TLS server side of mw::TlsContext with the
// test's certificate, answering each query on a connection with whatever the handler returns. Connections stay
// open for more queries, as a real DoT server's do, until the client hangs up or drop_connections() is called.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "IP.hpp"
#include "dns_message.hpp"
#include "mw/tls_context.hpp"
#include "support/fake_dns_server.hpp"
#include "support/tls_cert.hpp"

namespace support {
    class FakeDotServer {
    public:
        // the messages to send back, each framed with its length (unless framed is false: then written as they
        // are and the connection closed). empty: stay silent, the client times out
        using Handler = std::function<std::vector<std::vector<std::byte>>(const types::DnsQuery& query)>;

        FakeDotServer(const mw::test::TestCert& cert, Handler handler, bool framed = true) : handler_(std::move(handler)), framed_(framed) {
            auto ctx = mw::TlsContext::create(cert.cert, cert.key);
            if (!ctx) throw std::runtime_error("FakeDotServer: " + ctx.error());
            ctx_ = ctx->get();
            SSL_CTX_up_ref(ctx_);

            listen_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            int one = 1;
            ::setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in addr{};
            addr.sin_family      = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::bind(listen_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(listen_, 16) != 0)
                throw std::runtime_error("FakeDotServer: cannot listen");
            socklen_t len = sizeof(addr);
            ::getsockname(listen_, reinterpret_cast<sockaddr*>(&addr), &len);
            port_   = ntohs(addr.sin_port);
            thread_ = std::thread([this] { accept_loop(); });
        }

        ~FakeDotServer() {
            stop_ = true;
            thread_.join();
            drop_connections();
            for (auto& t : workers_) t.join();
            ::close(listen_);
            SSL_CTX_free(ctx_);
        }

        FakeDotServer(const FakeDotServer&)            = delete;
        FakeDotServer& operator=(const FakeDotServer&) = delete;

        uint16_t port() const { return port_; }
        types::IP ip() const { return types::IP("127.0.0.1"); }
        int handshakes() const { return handshakes_.load(); } // completed TLS handshakes
        int queries() const { return queries_.load(); }

        std::string last_sni() const {
            std::lock_guard lock(mutex_);
            return last_sni_;
        }

        // hangs up on every open connection, as a server does to idle clients
        void drop_connections() {
            std::lock_guard lock(mutex_);
            for (int fd : open_) ::shutdown(fd, SHUT_RDWR);
        }

        // the usual reply: the question echoed, the result's sections, rcode
        static std::vector<std::vector<std::byte>> reply(const types::DnsQuery& query, const types::ResolveResult& result) {
            return { types::encode_response(query, result) };
        }

    private:
        Handler handler_;
        bool framed_;
        SSL_CTX* ctx_ = nullptr;
        int listen_   = -1;
        uint16_t port_ = 0;
        std::atomic<bool> stop_{ false };
        std::atomic<int> handshakes_{ 0 };
        std::atomic<int> queries_{ 0 };
        std::thread thread_;
        mutable std::mutex mutex_;
        std::vector<int> open_;
        std::vector<std::thread> workers_;
        std::string last_sni_;

        void accept_loop() {
            while (!stop_) {
                pollfd p{ listen_, POLLIN, 0 };
                if (::poll(&p, 1, 20) <= 0) continue;
                int fd = ::accept4(listen_, nullptr, nullptr, SOCK_CLOEXEC);
                if (fd < 0) continue;
                // a stuck read gives up instead of hanging the test
                timeval tv{ 2, 0 };
                ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                std::lock_guard lock(mutex_);
                open_.push_back(fd);
                workers_.emplace_back([this, fd] { serve(fd); });
            }
        }

        bool read_exact(SSL* ssl, void* out, std::size_t n) {
            auto* p = static_cast<unsigned char*>(out);
            while (n > 0) {
                std::size_t got = 0;
                if (SSL_read_ex(ssl, p, n, &got) != 1) return false;
                p += got;
                n -= got;
            }
            return true;
        }

        void serve(int fd) {
            SSL* ssl = SSL_new(ctx_);
            SSL_set_fd(ssl, fd);
            if (SSL_accept(ssl) == 1) {
                handshakes_++;
                if (const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) {
                    std::lock_guard lock(mutex_);
                    last_sni_ = sni;
                }
                while (!stop_) {
                    uint8_t prefix[2];
                    if (!read_exact(ssl, prefix, 2)) break;
                    std::vector<std::byte> msg(static_cast<std::size_t>(prefix[0] << 8 | prefix[1]));
                    if (!read_exact(ssl, msg.data(), msg.size())) break;
                    auto query = types::parse_query(msg);
                    if (!query) break;
                    queries_++;
                    for (const auto& out : handler_(*query)) {
                        if (framed_) {
                            const uint8_t len[2] = { static_cast<uint8_t>(out.size() >> 8), static_cast<uint8_t>(out.size() & 0xFF) };
                            SSL_write(ssl, len, 2);
                        }
                        SSL_write(ssl, out.data(), static_cast<int>(out.size()));
                    }
                    if (!framed_) break;
                }
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
            std::lock_guard lock(mutex_);
            std::erase(open_, fd);
            ::close(fd);
        }
    };
} // namespace support

#endif
