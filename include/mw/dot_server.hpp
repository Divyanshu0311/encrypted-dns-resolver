#pragma once
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>

#include "mw/admission.hpp"
#include "mw/config.hpp"
#include "mw/middleware.hpp"
#include "mw/tls_context.hpp"
#include "mw/types.hpp"

namespace mw {

    struct DotServerOptions {
        std::string host            = "0.0.0.0";
        uint16_t port               = 853; // 0 picks a free port
        std::size_t max_connections = 1000;
        Ms idle_timeout{ 10000 };                            // only while nothing is outstanding; covers the handshake too
        std::size_t max_pending_per_connection = 100;        // at the cap, reading pauses until answers go out
        std::size_t max_unsent_bytes           = 256 * 1024; // a client that stops reading its answers is closed
    };

    DotServerOptions dot_server_options(const Config& cfg);

    // DNS over TLS (RFC 7858) on one epoll thread. Linux only.
    // blocked sources are reset at accept(), before any TLS work, and again before each query is handled
    class DotServer {
    public:
        DotServer(DotServerOptions options, const TlsContext& tls, const Admission& admission, Middleware& middleware);
        ~DotServer();

        DotServer(const DotServer&)            = delete;
        DotServer& operator=(const DotServer&) = delete;

        // binds, listens and starts the I/O thread. ignores SIGPIPE for the whole process
        std::expected<void, std::string> start();
        // idempotent; closes every connection
        void stop();

        uint16_t port() const noexcept; // the bound port, useful when options.port is 0
        std::size_t connection_count() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace mw
