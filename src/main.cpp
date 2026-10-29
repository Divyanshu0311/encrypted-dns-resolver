#include <cstdio>
#include <exception>

#include "mw/config.hpp"
#include "mw/logger.hpp"

#ifdef __linux__
#include <csignal>
#include <optional>
#include <pthread.h>

#include "mw/admin_server.hpp"
#include "mw/admission.hpp"
#include "mw/dot_server.hpp"
#include "mw/middleware.hpp"
#include "mw/resolver_factory.hpp"
#include "mw/tls_context.hpp"
#endif

namespace {

#ifdef __linux__
    int serve(const mw::Config& cfg) {
        if (cfg.tls_cert.empty()) {
            mw::error("tls_cert and tls_key must be set to serve DNS over TLS");
            return 1;
        }
        auto tls = mw::TlsContext::create(cfg.tls_cert, cfg.tls_key);
        if (!tls) {
            mw::error("{}", tls.error());
            return 1;
        }
        auto admission = mw::Admission::load(cfg.blocked_domains_file);
        if (!admission) {
            mw::error("{}", admission.error());
            return 1;
        }

        // blocked before any thread starts, so every thread inherits the mask and sigwait() below gets them
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &signals, nullptr);

        mw::ResolverShared shared; // the cache and fault switch, also read by the admin page
        mw::Middleware middleware(cfg, mw::make_factory(cfg, std::nullopt, shared));
        middleware.start();
        mw::DotServer server(mw::dot_server_options(cfg), *tls, *admission, middleware);
        if (auto started = server.start(); !started) {
            mw::error("{}", started.error());
            middleware.stop(mw::Ms(0));
            return 1;
        }
        std::optional<mw::AdminServer> admin;
        if (cfg.admin_listen) {
            admin.emplace(cfg, middleware, *admission, shared);
            if (auto started = admin->start(); !started) {
                mw::error("{}", started.error());
                server.stop(mw::Ms(0));
                middleware.stop(mw::Ms(0));
                return 1;
            }
        }

        int sig = 0;
        sigwait(&signals, &sig);
        mw::info("{} received, shutting down", sig == SIGINT ? "SIGINT" : "SIGTERM");
        // stop accepting and let answers already being looked up go out, then fail whatever is left.
        // the admin page goes first: its requests use the middleware
        if (admin) admin->stop();
        server.stop(mw::Ms(2000));
        middleware.stop(mw::Ms(2000));
        return 0;
    }
#endif

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <config-file>\n", argv[0]);
        return 2;
    }
    auto cfg = mw::load_config(argv[1]);
    if (!cfg) {
        std::fprintf(stderr, "%s: %s\n", argv[1], cfg.error().c_str());
        return 1;
    }
    mw::set_log_level(cfg->log_level);
#ifdef __linux__
    try {
        return serve(*cfg);
    } catch (const std::exception& e) {
        mw::error("fatal: {}", e.what());
        return 1;
    }
#else
    std::fprintf(stderr, "the DNS-over-TLS server needs Linux (epoll)\n");
    return 1;
#endif
}
