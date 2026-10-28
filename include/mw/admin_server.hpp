#pragma once
#include<cstdint>
#include<expected>
#include<memory>
#include<string>

#include "mw/admission.hpp"
#include "mw/config.hpp"
#include "mw/middleware.hpp"
#include "mw/resolver_factory.hpp"

// Will hold: mw::AdminServer (the demo / admin web page and its JSON API)

namespace mw {

// A small HTTP/1.1 server for the admin page: serves admin_ui_dir/index.html and a JSON API.
//
//   GET  /api/status              configuration summary
//   GET  /api/metrics             counters, latency histogram, workers, cache, load test progress
//   GET  /api/queries?after=N     the query log after seq N
//   GET  /api/lookup?name=&type=&via=   via = server (the full middleware path), recursive or upstream:IP:PORT
//   POST /api/load?count=&concurrency=&names=popular|unique   starts a load test through the middleware
//   POST /api/flood?client=IP&count=N   one client sends N queries at once (rate limiting, blocking)
//   POST /api/faults?fail_rate=0.5      makes that share of lookups fail, to trip the circuit breakers
//   POST /api/cache/flush               empties every cache
//
// No TLS and no login: bind it to loopback. Requests whose Host isn't a loopback name are refused, so a web
// page can't reach it through DNS rebinding.
class AdminServer {
  private:
    struct Impl;
    std::shared_ptr<Impl> impl_; // shared with the request threads

  public:
    // middleware and admission must outlive stop()
    AdminServer(Config config, Middleware& middleware, const Admission& admission, ResolverShared shared);
    ~AdminServer();

    AdminServer(const AdminServer&) = delete;
    AdminServer& operator=(const AdminServer&) = delete;

    // binds and starts the accept thread. returns the bound port
    std::expected<uint16_t, std::string> start();

    // idempotent. stops accepting, cancels a running load test and waits for requests in progress
    void stop();
};

} // namespace mw
