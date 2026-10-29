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
//   GET  /api/status              configuration summary, the resolvers the server can switch between
//   GET  /api/metrics             counters, latency histogram, workers, cache, progress of the running tests
//   GET  /api/queries?after=N     the query log after seq N
//   GET  /api/lookup?name=&type=&via=   via = server (the full middleware path), recursive or upstream:IP:PORT
//   POST /api/resolver?id=              switches the resolver every worker uses (and flushes the cache)
//   POST /api/load?count=&concurrency=&names=popular|unique   a burst of queries through the middleware
//   POST /api/traffic?rate=&names=popular|mixed|unique        a steady stream until POST /api/traffic/stop
//   POST /api/abuse?client=IP&rate=&seconds=   one client sending at a steady rate (rate limiting, blocking)
//   POST /api/abuse/stop, /api/unblock?client=IP
//   POST /api/faults?fail_rate=0.5      makes that share of lookups fail, to trip the circuit breakers
//   POST /api/cache/flush               empties every cache
//   POST /api/tls/probe?ip=&port=853&name=   one TLS handshake: the certificate presented and whether it passed
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
