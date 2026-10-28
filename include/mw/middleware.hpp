#pragma once
#include<atomic>
#include<memory>
#include<string_view>
#include<vector>

#include "mw/block_list.hpp"
#include "mw/config.hpp"
#include "mw/deadline_timer.hpp"
#include "mw/inflight_table.hpp"
#include "mw/load_balancer.hpp"
#include "mw/metrics.hpp"
#include "mw/query_log.hpp"
#include "mw/rate_limiter.hpp"
#include "mw/types.hpp"
#include "mw/worker.hpp"

// Will hold: mw::Middleware

namespace mw {

// the facade, and the only class the front end uses.
// the callback may run inside submit() on the caller's thread, or later on a worker or timer
// thread. it must be thread safe and must not need a lock the caller holds while calling submit()
class Middleware {
  private:
    // this exact order: destruction runs in reverse, so workers stop before the timer and table they use
    const Config config_;
    Clock clock_;
    Metrics metrics_;
    QueryLog query_log_;
    RateLimiter limiter_;
    BlockList blocklist_;
    InFlightTable inflight_;
    DeadlineTimer timer_;
    std::vector<std::unique_ptr<Worker>> workers_;
    std::unique_ptr<LoadBalancer> lb_; // built after the workers exist
    std::atomic<bool> started_{false};
    std::atomic<bool> stopping_{false};

    // worker threads
    void on_complete(const QueryKey& key, ResolveResult r);
    // caller's thread
    void log_replies(std::string_view name, RecordType type, const ClientInfo& client, ResultCallback& cb) noexcept;
    void reply_now(ResultCallback& cb, Rcode rc, const char* why) noexcept;

  public:
    // threads are not started here
    Middleware(Config config, ResolverFactory factory, Clock clock = steady_clock_fn());
    ~Middleware();

    Middleware(const Middleware&) = delete;
    Middleware& operator=(const Middleware&) = delete;

    void start();

    // never blocks, never throws. cb runs exactly once
    void submit(std::string_view name, RecordType type, ClientInfo client, ResultCallback cb) noexcept;

    // for the front end: check at accept(), before the TLS handshake, and again per query.
    // both fail open, so a broken block list never locks every client out
    bool is_blocked(std::string_view ip) const noexcept;
    // a bad frame, failed TLS handshake or malformed query from ip
    void report_abuse(std::string_view ip) noexcept;

    // idempotent. waits up to drain_timeout for in-flight lookups, then fails the rest
    void stop(Ms drain_timeout);

    MetricsSnapshot metrics_snapshot() const;
    // for a query the front end answered itself (a blocked domain), so it still shows in the query log
    void log_reply(std::string_view name, RecordType type, const ClientInfo& client, const ResolveResult& result) noexcept;
    // replies sent after seq `after`, every path included (rate limited, timed out, ...)
    std::vector<QueryLogEntry> recent_queries(uint64_t after) const;
    std::vector<WorkerStats> worker_stats() const;
};

} // namespace mw
