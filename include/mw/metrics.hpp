#pragma once
#include<array>
#include<atomic>
#include<cstddef>
#include<cstdint>
#include<string>

#include "mw/types.hpp"

// Will hold: mw::Metrics (lock free counters + latency histogram)

namespace mw {

// 11 bounded buckets plus one for everything above 2000 ms
inline constexpr std::size_t kLatencyBuckets = 12;
// one slot per rcode 0-5, the last one for anything else
inline constexpr std::size_t kRcodeSlots = 7;

// plain copy of the counters. not perfectly consistent, the counters are read one by one
struct MetricsSnapshot {
  uint64_t received = 0;
  uint64_t rate_limited = 0;
  uint64_t overload = 0;
  uint64_t timeouts = 0;
  uint64_t coalesced = 0;
  uint64_t resolver_exceptions = 0;
  uint64_t blocked_queries = 0;  // refused because the client is blocked
  uint64_t blocks_started = 0;   // clients that got blocked
  uint64_t domain_refusals = 0;  // refused because the name is on the blocked domains list
  std::array<uint64_t, kRcodeSlots> replies_by_rcode{};
  std::array<uint64_t, kLatencyBuckets> latency_buckets{};
  uint64_t total_replies = 0;
  double p50_ms = 0;
  double p95_ms = 0;
  double p99_ms = 0;
};

class Metrics {
  private:
    std::atomic<uint64_t> received_{0};
    std::atomic<uint64_t> rate_limited_{0};
    std::atomic<uint64_t> overload_{0};
    std::atomic<uint64_t> timeouts_{0};
    std::atomic<uint64_t> coalesced_{0};
    std::atomic<uint64_t> resolver_exceptions_{0};
    std::atomic<uint64_t> blocked_queries_{0};
    std::atomic<uint64_t> blocks_started_{0};
    std::atomic<uint64_t> domain_refusals_{0};
    std::array<std::atomic<uint64_t>, kRcodeSlots> replies_by_rcode_{};
    std::array<std::atomic<uint64_t>, kLatencyBuckets> latency_buckets_{};

  public:
    // a latency goes in the first bucket whose bound is >= it; above 2000 ms goes in the last one
    static constexpr std::array<std::int64_t, 11> kBucketUpperMs{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000};

    Metrics() = default;
    Metrics(const Metrics&) = delete;
    Metrics& operator=(const Metrics&) = delete;

    void on_received() { received_.fetch_add(1, std::memory_order_relaxed); }
    void on_rate_limited() { rate_limited_.fetch_add(1, std::memory_order_relaxed); }
    void on_overload() { overload_.fetch_add(1, std::memory_order_relaxed); }
    void on_timeout() { timeouts_.fetch_add(1, std::memory_order_relaxed); }
    void on_coalesced() { coalesced_.fetch_add(1, std::memory_order_relaxed); }
    void on_resolver_exception() { resolver_exceptions_.fetch_add(1, std::memory_order_relaxed); }
    void on_blocked_query() { blocked_queries_.fetch_add(1, std::memory_order_relaxed); }
    void on_block_started() { blocks_started_.fetch_add(1, std::memory_order_relaxed); }
    void on_domain_refused() { domain_refusals_.fetch_add(1, std::memory_order_relaxed); }

    // exactly once per reply delivered
    void record_reply(Rcode rc, Ms latency);

    MetricsSnapshot snapshot() const;
};

// multi line report. an infinite percentile prints as >2000
std::string format_snapshot(const MetricsSnapshot& s);

} // namespace mw
