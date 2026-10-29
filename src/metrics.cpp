#include "mw/metrics.hpp"
#include<format>
#include<limits>

namespace mw {
namespace {

// upper bound of the first bucket where the running count reaches p * total
double percentile(const std::array<uint64_t, kLatencyBuckets>& buckets, uint64_t total, double p) {
  if (total == 0)
    return 0;
  double target = p * static_cast<double>(total);
  uint64_t running = 0;
  for (std::size_t i = 0; i < buckets.size(); i++) {
    running += buckets[i];
    if (static_cast<double>(running) >= target) {
      if (i == Metrics::kBucketUpperMs.size())
        return std::numeric_limits<double>::infinity();
      return static_cast<double>(Metrics::kBucketUpperMs[i]);
    }
  }
  return std::numeric_limits<double>::infinity();
}

std::string show_ms(double ms) {
  if (ms == std::numeric_limits<double>::infinity())
    return ">2000";
  return std::format("{}", ms);
}

} // namespace

void Metrics::record_reply(Rcode rc, Ms latency) {
  std::size_t slot = static_cast<std::size_t>(rc);
  if (slot >= kRcodeSlots - 1)
    slot = kRcodeSlots - 1;
  replies_by_rcode_[slot].fetch_add(1, std::memory_order_relaxed);

  std::size_t bucket = Metrics::kBucketUpperMs.size();
  for (std::size_t i = 0; i < Metrics::kBucketUpperMs.size(); i++) {
    if (latency.count() <= Metrics::kBucketUpperMs[i]) {
      bucket = i;
      break;
    }
  }
  latency_buckets_[bucket].fetch_add(1, std::memory_order_relaxed);
}

MetricsSnapshot Metrics::snapshot() const {
  MetricsSnapshot s;
  s.received = received_.load(std::memory_order_relaxed);
  s.rate_limited = rate_limited_.load(std::memory_order_relaxed);
  s.overload = overload_.load(std::memory_order_relaxed);
  s.timeouts = timeouts_.load(std::memory_order_relaxed);
  s.coalesced = coalesced_.load(std::memory_order_relaxed);
  s.resolver_exceptions = resolver_exceptions_.load(std::memory_order_relaxed);
  s.blocked_queries = blocked_queries_.load(std::memory_order_relaxed);
  s.blocks_started = blocks_started_.load(std::memory_order_relaxed);
  s.domain_refusals = domain_refusals_.load(std::memory_order_relaxed);
  for (std::size_t i = 0; i < kRcodeSlots; i++)
    s.replies_by_rcode[i] = replies_by_rcode_[i].load(std::memory_order_relaxed);
  for (std::size_t i = 0; i < kLatencyBuckets; i++) {
    s.latency_buckets[i] = latency_buckets_[i].load(std::memory_order_relaxed);
    s.total_replies += s.latency_buckets[i];
  }
  s.p50_ms = percentile(s.latency_buckets, s.total_replies, 0.50);
  s.p95_ms = percentile(s.latency_buckets, s.total_replies, 0.95);
  s.p99_ms = percentile(s.latency_buckets, s.total_replies, 0.99);
  return s;
}

std::string format_snapshot(const MetricsSnapshot& s) {
  static constexpr const char* kRcodeNames[kRcodeSlots] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "OTHER"};

  std::string out;
  out += std::format("received            {}\n", s.received);
  out += std::format("rate limited        {}\n", s.rate_limited);
  out += std::format("overload            {}\n", s.overload);
  out += std::format("timeouts            {}\n", s.timeouts);
  out += std::format("coalesced           {}\n", s.coalesced);
  out += std::format("resolver exceptions {}\n", s.resolver_exceptions);
  out += std::format("blocked queries     {}\n", s.blocked_queries);
  out += std::format("clients blocked     {}\n", s.blocks_started);
  out += std::format("domains refused     {}\n", s.domain_refusals);
  out += std::format("replies             {}\n", s.total_replies);
  for (std::size_t i = 0; i < kRcodeSlots; i++)
    out += std::format("  {:<17} {}\n", kRcodeNames[i], s.replies_by_rcode[i]);
  out += std::format("latency p50 {} ms, p95 {} ms, p99 {} ms\n", show_ms(s.p50_ms), show_ms(s.p95_ms), show_ms(s.p99_ms));
  out += "latency buckets\n";
  for (std::size_t i = 0; i < kLatencyBuckets; i++) {
    if (i < Metrics::kBucketUpperMs.size())
      out += std::format("  <= {:<5} ms {}\n", Metrics::kBucketUpperMs[i], s.latency_buckets[i]);
    else
      out += std::format("  >  2000  ms {}\n", s.latency_buckets[i]);
  }
  return out;
}

} // namespace mw
