#include "mw/metrics.hpp"

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <limits>
#include <string>
#include <thread>
#include <vector>

TEST(Metrics, FreshSnapshotIsAllZero) {
  mw::Metrics m;
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.received, 0u);
  EXPECT_SHOW_EQ(s.rate_limited, 0u);
  EXPECT_SHOW_EQ(s.overload, 0u);
  EXPECT_SHOW_EQ(s.timeouts, 0u);
  EXPECT_SHOW_EQ(s.coalesced, 0u);
  EXPECT_SHOW_EQ(s.resolver_exceptions, 0u);
  EXPECT_SHOW_EQ(s.total_replies, 0u);
  EXPECT_SHOW_EQ(s.p50_ms, 0.0);
  EXPECT_SHOW_EQ(s.p95_ms, 0.0);
  EXPECT_SHOW_EQ(s.p99_ms, 0.0);
}

TEST(Metrics, CountersIncrement) {
  mw::Metrics m;
  m.on_received();
  m.on_received();
  m.on_rate_limited();
  m.on_overload();
  m.on_timeout();
  m.on_coalesced();
  m.on_resolver_exception();
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.received, 2u);
  EXPECT_SHOW_EQ(s.rate_limited, 1u);
  EXPECT_SHOW_EQ(s.overload, 1u);
  EXPECT_SHOW_EQ(s.timeouts, 1u);
  EXPECT_SHOW_EQ(s.coalesced, 1u);
  EXPECT_SHOW_EQ(s.resolver_exceptions, 1u);
}

TEST(Metrics, LatencyBuckets) {
  mw::Metrics m;
  m.record_reply(mw::Rcode::NoError, mw::Ms(3));    // <= 5 ms bucket (index 2)
  m.record_reply(mw::Rcode::NoError, mw::Ms(2000)); // last bounded bucket (index 10)
  m.record_reply(mw::Rcode::NoError, mw::Ms(2500)); // overflow bucket (index 11)
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.latency_buckets[2], 1u);
  EXPECT_SHOW_EQ(s.latency_buckets[10], 1u);
  EXPECT_SHOW_EQ(s.latency_buckets[11], 1u);
  EXPECT_SHOW_EQ(s.total_replies, 3u);
}

TEST(Metrics, RepliesByRcode) {
  mw::Metrics m;
  m.record_reply(mw::Rcode::NoError, mw::Ms(1));
  m.record_reply(mw::Rcode::ServFail, mw::Ms(1));
  m.record_reply(mw::Rcode::Refused, mw::Ms(1));
  m.record_reply(mw::Rcode::NotAuth, mw::Ms(1)); // 9: goes in the "other" slot
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.replies_by_rcode[0], 1u);
  EXPECT_SHOW_EQ(s.replies_by_rcode[2], 1u);
  EXPECT_SHOW_EQ(s.replies_by_rcode[5], 1u);
  EXPECT_SHOW_EQ(s.replies_by_rcode[6], 1u);
}

TEST(Metrics, PercentilesMostlyFast) {
  mw::Metrics m;
  for (int i = 0; i < 100; ++i) {
    m.record_reply(mw::Rcode::NoError, mw::Ms(1));
  }
  m.record_reply(mw::Rcode::NoError, mw::Ms(900));
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.p50_ms, 1.0);
  EXPECT_SHOW_EQ(s.p99_ms, 1.0);
}

TEST(Metrics, PercentilesHalfSlow) {
  mw::Metrics m;
  for (int i = 0; i < 50; ++i) {
    m.record_reply(mw::Rcode::NoError, mw::Ms(1));
    m.record_reply(mw::Rcode::NoError, mw::Ms(900));
  }
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.p50_ms, 1.0);
  EXPECT_SHOW_EQ(s.p99_ms, 1000.0);
}

TEST(Metrics, PercentileInOverflowBucketIsInfinity) {
  mw::Metrics m;
  m.record_reply(mw::Rcode::NoError, mw::Ms(5000));
  const auto s = m.snapshot();
  EXPECT_SHOW_EQ(s.p50_ms, std::numeric_limits<double>::infinity());
  EXPECT_NE(mw::format_snapshot(s).find(">2000"), std::string::npos);
}

TEST(Metrics, ConcurrentIncrementsAreExact) {
  mw::Metrics m;
  {
    std::vector<std::jthread> threads;
    for (int t = 0; t < 8; ++t) {
      threads.emplace_back([&m] {
        for (int i = 0; i < 10000; ++i) {
          m.on_received();
        }
      });
    }
  }
  EXPECT_SHOW_EQ(m.snapshot().received, 80000u);
}

TEST(Metrics, FormatSnapshotMentionsCounters) {
  mw::Metrics m;
  m.on_received();
  m.record_reply(mw::Rcode::NoError, mw::Ms(1));
  const std::string text = mw::format_snapshot(m.snapshot());
  EXPECT_NE(text.find("received"), std::string::npos);
  EXPECT_NE(text.find("p50"), std::string::npos);
  EXPECT_NE(text.find("NOERROR"), std::string::npos);
}
