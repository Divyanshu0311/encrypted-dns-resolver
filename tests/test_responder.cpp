#include "mw/responder.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

mw::QueryKey example_key() {
  return mw::QueryKey{mw::DomainName("example.com."), mw::RecordType::A};
}

} // namespace

TEST(Responder, CompletesOnce) {
  mw::Metrics metrics;
  mw::test::FakeClock clock;
  int calls = 0;
  mw::Rcode seen = mw::Rcode::NoError;
  auto r = std::make_shared<mw::Responder>(example_key(), mw::ClientInfo{"10.0.0.1", 53, mw::Transport::Udp},
                                           [&](mw::ResolveResult res) {
                                             ++calls;
                                             seen = res.rcode;
                                           },
                                           clock.now(), metrics, clock.fn());

  EXPECT_SHOW_EQ(r->is_done(), false);
  EXPECT_SHOW_EQ(r->complete(mw::error_result(mw::Rcode::NXDomain)), true);
  EXPECT_SHOW_EQ(r->complete(mw::error_result(mw::Rcode::NoError)), false);
  EXPECT_SHOW_EQ(r->fail(mw::Rcode::ServFail), false);
  EXPECT_SHOW_EQ(calls, 1);
  EXPECT_SHOW_EQ(seen, mw::Rcode::NXDomain);
  EXPECT_SHOW_EQ(r->is_done(), true);
  EXPECT_SHOW_EQ(metrics.snapshot().total_replies, 1u);
}

TEST(Responder, Accessors) {
  mw::Metrics metrics;
  mw::test::FakeClock clock;
  mw::Responder r(example_key(), mw::ClientInfo{"10.0.0.9", 4242, mw::Transport::Tcp}, [](mw::ResolveResult) {}, clock.now(),
                  metrics, clock.fn());
  EXPECT_SHOW_EQ(r.key(), example_key());
  EXPECT_SHOW_EQ(r.client().address, "10.0.0.9");
  EXPECT_SHOW_EQ(r.client().port, 4242);
}

TEST(Responder, RacingCompleteAndFailRunCallbackOnce) {
  for (int round = 0; round < 1000; ++round) {
    mw::Metrics metrics;
    std::atomic<int> calls{0};
    std::atomic<int> winners{0};
    auto r = std::make_shared<mw::Responder>(example_key(), mw::ClientInfo{}, [&](mw::ResolveResult) { calls.fetch_add(1); },
                                             mw::SteadyClock::now(), metrics, mw::steady_clock_fn());
    std::atomic<bool> go{false};
    {
      std::vector<std::jthread> threads;
      for (int t = 0; t < 16; ++t) {
        threads.emplace_back([&, t] {
          go.wait(false); // block, don't spin: spinning 16 threads crawls under TSan
          const bool won = (t % 2 == 0) ? r->complete(mw::error_result(mw::Rcode::NoError)) : r->fail(mw::Rcode::ServFail);
          if (won) {
            winners.fetch_add(1);
          }
        });
      }
      go.store(true);
      go.notify_all();
    }
    ASSERT_SHOW_EQ(calls.load(), 1);
    ASSERT_SHOW_EQ(winners.load(), 1);
  }
}

TEST(Responder, ThrowingCallbackDoesNotEscape) {
  mw::Metrics metrics;
  mw::test::FakeClock clock;
  auto r = std::make_shared<mw::Responder>(example_key(), mw::ClientInfo{}, [](mw::ResolveResult) { throw std::runtime_error("boom"); },
                                           clock.now(), metrics, clock.fn());
  mw::set_log_level(mw::LogLevel::Error); // keep the expected warning out of the output
  bool result = false;
  EXPECT_NO_THROW(result = r->complete(mw::error_result(mw::Rcode::NoError)));
  mw::set_log_level(mw::LogLevel::Info);
  EXPECT_SHOW_EQ(result, true);
}

TEST(Responder, RecordsLatencyFromClock) {
  mw::Metrics metrics;
  mw::test::FakeClock clock;
  auto r = std::make_shared<mw::Responder>(example_key(), mw::ClientInfo{}, [](mw::ResolveResult) {}, clock.now(), metrics, clock.fn());
  clock.advance(mw::Ms(150)); // 150 ms lands in the <= 200 ms bucket (index 7)
  r->complete(mw::error_result(mw::Rcode::NoError));
  const auto s = metrics.snapshot();
  EXPECT_SHOW_EQ(s.latency_buckets[7], 1u);
  EXPECT_SHOW_EQ(s.total_replies, 1u);
}
