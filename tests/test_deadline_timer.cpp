#include "mw/deadline_timer.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <vector>

namespace {

using namespace std::chrono_literals;

// a responder that remembers when (and with what) its callback ran
struct Probe {
  std::atomic<int> calls{0};
  std::atomic<mw::Rcode> rcode{mw::Rcode::NoError};
  std::atomic<mw::TimePoint> at{};
  std::shared_ptr<mw::Responder> responder;

  Probe(mw::Metrics& metrics, std::string name = "example.com.") {
    responder = std::make_shared<mw::Responder>(mw::QueryKey{mw::DomainName(name), mw::RecordType::A}, mw::ClientInfo{},
                                                [this](mw::ResolveResult r) {
                                                  rcode.store(r.rcode);
                                                  at.store(mw::SteadyClock::now());
                                                  calls.fetch_add(1);
                                                },
                                                mw::SteadyClock::now(), metrics, mw::steady_clock_fn());
  }
};

} // namespace

TEST(DeadlineTimer, FailsAtDeadline) {
  mw::Metrics metrics;
  mw::DeadlineTimer timer(metrics);
  Probe p(metrics);
  const auto start = mw::SteadyClock::now();
  timer.schedule(start + 30ms, p.responder);

  ASSERT_TRUE(mw::test::eventually([&] { return p.calls.load() == 1; }, mw::Ms(500)));
  const auto elapsed = std::chrono::duration_cast<mw::Ms>(p.at.load() - start).count();
  EXPECT_GE(elapsed, 30);
  EXPECT_LE(elapsed, 100);
  EXPECT_SHOW_EQ(p.rcode.load(), mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(metrics.snapshot().timeouts, 1u);
}

TEST(DeadlineTimer, CompletedResponderIsNotFailed) {
  mw::Metrics metrics;
  mw::DeadlineTimer timer(metrics);
  Probe p(metrics);
  timer.schedule(mw::SteadyClock::now() + 20ms, p.responder);
  p.responder->complete(mw::error_result(mw::Rcode::NoError));

  ASSERT_TRUE(mw::test::eventually([&] { return timer.pending() == 0; }, mw::Ms(500)));
  EXPECT_SHOW_EQ(p.calls.load(), 1);
  EXPECT_SHOW_EQ(p.rcode.load(), mw::Rcode::NoError);
  EXPECT_SHOW_EQ(metrics.snapshot().timeouts, 0u);
}

TEST(DeadlineTimer, ExpiredWeakPointerIsSkipped) {
  mw::Metrics metrics;
  mw::DeadlineTimer timer(metrics);
  {
    Probe p(metrics);
    timer.schedule(mw::SteadyClock::now() + 10ms, p.responder);
  } // responder destroyed here
  ASSERT_TRUE(mw::test::eventually([&] { return timer.pending() == 0; }, mw::Ms(500)));
  EXPECT_SHOW_EQ(metrics.snapshot().timeouts, 0u);
}

TEST(DeadlineTimer, FiresInDeadlineOrder) {
  mw::Metrics metrics;
  mw::DeadlineTimer timer(metrics);
  Probe late(metrics, "late.test.");
  Probe early(metrics, "early.test.");
  const auto now = mw::SteadyClock::now();
  timer.schedule(now + 50ms, late.responder);
  timer.schedule(now + 10ms, early.responder);

  ASSERT_TRUE(mw::test::eventually([&] { return late.calls.load() == 1 && early.calls.load() == 1; }, mw::Ms(500)));
  EXPECT_LT(early.at.load(), late.at.load());
  EXPECT_LT(std::chrono::duration_cast<mw::Ms>(early.at.load() - now).count(), 45);
  EXPECT_SHOW_EQ(metrics.snapshot().timeouts, 2u);
}

TEST(DeadlineTimer, DestroyWithPendingEntriesIsPrompt) {
  mw::Metrics metrics;
  Probe p(metrics);
  const auto start = mw::SteadyClock::now();
  {
    mw::DeadlineTimer timer(metrics);
    timer.schedule(start + std::chrono::hours(1), p.responder);
    EXPECT_SHOW_EQ(timer.pending(), 1u);
  }
  EXPECT_LT(std::chrono::duration_cast<mw::Ms>(mw::SteadyClock::now() - start).count(), 100);
  EXPECT_SHOW_EQ(p.calls.load(), 0);
}

TEST(DeadlineTimer, StopIsIdempotent) {
  mw::Metrics metrics;
  mw::DeadlineTimer timer(metrics);
  timer.stop();
  timer.stop();
  EXPECT_SHOW_EQ(timer.pending(), 0u);
}
