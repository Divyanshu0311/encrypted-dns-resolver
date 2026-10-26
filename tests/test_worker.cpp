#include "mw/worker.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using mw::test::FakeClock;
using mw::test::FakeResolver;
using mw::test::eventually;

// collects what the worker hands to on_complete
struct Completions {
  std::mutex mutex;
  std::vector<mw::Rcode> rcodes;
  std::atomic<int> count{0};

  mw::CompletionFn fn() {
    return [this](const mw::QueryKey&, mw::ResolveResult r) {
      {
        std::lock_guard<std::mutex> lock(mutex);
        rcodes.push_back(r.rcode);
      }
      count.fetch_add(1);
    };
  }
  mw::Rcode last() {
    std::lock_guard<std::mutex> lock(mutex);
    return rcodes.back();
  }
};

struct Fixture {
  mw::Metrics metrics;
  FakeClock clock;
  std::shared_ptr<FakeResolver::State> state = std::make_shared<FakeResolver::State>();
  Completions done;
  std::unique_ptr<mw::Worker> worker;

  explicit Fixture(std::size_t capacity = 16, mw::WorkerTuning tuning = {}) {
    worker = std::make_unique<mw::Worker>(0, std::make_unique<FakeResolver>(state), capacity, done.fn(), tuning, metrics, clock.fn());
  }

  mw::Job job(const std::string& name = "example.com.") {
    return mw::Job{mw::QueryKey{mw::DomainName(name), mw::RecordType::A}, clock.now() + mw::Ms(1000)};
  }
};

struct QuietLogs {
  QuietLogs() { mw::set_log_level(mw::LogLevel::Error); }
  ~QuietLogs() { mw::set_log_level(mw::LogLevel::Info); }
};

} // namespace

TEST(Worker, NullResolverThrows) {
  mw::Metrics metrics;
  EXPECT_THROW(mw::Worker(0, nullptr, 4, [](const mw::QueryKey&, mw::ResolveResult) {}, {}, metrics, mw::steady_clock_fn()),
               std::invalid_argument);
}

TEST(Worker, ResolvesAndReports) {
  Fixture f;
  f.worker->start();
  ASSERT_SHOW_EQ(f.worker->try_submit(f.job()), true);
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 1; }));
  EXPECT_SHOW_EQ(f.done.last(), mw::Rcode::NoError);
  EXPECT_TRUE(eventually([&] { return f.worker->outstanding() == 0; }));
  EXPECT_SHOW_EQ(f.worker->stats().total_calls, 1u);
}

TEST(Worker, ThrowingResolverGivesServFail) {
  QuietLogs quiet;
  Fixture f;
  f.state->set_throws(true);
  f.worker->start();
  f.worker->try_submit(f.job());
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 1; }));
  EXPECT_SHOW_EQ(f.done.last(), mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(f.metrics.snapshot().resolver_exceptions, 1u);
  EXPECT_SHOW_EQ(f.worker->stats().total_failures, 1u);
}

TEST(Worker, ExpiredJobSkipsResolver) {
  Fixture f;
  f.worker->start();
  mw::Job late = f.job();
  late.deadline = f.clock.now(); // already due
  f.worker->try_submit(late);
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 1; }));
  EXPECT_SHOW_EQ(f.done.last(), mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(f.state->calls.load(), 0);
  EXPECT_SHOW_EQ(f.worker->stats().consecutive_failures, 0u); // not the resolver's fault
}

TEST(Worker, QueueFillsWhenNotStarted) {
  Fixture f(2);
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job("a.test.")), true);
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job("b.test.")), true);
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job("c.test.")), false);
  EXPECT_SHOW_EQ(f.worker->outstanding(), 2u);

  f.worker->start();
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 2; }));
  EXPECT_TRUE(eventually([&] { return f.worker->outstanding() == 0; }));
}

TEST(Worker, EwmaFollowsSamples) {
  Fixture f;
  f.worker->start();
  f.worker->try_submit(f.job());
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 1; }));
  // the fake clock never moves, so every sample is 0 ms
  EXPECT_SHOW_EQ(f.worker->ewma_ms(), 0.0);
}

TEST(Worker, BreakerOpensProbesAndCloses) {
  QuietLogs quiet;
  Fixture f(16, mw::WorkerTuning{3, mw::Ms(1000), 0.2});
  f.state->set_rcode(mw::Rcode::ServFail);
  f.worker->start();

  for (int i = 0; i < 3; ++i) {
    ASSERT_SHOW_EQ(f.worker->try_submit(f.job()), true);
    ASSERT_TRUE(eventually([&] { return f.done.count.load() == i + 1; }));
  }
  EXPECT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::Open);
  EXPECT_SHOW_EQ(f.worker->accepting(f.clock.now()), false);
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job()), false);

  // cooldown passes: exactly one probe is admitted
  f.clock.advance(mw::Ms(1000));
  EXPECT_SHOW_EQ(f.worker->accepting(f.clock.now()), true);
  f.state->close_gate(); // hold the probe so we can look at HalfOpen
  f.state->set_rcode(mw::Rcode::NoError);
  ASSERT_SHOW_EQ(f.worker->try_submit(f.job()), true);
  EXPECT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::HalfOpen);
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job()), false);

  // probe succeeds: closed again
  f.state->open_gate();
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 4; }));
  EXPECT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::Closed);
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job()), true);
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 5; }));
}

TEST(Worker, FailedProbeReopens) {
  QuietLogs quiet;
  Fixture f(16, mw::WorkerTuning{3, mw::Ms(1000), 0.2});
  f.state->set_rcode(mw::Rcode::ServFail);
  f.worker->start();
  for (int i = 0; i < 3; ++i) {
    f.worker->try_submit(f.job());
    ASSERT_TRUE(eventually([&] { return f.done.count.load() == i + 1; }));
  }
  f.clock.advance(mw::Ms(1000));
  ASSERT_SHOW_EQ(f.worker->try_submit(f.job()), true); // the probe, still failing
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 4; }));
  EXPECT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::Open);
  EXPECT_SHOW_EQ(f.worker->stats().breaker_trips, 2u); // opened, probe failed, opened again
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job()), false);
}

TEST(Worker, NxDomainIsNotAFailure) {
  Fixture f(16, mw::WorkerTuning{1, mw::Ms(1000), 0.2});
  f.state->set_rcode(mw::Rcode::NXDomain);
  f.worker->start();
  f.worker->try_submit(f.job());
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 1; }));
  EXPECT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::Closed);
}

TEST(Worker, ProbeSlotReturnedWhenQueueFull) {
  QuietLogs quiet;
  Fixture f(1, mw::WorkerTuning{1, mw::Ms(1000), 0.2});
  f.state->set_rcode(mw::Rcode::ServFail);
  f.worker->start();
  f.worker->try_submit(f.job());
  ASSERT_TRUE(eventually([&] { return f.done.count.load() == 1; }));
  ASSERT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::Open);
  f.worker->stop(); // nothing drains the queue from here on

  f.clock.advance(mw::Ms(1000));
  // the queue is closed now, so this push fails and the probe slot must come back
  EXPECT_SHOW_EQ(f.worker->try_submit(f.job()), false);
  EXPECT_SHOW_EQ(f.worker->stats().breaker, mw::BreakerState::Open);
  EXPECT_SHOW_EQ(f.worker->accepting(f.clock.now()), true);
}

TEST(Worker, StopWithQueuedJobsReturnsAndIsIdempotent) {
  Fixture f(8);
  f.state->close_gate();
  f.worker->start();
  for (int i = 0; i < 5; ++i) {
    f.worker->try_submit(f.job("q" + std::to_string(i) + ".test."));
  }
  ASSERT_TRUE(eventually([&] { return f.state->calls.load() == 1; }));
  f.state->open_gate(); // the running resolve() has to finish before stop() can join
  f.worker->stop();
  f.worker->stop();
  EXPECT_LT(f.done.count.load(), 5 + 1);
}
