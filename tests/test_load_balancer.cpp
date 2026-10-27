#include "mw/load_balancer.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using mw::test::FakeClock;
using mw::test::FakeResolver;

// workers are built but never started, so their queues fill without draining
struct Pool {
  mw::Metrics metrics;
  FakeClock clock;
  std::shared_ptr<FakeResolver::State> state = std::make_shared<FakeResolver::State>();
  std::vector<std::unique_ptr<mw::Worker>> workers;

  Pool(std::size_t n, std::size_t capacity = 16, mw::WorkerTuning tuning = {}) {
    for (std::size_t i = 0; i < n; ++i) {
      workers.push_back(std::make_unique<mw::Worker>(i, std::make_unique<FakeResolver>(state), capacity,
                                                     [](const mw::QueryKey&, mw::ResolveResult) {}, tuning, metrics, clock.fn()));
    }
  }

  std::vector<mw::Worker*> raw() {
    std::vector<mw::Worker*> out;
    for (auto& w : workers) {
      out.push_back(w.get());
    }
    return out;
  }

  mw::Job job(const std::string& name = "example.com.") {
    return mw::Job{mw::QueryKey{mw::DomainName(name), mw::RecordType::A}, clock.now() + mw::Ms(1000)};
  }
};

} // namespace

TEST(LoadBalancer, RejectsEmptyOrNull) {
  FakeClock clock;
  EXPECT_THROW(mw::LoadBalancer({}, mw::LbPolicy::RoundRobin, clock.fn()), std::invalid_argument);
  EXPECT_THROW(mw::LoadBalancer({nullptr}, mw::LbPolicy::RoundRobin, clock.fn()), std::invalid_argument);
}

TEST(LoadBalancer, RoundRobinCycles) {
  Pool pool(3);
  mw::LoadBalancer lb(pool.raw(), mw::LbPolicy::RoundRobin, pool.clock.fn());
  EXPECT_SHOW_EQ(lb.policy(), mw::LbPolicy::RoundRobin);
  EXPECT_SHOW_EQ(lb.pick()->id(), 0u);
  EXPECT_SHOW_EQ(lb.pick()->id(), 1u);
  EXPECT_SHOW_EQ(lb.pick()->id(), 2u);
  EXPECT_SHOW_EQ(lb.pick()->id(), 0u);
}

TEST(LoadBalancer, LeastOutstandingPicksEmptiest) {
  Pool pool(3);
  mw::LoadBalancer lb(pool.raw(), mw::LbPolicy::LeastOutstanding, pool.clock.fn());
  EXPECT_SHOW_EQ(lb.pick()->id(), 0u); // all tied: lowest id

  pool.workers[0]->try_submit(pool.job());
  pool.workers[0]->try_submit(pool.job());
  pool.workers[1]->try_submit(pool.job());
  EXPECT_SHOW_EQ(lb.pick()->id(), 2u);

  pool.workers[2]->try_submit(pool.job());
  EXPECT_SHOW_EQ(lb.pick()->id(), 1u); // 1 and 2 tied at one job: lower id
}

TEST(LoadBalancer, OpenBreakerIsNeverPicked) {
  // threshold 1: a single failure opens the breaker. drive it by running each worker once
  Pool pool(2, 16, mw::WorkerTuning{1, mw::Ms(5000), 0.2});
  pool.state->set_rcode(mw::Rcode::ServFail);
  mw::set_log_level(mw::LogLevel::Error);
  pool.workers[0]->try_submit(pool.job());
  pool.workers[0]->start();
  ASSERT_TRUE(mw::test::eventually([&] { return pool.workers[0]->stats().breaker == mw::BreakerState::Open; }));

  mw::LoadBalancer lb(pool.raw(), mw::LbPolicy::LeastOutstanding, pool.clock.fn());
  for (int i = 0; i < 10; ++i) {
    EXPECT_SHOW_EQ(lb.pick()->id(), 1u);
  }

  pool.workers[1]->try_submit(pool.job());
  pool.workers[1]->start();
  ASSERT_TRUE(mw::test::eventually([&] { return pool.workers[1]->stats().breaker == mw::BreakerState::Open; }));
  mw::set_log_level(mw::LogLevel::Info);

  EXPECT_SHOW_EQ(lb.pick(), nullptr);
  EXPECT_SHOW_EQ(lb.submit(pool.job()), false);
}

TEST(LoadBalancer, SubmitFallsBackWhenFirstChoiceFull) {
  Pool pool(2, 1);
  mw::LoadBalancer lb(pool.raw(), mw::LbPolicy::RoundRobin, pool.clock.fn());
  ASSERT_SHOW_EQ(pool.workers[0]->try_submit(pool.job()), true); // worker 0 is now full

  EXPECT_SHOW_EQ(lb.submit(pool.job()), true); // round robin starts at 0, lands on 1
  EXPECT_SHOW_EQ(pool.workers[1]->outstanding(), 1u);
  EXPECT_SHOW_EQ(lb.submit(pool.job()), false); // both full now: overload
}

TEST(LoadBalancer, PowerOfTwoUsesEveryWorker) {
  Pool pool(4);
  mw::LoadBalancer lb(pool.raw(), mw::LbPolicy::PowerOfTwo, pool.clock.fn());
  std::set<std::size_t> seen;
  for (int i = 0; i < 1000; ++i) {
    seen.insert(lb.pick()->id());
  }
  EXPECT_SHOW_EQ(seen.size(), 4u);
}

TEST(LoadBalancer, PowerOfTwoSingleWorker) {
  Pool pool(1);
  mw::LoadBalancer lb(pool.raw(), mw::LbPolicy::PowerOfTwo, pool.clock.fn());
  EXPECT_SHOW_EQ(lb.pick()->id(), 0u);
  EXPECT_SHOW_EQ(lb.submit(pool.job()), true);
}
