#include "mw/middleware.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using mw::test::FakeResolver;
using mw::test::eventually;

mw::Config test_config() {
  mw::Config cfg;
  cfg.mode = mw::Mode::Recursive;
  cfg.workers = 2;
  cfg.queue_capacity = 16;
  cfg.request_timeout = mw::Ms(2000);
  cfg.log_level = mw::LogLevel::Error; // keep expected warnings out of the test output
  return cfg;
}

// one slot per submit(): how many times its callback ran and with what
struct Replies {
  explicit Replies(std::size_t n) : calls(n), rcodes(n), answers(n) {}

  mw::ResultCallback cb(std::size_t i) {
    return [this, i](mw::ResolveResult r) {
      rcodes[i].store(r.rcode);
      answers[i].store(static_cast<int>(r.answer.size()));
      calls[i].fetch_add(1);
    };
  }
  int total() const {
    int sum = 0;
    for (const auto& c : calls) {
      sum += c.load();
    }
    return sum;
  }
  bool all_exactly_once() const {
    for (const auto& c : calls) {
      if (c.load() != 1) {
        return false;
      }
    }
    return true;
  }

  std::vector<std::atomic<int>> calls;
  std::vector<std::atomic<mw::Rcode>> rcodes;
  std::vector<std::atomic<int>> answers;
};

mw::ClientInfo client(const std::string& address = "10.0.0.1") {
  return mw::ClientInfo{address, 5353, mw::Transport::Udp};
}

} // namespace

TEST(Middleware, ResolvesAQuery) {
  auto state = std::make_shared<FakeResolver::State>();
  mw::Middleware m(test_config(), FakeResolver::factory(state));
  m.start();
  Replies replies(1);
  m.submit("example.com.", mw::RecordType::A, client(), replies.cb(0));
  ASSERT_TRUE(eventually([&] { return replies.total() == 1; }));
  EXPECT_SHOW_EQ(replies.rcodes[0].load(), mw::Rcode::NoError);
  EXPECT_SHOW_EQ(replies.answers[0].load(), 1);
  EXPECT_SHOW_EQ(m.metrics_snapshot().received, 1u);
  EXPECT_SHOW_EQ(m.worker_stats().size(), 2u);
}

TEST(Middleware, CoalescesIdenticalQueries) {
  auto state = std::make_shared<FakeResolver::State>();
  state->close_gate();
  mw::Middleware m(test_config(), FakeResolver::factory(state));
  m.start();

  Replies replies(50);
  {
    std::vector<std::jthread> threads;
    for (int t = 0; t < 5; ++t) {
      threads.emplace_back([&, t] {
        for (int i = 0; i < 10; ++i) {
          // different spellings of the same name all share one lookup
          const char* name = (i % 2 == 0) ? "example.com." : "Example.COM";
          m.submit(name, mw::RecordType::A, client(), replies.cb(static_cast<std::size_t>(t * 10 + i)));
        }
      });
    }
  }
  ASSERT_TRUE(eventually([&] { return state->calls.load() == 1; }));
  EXPECT_SHOW_EQ(replies.total(), 0);
  state->open_gate();

  ASSERT_TRUE(eventually([&] { return replies.total() == 50; }));
  EXPECT_SHOW_EQ(state->calls.load(), 1);
  EXPECT_SHOW_EQ(m.metrics_snapshot().coalesced, 49u);
  for (std::size_t i = 0; i < 50; ++i) {
    EXPECT_SHOW_EQ(replies.rcodes[i].load(), mw::Rcode::NoError);
    EXPECT_SHOW_EQ(replies.answers[i].load(), 1);
  }
}

TEST(Middleware, SlowResolverTimesOut) {
  auto state = std::make_shared<FakeResolver::State>();
  state->close_gate();
  auto cfg = test_config();
  cfg.request_timeout = mw::Ms(100);
  mw::Middleware m(cfg, FakeResolver::factory(state));
  m.start();

  Replies replies(1);
  const auto start = mw::SteadyClock::now();
  m.submit("slow.test.", mw::RecordType::A, client(), replies.cb(0));
  ASSERT_TRUE(eventually([&] { return replies.total() == 1; }));
  const auto elapsed = std::chrono::duration_cast<mw::Ms>(mw::SteadyClock::now() - start).count();
  EXPECT_GE(elapsed, 100);
  EXPECT_LE(elapsed, 400);
  EXPECT_SHOW_EQ(replies.rcodes[0].load(), mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(m.metrics_snapshot().timeouts, 1u);

  state->open_gate(); // the late answer is dropped, still exactly one callback
  ASSERT_TRUE(eventually([&] { return state->finished.load() == 1; }));
  m.stop(mw::Ms(500));
  EXPECT_SHOW_EQ(replies.calls[0].load(), 1);
}

TEST(Middleware, OverloadGivesServFail) {
  auto state = std::make_shared<FakeResolver::State>();
  state->close_gate();
  auto cfg = test_config();
  cfg.workers = 1;
  cfg.queue_capacity = 1;
  mw::Middleware m(cfg, FakeResolver::factory(state));
  m.start();

  Replies replies(3);
  m.submit("one.test.", mw::RecordType::A, client(), replies.cb(0));
  ASSERT_TRUE(eventually([&] { return state->calls.load() == 1; })); // running, queue empty again
  m.submit("two.test.", mw::RecordType::A, client(), replies.cb(1));   // fills the queue
  m.submit("three.test.", mw::RecordType::A, client(), replies.cb(2)); // nowhere to go

  EXPECT_SHOW_EQ(replies.calls[2].load(), 1); // answered inside submit()
  EXPECT_SHOW_EQ(replies.rcodes[2].load(), mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(m.metrics_snapshot().overload, 1u);

  state->open_gate();
  ASSERT_TRUE(eventually([&] { return replies.total() == 3; }));
  EXPECT_SHOW_EQ(replies.rcodes[0].load(), mw::Rcode::NoError);
  EXPECT_SHOW_EQ(replies.rcodes[1].load(), mw::Rcode::NoError);
}

TEST(Middleware, RateLimitRefuses) {
  auto state = std::make_shared<FakeResolver::State>();
  auto cfg = test_config();
  cfg.rate_limit_qps = 1;
  cfg.rate_limit_burst = 1;
  mw::Middleware m(cfg, FakeResolver::factory(state));
  m.start();

  Replies replies(3);
  m.submit("a.test.", mw::RecordType::A, client("10.0.0.1"), replies.cb(0));
  m.submit("b.test.", mw::RecordType::A, client("10.0.0.1"), replies.cb(1));
  m.submit("c.test.", mw::RecordType::A, client("10.0.0.2"), replies.cb(2)); // own bucket
  ASSERT_TRUE(eventually([&] { return replies.total() == 3; }));
  EXPECT_SHOW_EQ(replies.rcodes[0].load(), mw::Rcode::NoError);
  EXPECT_SHOW_EQ(replies.rcodes[1].load(), mw::Rcode::Refused);
  EXPECT_SHOW_EQ(replies.rcodes[2].load(), mw::Rcode::NoError);
  EXPECT_SHOW_EQ(m.metrics_snapshot().rate_limited, 1u);
}

TEST(Middleware, InvalidNameIsFormErr) {
  auto state = std::make_shared<FakeResolver::State>();
  mw::Middleware m(test_config(), FakeResolver::factory(state));
  m.start();

  Replies replies(3);
  m.submit("a..b", mw::RecordType::A, client(), replies.cb(0));
  m.submit(".a.", mw::RecordType::A, client(), replies.cb(1));
  m.submit(std::string(64, 'a') + ".com.", mw::RecordType::A, client(), replies.cb(2));
  EXPECT_SHOW_EQ(replies.total(), 3); // all answered inside submit()
  for (std::size_t i = 0; i < 3; ++i) {
    EXPECT_SHOW_EQ(replies.rcodes[i].load(), mw::Rcode::FormErr);
  }
  EXPECT_SHOW_EQ(state->calls.load(), 0);
}

TEST(Middleware, SubmitBeforeStartOrAfterStopIsServFail) {
  auto state = std::make_shared<FakeResolver::State>();
  mw::Middleware m(test_config(), FakeResolver::factory(state));
  Replies replies(2);
  m.submit("example.com.", mw::RecordType::A, client(), replies.cb(0));
  EXPECT_SHOW_EQ(replies.calls[0].load(), 1);
  EXPECT_SHOW_EQ(replies.rcodes[0].load(), mw::Rcode::ServFail);

  m.start();
  m.stop(mw::Ms(0));
  m.submit("example.com.", mw::RecordType::A, client(), replies.cb(1));
  EXPECT_SHOW_EQ(replies.calls[1].load(), 1);
  EXPECT_SHOW_EQ(replies.rcodes[1].load(), mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(state->calls.load(), 0);
}

TEST(Middleware, StopFailsInFlightQueriesOnce) {
  auto state = std::make_shared<FakeResolver::State>();
  state->delay = mw::Ms(100);
  auto cfg = test_config();
  cfg.workers = 1;
  mw::Middleware m(cfg, FakeResolver::factory(state));
  m.start();

  Replies replies(4);
  m.submit("a.test.", mw::RecordType::A, client(), replies.cb(0));
  m.submit("b.test.", mw::RecordType::A, client(), replies.cb(1));
  m.submit("c.test.", mw::RecordType::A, client(), replies.cb(2));
  m.submit("c.test.", mw::RecordType::A, client(), replies.cb(3)); // coalesced follower
  ASSERT_TRUE(eventually([&] { return state->calls.load() == 1; }));

  m.stop(mw::Ms(0));
  m.stop(mw::Ms(0));
  EXPECT_TRUE(replies.all_exactly_once());
  EXPECT_SHOW_EQ(replies.rcodes[3].load(), mw::Rcode::ServFail);
}

TEST(Middleware, FactoryProblemsSurface) {
  EXPECT_THROW(mw::Middleware(test_config(), [] { return std::unique_ptr<backend::Resolver>(); }), std::runtime_error);
  EXPECT_THROW(mw::Middleware(test_config(), []() -> std::unique_ptr<backend::Resolver> { throw std::logic_error("no"); }),
               std::logic_error);
}

TEST(Middleware, ThrowingCallbackDoesNotBreakAnything) {
  auto state = std::make_shared<FakeResolver::State>();
  mw::Middleware m(test_config(), FakeResolver::factory(state));
  m.start();
  std::atomic<int> calls{0};
  m.submit("a..b", mw::RecordType::A, client(), [&](mw::ResolveResult) {
    calls.fetch_add(1);
    throw std::runtime_error("front end bug");
  });
  m.submit("example.com.", mw::RecordType::A, client(), [&](mw::ResolveResult) {
    calls.fetch_add(1);
    throw std::runtime_error("front end bug");
  });
  ASSERT_TRUE(eventually([&] { return calls.load() == 2; }));
}

// the most important property: every submit() gets exactly one callback, whichever path it takes
TEST(Middleware, EverySubmitGetsExactlyOneCallback) {
  auto state = std::make_shared<FakeResolver::State>();
  state->delay = mw::Ms(1);
  auto cfg = test_config();
  cfg.workers = 3;
  cfg.queue_capacity = 4;
  cfg.request_timeout = mw::Ms(50);
  cfg.rate_limit_qps = 2000;
  cfg.rate_limit_burst = 100;
  cfg.failure_threshold = 3;
  cfg.cooldown = mw::Ms(100);
  mw::Middleware m(cfg, FakeResolver::factory(state));

  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kPerThread = 500;
  Replies replies(kThreads * kPerThread + 1);
  m.submit("early.test.", mw::RecordType::A, client(), replies.cb(kThreads * kPerThread)); // before start
  m.start();
  {
    std::vector<std::jthread> threads;
    for (std::size_t t = 0; t < kThreads; ++t) {
      threads.emplace_back([&, t] {
        for (std::size_t i = 0; i < kPerThread; ++i) {
          const std::size_t slot = t * kPerThread + i;
          std::string name;
          switch (i % 5) {
          case 0: name = "hot" + std::to_string(i % 3) + ".test."; break; // coalescing
          case 1: name = "bad..name"; break;                                  // FormErr
          default: name = "host" + std::to_string(slot) + ".test."; break;    // unique
          }
          if (i == kPerThread / 2 && t == 0) {
            state->set_rcode(mw::Rcode::ServFail); // trip some breakers half way
          }
          const auto type = (i % 2 == 0) ? mw::RecordType::A : mw::RecordType::AAAA;
          m.submit(name, type, client("10.0.0." + std::to_string(t % 3)), replies.cb(slot));
        }
      });
    }
  }
  m.stop(mw::Ms(1000));
  EXPECT_TRUE(replies.all_exactly_once());
  EXPECT_SHOW_EQ(replies.total(), static_cast<int>(kThreads * kPerThread + 1));
  const auto s = m.metrics_snapshot();
  EXPECT_SHOW_EQ(s.received, kThreads * kPerThread + 1);
  EXPECT_SHOW_EQ(s.total_replies, kThreads * kPerThread + 1);
}
