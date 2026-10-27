#pragma once

// Test doubles: FakeClock (time only moves when the test says so) and FakeResolver (a
// backend::Resolver whose answers, failures, delay and "gate" the test controls). The fake's
// state is shared, so the test keeps a handle after the Worker takes ownership of the resolver.

#include "backend/Resolver.hpp"
#include "mw/types.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace mw::test {

class FakeClock {
public:
  FakeClock() : now_(std::make_shared<std::atomic<TimePoint>>(TimePoint{} + std::chrono::hours(1))) {}

  Clock fn() const {
    return [now = now_] { return now->load(); };
  }
  TimePoint now() const { return now_->load(); }
  void advance(Ms by) { now_->store(now_->load() + by); }

private:
  std::shared_ptr<std::atomic<TimePoint>> now_;
};

class FakeResolver : public backend::Resolver {
public:
  struct State {
    std::mutex mutex;
    std::condition_variable cv;
    bool gate_open = true;   // closed: resolve() blocks until it opens
    Rcode rcode = Rcode::NoError;
    bool throws = false;
    Ms delay{0};
    std::atomic<int> calls{0};    // resolve() entered
    std::atomic<int> finished{0}; // resolve() returned or threw

    void close_gate() {
      std::lock_guard<std::mutex> lock(mutex);
      gate_open = false;
    }
    void open_gate() {
      {
        std::lock_guard<std::mutex> lock(mutex);
        gate_open = true;
      }
      cv.notify_all();
    }
    void set_rcode(Rcode rc) {
      std::lock_guard<std::mutex> lock(mutex);
      rcode = rc;
    }
    void set_throws(bool t) {
      std::lock_guard<std::mutex> lock(mutex);
      throws = t;
    }
  };

  explicit FakeResolver(std::shared_ptr<State> state) : state_(std::move(state)) {}

  // a factory whose resolvers all share one state
  static ResolverFactory factory(std::shared_ptr<State> state) {
    return [state]() -> std::unique_ptr<backend::Resolver> { return std::make_unique<FakeResolver>(state); };
  }

  types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                               const bool) override {
    state_->calls.fetch_add(1);
    struct Finished {
      State* s;
      ~Finished() { s->finished.fetch_add(1); }
    } finished{state_.get()};

    std::unique_lock<std::mutex> lock(state_->mutex);
    // bounded so a forgotten open_gate() fails the test instead of hanging it
    state_->cv.wait_for(lock, std::chrono::seconds(10), [this] { return state_->gate_open; });
    const Rcode rc = state_->rcode;
    const bool throws = state_->throws;
    const Ms delay = state_->delay;
    lock.unlock();

    if (delay.count() > 0) {
      std::this_thread::sleep_for(delay);
    }
    if (throws) {
      throw std::runtime_error("fake: resolver failure");
    }
    types::ResolveResult result{rc, {}, {}, {}};
    if (rc == Rcode::NoError) {
      result.answer.push_back({name, type, rclass, 30, {10, 0, 0, 1}});
    }
    return result;
  }

private:
  std::shared_ptr<State> state_;
};

// polls until pred() is true or the timeout passes; returns the final pred()
template <typename Pred>
bool eventually(Pred pred, Ms timeout = Ms(2000)) {
  const auto give_up = SteadyClock::now() + timeout;
  while (!pred()) {
    if (SteadyClock::now() >= give_up) {
      return pred();
    }
    std::this_thread::sleep_for(Ms(1));
  }
  return true;
}

} // namespace mw::test
