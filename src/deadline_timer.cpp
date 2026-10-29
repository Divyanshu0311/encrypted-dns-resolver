#include "mw/deadline_timer.hpp"
#include<utility>

namespace mw {

DeadlineTimer::DeadlineTimer(Metrics& metrics) : metrics_(metrics) {
  thread_ = std::jthread([this](std::stop_token st) { run(st); });
}

DeadlineTimer::~DeadlineTimer() {
  stop();
}

void DeadlineTimer::schedule(TimePoint deadline, std::weak_ptr<Responder> r) {
  bool earliest;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    heap_.push(Entry{deadline, std::move(r)});
    earliest = heap_.top().deadline == deadline;
  }
  if (earliest)
    cv_.notify_one();
}

std::size_t DeadlineTimer::pending() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return heap_.size();
}

void DeadlineTimer::stop() {
  thread_.request_stop();
  if (thread_.joinable())
    thread_.join();
  std::lock_guard<std::mutex> lock(mutex_);
  heap_ = {};
}

void DeadlineTimer::run(std::stop_token st) {
  while (!st.stop_requested()) {
    std::vector<std::weak_ptr<Responder>> expired;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      if (heap_.empty()) {
        cv_.wait(lock, st, [this] { return !heap_.empty(); });
      }
      else {
        // wake at the deadline, or earlier if something sooner gets scheduled
        TimePoint next = heap_.top().deadline;
        cv_.wait_until(lock, st, next, [this, next] { return heap_.top().deadline < next; });
      }
      if (st.stop_requested())
        return;

      TimePoint now = SteadyClock::now();
      while (!heap_.empty() && heap_.top().deadline <= now) {
        expired.push_back(heap_.top().responder);
        heap_.pop();
      }
    }

    // never call fail() under mutex_: it runs front end code that may submit() again
    // and schedule a new deadline, which would deadlock
    for (auto& weak : expired) {
      if (auto r = weak.lock()) {
        if (r->fail(Rcode::ServFail, "timed out"))
          metrics_.on_timeout();
      }
    }
  }
}

} // namespace mw
