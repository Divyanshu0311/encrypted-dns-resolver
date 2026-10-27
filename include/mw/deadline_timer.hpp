#pragma once
#include<condition_variable>
#include<cstddef>
#include<memory>
#include<mutex>
#include<queue>
#include<stop_token>
#include<thread>
#include<vector>

#include "mw/metrics.hpp"
#include "mw/responder.hpp"
#include "mw/types.hpp"

// Will hold: mw::DeadlineTimer

namespace mw {

// one background thread that fails every request still unanswered at its deadline with
// ServFail. uses the real steady clock, wait_until needs real time
class DeadlineTimer {
  private:
    struct Entry {
      TimePoint deadline;
      std::weak_ptr<Responder> responder; // weak, so a finished request is not kept alive
    };
    // makes the priority queue a min heap
    struct Later {
      bool operator()(const Entry& a, const Entry& b) const { return a.deadline > b.deadline; }
    };

    std::priority_queue<Entry, std::vector<Entry>, Later> heap_;
    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    Metrics& metrics_;
    std::jthread thread_; // last, so everything above exists before the thread starts

    void run(std::stop_token st);

  public:
    explicit DeadlineTimer(Metrics& metrics);
    ~DeadlineTimer();

    DeadlineTimer(const DeadlineTimer&) = delete;
    DeadlineTimer& operator=(const DeadlineTimer&) = delete;

    void schedule(TimePoint deadline, std::weak_ptr<Responder> r);

    // entries still in the heap, some may already be completed
    std::size_t pending() const;

    // idempotent. remaining entries are dropped
    void stop();
};

} // namespace mw
