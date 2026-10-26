#pragma once
#include<atomic>
#include<cstddef>
#include<cstdint>
#include<functional>
#include<memory>
#include<mutex>
#include<stop_token>
#include<thread>

#include "backend/Resolver.hpp"
#include "mw/bounded_queue.hpp"
#include "mw/metrics.hpp"
#include "mw/types.hpp"

// Will hold: mw::Worker

namespace mw {

struct Job {
  QueryKey key;
  TimePoint deadline;
};

using CompletionFn = std::function<void(const QueryKey&, ResolveResult)>;

// Closed: normal. Open: refuses all work until the cooldown passes.
// HalfOpen: one probe job decides whether it closes again
enum class BreakerState : uint8_t {
  Closed,
  Open,
  HalfOpen
};

struct WorkerTuning {
  uint32_t failure_threshold = 5;
  Ms cooldown{5000};
  double ewma_alpha = 0.2;
};

struct WorkerStats {
  std::size_t id;
  std::size_t outstanding;
  double ewma_ms;
  uint32_t consecutive_failures;
  uint64_t total_calls;
  uint64_t total_failures;
  uint64_t breaker_trips; // times the breaker went Open
  BreakerState breaker;
};

// one thread with its own queue and its own resolver chain. resolves jobs one at a time,
// tracks its own health and refuses work while its circuit breaker is open
class Worker {
  private:
    const std::size_t id_;
    std::unique_ptr<backend::Resolver> resolver_; // only used by the worker thread
    BoundedQueue<Job> queue_;
    CompletionFn on_complete_; // once per finished job
    const WorkerTuning tuning_;
    Metrics& metrics_;
    Clock clock_;

    std::atomic<std::size_t> outstanding_{0}; // queued or running
    std::atomic<double> ewma_ms_{0};          // 0 until the first sample
    std::atomic<uint64_t> total_calls_{0};
    std::atomic<uint64_t> total_failures_{0};
    std::atomic<uint64_t> breaker_trips_{0};

    mutable std::mutex breaker_mutex_; // guards the four below
    BreakerState breaker_ = BreakerState::Closed;
    uint32_t consecutive_failures_ = 0;
    TimePoint open_until_{};
    bool probe_in_flight_ = false;

    std::jthread thread_; // last

    // claimed_probe says whether this call took the half open probe slot
    bool admit(TimePoint now, bool& claimed_probe);
    void run(std::stop_token st);
    void record_outcome(bool failed, TimePoint now);

  public:
    // does not start the thread, so tests can fill the queue with nothing draining it
    Worker(std::size_t id, std::unique_ptr<backend::Resolver> resolver, std::size_t queue_capacity, CompletionFn on_complete, WorkerTuning tuning,
           Metrics& metrics, Clock clock);
    ~Worker();

    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;

    void start();
    // a resolve() already running can't be interrupted, so this waits for it
    void stop();

    bool try_submit(Job job);
    bool accepting(TimePoint now) const;

    std::size_t id() const noexcept { return id_; }
    std::size_t outstanding() const noexcept { return outstanding_.load(std::memory_order_relaxed); }
    double ewma_ms() const noexcept { return ewma_ms_.load(std::memory_order_relaxed); }
    WorkerStats stats() const;
};

} // namespace mw
