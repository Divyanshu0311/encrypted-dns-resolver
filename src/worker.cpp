#include "mw/worker.hpp"
#include<chrono>
#include<exception>
#include<stdexcept>
#include<utility>

#include "mw/logger.hpp"

namespace mw {

Worker::Worker(std::size_t id, std::unique_ptr<backend::Resolver> resolver, std::size_t queue_capacity, CompletionFn on_complete, WorkerTuning tuning,
               Metrics& metrics, Clock clock)
    : id_(id), resolver_(std::move(resolver)), queue_(queue_capacity), on_complete_(std::move(on_complete)), tuning_(tuning), metrics_(metrics),
      clock_(std::move(clock)) {
  if (!resolver_)
    throw std::invalid_argument("Worker needs a resolver");
}

Worker::~Worker() {
  stop();
}

void Worker::start() {
  if (thread_.joinable())
    return;
  thread_ = std::jthread([this](std::stop_token st) { run(st); });
}

void Worker::stop() {
  queue_.close();
  thread_.request_stop();
  if (thread_.joinable())
    thread_.join();
}

bool Worker::try_submit(Job job) {
  bool claimed_probe = false;
  if (!admit(clock_(), claimed_probe))
    return false;

  outstanding_.fetch_add(1, std::memory_order_relaxed);
  if (!queue_.try_push(std::move(job))) {
    outstanding_.fetch_sub(1, std::memory_order_relaxed);
    if (claimed_probe) {
      // give the probe slot back. open_until_ is kept so the next submit can probe again
      std::lock_guard<std::mutex> lock(breaker_mutex_);
      if (breaker_ == BreakerState::HalfOpen) {
        breaker_ = BreakerState::Open;
        probe_in_flight_ = false;
      }
    }
    return false;
  }
  return true;
}

bool Worker::accepting(TimePoint now) const {
  std::lock_guard<std::mutex> lock(breaker_mutex_);
  switch (breaker_) {
  case BreakerState::Closed: return true;
  case BreakerState::Open: return now >= open_until_;
  case BreakerState::HalfOpen: return false;
  }
  return false;
}

WorkerStats Worker::stats() const {
  WorkerStats s{};
  s.id = id_;
  s.outstanding = outstanding();
  s.ewma_ms = ewma_ms();
  s.total_calls = total_calls_.load(std::memory_order_relaxed);
  s.total_failures = total_failures_.load(std::memory_order_relaxed);
  s.breaker_trips = breaker_trips_.load(std::memory_order_relaxed);
  std::lock_guard<std::mutex> lock(breaker_mutex_);
  s.consecutive_failures = consecutive_failures_;
  s.breaker = breaker_;
  return s;
}

bool Worker::admit(TimePoint now, bool& claimed_probe) {
  std::lock_guard<std::mutex> lock(breaker_mutex_);
  switch (breaker_) {
  case BreakerState::Closed:
    return true;
  case BreakerState::Open:
    if (now < open_until_)
      return false;
    // cooldown over: this job is the probe
    breaker_ = BreakerState::HalfOpen;
    probe_in_flight_ = true;
    claimed_probe = true;
    return true;
  case BreakerState::HalfOpen:
    return false;
  }
  return false;
}

void Worker::run(std::stop_token st) {
  while (auto job = queue_.pop(st)) {
    TimePoint start = clock_();
    ResolveResult result;

    if (start >= job->deadline) {
      // too late to bother. not the resolver's fault so it is not a breaker failure, but
      // if this was the probe, reopen with no cooldown so the probe slot isn't lost
      result = error_result(Rcode::ServFail);
      std::lock_guard<std::mutex> lock(breaker_mutex_);
      if (breaker_ == BreakerState::HalfOpen) {
        breaker_ = BreakerState::Open;
        open_until_ = start;
        probe_in_flight_ = false;
      }
    }
    else {
      bool threw = false;
      try {
        result = resolver_->resolve(job->key.name, job->key.type, RecordClass::IN);
      }
      catch (const std::exception& e) {
        warn("worker {}: resolver threw for {}: {}", id_, std::string(job->key.name), e.what());
        threw = true;
      }
      catch (...) {
        warn("worker {}: resolver threw for {}", id_, std::string(job->key.name));
        threw = true;
      }
      if (threw) {
        metrics_.on_resolver_exception();
        result = error_result(Rcode::ServFail);
      }

      // NXDomain and NoError are successes, only ServFail (or a throw) counts against us
      bool failed = threw || result.rcode == Rcode::ServFail;

      TimePoint end = clock_();
      double sample = std::chrono::duration<double, std::milli>(end - start).count();
      if (total_calls_.load(std::memory_order_relaxed) == 0)
        ewma_ms_.store(sample, std::memory_order_relaxed);
      else
        ewma_ms_.store(tuning_.ewma_alpha * sample + (1 - tuning_.ewma_alpha) * ewma_ms_.load(std::memory_order_relaxed), std::memory_order_relaxed);
      total_calls_.fetch_add(1, std::memory_order_relaxed);
      if (failed)
        total_failures_.fetch_add(1, std::memory_order_relaxed);
      record_outcome(failed, end);
    }

    try {
      on_complete_(job->key, std::move(result));
    }
    catch (...) {
      warn("worker {}: completion handler threw", id_);
    }
    outstanding_.fetch_sub(1, std::memory_order_relaxed);
  }
}

void Worker::record_outcome(bool failed, TimePoint now) {
  std::lock_guard<std::mutex> lock(breaker_mutex_);
  switch (breaker_) {
  case BreakerState::Closed:
    if (!failed) {
      consecutive_failures_ = 0;
    }
    else if (++consecutive_failures_ >= tuning_.failure_threshold) {
      breaker_ = BreakerState::Open;
      open_until_ = now + tuning_.cooldown;
      breaker_trips_.fetch_add(1, std::memory_order_relaxed);
      warn("worker {}: breaker open after {} failures in a row", id_, consecutive_failures_);
    }
    break;
  case BreakerState::HalfOpen:
    // the first job to finish decides, even if it is not the probe
    if (!failed) {
      breaker_ = BreakerState::Closed;
      consecutive_failures_ = 0;
      info("worker {}: breaker closed", id_);
    }
    else {
      breaker_ = BreakerState::Open;
      open_until_ = now + tuning_.cooldown;
      breaker_trips_.fetch_add(1, std::memory_order_relaxed);
    }
    probe_in_flight_ = false;
    break;
  case BreakerState::Open:
    break;
  }
}

} // namespace mw
