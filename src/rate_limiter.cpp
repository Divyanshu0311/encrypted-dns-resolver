#include "mw/rate_limiter.hpp"
#include<algorithm>
#include<chrono>
#include<stdexcept>
#include<utility>

namespace mw {

RateLimiter::RateLimiter(double qps, double burst, Clock clock) : qps_(qps), burst_(burst), clock_(std::move(clock)) {
  if (qps_ < 0)
    throw std::invalid_argument("RateLimiter qps must be >= 0");
  if (qps_ > 0 && burst_ < 1)
    throw std::invalid_argument("RateLimiter burst must be >= 1 when qps > 0");
}

bool RateLimiter::allow(const std::string& address) {
  if (!enabled())
    return true;

  TimePoint now = clock_();
  std::lock_guard<std::mutex> lock(mutex_);

  if (++calls_since_sweep_ >= kSweepEvery) {
    calls_since_sweep_ = 0;
    sweep(now);
  }

  // a new client starts with a full bucket
  auto [it, inserted] = buckets_.try_emplace(address, Bucket{burst_, now});
  Bucket& b = it->second;
  if (!inserted) {
    double seconds = std::chrono::duration<double>(now - b.last).count();
    b.tokens = std::min(burst_, b.tokens + seconds * qps_);
    b.last = now;
  }
  if (b.tokens >= 1) {
    b.tokens -= 1;
    return true;
  }
  return false;
}

std::size_t RateLimiter::tracked_clients() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return buckets_.size();
}

void RateLimiter::sweep(TimePoint now) {
  std::erase_if(buckets_, [now](const auto& entry) { return now - entry.second.last > kIdle; });
}

} // namespace mw
