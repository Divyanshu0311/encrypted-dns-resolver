#pragma once
#include<cstddef>
#include<cstdint>
#include<mutex>
#include<string>
#include<unordered_map>

#include "mw/types.hpp"

// Will hold: mw::RateLimiter

namespace mw {

// token bucket per client address. with qps == 0 it allows everything
class RateLimiter {
  private:
    struct Bucket {
      double tokens;
      TimePoint last;
    };

    const double qps_;   // refill rate per second
    const double burst_; // bucket size
    Clock clock_;
    mutable std::mutex mutex_; // guards the map and the counter
    std::unordered_map<std::string, Bucket> buckets_;
    uint64_t calls_since_sweep_ = 0;

    static constexpr Ms kIdle{60000}; // idle time before a bucket is dropped
    static constexpr uint64_t kSweepEvery = 1024;

    void sweep(TimePoint now);

  public:
    RateLimiter(double qps, double burst, Clock clock);

    bool allow(const std::string& address);

    bool enabled() const noexcept { return qps_ > 0; }
    std::size_t tracked_clients() const;
};

} // namespace mw
