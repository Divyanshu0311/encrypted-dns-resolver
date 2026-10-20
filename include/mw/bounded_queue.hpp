#pragma once
#include <mutex>
#include<condition_variable>
#include<cstdlib>
#include<deque>
#include<functional>
#include<stop_token>
#include<thread>
#include<stdexcept>
#include<cstddef>
#include<utility>
#include<optional>
// Will hold: mw::BoundedQueue

namespace mw {
template<typename T>
class BoundedQueue {
  private:
    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    std::deque<T> items_;
    const std::size_t capacity_;
    bool closed_;

  public:
  explicit BoundedQueue(std::size_t capacity) : capacity_(capacity) {
    if (capacity_ == 0) {
      throw std::invalid_argument("BoundedQueue capacity must be > 0");
    }
  }

  BoundedQueue(const BoundedQueue&) = delete;
  BoundedQueue& operator=(const BoundedQueue&) = delete;
  BoundedQueue(BoundedQueue&&) = delete;
  BoundedQueue& operator=(BoundedQueue&&) = delete;



};

} // namespace mw
