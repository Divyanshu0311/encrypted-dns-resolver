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
// fixed capacity, thread safe FIFO. push never blocks, pop blocks until there is an
// item, a stop request, or the queue is closed
template<typename T>
class BoundedQueue {
  private:
    mutable std::mutex mutex_;
    std::condition_variable_any cv_; // _any so wait() can take a stop_token
    std::deque<T> items_;
    const std::size_t capacity_;
    bool closed_ = false;

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

    // false if full or closed
    bool try_push(T item) {
      {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || items_.size() >= capacity_)
          return false;
        items_.push_back(std::move(item));
      }
      cv_.notify_one();
      return true;
    }

    // still hands out queued items after close() so the work drains.
    // nullopt on a stop request, or when closed and empty
    std::optional<T> pop(std::stop_token st) {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait(lock, st, [this] { return !items_.empty() || closed_; });
      if (st.stop_requested() || items_.empty())
        return std::nullopt;
      T item = std::move(items_.front());
      items_.pop_front();
      return item;
    }

    void close() {
      {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
      }
      cv_.notify_all();
    }

    std::size_t size() const {
      std::lock_guard<std::mutex> lock(mutex_);
      return items_.size();
    }

    std::size_t capacity() const noexcept { return capacity_; }

    bool closed() const {
      std::lock_guard<std::mutex> lock(mutex_);
      return closed_;
    }
};

} // namespace mw
