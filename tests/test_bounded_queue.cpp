#include "mw/bounded_queue.hpp"

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <thread>

namespace {

using namespace std::chrono_literals;

std::future<std::optional<int>> pop_async(mw::BoundedQueue<int>& q, std::stop_token st) {
  return std::async(std::launch::async, [&q, st] { return q.pop(st); });
}

} // namespace

TEST(BoundedQueue, ZeroCapacityThrows) {
  EXPECT_THROW(mw::BoundedQueue<int>(0), std::invalid_argument);
}

TEST(BoundedQueue, PushUntilFull) {
  mw::BoundedQueue<int> q(3);
  EXPECT_SHOW_EQ(q.capacity(), 3u);
  EXPECT_SHOW_EQ(q.try_push(1), true);
  EXPECT_SHOW_EQ(q.try_push(2), true);
  EXPECT_SHOW_EQ(q.try_push(3), true);
  EXPECT_SHOW_EQ(q.try_push(4), false);
  EXPECT_SHOW_EQ(q.size(), 3u);
}

TEST(BoundedQueue, FifoOrder) {
  mw::BoundedQueue<int> q(4);
  for (int i = 1; i <= 4; ++i) {
    q.try_push(i);
  }
  std::stop_source never;
  for (int i = 1; i <= 4; ++i) {
    EXPECT_SHOW_EQ(q.pop(never.get_token()), std::optional<int>(i));
  }
}

TEST(BoundedQueue, CloseWakesBlockedPop) {
  mw::BoundedQueue<int> q(1);
  std::stop_source never;
  auto popped = pop_async(q, never.get_token());
  std::this_thread::sleep_for(20ms);
  q.close();
  ASSERT_SHOW_EQ(popped.wait_for(100ms), std::future_status::ready);
  EXPECT_SHOW_EQ(popped.get(), std::nullopt);
}

TEST(BoundedQueue, StopRequestWakesBlockedPop) {
  mw::BoundedQueue<int> q(1);
  std::stop_source stop;
  auto popped = pop_async(q, stop.get_token());
  std::this_thread::sleep_for(20ms);
  stop.request_stop();
  ASSERT_SHOW_EQ(popped.wait_for(100ms), std::future_status::ready);
  EXPECT_SHOW_EQ(popped.get(), std::nullopt);
}

TEST(BoundedQueue, PopWakesOnPush) {
  mw::BoundedQueue<int> q(1);
  std::stop_source never;
  auto popped = pop_async(q, never.get_token());
  std::this_thread::sleep_for(20ms);
  q.try_push(7);
  ASSERT_SHOW_EQ(popped.wait_for(100ms), std::future_status::ready);
  EXPECT_SHOW_EQ(popped.get(), std::optional<int>(7));
}

TEST(BoundedQueue, CloseDrainsQueuedItemsAndRejectsNewOnes) {
  mw::BoundedQueue<int> q(3);
  q.try_push(1);
  q.try_push(2);
  q.close();
  EXPECT_SHOW_EQ(q.closed(), true);
  EXPECT_SHOW_EQ(q.try_push(3), false);

  std::stop_source never;
  EXPECT_SHOW_EQ(q.pop(never.get_token()), std::optional<int>(1));
  EXPECT_SHOW_EQ(q.pop(never.get_token()), std::optional<int>(2));
  EXPECT_SHOW_EQ(q.pop(never.get_token()), std::nullopt);
}

TEST(BoundedQueue, CloseIsIdempotent) {
  mw::BoundedQueue<int> q(1);
  q.close();
  q.close();
  EXPECT_SHOW_EQ(q.closed(), true);
}

TEST(BoundedQueue, MoveOnlyItems) {
  mw::BoundedQueue<std::unique_ptr<int>> q(1);
  EXPECT_SHOW_EQ(q.try_push(std::make_unique<int>(5)), true);
  std::stop_source never;
  auto item = q.pop(never.get_token());
  ASSERT_SHOW_EQ(item.has_value(), true);
  EXPECT_SHOW_EQ(**item, 5);
}
