#include "mw/rate_limiter.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <stdexcept>

using mw::test::FakeClock;

TEST(RateLimiter, RejectsBadSettings) {
  FakeClock clock;
  EXPECT_THROW(mw::RateLimiter(-1, 5, clock.fn()), std::invalid_argument);
  EXPECT_THROW(mw::RateLimiter(10, 0.5, clock.fn()), std::invalid_argument);
  EXPECT_NO_THROW(mw::RateLimiter(0, 0, clock.fn()));
}

TEST(RateLimiter, DisabledAllowsEverything) {
  FakeClock clock;
  mw::RateLimiter limiter(0, 0, clock.fn());
  EXPECT_SHOW_EQ(limiter.enabled(), false);
  int allowed = 0;
  for (int i = 0; i < 10000; ++i) {
    allowed += limiter.allow("10.0.0.1") ? 1 : 0;
  }
  EXPECT_SHOW_EQ(allowed, 10000);
  EXPECT_SHOW_EQ(limiter.tracked_clients(), 0u);
}

TEST(RateLimiter, BurstThenRefill) {
  FakeClock clock;
  mw::RateLimiter limiter(10, 5, clock.fn());
  for (int i = 0; i < 5; ++i) {
    EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), true);
  }
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), false);

  clock.advance(mw::Ms(100)); // 10 qps: one token per 100 ms
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), true);
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), false);
}

TEST(RateLimiter, RefillCapsAtBurst) {
  FakeClock clock;
  mw::RateLimiter limiter(10, 2, clock.fn());
  limiter.allow("10.0.0.1");
  clock.advance(mw::Ms(60000));
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), true);
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), true);
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), false);
}

TEST(RateLimiter, AddressesAreIndependent) {
  FakeClock clock;
  mw::RateLimiter limiter(1, 1, clock.fn());
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), true);
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.1"), false);
  EXPECT_SHOW_EQ(limiter.allow("10.0.0.2"), true);
  EXPECT_SHOW_EQ(limiter.tracked_clients(), 2u);
}

TEST(RateLimiter, IdleBucketsAreSwept) {
  FakeClock clock;
  mw::RateLimiter limiter(10, 5, clock.fn());
  limiter.allow("10.0.0.1");
  clock.advance(mw::Ms(61000));
  for (int i = 0; i < 1024; ++i) {
    limiter.allow("10.0.0.2");
  }
  EXPECT_SHOW_EQ(limiter.tracked_clients(), 1u);
}
