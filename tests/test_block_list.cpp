#include "mw/block_list.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using mw::test::FakeClock;

namespace {

mw::BlockPolicy policy(uint32_t rate_limit_strikes = 3, uint32_t protocol_strikes = 10, std::size_t max_entries = 100) {
  mw::BlockPolicy p;
  p.rate_limit_strikes = rate_limit_strikes;
  p.protocol_strikes = protocol_strikes;
  p.window = mw::Ms(10000);
  p.duration = mw::Ms(60000);
  p.max_entries = max_entries;
  return p;
}

void strike_n(mw::BlockList& list, const std::string& ip, mw::Offence offence, int n) {
  for (int i = 0; i < n; ++i) {
    list.strike(ip, offence);
  }
}

} // namespace

TEST(BlockList, RejectsBadSettings) {
  FakeClock clock;
  auto zero_window = policy();
  zero_window.window = mw::Ms(0);
  auto zero_duration = policy();
  zero_duration.duration = mw::Ms(0);
  EXPECT_THROW(mw::BlockList(zero_window, clock.fn()), std::invalid_argument);
  EXPECT_THROW(mw::BlockList(zero_duration, clock.fn()), std::invalid_argument);
  EXPECT_THROW(mw::BlockList(policy(3, 10, 0), clock.fn()), std::invalid_argument);
  EXPECT_NO_THROW(mw::BlockList(mw::BlockPolicy{}, clock.fn()));
}

TEST(BlockList, DisabledByDefault) {
  FakeClock clock;
  mw::BlockList list(mw::BlockPolicy{}, clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 100);
  strike_n(list, "10.0.0.1", mw::Offence::Protocol, 100);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  EXPECT_SHOW_EQ(list.tracked_sources(), 0u);
}

TEST(BlockList, BlocksAtRateLimitThreshold) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::RateLimited), false);
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::RateLimited), false);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::RateLimited), true);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
}

TEST(BlockList, ProtocolStrikesHaveTheirOwnHigherThreshold) {
  FakeClock clock;
  mw::BlockList list(policy(3, 10), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::Protocol, 9);
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  EXPECT_SHOW_EQ_AS("9 protocol + 2 rate-limit strikes", list.is_blocked("10.0.0.1"), false);
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::Protocol), true);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
}

TEST(BlockList, DisablingOneOffenceLeavesTheOther) {
  FakeClock clock;
  mw::BlockList list(policy(0, 2), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 50);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  strike_n(list, "10.0.0.1", mw::Offence::Protocol, 2);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
}

TEST(BlockList, StrikesOutsideTheWindowAreForgotten) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  clock.advance(mw::Ms(10001));
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::RateLimited), true);
}

TEST(BlockList, BlockEndsAfterDuration) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 3);
  clock.advance(mw::Ms(59999));
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
  clock.advance(mw::Ms(1));
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
}

TEST(BlockList, StrikesDuringABlockDoNotExtendIt) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 3);
  clock.advance(mw::Ms(30000));
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::RateLimited), false);
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 5);
  clock.advance(mw::Ms(30000));
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
}

TEST(BlockList, StartsFreshAfterABlockEnds) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 3);
  clock.advance(mw::Ms(60000));
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  EXPECT_SHOW_EQ(list.strike("10.0.0.1", mw::Offence::RateLimited), true);
}

TEST(BlockList, SourcesAreIndependent) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 3);
  strike_n(list, "10.0.0.2", mw::Offence::RateLimited, 2);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.2"), false);
  EXPECT_SHOW_EQ(list.tracked_sources(), 2u);
}

TEST(BlockList, MappedIpv4SharesTheIpv4Entry) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  list.strike("::ffff:10.0.0.1", mw::Offence::RateLimited);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
  EXPECT_SHOW_EQ(list.is_blocked("::ffff:10.0.0.1"), true);
  EXPECT_SHOW_EQ(list.tracked_sources(), 1u);
}

TEST(BlockList, Ipv6IsBlockedPerSlash64) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  list.strike("2001:db8::1", mw::Offence::RateLimited);
  list.strike("2001:db8::2", mw::Offence::RateLimited);
  list.strike("2001:db8::ffff:3", mw::Offence::RateLimited);
  EXPECT_SHOW_EQ(list.is_blocked("2001:db8::abcd"), true);
  EXPECT_SHOW_EQ(list.is_blocked("2001:db8:0:1::1"), false);
}

TEST(BlockList, FullTableIgnoresNewcomers) {
  FakeClock clock;
  mw::BlockList list(policy(3, 10, 2), clock.fn());
  list.strike("10.0.0.1", mw::Offence::RateLimited);
  list.strike("10.0.0.2", mw::Offence::RateLimited);
  strike_n(list, "10.0.0.3", mw::Offence::RateLimited, 3);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.3"), false);
  EXPECT_SHOW_EQ(list.tracked_sources(), 2u);

  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  EXPECT_SHOW_EQ_AS("a source already tracked", list.is_blocked("10.0.0.1"), true);
}

TEST(BlockList, SweepRemovesExpiredEntriesButKeepsBlocks) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  list.strike("10.0.0.1", mw::Offence::RateLimited);
  strike_n(list, "10.0.0.2", mw::Offence::RateLimited, 3);
  clock.advance(mw::Ms(10001));
  strike_n(list, "10.0.0.3", mw::Offence::Protocol, 1024);
  EXPECT_SHOW_EQ_AS("10.0.0.1 swept, 10.0.0.2 and 10.0.0.3 kept", list.tracked_sources(), 2u);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.2"), true);
}

TEST(BlockList, NonAddressesAreNeverTracked) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  for (const std::string ip : {"", "not an ip", "10.0.0.1:53", "10.0.0.256"}) {
    strike_n(list, ip, mw::Offence::RateLimited, 3);
    EXPECT_SHOW_EQ_AS("is_blocked(\"" + ip + "\")", list.is_blocked(ip), false);
  }
  EXPECT_SHOW_EQ(list.tracked_sources(), 0u);
}

TEST(BlockList, KeyFor) {
  using mw::BlockList;
  EXPECT_SHOW_EQ(BlockList::key_for("10.0.0.1"), std::optional<std::string>(std::string("\x0a\x00\x00\x01", 4)));
  EXPECT_SHOW_EQ(BlockList::key_for("::ffff:10.0.0.1"), BlockList::key_for("10.0.0.1"));
  EXPECT_SHOW_EQ(BlockList::key_for("2001:db8::1"), std::optional<std::string>(std::string("\x20\x01\x0d\xb8\x00\x00\x00\x00", 8)));
  EXPECT_SHOW_EQ(BlockList::key_for("2001:db8::1"), BlockList::key_for("2001:db8::ffff:2"));
  EXPECT_SHOW_NE(BlockList::key_for("2001:db8::1"), BlockList::key_for("2001:db8:0:1::1"));
  EXPECT_SHOW_EQ(BlockList::key_for("garbage"), std::nullopt);
}

TEST(BlockList, ConcurrentReadersAndWriter) {
  FakeClock clock;
  mw::BlockList list(policy(3, 10, 100000), clock.fn());
  std::atomic<bool> done{false};
  std::vector<std::thread> readers;
  for (int t = 0; t < 4; ++t) {
    readers.emplace_back([&] {
      while (!done.load()) {
        list.is_blocked("10.0.0.1");
        list.tracked_sources();
      }
    });
  }
  for (int i = 0; i < 2000; ++i) {
    list.strike("10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256), mw::Offence::RateLimited);
  }
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  done.store(true);
  for (auto& r : readers) {
    r.join();
  }
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
}

TEST(BlockList, CountsBlockedSources) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 3);
  strike_n(list, "10.0.0.2", mw::Offence::RateLimited, 3);
  strike_n(list, "10.0.0.3", mw::Offence::RateLimited, 1); // tracked, not blocked
  EXPECT_SHOW_EQ(list.blocked_count(), 2u);
  clock.advance(mw::Ms(60001));
  EXPECT_SHOW_EQ(list.blocked_count(), 0u);
}

TEST(BlockList, UnblockLiftsTheBlockAndForgetsStrikes) {
  FakeClock clock;
  mw::BlockList list(policy(), clock.fn());
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 3);
  ASSERT_SHOW_EQ(list.is_blocked("10.0.0.1"), true);
  EXPECT_SHOW_EQ(list.unblock("10.0.0.1"), true);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  // strikes start again from zero
  strike_n(list, "10.0.0.1", mw::Offence::RateLimited, 2);
  EXPECT_SHOW_EQ(list.is_blocked("10.0.0.1"), false);
  EXPECT_SHOW_EQ(list.unblock("10.0.0.1"), false); // tracked but not blocked
  EXPECT_SHOW_EQ(list.unblock("not an ip"), false);
}
