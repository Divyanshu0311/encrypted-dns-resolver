#include "mw/types.hpp"

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace {

// Minimal backend::Resolver subclass: records how it was called and whether it was destroyed.
class RecordingResolver : public backend::Resolver {
public:
  explicit RecordingResolver(bool* destroyed = nullptr) : destroyed_(destroyed) {}
  ~RecordingResolver() override {
    if (destroyed_ != nullptr) {
      *destroyed_ = true;
    }
  }

  types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type,
                               const types::RecordClass, const bool) override {
    last_name = std::string(name);
    last_type = type;
    return mw::error_result(mw::Rcode::NXDomain);
  }

  std::string last_name;
  mw::RecordType last_type = mw::RecordType::ANY;

private:
  bool* destroyed_;
};

std::uint16_t raw(mw::RecordType type) {
  return static_cast<std::uint16_t>(type);
}

mw::QueryKey key(const std::string& name, mw::RecordType type) {
  return mw::QueryKey{mw::DomainName(name), type};
}

} // namespace

// ---- aliases onto Arnav's types ----

TEST(Aliases, AreArnavsTypes) {
  static_assert(std::is_same_v<mw::RecordType, types::RecordType>);
  static_assert(std::is_same_v<mw::Rcode, types::Rcode>);
  static_assert(std::is_same_v<mw::ResolveResult, types::ResolveResult>);
  static_assert(std::is_same_v<mw::DomainName, types::DomainName>);
  SUCCEED();
}

TEST(RecordType, UnnamedValuesRoundTrip) {
  EXPECT_SHOW_EQ(raw(static_cast<mw::RecordType>(65)), 65);
  EXPECT_SHOW_EQ(raw(static_cast<mw::RecordType>(257)), 257);
  EXPECT_SHOW_EQ(raw(static_cast<mw::RecordType>(65535)), 65535);
}

// ---- error_result ----

TEST(ErrorResult, ServFailHasNoRecords) {
  const auto r = mw::error_result(mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(r.answer.size(), 0u);
  EXPECT_SHOW_EQ(r.authority.size(), 0u);
  EXPECT_SHOW_EQ(r.additional.size(), 0u);
}

TEST(ErrorResult, KeepsEveryRcode) {
  for (auto rc : {mw::Rcode::NoError, mw::Rcode::FormErr, mw::Rcode::ServFail,
                  mw::Rcode::NXDomain, mw::Rcode::NotImp, mw::Rcode::Refused}) {
    EXPECT_SHOW_EQ(mw::error_result(rc).rcode, rc);
  }
}

// ---- backend::Resolver / ResolverFactory ----

TEST(Resolver, CopyingIsDisabled) {
  static_assert(std::is_abstract_v<backend::Resolver>);
  static_assert(std::has_virtual_destructor_v<backend::Resolver>);
  static_assert(!std::is_copy_constructible_v<RecordingResolver>);
  static_assert(!std::is_copy_assignable_v<RecordingResolver>);
  SUCCEED();
}

TEST(Resolver, DispatchesThroughBasePointer) {
  std::unique_ptr<backend::Resolver> resolver = std::make_unique<RecordingResolver>();
  const auto result =
      resolver->resolve(mw::DomainName("example.com."), mw::RecordType::MX, mw::RecordClass::IN);

  EXPECT_SHOW_EQ(result.rcode, mw::Rcode::NXDomain);
  auto& concrete = static_cast<RecordingResolver&>(*resolver);
  EXPECT_SHOW_EQ(concrete.last_name, "example.com.");
  EXPECT_SHOW_EQ(concrete.last_type, mw::RecordType::MX);
}

TEST(Resolver, DeletingThroughBaseRunsSubclassDestructor) {
  bool destroyed = false;
  {
    std::unique_ptr<backend::Resolver> resolver = std::make_unique<RecordingResolver>(&destroyed);
  }
  EXPECT_SHOW_EQ(destroyed, true);
}

TEST(ResolverFactory, EachCallReturnsNewInstance) {
  int built = 0;
  mw::ResolverFactory factory = [&built]() -> std::unique_ptr<backend::Resolver> {
    ++built;
    return std::make_unique<RecordingResolver>();
  };

  auto r1 = factory();
  auto r2 = factory();
  ASSERT_SHOW_NE(r1.get(), nullptr);
  ASSERT_SHOW_NE(r2.get(), nullptr);
  EXPECT_SHOW_NE(r1.get(), r2.get());
  EXPECT_SHOW_EQ(built, 2);
}

// ---- types.hpp ----

TEST(Transport, Values) {
  static_assert(std::is_same_v<std::underlying_type_t<mw::Transport>, std::uint8_t>);
  EXPECT_SHOW_NE(mw::Transport::Udp, mw::Transport::Tcp);
  EXPECT_SHOW_NE(mw::Transport::Udp, mw::Transport::Dot);
  EXPECT_SHOW_NE(mw::Transport::Tcp, mw::Transport::Dot);
  // new values go at the end so existing ones keep their numbers
  EXPECT_SHOW_EQ_AS("Udp value", static_cast<int>(mw::Transport::Udp), 0);
  EXPECT_SHOW_EQ_AS("Tcp value", static_cast<int>(mw::Transport::Tcp), 1);
  EXPECT_SHOW_EQ_AS("Dot value", static_cast<int>(mw::Transport::Dot), 2);
}

TEST(LbPolicy, Values) {
  static_assert(std::is_same_v<std::underlying_type_t<mw::LbPolicy>, std::uint8_t>);
  EXPECT_SHOW_NE(mw::LbPolicy::RoundRobin, mw::LbPolicy::LeastOutstanding);
  EXPECT_SHOW_NE(mw::LbPolicy::LeastOutstanding, mw::LbPolicy::PowerOfTwo);
  EXPECT_SHOW_NE(mw::LbPolicy::RoundRobin, mw::LbPolicy::PowerOfTwo);
}

TEST(ClientInfo, Defaults) {
  mw::ClientInfo info;
  EXPECT_SHOW_EQ(info.address, "");
  EXPECT_SHOW_EQ(info.port, 0);
  EXPECT_SHOW_EQ(info.transport, mw::Transport::Udp);
}

TEST(ClientInfo, HoldsADotClient) {
  const mw::ClientInfo info{"10.0.0.1", 853, mw::Transport::Dot};
  EXPECT_SHOW_EQ(info.address, "10.0.0.1");
  EXPECT_SHOW_EQ(info.port, 853);
  EXPECT_SHOW_EQ(info.transport, mw::Transport::Dot);
}

TEST(ResultCallback, AcceptsMoveOnlyCallable) {
  auto owned = std::make_unique<mw::Rcode>(mw::Rcode::NoError);
  mw::Rcode* seen = owned.get();
  // A lambda that owns a unique_ptr is move-only; std::function would reject it.
  mw::ResultCallback cb = [p = std::move(owned)](mw::ResolveResult r) { *p = r.rcode; };
  static_assert(!std::is_copy_constructible_v<mw::ResultCallback>);

  cb(mw::error_result(mw::Rcode::Refused));
  EXPECT_SHOW_EQ(*seen, mw::Rcode::Refused);
}

TEST(QueryKey, Equality) {
  const auto a = key("example.com.", mw::RecordType::A);
  EXPECT_SHOW_EQ(a, key("example.com.", mw::RecordType::A));
  EXPECT_SHOW_NE(a, key("example.com.", mw::RecordType::AAAA));
  EXPECT_SHOW_NE(a, key("example.org.", mw::RecordType::A));
}

TEST(QueryKey, IsCaseInsensitive) {
  EXPECT_SHOW_EQ(key("Example.COM.", mw::RecordType::A), key("example.com.", mw::RecordType::A));
  EXPECT_SHOW_EQ(mw::QueryKeyHash{}(key("Example.COM.", mw::RecordType::A)),
                 mw::QueryKeyHash{}(key("example.com.", mw::RecordType::A)));
}

TEST(QueryKeyHash, EqualKeysHashEqually) {
  static_assert(noexcept(mw::QueryKeyHash{}(std::declval<const mw::QueryKey&>())));
  const mw::QueryKeyHash hash;
  EXPECT_SHOW_EQ(hash(key(std::string("example.") + "com.", mw::RecordType::A)),
                 hash(key("example.com.", mw::RecordType::A)));
}

TEST(QueryKeyHash, MatchesSpecifiedFormula) {
  const auto k = key("example.com.", mw::RecordType::AAAA);
  const std::size_t h1 = std::hash<mw::DomainName>{}(k.name);
  const std::size_t h2 = std::hash<std::uint16_t>{}(28);
  const std::size_t expected = h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
  EXPECT_SHOW_EQ(mw::QueryKeyHash{}(k), expected);
}

TEST(QueryKeyHash, DifferentTypesAreDifferentKeys) {
  std::unordered_map<mw::QueryKey, int, mw::QueryKeyHash> map;
  map[key("example.com.", mw::RecordType::A)] = 1;
  map[key("example.com.", mw::RecordType::AAAA)] = 2;
  map[key("example.com.", static_cast<mw::RecordType>(65))] = 3;

  ASSERT_SHOW_EQ(map.size(), 3u);
  EXPECT_SHOW_EQ(map[key("example.com.", mw::RecordType::A)], 1);
  EXPECT_SHOW_EQ(map[key("example.com.", mw::RecordType::AAAA)], 2);
  EXPECT_SHOW_EQ(map[key("example.com.", static_cast<mw::RecordType>(65))], 3);
  EXPECT_SHOW_NE(mw::QueryKeyHash{}(key("example.com.", mw::RecordType::A)),
                 mw::QueryKeyHash{}(key("example.com.", mw::RecordType::AAAA)));
}

TEST(Clock, SteadyClockFnTracksSteadyClock) {
  static_assert(std::is_same_v<mw::SteadyClock, std::chrono::steady_clock>);
  static_assert(std::is_same_v<mw::Ms, std::chrono::milliseconds>);

  const mw::Clock clock = mw::steady_clock_fn();
  ASSERT_SHOW_EQ(static_cast<bool>(clock), true);
  const mw::TimePoint before = mw::SteadyClock::now();
  const mw::TimePoint t1 = clock();
  const mw::TimePoint t2 = clock();
  const mw::TimePoint after = mw::SteadyClock::now();
  EXPECT_SHOW_EQ(before <= t1, true);
  EXPECT_SHOW_EQ(t1 <= t2, true);
  EXPECT_SHOW_EQ(t2 <= after, true);
}

TEST(Clock, CanBeReplacedWithFakeClock) {
  mw::TimePoint now{};
  mw::Clock clock = [&now] { return now; };
  EXPECT_SHOW_EQ((clock() - mw::TimePoint{}).count(), 0);
  now += mw::Ms(250);
  EXPECT_SHOW_EQ(std::chrono::duration_cast<mw::Ms>(clock() - mw::TimePoint{}).count(), 250);
}
