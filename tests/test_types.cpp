#include "mw/resolver_interface.hpp"
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

// Minimal IResolver subclass: records how it was called and whether it was destroyed.
class RecordingResolver : public mw::IResolver {
public:
  explicit RecordingResolver(bool* destroyed = nullptr) : destroyed_(destroyed) {}
  ~RecordingResolver() override {
    if (destroyed_ != nullptr) {
      *destroyed_ = true;
    }
  }

  mw::ResolveResult resolve(std::string_view name, mw::RecordType type) override {
    last_name = std::string(name);
    last_type = type;
    return mw::ResolveResult::error(mw::Rcode::NXDomain);
  }

  std::string last_name;
  mw::RecordType last_type = mw::RecordType::ANY;

private:
  bool* destroyed_;
};

std::uint16_t raw(mw::RecordType type) {
  return static_cast<std::uint16_t>(type);
}

int raw(mw::Rcode rcode) {
  return static_cast<int>(rcode);
}

} // namespace

// ---- resolver_interface.hpp: enums ----

TEST(RecordType, NamedValues) {
  using RT = mw::RecordType;
  static_assert(std::is_same_v<std::underlying_type_t<RT>, std::uint16_t>);
  EXPECT_SHOW_EQ(raw(RT::A), 1);
  EXPECT_SHOW_EQ(raw(RT::NS), 2);
  EXPECT_SHOW_EQ(raw(RT::CNAME), 5);
  EXPECT_SHOW_EQ(raw(RT::SOA), 6);
  EXPECT_SHOW_EQ(raw(RT::PTR), 12);
  EXPECT_SHOW_EQ(raw(RT::MX), 15);
  EXPECT_SHOW_EQ(raw(RT::TXT), 16);
  EXPECT_SHOW_EQ(raw(RT::AAAA), 28);
  EXPECT_SHOW_EQ(raw(RT::ANY), 255);
}

TEST(RecordType, UnnamedValuesRoundTrip) {
  EXPECT_SHOW_EQ(raw(static_cast<mw::RecordType>(65)), 65);   // HTTPS
  EXPECT_SHOW_EQ(raw(static_cast<mw::RecordType>(257)), 257); // CAA
  EXPECT_SHOW_EQ(raw(static_cast<mw::RecordType>(65535)), 65535);
}

TEST(Rcode, NamedValues) {
  using R = mw::Rcode;
  static_assert(std::is_same_v<std::underlying_type_t<R>, std::uint8_t>);
  EXPECT_SHOW_EQ(raw(R::NoError), 0);
  EXPECT_SHOW_EQ(raw(R::FormErr), 1);
  EXPECT_SHOW_EQ(raw(R::ServFail), 2);
  EXPECT_SHOW_EQ(raw(R::NXDomain), 3);
  EXPECT_SHOW_EQ(raw(R::NotImp), 4);
  EXPECT_SHOW_EQ(raw(R::Refused), 5);
}

// ---- resolver_interface.hpp: ResourceRecord / ResolveResult ----

TEST(ResourceRecord, Defaults) {
  mw::ResourceRecord rr{};
  EXPECT_SHOW_EQ(rr.rclass, 1);
  EXPECT_SHOW_EQ(rr.ttl, 0u);
  EXPECT_SHOW_EQ(rr.name, "");
  EXPECT_SHOW_EQ(rr.rdata.size(), 0u);
}

TEST(ResourceRecord, TtlIs32Bit) {
  static_assert(std::is_same_v<decltype(mw::ResourceRecord::ttl), std::uint32_t>);
  mw::ResourceRecord rr{};
  rr.ttl = 86400u * 7; // one week does not fit in 16 bits
  EXPECT_SHOW_EQ(rr.ttl, 604800u);
}

TEST(ResourceRecord, Equality) {
  const mw::ResourceRecord original{
      "example.com.", mw::RecordType::A, 1, 300,
      {std::byte{93}, std::byte{184}, std::byte{216}, std::byte{34}}};
  mw::ResourceRecord copy = original;
  EXPECT_SHOW_EQ_AS("unchanged copy", copy, original);

  copy.ttl = 301;
  EXPECT_SHOW_NE_AS("copy with other ttl", copy, original);

  copy = original;
  copy.rdata.back() = std::byte{35};
  EXPECT_SHOW_NE_AS("copy with other rdata", copy, original);

  copy = original;
  copy.type = mw::RecordType::AAAA;
  EXPECT_SHOW_NE_AS("copy with other type", copy, original);
}

TEST(ResolveResult, DefaultIsEmptyNoError) {
  mw::ResolveResult r;
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::NoError);
  EXPECT_SHOW_EQ(r.answers.size(), 0u);
  EXPECT_SHOW_EQ(r.authority.size(), 0u);
}

TEST(ResolveResult, ErrorServFail) {
  const auto r = mw::ResolveResult::error(mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(r.answers.size(), 0u);
  EXPECT_SHOW_EQ(r.authority.size(), 0u);
}

TEST(ResolveResult, ErrorKeepsEveryRcode) {
  for (auto rc : {mw::Rcode::NoError, mw::Rcode::FormErr, mw::Rcode::ServFail,
                  mw::Rcode::NXDomain, mw::Rcode::NotImp, mw::Rcode::Refused}) {
    EXPECT_SHOW_EQ(mw::ResolveResult::error(rc).rcode, rc);
  }
}

TEST(ResolveResult, Equality) {
  mw::ResolveResult original;
  original.answers.push_back({"example.com.", mw::RecordType::A, 1, 60, {std::byte{1}}});
  mw::ResolveResult copy = original;
  EXPECT_SHOW_EQ_AS("unchanged copy", copy, original);

  copy.rcode = mw::Rcode::NXDomain;
  EXPECT_SHOW_NE_AS("copy with other rcode", copy, original);

  copy = original;
  copy.authority.push_back(original.answers.front());
  EXPECT_SHOW_NE_AS("copy with extra authority", copy, original);

  EXPECT_SHOW_EQ(mw::ResolveResult::error(mw::Rcode::Refused),
                 mw::ResolveResult::error(mw::Rcode::Refused));
  EXPECT_SHOW_NE(mw::ResolveResult::error(mw::Rcode::Refused),
                 mw::ResolveResult::error(mw::Rcode::ServFail));
}

// ---- resolver_interface.hpp: IResolver / ResolverFactory ----

TEST(IResolver, IsAbstractWithVirtualDestructor) {
  static_assert(std::is_abstract_v<mw::IResolver>);
  static_assert(std::has_virtual_destructor_v<mw::IResolver>);
  SUCCEED();
}

TEST(IResolver, CopyingIsDisabled) {
  static_assert(!std::is_copy_constructible_v<mw::IResolver>);
  static_assert(!std::is_copy_assignable_v<mw::IResolver>);
  // The deleted copy is inherited by every subclass.
  static_assert(!std::is_copy_constructible_v<RecordingResolver>);
  static_assert(!std::is_copy_assignable_v<RecordingResolver>);
  // ...but subclasses can still be default-constructed.
  static_assert(std::is_default_constructible_v<RecordingResolver>);
  SUCCEED();
}

TEST(IResolver, DispatchesThroughBasePointer) {
  std::unique_ptr<mw::IResolver> resolver = std::make_unique<RecordingResolver>();
  const auto result = resolver->resolve("example.com.", mw::RecordType::MX);

  EXPECT_SHOW_EQ(result, mw::ResolveResult::error(mw::Rcode::NXDomain));
  auto& concrete = static_cast<RecordingResolver&>(*resolver);
  EXPECT_SHOW_EQ(concrete.last_name, "example.com.");
  EXPECT_SHOW_EQ(concrete.last_type, mw::RecordType::MX);
}

TEST(IResolver, DeletingThroughBaseRunsSubclassDestructor) {
  bool destroyed = false;
  {
    std::unique_ptr<mw::IResolver> resolver = std::make_unique<RecordingResolver>(&destroyed);
  }
  EXPECT_SHOW_EQ(destroyed, true);
}

TEST(ResolverFactory, EachCallReturnsNewInstance) {
  int built = 0;
  mw::ResolverFactory factory = [&built]() -> std::unique_ptr<mw::IResolver> {
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

TEST(ResultCallback, AcceptsMoveOnlyCallable) {
  auto owned = std::make_unique<mw::Rcode>(mw::Rcode::NoError);
  mw::Rcode* seen = owned.get();
  // A lambda that owns a unique_ptr is move-only; std::function would reject it.
  mw::ResultCallback cb = [p = std::move(owned)](mw::ResolveResult r) { *p = r.rcode; };
  static_assert(!std::is_copy_constructible_v<mw::ResultCallback>);

  cb(mw::ResolveResult::error(mw::Rcode::Refused));
  EXPECT_SHOW_EQ(*seen, mw::Rcode::Refused);
}

TEST(QueryKey, Equality) {
  const mw::QueryKey a{"example.com.", mw::RecordType::A};
  EXPECT_SHOW_EQ(a, (mw::QueryKey{"example.com.", mw::RecordType::A}));
  EXPECT_SHOW_NE(a, (mw::QueryKey{"example.com.", mw::RecordType::AAAA}));
  EXPECT_SHOW_NE(a, (mw::QueryKey{"example.org.", mw::RecordType::A}));
}

TEST(QueryKeyHash, EqualKeysHashEqually) {
  static_assert(noexcept(mw::QueryKeyHash{}(std::declval<const mw::QueryKey&>())));
  const mw::QueryKeyHash hash;
  const mw::QueryKey a{"example.com.", mw::RecordType::A};
  const mw::QueryKey b{std::string("example.") + "com.", mw::RecordType::A};
  EXPECT_SHOW_EQ(hash(b), hash(a));
}

TEST(QueryKeyHash, MatchesSpecifiedFormula) {
  const mw::QueryKey key{"example.com.", mw::RecordType::AAAA};
  const std::size_t h1 = std::hash<std::string>{}(key.name);
  const std::size_t h2 = std::hash<std::uint16_t>{}(28);
  const std::size_t expected = h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
  EXPECT_SHOW_EQ(mw::QueryKeyHash{}(key), expected);
}

TEST(QueryKeyHash, DifferentTypesAreDifferentKeys) {
  std::unordered_map<mw::QueryKey, int, mw::QueryKeyHash> map;
  map[{"example.com.", mw::RecordType::A}] = 1;
  map[{"example.com.", mw::RecordType::AAAA}] = 2;
  map[{"example.com.", static_cast<mw::RecordType>(65)}] = 3;

  ASSERT_SHOW_EQ(map.size(), 3u);
  EXPECT_SHOW_EQ((map[{"example.com.", mw::RecordType::A}]), 1);
  EXPECT_SHOW_EQ((map[{"example.com.", mw::RecordType::AAAA}]), 2);
  EXPECT_SHOW_EQ((map[{"example.com.", static_cast<mw::RecordType>(65)}]), 3);
  EXPECT_SHOW_NE(mw::QueryKeyHash{}({"example.com.", mw::RecordType::A}),
                 mw::QueryKeyHash{}({"example.com.", mw::RecordType::AAAA}));
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
