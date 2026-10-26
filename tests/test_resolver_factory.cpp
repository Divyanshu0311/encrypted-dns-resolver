#include "mw/resolver_factory.hpp"

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

mw::ResolveResult ask(backend::Resolver& r, const char* name, mw::RecordType type) {
  return r.resolve(mw::DomainName(name), type, mw::RecordClass::IN);
}

} // namespace

TEST(StubResolver, AnswersA) {
  mw::StubResolver stub(mw::StubOptions{});
  const auto r = ask(stub, "example.com.", mw::RecordType::A);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::NoError);
  ASSERT_SHOW_EQ(r.answer.size(), 1u);
  EXPECT_SHOW_EQ(r.answer[0].name, mw::DomainName("example.com."));
  EXPECT_SHOW_EQ(r.answer[0].type, mw::RecordType::A);
  EXPECT_SHOW_EQ(r.answer[0].ttl, 60u);
  EXPECT_SHOW_EQ(r.answer[0].rdata, (std::vector<std::uint8_t>{127, 0, 0, 1}));
}

TEST(StubResolver, AnswersAaaa) {
  mw::StubResolver stub(mw::StubOptions{});
  const auto r = ask(stub, "example.com.", mw::RecordType::AAAA);
  ASSERT_SHOW_EQ(r.answer.size(), 1u);
  std::vector<std::uint8_t> loopback(16, 0);
  loopback.back() = 1;
  EXPECT_SHOW_EQ(r.answer[0].rdata, loopback);
}

TEST(StubResolver, NxTestIsNxDomain) {
  mw::StubResolver stub(mw::StubOptions{});
  EXPECT_SHOW_EQ(ask(stub, "nx.test.", mw::RecordType::A).rcode, mw::Rcode::NXDomain);
  EXPECT_SHOW_EQ(ask(stub, "NX.Test.", mw::RecordType::A).rcode, mw::Rcode::NXDomain);
}

TEST(StubResolver, OtherTypesAreEmptyNoError) {
  mw::StubResolver stub(mw::StubOptions{});
  const auto r = ask(stub, "example.com.", mw::RecordType::MX);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::NoError);
  EXPECT_SHOW_EQ(r.answer.size(), 0u);
}

TEST(StubResolver, InjectedFailures) {
  mw::StubResolver thrower(mw::StubOptions{mw::Ms(0), 0.0, 1.0, 42});
  for (int i = 0; i < 20; ++i) {
    EXPECT_THROW(ask(thrower, "example.com.", mw::RecordType::A), std::runtime_error);
  }
  mw::StubResolver failer(mw::StubOptions{mw::Ms(0), 1.0, 0.0, 42});
  for (int i = 0; i < 20; ++i) {
    EXPECT_SHOW_EQ(ask(failer, "example.com.", mw::RecordType::A).rcode, mw::Rcode::ServFail);
  }
}

TEST(StubResolver, RejectsBadRates) {
  EXPECT_THROW(mw::StubResolver(mw::StubOptions{mw::Ms(0), 1.5, 0.0, 1}), std::invalid_argument);
  EXPECT_THROW(mw::StubResolver(mw::StubOptions{mw::Ms(0), 0.0, -0.1, 1}), std::invalid_argument);
}

TEST(MakeFactory, EachCallBuildsANewResolver) {
  mw::Config cfg;
  auto factory = mw::make_factory(cfg, mw::StubOptions{});
  auto a = factory();
  auto b = factory();
  ASSERT_SHOW_NE(a.get(), nullptr);
  ASSERT_SHOW_NE(b.get(), nullptr);
  EXPECT_SHOW_NE(a.get(), b.get());
  EXPECT_SHOW_EQ(ask(*a, "example.com.", mw::RecordType::A).rcode, mw::Rcode::NoError);
}

TEST(MakeFactory, WithoutStubOptionsStillWorks) {
  mw::set_log_level(mw::LogLevel::Error); // it warns that real resolvers are not wired in
  mw::Config cfg;
  auto factory = mw::make_factory(cfg);
  mw::set_log_level(mw::LogLevel::Info);
  auto r = factory();
  ASSERT_SHOW_NE(r.get(), nullptr);
  EXPECT_SHOW_EQ(ask(*r, "nx.test.", mw::RecordType::A).rcode, mw::Rcode::NXDomain);
}
