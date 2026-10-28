#include "mw/resolver_factory.hpp"

#include "support/fake_dns_server.hpp"
#include "support/show.hpp"
#include "support/temp_dir.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
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

TEST(MakeFactory, ForwardingChainAsksTheUpstream) {
  support::FakeDnsServer upstream([](const types::DnsQuery& q, bool) {
    return support::FakeDnsServer::reply(q, support::result(mw::Rcode::NoError, {support::a_record(q.name, "192.0.2.1")}));
  });
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", upstream.port()}};
  mw::ResolverShared shared;
  auto factory = mw::make_factory(cfg, std::nullopt, shared);
  auto a = factory();
  auto b = factory();

  const auto first = ask(*a, "www.example.com.", mw::RecordType::A);
  EXPECT_SHOW_EQ(first.rcode, mw::Rcode::NoError);
  EXPECT_SHOW_EQ(first.served_by, "upstream 127.0.0.1:" + std::to_string(upstream.port()));
  // the chains share one cache
  EXPECT_SHOW_EQ(ask(*b, "www.example.com.", mw::RecordType::A).served_by, std::string("cache"));
  EXPECT_SHOW_EQ(shared.cache->stats().hits, 1u);
}

TEST(MakeFactory, RecordsFileIsAskedFirst) {
  support::TempDir dir;
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", support::closed_port()}};
  cfg.records_file = dir.write("records.txt", "10.0.0.5 printer.lan\n");
  auto chain = mw::make_factory(cfg)();
  const auto r = ask(*chain, "printer.lan.", mw::RecordType::A);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::NoError);
  EXPECT_SHOW_EQ(r.served_by, std::string("records file"));
  ASSERT_SHOW_EQ(r.answer.size(), 1u);
  EXPECT_SHOW_EQ(r.answer[0].rdata, (std::vector<std::uint8_t>{10, 0, 0, 5}));
  // anything else falls through to the (dead) upstream
  EXPECT_SHOW_EQ(ask(*chain, "example.com.", mw::RecordType::A).rcode, mw::Rcode::ServFail);
}

TEST(MakeFactory, ZoneFileRecords) {
  support::TempDir dir;
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", support::closed_port()}};
  cfg.records_file = dir.write("demo.zone", "$ORIGIN demo.lan.\n"
                                            "@    3600 IN SOA ns admin 1 3600 600 86400 60\n"
                                            "@    3600 IN NS  ns\n"
                                            "ns   3600 IN A   10.0.0.1\n"
                                            "www  3600 IN A   10.0.0.80\n");
  auto chain = mw::make_factory(cfg)();
  const auto r = ask(*chain, "www.demo.lan.", mw::RecordType::A);
  ASSERT_SHOW_EQ(r.answer.size(), 1u);
  EXPECT_SHOW_EQ(r.answer[0].rdata, (std::vector<std::uint8_t>{10, 0, 0, 80}));
  EXPECT_SHOW_EQ(ask(*chain, "nope.demo.lan.", mw::RecordType::A).rcode, mw::Rcode::NXDomain);
}

TEST(MakeFactory, InjectedFaultsFailLookups) {
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", support::closed_port()}};
  mw::ResolverShared shared;
  auto chain = mw::make_factory(cfg, std::nullopt, shared)();
  shared.faults->fail_rate = 1.0;
  const auto r = ask(*chain, "example.com.", mw::RecordType::A);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(r.served_by, std::string("injected fault"));
}

TEST(MakeFactory, RejectsBadUpstreamsUpFront) {
  mw::Config cfg;
  EXPECT_THROW(mw::make_factory(cfg), std::invalid_argument); // forwarding with no upstreams
  cfg.upstreams = {mw::Upstream{"dns.google", 53}};
  EXPECT_THROW(mw::make_factory(cfg), std::invalid_argument);
}

TEST(MakeFactory, RecursiveModeNeedsNoUpstreams) {
  mw::Config cfg;
  cfg.mode = mw::Mode::Recursive;
  auto factory = mw::make_factory(cfg);
  EXPECT_SHOW_NE(factory().get(), nullptr);
}
