#include "mw/resolver_factory.hpp"

#include "support/fake_dns_server.hpp"
#include "support/fake_dot_server.hpp"
#include "support/tls_cert.hpp"
#include "support/show.hpp"
#include "support/temp_dir.hpp"

#include <gtest/gtest.h>

#include <algorithm>
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

TEST(MakeFactory, ResolverCanBeSwitchedAtRunTime) {
  auto answering = [](const char* ip) {
    return [ip](const types::DnsQuery& q, bool) { return support::FakeDnsServer::reply(q, support::result(mw::Rcode::NoError, {support::a_record(q.name, ip)})); };
  };
  support::FakeDnsServer first(answering("192.0.2.1"));
  support::FakeDnsServer second(answering("192.0.2.2"));
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", first.port()}, mw::Upstream{"127.0.0.1", second.port()}};
  mw::ResolverShared shared;
  auto chain = mw::make_factory(cfg, std::nullopt, shared)();

  const auto& choices = shared.resolvers->choices;
  ASSERT_SHOW_EQ(choices.size(), 10u); // both together, each alone, three public resolvers plain and over TLS, recursive
  EXPECT_SHOW_EQ(choices.front().id, std::string("configured"));
  EXPECT_SHOW_EQ(choices.back().id, std::string("recursive"));
  EXPECT_SHOW_EQ(shared.resolvers->active.load(), 0u);

  EXPECT_SHOW_EQ(ask(*chain, "a.example.", mw::RecordType::A).answer[0].rdata, (std::vector<std::uint8_t>{192, 0, 2, 1}));
  auto only_second = shared.resolvers->find("upstream:127.0.0.1:" + std::to_string(second.port()));
  ASSERT_TRUE(only_second.has_value());
  shared.resolvers->active = *only_second;
  EXPECT_SHOW_EQ(ask(*chain, "b.example.", mw::RecordType::A).answer[0].rdata, (std::vector<std::uint8_t>{192, 0, 2, 2}));
  EXPECT_FALSE(shared.resolvers->find("nonsense").has_value());
}

TEST(MakeFactory, RecursiveModeStartsOnTheRecursiveResolver) {
  mw::Config cfg;
  cfg.mode = mw::Mode::Recursive;
  mw::ResolverShared shared;
  mw::make_factory(cfg, std::nullopt, shared);
  EXPECT_SHOW_EQ(shared.resolvers->choices[shared.resolvers->active].id, std::string("recursive"));
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

TEST(MakeFactory, TlsUpstreamIsAskedOverTlsWithItsCertificateChecked) {
  support::TempDir dir;
  mw::test::TestCa ca(dir);
  support::FakeDotServer upstream(ca.issue("server"), [](const types::DnsQuery& q) {
    return support::FakeDotServer::reply(q, support::result(mw::Rcode::NoError, {support::a_record(q.name, "192.0.2.53")}));
  });
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", upstream.port(), true, "dns.test"}};
  cfg.upstream_ca_file = ca.cert_file();
  mw::ResolverShared shared;
  auto chain = mw::make_factory(cfg, std::nullopt, shared)();

  const auto r = ask(*chain, "www.example.com.", mw::RecordType::A);
  EXPECT_SHOW_EQ(r.rcode, mw::Rcode::NoError);
  EXPECT_SHOW_EQ(r.served_by, "upstream 127.0.0.1:" + std::to_string(upstream.port()) + " (dns.test) over TLS");
  EXPECT_SHOW_EQ(shared.upstream_tls->stats().handshakes, 1u);
  EXPECT_SHOW_EQ(shared.resolvers->choices.front().label, "Forward to 127.0.0.1:" + std::to_string(upstream.port()) + " over TLS (dns.test)");
  EXPECT_TRUE(shared.resolvers->find("dot:1.1.1.1:853").has_value());
}

TEST(MakeFactory, TlsUpstreamWithTheWrongNameFails) {
  support::TempDir dir;
  mw::test::TestCa ca(dir);
  support::FakeDotServer upstream(ca.issue("server"), [](const types::DnsQuery& q) {
    return support::FakeDotServer::reply(q, support::result(mw::Rcode::NoError, {support::a_record(q.name, "192.0.2.53")}));
  });
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"127.0.0.1", upstream.port(), true, "evil.test"}};
  cfg.upstream_ca_file = ca.cert_file();
  mw::ResolverShared shared;
  auto chain = mw::make_factory(cfg, std::nullopt, shared)();
  EXPECT_SHOW_EQ(ask(*chain, "www.example.com.", mw::RecordType::A).rcode, mw::Rcode::ServFail);
  EXPECT_SHOW_EQ(shared.upstream_tls->stats().rejected, 1u);
  EXPECT_SHOW_EQ(upstream.queries(), 0);
}

TEST(MakeFactory, UnreadableCaFileFailsUpFront) {
  support::TempDir dir;
  mw::Config cfg;
  cfg.upstreams = {mw::Upstream{"1.1.1.1", 853, true, "cloudflare-dns.com"}};
  cfg.upstream_ca_file = dir.write("not-a-cert.pem", "hello");
  EXPECT_THROW(mw::make_factory(cfg), std::invalid_argument);
}

TEST(UpstreamLabels, IdsAndLabels) {
  auto tls = std::make_shared<backend::TlsClient>();
  backend::Endpoint plain{types::IP("8.8.8.8"), 53, nullptr, ""};
  backend::Endpoint odd_port{types::IP("::1"), 5353, nullptr, ""};
  backend::Endpoint dot{types::IP("1.1.1.1"), 853, tls, "cloudflare-dns.com"};
  EXPECT_SHOW_EQ(mw::upstream_id(plain), std::string("upstream:8.8.8.8:53"));
  EXPECT_SHOW_EQ(mw::upstream_id(dot), std::string("dot:1.1.1.1:853"));
  EXPECT_SHOW_EQ(mw::upstream_label(plain), std::string("8.8.8.8"));
  EXPECT_SHOW_EQ(mw::upstream_label(odd_port), std::string("[::1]:5353"));
  EXPECT_SHOW_EQ(mw::upstream_label(dot), std::string("1.1.1.1 over TLS (cloudflare-dns.com)"));
  const auto pub = mw::public_upstreams(tls);
  EXPECT_SHOW_EQ(std::ranges::count_if(pub, [](const auto& e) { return e.tls != nullptr && !e.tls_name.empty(); }), 3);
}
