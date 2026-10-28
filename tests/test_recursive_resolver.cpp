#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "backend/Cache.hpp"
#include "backend/RecursiveResolver.hpp"
#include "support/fake_dns_server.hpp"

// A small DNS tree on loopback, every server on the same port:
//
//   127.0.0.1  root        delegates test. to ns.test. (glue 127.0.0.2)
//   127.0.0.2  test.       delegates example.test. and other.test. to ns1.example.test. (glue 127.0.0.3),
//                          noglue.test. to ns1.example.test. without glue
//   127.0.0.3  example.test., other.test. and noglue.test.

namespace {
    using namespace std::chrono_literals;
    using support::a_record;
    using support::FakeDnsServer;
    using support::name_record;
    using support::result;
    using support::soa_record;
    using types::DomainName;
    using types::Rcode;
    using types::RecordClass;
    using types::RecordType;

    bool under(const std::string& name, const std::string& zone) {
        return DomainName(zone).is_ancestor_of(DomainName(name));
    }

    std::vector<std::vector<std::byte>> root(const types::DnsQuery& q, bool) {
        if (!under(q.name, "test.")) return FakeDnsServer::reply(q, result(Rcode::NXDomain, {}, { soa_record(".") }));
        return FakeDnsServer::reply(q, result(Rcode::NoError, {}, { name_record("test.", RecordType::NS, "ns.test.") }, { a_record("ns.test.", "127.0.0.2") }));
    }

    std::vector<std::vector<std::byte>> tld(const types::DnsQuery& q, bool) {
        for (const char* zone : { "example.test.", "other.test." })
            if (under(q.name, zone))
                return FakeDnsServer::reply(q, result(Rcode::NoError, {}, { name_record(zone, RecordType::NS, "ns1.example.test.") },
                                                      { a_record("ns1.example.test.", "127.0.0.3") }));
        if (under(q.name, "noglue.test."))
            return FakeDnsServer::reply(q, result(Rcode::NoError, {}, { name_record("noglue.test.", RecordType::NS, "ns1.example.test.") }));
        return FakeDnsServer::reply(q, result(Rcode::NXDomain, {}, { soa_record("test.") }));
    }

    std::vector<std::vector<std::byte>> leaf(const types::DnsQuery& q, bool) {
        const DomainName name(q.name);
        auto is = [&](const char* n) { return name == DomainName(n); };
        if (is("www.example.test.") && q.type == RecordType::A)
            // the extra record is outside the question's chain and must not be believed
            return FakeDnsServer::reply(q, result(Rcode::NoError, { a_record(q.name, "192.0.2.10"), a_record("www.bank.test.", "6.6.6.6") }));
        if (is("www.example.test."))
            return FakeDnsServer::reply(q, result(Rcode::NoError, {}, { soa_record("example.test.") })); // NODATA
        if (is("ns1.example.test.") && q.type == RecordType::A) return FakeDnsServer::reply(q, result(Rcode::NoError, { a_record(q.name, "127.0.0.3") }));
        if (is("alias.example.test."))
            return FakeDnsServer::reply(q, result(Rcode::NoError, { name_record(q.name, RecordType::CNAME, "www.example.test."),
                                                                    a_record("www.example.test.", "192.0.2.10") }));
        if (is("away.example.test."))
            return FakeDnsServer::reply(q, result(Rcode::NoError, { name_record(q.name, RecordType::CNAME, "www.other.test.") }));
        if (is("www.other.test.") && q.type == RecordType::A) return FakeDnsServer::reply(q, result(Rcode::NoError, { a_record(q.name, "192.0.2.20") }));
        if (is("www.noglue.test.") && q.type == RecordType::A) return FakeDnsServer::reply(q, result(Rcode::NoError, { a_record(q.name, "192.0.2.30") }));
        return FakeDnsServer::reply(q, result(Rcode::NXDomain, {}, { soa_record("example.test.") }));
    }

    class RecursiveResolverTest : public ::testing::Test {
    protected:
        std::unique_ptr<FakeDnsServer> root_server, tld_server, leaf_server;
        backend::Cache cache;
        std::unique_ptr<backend::RecursiveResolver> resolver;

        void SetUp() override {
            root_server = std::make_unique<FakeDnsServer>(root, "127.0.0.1", 0);
            const uint16_t port = root_server->port();
            try {
                tld_server  = std::make_unique<FakeDnsServer>(tld, "127.0.0.2", port);
                leaf_server = std::make_unique<FakeDnsServer>(leaf, "127.0.0.3", port);
            } catch (const std::runtime_error& e) {
                GTEST_SKIP() << "needs 127.0.0.2 and 127.0.0.3 on the loopback interface: " << e.what();
            }
            backend::RecursiveOptions opts;
            opts.roots          = { types::IP("127.0.0.1") };
            opts.port           = port;
            opts.server_timeout = 300ms;
            opts.total_timeout  = 3000ms;
            resolver            = std::make_unique<backend::RecursiveResolver>(cache, opts);
        }

        types::ResolveResult ask(const std::string& name, RecordType type = RecordType::A) {
            return resolver->resolve(DomainName(name), type, RecordClass::IN);
        }
    };
} // namespace

TEST_F(RecursiveResolverTest, FollowsReferralsToTheAnswer) {
    const auto r = ask("www.example.test.");
    EXPECT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 10 }));
    EXPECT_EQ(r.served_by, "recursive, 3 servers asked");
    EXPECT_EQ(root_server->udp_queries(), 1);
    EXPECT_EQ(tld_server->udp_queries(), 1);
    EXPECT_EQ(leaf_server->udp_queries(), 1);
}

TEST_F(RecursiveResolverTest, CachedAnswerAndReferralsAreReused) {
    ask("www.example.test.");
    EXPECT_EQ(ask("www.example.test.").served_by, "cache");

    // a new name in the same zone goes straight to its server
    ask("alias.example.test.");
    EXPECT_EQ(root_server->udp_queries(), 1);
    EXPECT_EQ(tld_server->udp_queries(), 1);
    EXPECT_EQ(leaf_server->udp_queries(), 2);
}

TEST_F(RecursiveResolverTest, FollowsCnameInsideTheZone) {
    const auto r = ask("alias.example.test.");
    ASSERT_EQ(r.answer.size(), 2u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[1].rdata, (std::vector<uint8_t>{ 192, 0, 2, 10 }));
}

TEST_F(RecursiveResolverTest, FollowsCnameIntoAnotherZone) {
    const auto r = ask("away.example.test.");
    EXPECT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 2u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[1].name, DomainName("www.other.test."));
    EXPECT_EQ(r.answer[1].rdata, (std::vector<uint8_t>{ 192, 0, 2, 20 }));
}

TEST_F(RecursiveResolverTest, ResolvesNameServersWithoutGlue) {
    const auto r = ask("www.noglue.test.");
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 30 }));
}

TEST_F(RecursiveResolverTest, NxDomain) {
    const auto r = ask("missing.example.test.");
    EXPECT_EQ(r.rcode, Rcode::NXDomain);
    EXPECT_TRUE(r.answer.empty());
}

TEST_F(RecursiveResolverTest, NoDataIsNoErrorWithTheSoa) {
    const auto r = ask("www.example.test.", RecordType::AAAA);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    EXPECT_TRUE(r.answer.empty());
    ASSERT_EQ(r.authority.size(), 1u);
    EXPECT_EQ(r.authority[0].type, RecordType::SOA);
}

TEST_F(RecursiveResolverTest, RecordsOutsideTheChainAreNotCached) {
    ask("www.example.test.");
    EXPECT_TRUE(cache.find(DomainName("www.bank.test."), RecordType::A, RecordClass::IN).empty());
}

TEST_F(RecursiveResolverTest, WithoutRecursionOnlyTheCacheAnswers) {
    EXPECT_EQ(resolver->resolve(DomainName("www.example.test."), RecordType::A, RecordClass::IN, false).rcode, Rcode::Refused);
    EXPECT_EQ(root_server->udp_queries(), 0);
    ask("www.example.test.");
    EXPECT_EQ(resolver->resolve(DomainName("www.example.test."), RecordType::A, RecordClass::IN, false).rcode, Rcode::NoError);
}

TEST(RecursiveResolver, UnreachableRootsGiveServFail) {
    backend::Cache cache;
    backend::RecursiveOptions opts;
    opts.roots          = { types::IP("127.0.0.1") };
    opts.port           = support::closed_port();
    opts.server_timeout = 200ms;
    backend::RecursiveResolver resolver(cache, opts);
    EXPECT_EQ(resolver.resolve(DomainName("www.example.test."), RecordType::A, RecordClass::IN).rcode, Rcode::ServFail);
}
