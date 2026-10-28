#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

#include "backend/Cache.hpp"
#include "backend/ForwardingResolver.hpp"
#include "support/fake_dns_server.hpp"

namespace {
    using namespace std::chrono_literals;
    using support::FakeDnsServer;
    using types::DomainName;
    using types::Rcode;
    using types::RecordClass;
    using types::RecordType;

    backend::Endpoint endpoint(const FakeDnsServer& server) {
        return backend::Endpoint{ server.ip(), server.port() };
    }

    types::ResolveResult ask(backend::Resolver& r, const std::string& name, RecordType type = RecordType::A) {
        return r.resolve(DomainName(name), type, RecordClass::IN);
    }

    // answers every A question with 192.0.2.1
    FakeDnsServer::Handler answers_a() {
        return [](const types::DnsQuery& q, bool) { return FakeDnsServer::reply(q, support::result(Rcode::NoError, { support::a_record(q.name, "192.0.2.1") })); };
    }
} // namespace

TEST(ForwardingResolver, AnswersAndCaches) {
    FakeDnsServer upstream(answers_a());
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(upstream) }, cache, 500ms);

    const auto first = ask(resolver, "www.example.com.");
    EXPECT_EQ(first.rcode, Rcode::NoError);
    ASSERT_EQ(first.answer.size(), 1u);
    EXPECT_EQ(first.answer[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 1 }));
    EXPECT_EQ(first.served_by, "upstream 127.0.0.1:" + std::to_string(upstream.port()));

    const auto second = ask(resolver, "WWW.example.com.");
    EXPECT_EQ(second.served_by, "cache");
    ASSERT_EQ(second.answer.size(), 1u);
    EXPECT_EQ(upstream.udp_queries(), 1);
}

TEST(ForwardingResolver, SetsRecursionDesiredFromTheCaller) {
    std::atomic<int> with_rd{ 0 };
    FakeDnsServer upstream([&](const types::DnsQuery& q, bool) {
        if (q.recursion_desired) with_rd++;
        return FakeDnsServer::reply(q, support::result(Rcode::NoError));
    });
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(upstream) }, cache, 500ms);
    resolver.resolve(DomainName("a.example."), RecordType::A, RecordClass::IN, true);
    resolver.resolve(DomainName("b.example."), RecordType::A, RecordClass::IN, false);
    EXPECT_EQ(with_rd.load(), 1);
}

TEST(ForwardingResolver, MovesOnFromADeadUpstream) {
    FakeDnsServer upstream(answers_a());
    backend::Cache cache;
    backend::ForwardingResolver resolver({ backend::Endpoint{ types::IP("127.0.0.1"), support::closed_port() }, endpoint(upstream) }, cache, 500ms);
    const auto r = ask(resolver, "example.com.");
    EXPECT_EQ(r.rcode, Rcode::NoError);
    EXPECT_EQ(r.answer.size(), 1u);

    // the upstream that worked is asked first next time
    ask(resolver, "other.example.");
    EXPECT_EQ(upstream.udp_queries(), 2);
}

TEST(ForwardingResolver, ServFailAndRefusedTryTheNextUpstream) {
    FakeDnsServer broken([](const types::DnsQuery& q, bool) { return FakeDnsServer::reply(q, support::result(Rcode::ServFail)); });
    FakeDnsServer refusing([](const types::DnsQuery& q, bool) { return FakeDnsServer::reply(q, support::result(Rcode::Refused)); });
    FakeDnsServer good(answers_a());
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(broken), endpoint(refusing), endpoint(good) }, cache, 500ms);
    EXPECT_EQ(ask(resolver, "example.com.").rcode, Rcode::NoError);
    EXPECT_EQ(broken.udp_queries(), 1);
    EXPECT_EQ(refusing.udp_queries(), 1);
}

TEST(ForwardingResolver, SilentUpstreamsGiveServFail) {
    FakeDnsServer silent([](const types::DnsQuery&, bool) { return std::vector<std::vector<std::byte>>{}; });
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(silent) }, cache, 100ms);
    const auto start = std::chrono::steady_clock::now();
    const auto r     = ask(resolver, "example.com.");
    EXPECT_EQ(r.rcode, Rcode::ServFail);
    EXPECT_EQ(r.served_by, "no upstream answered");
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
}

TEST(ForwardingResolver, NxDomainIsPassedOn) {
    FakeDnsServer upstream([](const types::DnsQuery& q, bool) {
        return FakeDnsServer::reply(q, support::result(Rcode::NXDomain, {}, { support::soa_record("example.") }));
    });
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(upstream) }, cache, 500ms);
    const auto r = ask(resolver, "nope.example.");
    EXPECT_EQ(r.rcode, Rcode::NXDomain);
    EXPECT_EQ(r.authority.size(), 1u);
}

TEST(ForwardingResolver, IgnoresRepliesThatDontMatchTheQuestion) {
    FakeDnsServer upstream([](const types::DnsQuery& q, bool) {
        // a forged reply first (wrong ID, poisoned address), then the real one
        types::DnsQuery forged = q;
        forged.id ^= 0x5555;
        auto out = FakeDnsServer::reply(forged, support::result(Rcode::NoError, { support::a_record(q.name, "6.6.6.6") }));
        auto real = FakeDnsServer::reply(q, support::result(Rcode::NoError, { support::a_record(q.name, "192.0.2.1") }));
        out.push_back(real[0]);
        return out;
    });
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(upstream) }, cache, 500ms);
    const auto r = ask(resolver, "bank.example.");
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 1 }));
}

TEST(ForwardingResolver, TruncatedReplyIsRetriedOverTcp) {
    FakeDnsServer upstream([](const types::DnsQuery& q, bool tcp) {
        if (!tcp) return FakeDnsServer::truncated(q);
        return FakeDnsServer::reply(q, support::result(Rcode::NoError, { support::a_record(q.name, "192.0.2.9") }));
    });
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(upstream) }, cache, 500ms);
    const auto r = ask(resolver, "big.example.");
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 9 }));
    EXPECT_EQ(upstream.udp_queries(), 1);
    EXPECT_EQ(upstream.tcp_queries(), 1);
}

TEST(ForwardingResolver, CachesOnlyTheQuestionsOwnChain) {
    FakeDnsServer upstream([](const types::DnsQuery& q, bool) {
        return FakeDnsServer::reply(q, support::result(Rcode::NoError, { support::name_record(q.name, RecordType::CNAME, "cdn.example.net."),
                                                                          support::a_record("cdn.example.net.", "192.0.2.5"),
                                                                          support::a_record("bank.example.", "6.6.6.6") }));
    });
    backend::Cache cache;
    backend::ForwardingResolver resolver({ endpoint(upstream) }, cache, 500ms);
    ask(resolver, "www.example.com.");

    EXPECT_EQ(cache.find(DomainName("cdn.example.net."), RecordType::A, RecordClass::IN).size(), 1u);
    EXPECT_TRUE(cache.find(DomainName("bank.example."), RecordType::A, RecordClass::IN).empty());
    // the chain answers from the cache next time
    EXPECT_EQ(ask(resolver, "www.example.com.").served_by, "cache");
}

TEST(ForwardingResolver, NeedsAnUpstream) {
    backend::Cache cache;
    EXPECT_THROW(backend::ForwardingResolver({}, cache), std::invalid_argument);
}

TEST(ForwardingResolver, ResolversSharingAPreferenceSkipADeadUpstreamTogether) {
    FakeDnsServer silent([](const types::DnsQuery&, bool) { return std::vector<std::vector<std::byte>>{}; });
    FakeDnsServer good(answers_a());
    backend::Cache cache;
    auto preferred = std::make_shared<std::atomic<std::size_t>>(0);
    backend::ForwardingResolver first({ endpoint(silent), endpoint(good) }, cache, 100ms, preferred);
    backend::ForwardingResolver second({ endpoint(silent), endpoint(good) }, cache, 100ms, preferred);

    ask(first, "a.example.");
    ask(second, "b.example.");
    EXPECT_EQ(silent.udp_queries(), 1); // only the first resolver waited for it
    EXPECT_EQ(good.udp_queries(), 2);
}
