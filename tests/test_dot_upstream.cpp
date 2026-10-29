#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "backend/Cache.hpp"
#include "backend/ForwardingResolver.hpp"
#include "backend/Upstream.hpp"
#include "support/fake_dns_server.hpp"
#include "support/fake_dot_server.hpp"
#include "support/temp_dir.hpp"
#include "support/tls_cert.hpp"

// DNS-over-TLS to the upstream: queries complete over TLS, the certificate is checked (chain, name or IP,
// lifetime) and anything that fails is a SERVFAIL, never a fallback to plain DNS.

namespace {
    using namespace std::chrono_literals;
    using support::FakeDotServer;
    using types::DomainName;
    using types::Rcode;
    using types::RecordClass;
    using types::RecordType;

    FakeDotServer::Handler answers(const std::string& ip) {
        return [ip](const types::DnsQuery& q) { return FakeDotServer::reply(q, support::result(Rcode::NoError, { support::a_record(q.name, ip) })); };
    }

    class DotUpstream : public ::testing::Test {
    protected:
        support::TempDir dir;
        mw::test::TestCa ca{ dir };
        mw::test::TestCert cert = ca.issue("server"); // dns.test and 127.0.0.1
        std::shared_ptr<backend::TlsClient> tls = std::make_shared<backend::TlsClient>();
        backend::Cache cache;

        void SetUp() override { ASSERT_TRUE(tls->configure(ca.cert_file()).has_value()); }

        backend::Endpoint endpoint(const FakeDotServer& server, const std::string& name = "dns.test") const {
            return backend::Endpoint{ server.ip(), server.port(), tls, name };
        }

        types::ResolveResult ask(const backend::Endpoint& e, const std::string& name = "example.com.", std::chrono::milliseconds timeout = 1000ms) {
            backend::ForwardingResolver resolver({ e }, cache, timeout);
            return resolver.resolve(DomainName(name), RecordType::A, RecordClass::IN);
        }

        // asks with a certificate the server presents, expecting it to be refused for reason
        void expect_rejected(const mw::test::TestCert& bad, const std::string& name, const std::string& reason) {
            FakeDotServer server(bad, answers("192.0.2.1"));
            const auto r = ask(endpoint(server, name));
            EXPECT_EQ(r.rcode, Rcode::ServFail);
            EXPECT_EQ(server.queries(), 0) << "the question must not be sent before the certificate is accepted";
            const auto s = tls->stats();
            EXPECT_EQ(s.rejected, 1u);
            EXPECT_EQ(s.handshakes, 0u);
            EXPECT_NE(s.last_rejection.find(reason), std::string::npos) << s.last_rejection;
        }
    };
} // namespace

// ---- a query completing over TLS ----

TEST_F(DotUpstream, AnswersOverTlsWithAVerifiedCertificate) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    const auto r = ask(endpoint(server));
    ASSERT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 1 }));
    EXPECT_EQ(r.served_by, "upstream 127.0.0.1:" + std::to_string(server.port()) + " (dns.test) over TLS");

    EXPECT_EQ(server.queries(), 1);
    EXPECT_EQ(server.last_sni(), "dns.test"); // the name is sent as SNI
    const auto s = tls->stats();
    EXPECT_EQ(s.queries, 1u);
    EXPECT_EQ(s.handshakes, 1u);
    EXPECT_EQ(s.rejected, 0u);
    EXPECT_EQ(s.last_subject, "CN=dns.test");
    EXPECT_EQ(s.last_issuer, "CN=Test CA");
}

TEST_F(DotUpstream, QueriesArePadded) {
    std::atomic<int> padded{ 0 };
    FakeDotServer server(cert, [&padded](const types::DnsQuery& q) {
        if (q.wants_padding) padded++;
        return FakeDotServer::reply(q, support::result(Rcode::NoError, { support::a_record(q.name, "192.0.2.1") }));
    });
    EXPECT_EQ(ask(endpoint(server), "a.io.").rcode, Rcode::NoError);
    EXPECT_EQ(ask(endpoint(server), "a-much-longer-name-that-changes-the-message-size.example.org.").rcode, Rcode::NoError);
    EXPECT_EQ(padded.load(), 2);
}

TEST_F(DotUpstream, WithoutANameTheCertificateMustListTheAddress) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    EXPECT_EQ(ask(endpoint(server, "")).rcode, Rcode::NoError);
    EXPECT_EQ(tls->stats().handshakes, 1u);
}

TEST_F(DotUpstream, ConnectionIsKeptForTheNextQuery) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    backend::ForwardingResolver resolver({ endpoint(server) }, cache, 1000ms);
    for (const char* name : { "a.example.", "b.example.", "c.example." })
        EXPECT_EQ(resolver.resolve(DomainName(name), RecordType::A, RecordClass::IN).rcode, Rcode::NoError);
    EXPECT_EQ(server.handshakes(), 1);
    EXPECT_EQ(server.queries(), 3);
    EXPECT_EQ(tls->stats().reused, 2u);
}

TEST_F(DotUpstream, ServerClosingAKeptConnectionIsNotAnError) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    backend::ForwardingResolver resolver({ endpoint(server) }, cache, 1000ms);
    EXPECT_EQ(resolver.resolve(DomainName("a.example."), RecordType::A, RecordClass::IN).rcode, Rcode::NoError);
    server.drop_connections();
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(resolver.resolve(DomainName("b.example."), RecordType::A, RecordClass::IN).rcode, Rcode::NoError);
    EXPECT_EQ(server.handshakes(), 2);
}

TEST_F(DotUpstream, AConnectionIsOnlyReusedForTheSameName) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    EXPECT_EQ(ask(endpoint(server, "dns.test"), "a.example.").rcode, Rcode::NoError);
    // a different name must be checked against the certificate again, not ride on the earlier handshake
    EXPECT_EQ(ask(endpoint(server, "other.test"), "b.example.").rcode, Rcode::ServFail);
    EXPECT_EQ(tls->stats().rejected, 1u);
}

// ---- certificate validation ----

TEST_F(DotUpstream, WrongNameIsRejected) {
    expect_rejected(cert, "other.test", "hostname mismatch");
}

TEST_F(DotUpstream, AddressNotInTheCertificateIsRejected) {
    expect_rejected(ca.issue("no-ip", { .ips = {} }), "", "IP address mismatch");
}

TEST_F(DotUpstream, UntrustedIssuerIsRejected) {
    mw::test::TestCa rogue(dir, "Rogue CA", "rogue");
    expect_rejected(rogue.issue("rogue-server"), "dns.test", "unable to get local issuer certificate");
}

TEST_F(DotUpstream, SelfSignedCertificateIsRejected) {
    expect_rejected(mw::test::make_test_cert(dir, "self-signed"), "localhost", "self");
}

TEST_F(DotUpstream, ExpiredCertificateIsRejected) {
    expect_rejected(ca.issue("expired", { .valid_from_s = -7200, .valid_for_s = 3600 }), "dns.test", "certificate has expired");
}

TEST_F(DotUpstream, NotYetValidCertificateIsRejected) {
    expect_rejected(ca.issue("future", { .valid_from_s = 3600, .valid_for_s = 3600 }), "dns.test", "certificate is not yet valid");
}

TEST_F(DotUpstream, WildcardDoesNotCoverTheParentName) {
    expect_rejected(ca.issue("wildcard", { .dns_names = { "*.dns.test" }, .ips = {} }), "dns.test", "hostname mismatch");
}

TEST_F(DotUpstream, TheSystemStoreDoesNotTrustATestCa) {
    auto system = std::make_shared<backend::TlsClient>();
    ASSERT_TRUE(system->configure().has_value());
    FakeDotServer server(cert, answers("192.0.2.1"));
    const auto r = ask(backend::Endpoint{ server.ip(), server.port(), system, "dns.test" });
    EXPECT_EQ(r.rcode, Rcode::ServFail);
    EXPECT_EQ(system->stats().rejected, 1u);
}

TEST_F(DotUpstream, ProbeShowsTheCertificateAndTheVerdict) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    const auto good = tls->probe(endpoint(server), 1000ms);
    EXPECT_TRUE(good.connected);
    EXPECT_TRUE(good.verified) << good.error;
    EXPECT_EQ(good.error, "");
    EXPECT_EQ(good.protocol, "TLSv1.3");
    EXPECT_FALSE(good.cipher.empty());
    EXPECT_EQ(good.subject, "CN=dns.test");
    EXPECT_EQ(good.issuer, "CN=Test CA");
    EXPECT_FALSE(good.not_after.empty());
    EXPECT_GT(good.handshake_ms, 0.0);

    const auto bad = tls->probe(endpoint(server, "bank.example"), 1000ms);
    EXPECT_TRUE(bad.connected);
    EXPECT_FALSE(bad.verified);
    EXPECT_NE(bad.error.find("hostname mismatch"), std::string::npos) << bad.error;
    EXPECT_EQ(bad.subject, "CN=dns.test"); // what was presented, though refused
    EXPECT_EQ(tls->stats().rejected, 1u);
    EXPECT_EQ(server.queries(), 0); // a probe asks nothing
}

// ---- invalid responses ----

TEST_F(DotUpstream, GarbageReplyIsServFail) {
    FakeDotServer server(cert, [](const types::DnsQuery&) { return std::vector<std::vector<std::byte>>{ std::vector<std::byte>(7, std::byte{ 0xAB }) }; });
    const auto r = ask(endpoint(server));
    EXPECT_EQ(r.rcode, Rcode::ServFail);
    EXPECT_EQ(r.served_by, "no upstream answered");
    EXPECT_EQ(tls->stats().failed, 1u);
}

TEST_F(DotUpstream, ReplyToAnotherQuestionIsServFail) {
    FakeDotServer server(cert, [](const types::DnsQuery& q) {
        types::DnsQuery other = q;
        other.id ^= 0x5555;
        return FakeDotServer::reply(other, support::result(Rcode::NoError, { support::a_record(q.name, "6.6.6.6") }));
    });
    EXPECT_EQ(ask(endpoint(server)).rcode, Rcode::ServFail);
}

TEST_F(DotUpstream, TruncatedReplyIsServFail) {
    FakeDotServer server(cert, [](const types::DnsQuery& q) {
        auto wire = types::encode_response(q, types::ResolveResult{});
        wire[2] |= std::byte{ 0x02 }; // TC: there is no smaller transport to retry on
        return std::vector<std::vector<std::byte>>{ wire };
    });
    EXPECT_EQ(ask(endpoint(server)).rcode, Rcode::ServFail);
}

TEST_F(DotUpstream, ReplyCutShortIsServFail) {
    // the length prefix promises 64 bytes, three arrive, then the server hangs up
    FakeDotServer server(cert, [](const types::DnsQuery&) { return std::vector<std::vector<std::byte>>{ { std::byte{ 0 }, std::byte{ 64 }, std::byte{ 1 }, std::byte{ 2 }, std::byte{ 3 } } }; },
                         false);
    EXPECT_EQ(ask(endpoint(server)).rcode, Rcode::ServFail);
}

TEST_F(DotUpstream, AFailedQueryDoesNotPoisonTheNextOne) {
    std::atomic<int> calls{ 0 };
    FakeDotServer server(cert, [&calls](const types::DnsQuery& q) {
        if (calls++ == 0) return std::vector<std::vector<std::byte>>{ std::vector<std::byte>(5, std::byte{ 0xFF }) };
        return FakeDotServer::reply(q, support::result(Rcode::NoError, { support::a_record(q.name, "192.0.2.1") }));
    });
    EXPECT_EQ(ask(endpoint(server), "a.example.").rcode, Rcode::ServFail);
    EXPECT_EQ(ask(endpoint(server), "b.example.").rcode, Rcode::NoError);
    EXPECT_EQ(server.handshakes(), 2); // the connection that carried garbage was not kept
}

// ---- upstream failure and timeouts ----

TEST_F(DotUpstream, SilentServerTimesOut) {
    FakeDotServer server(cert, [](const types::DnsQuery&) { return std::vector<std::vector<std::byte>>{}; });
    const auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(ask(endpoint(server), "example.com.", 200ms).rcode, Rcode::ServFail);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 1s);
    EXPECT_EQ(tls->stats().failed, 1u);
}

TEST_F(DotUpstream, ClosedPortFailsFast) {
    const auto start = std::chrono::steady_clock::now();
    const auto r     = ask(backend::Endpoint{ types::IP("127.0.0.1"), support::closed_port(), tls, "dns.test" });
    EXPECT_EQ(r.rcode, Rcode::ServFail);
    EXPECT_LT(std::chrono::steady_clock::now() - start, 500ms);
    EXPECT_EQ(tls->stats().failed, 1u);
}

TEST_F(DotUpstream, PlainDnsServerIsAFailureNotAFallback) {
    support::FakeDnsServer plain([](const types::DnsQuery& q, bool) { return support::FakeDnsServer::reply(q, support::result(Rcode::NoError)); });
    const auto r = ask(backend::Endpoint{ plain.ip(), plain.port(), tls, "dns.test" }, "example.com.", 300ms);
    EXPECT_EQ(r.rcode, Rcode::ServFail);
    EXPECT_EQ(plain.udp_queries(), 0);
    EXPECT_EQ(plain.tcp_queries(), 0);
    const auto s = tls->stats();
    EXPECT_EQ(s.failed, 1u);
    EXPECT_EQ(s.rejected, 0u);
}

TEST_F(DotUpstream, MovesOnToTheNextUpstreamWhenACertificateIsRejected) {
    FakeDotServer server(cert, answers("192.0.2.1"));
    backend::ForwardingResolver resolver({ endpoint(server, "impostor.test"), endpoint(server) }, cache, 1000ms);
    EXPECT_EQ(resolver.resolve(DomainName("example.com."), RecordType::A, RecordClass::IN).rcode, Rcode::NoError);
    const auto s = tls->stats();
    EXPECT_EQ(s.rejected, 1u);
    EXPECT_EQ(s.handshakes, 1u);
}

// ---- configuration ----

TEST(TlsClient, MissingCaFileIsAnError) {
    backend::TlsClient tls;
    const auto r = tls.configure("/nonexistent/ca.pem");
    ASSERT_FALSE(r.has_value());
    EXPECT_NE(r.error().find("/nonexistent/ca.pem"), std::string::npos) << r.error();
    EXPECT_FALSE(tls.configured());
}

TEST(TlsClient, ConfiguresOnce) {
    backend::TlsClient tls;
    EXPECT_TRUE(tls.configure().has_value());
    EXPECT_TRUE(tls.configured());
    EXPECT_FALSE(tls.configure().has_value());
}

TEST(TlsClient, UnconfiguredClientFailsEveryQuery) {
    auto tls = std::make_shared<backend::TlsClient>();
    backend::Cache cache;
    backend::ForwardingResolver resolver({ backend::Endpoint{ types::IP("127.0.0.1"), support::closed_port(), tls, "" } }, cache, 200ms);
    EXPECT_EQ(resolver.resolve(DomainName("example.com."), RecordType::A, RecordClass::IN).rcode, Rcode::ServFail);
    EXPECT_EQ(tls->stats().failed, 1u);
}

TEST(TlsClient, EndpointLabels) {
    EXPECT_EQ(backend::endpoint_label({ types::IP("1.1.1.1"), 853, nullptr, "cloudflare-dns.com" }), "1.1.1.1:853 (cloudflare-dns.com)");
    EXPECT_EQ(backend::endpoint_label({ types::IP("2606:4700::1111"), 53, nullptr, "" }), "[2606:4700::1111]:53");
}
