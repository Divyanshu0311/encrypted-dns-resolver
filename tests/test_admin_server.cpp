#include "mw/admin_server.hpp"

#include "support/fake_dot_server.hpp"
#include "support/fakes.hpp"
#include "support/show.hpp"
#include "support/temp_dir.hpp"
#include "support/tls_cert.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace {

struct HttpReply {
  int status = 0;
  std::string body;
};

// one request, Connection: close, so the reply ends when the server closes
HttpReply http(uint16_t port, const std::string& method, const std::string& target, const std::string& host = "127.0.0.1") {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval tv{5, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return {};
  }
  std::string req = method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
  ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);
  std::string raw;
  char buf[4096];
  ssize_t n;
  while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0)
    raw.append(buf, static_cast<std::size_t>(n));
  ::close(fd);

  HttpReply reply;
  if (raw.size() > 12)
    reply.status = std::stoi(raw.substr(9, 3));
  auto split = raw.find("\r\n\r\n");
  if (split != std::string::npos)
    reply.body = raw.substr(split + 4);
  return reply;
}

class AdminServerTest : public ::testing::Test {
  protected:
    support::TempDir dir;
    mw::Config cfg;
    mw::ResolverShared shared;
    mw::Admission admission;
    std::unique_ptr<mw::Middleware> middleware;
    std::unique_ptr<mw::AdminServer> admin;
    uint16_t port = 0;

    void SetUp() override {
      mw::set_log_level(mw::LogLevel::Error);
      cfg.workers = 2;
      cfg.admin_listen = mw::ListenAddress{"127.0.0.1", 0};
      cfg.admin_ui_dir = dir.path();
      dir.write("index.html", "<h1>console</h1>");
      auto blocked = mw::Admission::parse("ads.example\n");
      ASSERT_TRUE(blocked.has_value());
      admission = *blocked;
      middleware = std::make_unique<mw::Middleware>(cfg, mw::make_factory(cfg, mw::StubOptions{}));
      middleware->start();
      admin = std::make_unique<mw::AdminServer>(cfg, *middleware, admission, shared);
      auto started = admin->start();
      ASSERT_TRUE(started.has_value()) << started.error();
      port = *started;
    }

    void TearDown() override {
      if (admin)
        admin->stop();
      if (middleware)
        middleware->stop(mw::Ms(0));
      mw::set_log_level(mw::LogLevel::Info);
    }
};

bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

} // namespace

TEST_F(AdminServerTest, ServesThePage) {
  auto r = http(port, "GET", "/");
  EXPECT_SHOW_EQ(r.status, 200);
  EXPECT_SHOW_EQ(r.body, std::string("<h1>console</h1>"));
  EXPECT_SHOW_EQ(http(port, "GET", "/../secret").status, 404);
}

TEST_F(AdminServerTest, LookupGoesThroughTheMiddleware) {
  auto r = http(port, "GET", "/api/lookup?name=www.example.com&type=A&via=server");
  EXPECT_SHOW_EQ(r.status, 200);
  EXPECT_TRUE(contains(r.body, "\"rcode\":\"NOERROR\"")) << r.body;
  EXPECT_TRUE(contains(r.body, "\"data\":\"127.0.0.1\"")) << r.body;
  EXPECT_TRUE(contains(r.body, "\"served_by\":\"stub\"")) << r.body;

  // and shows up in the query log
  auto log = http(port, "GET", "/api/queries?after=0");
  EXPECT_TRUE(contains(log.body, "\"name\":\"www.example.com\"")) << log.body;
}

TEST_F(AdminServerTest, BlockedDomainIsRefused) {
  auto r = http(port, "GET", "/api/lookup?name=tracker.ads.example&via=server");
  EXPECT_TRUE(contains(r.body, "\"rcode\":\"REFUSED\"")) << r.body;
  EXPECT_TRUE(contains(r.body, "blocked domain")) << r.body;
}

TEST_F(AdminServerTest, BadRequests) {
  EXPECT_SHOW_EQ(http(port, "GET", "/api/lookup?via=server").status, 400);
  EXPECT_SHOW_EQ(http(port, "GET", "/api/lookup?name=x.com&type=BOGUS").status, 400);
  EXPECT_SHOW_EQ(http(port, "GET", "/api/lookup?name=x.com&via=nowhere").status, 400);
  EXPECT_SHOW_EQ(http(port, "POST", "/api/faults?fail_rate=2").status, 400);
  EXPECT_SHOW_EQ(http(port, "GET", "/api/nothing").status, 404);
  EXPECT_SHOW_EQ(http(port, "DELETE", "/api/status").status, 405);
}

TEST_F(AdminServerTest, ForeignHostIsRefused) {
  EXPECT_SHOW_EQ(http(port, "GET", "/api/status", "evil.example:8080").status, 403);
  EXPECT_SHOW_EQ(http(port, "GET", "/api/status", "localhost:8080").status, 200);
}

TEST_F(AdminServerTest, MetricsAndStatus) {
  http(port, "GET", "/api/lookup?name=a.example&via=server");
  auto m = http(port, "GET", "/api/metrics");
  EXPECT_SHOW_EQ(m.status, 200);
  EXPECT_TRUE(contains(m.body, "\"received\":1")) << m.body;
  EXPECT_TRUE(contains(m.body, "\"workers\":[{")) << m.body;
  auto s = http(port, "GET", "/api/status");
  EXPECT_TRUE(contains(s.body, "\"mode\":\"forwarding\"")) << s.body;
  EXPECT_TRUE(contains(s.body, "\"id\":\"recursive\"")) << s.body;
}

TEST_F(AdminServerTest, LoadTestRunsToTheEnd) {
  auto r = http(port, "POST", "/api/load?count=500&concurrency=50");
  EXPECT_SHOW_EQ(r.status, 200);
  for (int i = 0; i < 100; i++) {
    if (contains(http(port, "GET", "/api/load").body, "\"running\":false"))
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  auto done = http(port, "GET", "/api/load").body;
  EXPECT_TRUE(contains(done, "\"done\":500")) << done;
  EXPECT_TRUE(contains(done, "\"NOERROR\":500")) << done;
  // synthetic traffic stays out of the query log
  EXPECT_FALSE(contains(http(port, "GET", "/api/queries?after=0").body, "198.18."));
}

TEST_F(AdminServerTest, TrafficRunsUntilStopped) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/traffic?rate=2000&names=popular").status, 200);
  EXPECT_SHOW_EQ(http(port, "POST", "/api/traffic?rate=2000").status, 409); // one at a time
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  http(port, "POST", "/api/traffic/stop");
  for (int i = 0; i < 100 && contains(http(port, "GET", "/api/metrics").body, "\"traffic\":{\"running\":true"); i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  auto m = http(port, "GET", "/api/metrics").body;
  EXPECT_TRUE(contains(m, "\"traffic\":{\"running\":false")) << m;
  EXPECT_FALSE(contains(m, "\"names\":\"popular\",\"sent\":0,")) << m; // it did send something
  EXPECT_SHOW_EQ(http(port, "POST", "/api/traffic?names=everything").status, 400);
}

TEST_F(AdminServerTest, StubServerCannotSwitchResolver) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/resolver?id=recursive").status, 400);
}

TEST_F(AdminServerTest, AbuseValidatesItsInput) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/abuse?client=nobody").status, 400);
  EXPECT_SHOW_EQ(http(port, "POST", "/api/abuse?seconds=0").status, 400);
}

TEST_F(AdminServerTest, FaultsSwitchIsShared) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/faults?fail_rate=0.25").status, 200);
  EXPECT_SHOW_EQ(shared.faults->fail_rate.load(), 0.25);
}

// a rate limit low enough to trip in a few hundred milliseconds
class AdminAbuseTest : public AdminServerTest {
  protected:
    void SetUp() override {
      cfg.rate_limit_qps = 50;
      cfg.rate_limit_burst = 20;
      cfg.block_rate_limit_strikes = 10;
      cfg.block_duration = mw::Ms(60000);
      AdminServerTest::SetUp();
    }
};

TEST_F(AdminAbuseTest, FloodingClientGetsBlockedAndCanBeUnblocked) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/abuse?client=203.0.113.9&rate=1000&seconds=1").status, 200);
  // the client is over its limit within the first second
  for (int i = 0; i < 60 && !contains(http(port, "GET", "/api/metrics").body, "\"blocked_now\":true"); i++)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  auto m = http(port, "GET", "/api/metrics").body;
  EXPECT_TRUE(contains(m, "\"blocked_now\":true")) << m;
  EXPECT_TRUE(contains(m, "\"blocks_started\":1")) << m;
  EXPECT_TRUE(contains(m, "\"blocked_sources\":1")) << m;
  EXPECT_FALSE(contains(m, "\"first_blocked_s\":null")) << m;

  // another client is not affected
  auto other = http(port, "GET", "/api/lookup?name=www.example.com&via=server");
  EXPECT_TRUE(contains(other.body, "\"rcode\":\"NOERROR\"")) << other.body;

  auto u = http(port, "POST", "/api/unblock?client=203.0.113.9");
  EXPECT_TRUE(contains(u.body, "\"was_blocked\":true")) << u.body;
  EXPECT_TRUE(contains(http(port, "GET", "/api/metrics").body, "\"blocked_sources\":0"));
}

TEST_F(AdminAbuseTest, ClientUnderTheLimitIsNeverBlocked) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/abuse?client=203.0.113.10&rate=20&seconds=1").status, 200);
  std::this_thread::sleep_for(std::chrono::milliseconds(1300));
  auto m = http(port, "GET", "/api/metrics").body;
  EXPECT_TRUE(contains(m, "\"blocked_now\":false")) << m;
  EXPECT_TRUE(contains(m, "\"rate_limited\":0")) << m;
}

// a DNS-over-TLS upstream signed by a test CA the admin page's TLS client trusts
class AdminTlsTest : public AdminServerTest {
  protected:
    mw::test::TestCa ca{dir};
    support::FakeDotServer upstream{ca.issue("upstream"), [](const types::DnsQuery& q) {
                                      return support::FakeDotServer::reply(q, support::result(mw::Rcode::NoError, {support::a_record(q.name, "192.0.2.80")}));
                                    }};

    void SetUp() override {
      ASSERT_TRUE(shared.upstream_tls->configure(ca.cert_file()).has_value());
      cfg.upstreams = {mw::Upstream{"127.0.0.1", upstream.port(), true, "dns.test"}};
      AdminServerTest::SetUp();
    }

    std::string probe(const std::string& name) {
      return http(port, "POST", "/api/tls/probe?ip=127.0.0.1&port=" + std::to_string(upstream.port()) + "&name=" + name).body;
    }
};

TEST_F(AdminTlsTest, ProbeShowsAnAcceptedCertificate) {
  auto r = probe("dns.test");
  EXPECT_TRUE(contains(r, "\"verified\":true")) << r;
  EXPECT_TRUE(contains(r, "\"protocol\":\"TLSv1.3\"")) << r;
  EXPECT_TRUE(contains(r, "\"subject\":\"CN=dns.test\"")) << r;
  EXPECT_TRUE(contains(r, "\"issuer\":\"CN=Test CA\"")) << r;
  EXPECT_TRUE(contains(r, "\"checked_against\":\"name dns.test\"")) << r;
}

TEST_F(AdminTlsTest, ProbeShowsARejectedCertificate) {
  auto r = probe("bank.example");
  EXPECT_TRUE(contains(r, "\"connected\":true")) << r;
  EXPECT_TRUE(contains(r, "\"verified\":false")) << r;
  EXPECT_TRUE(contains(r, "hostname mismatch")) << r;
  auto m = http(port, "GET", "/api/metrics").body;
  EXPECT_TRUE(contains(m, "\"upstream_tls\":{")) << m;
  EXPECT_TRUE(contains(m, "\"rejected\":1")) << m;
  EXPECT_TRUE(contains(m, "\"last_rejection\":\"certificate rejected: hostname mismatch\"")) << m;
}

TEST_F(AdminTlsTest, LookupThroughATlsUpstream) {
  auto id = "dot:127.0.0.1:" + std::to_string(upstream.port());
  auto s = http(port, "GET", "/api/status").body;
  EXPECT_TRUE(contains(s, "\"id\":\"" + id + "\"")) << s;
  EXPECT_TRUE(contains(s, "tls://127.0.0.1:" + std::to_string(upstream.port()) + "#dns.test")) << s;
  auto r = http(port, "GET", "/api/lookup?name=www.example.com&via=" + id).body;
  EXPECT_TRUE(contains(r, "192.0.2.80")) << r;
  EXPECT_TRUE(contains(r, "(dns.test) over TLS")) << r;
  auto m = http(port, "GET", "/api/metrics").body;
  EXPECT_TRUE(contains(m, "\"queries\":1,\"handshakes\":1")) << m;
  EXPECT_TRUE(contains(m, "\"last_subject\":\"CN=dns.test\"")) << m;
}

TEST_F(AdminTlsTest, ProbeValidatesItsInput) {
  EXPECT_SHOW_EQ(http(port, "POST", "/api/tls/probe?ip=dns.google").status, 400);
  EXPECT_SHOW_EQ(http(port, "POST", "/api/tls/probe?ip=127.0.0.1&port=0").status, 400);
  EXPECT_SHOW_EQ(http(port, "POST", "/api/tls/probe?ip=127.0.0.1&name=a%20b").status, 400);
  EXPECT_SHOW_EQ(http(port, "GET", "/api/tls/probe?ip=127.0.0.1").status, 404);
}
