#include "mw/config.hpp"

#include "support/show.hpp"
#include "support/temp_dir.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

// the error must start with "line N:"
::testing::AssertionResult error_on_line(const std::string& text, int line) {
  const auto cfg = mw::parse_config(text);
  if (cfg) {
    return ::testing::AssertionFailure() << "parsed, expected an error on line " << line;
  }
  const std::string prefix = "line " + std::to_string(line) + ":";
  if (cfg.error().rfind(prefix, 0) != 0) {
    return ::testing::AssertionFailure() << "error '" << cfg.error() << "' does not start with '" << prefix << "'";
  }
  return ::testing::AssertionSuccess();
}

} // namespace

// ---- parse_upstream ----

TEST(ParseUpstream, Ipv4DefaultsToPort53) {
  const auto u = mw::parse_upstream("8.8.8.8");
  ASSERT_TRUE(u.has_value());
  EXPECT_SHOW_EQ(*u, (mw::Upstream{"8.8.8.8", 53}));
}

TEST(ParseUpstream, Ipv4WithPort) {
  const auto u = mw::parse_upstream("1.1.1.1:5353");
  ASSERT_TRUE(u.has_value());
  EXPECT_SHOW_EQ(*u, (mw::Upstream{"1.1.1.1", 5353}));
}

TEST(ParseUpstream, BracketedIpv6WithPort) {
  const auto u = mw::parse_upstream("[::1]:5353");
  ASSERT_TRUE(u.has_value());
  EXPECT_SHOW_EQ(*u, (mw::Upstream{"::1", 5353}));
}

TEST(ParseUpstream, BareIpv6) {
  const auto u = mw::parse_upstream("2606:4700::1111");
  ASSERT_TRUE(u.has_value());
  EXPECT_SHOW_EQ(*u, (mw::Upstream{"2606:4700::1111", 53}));
}

TEST(ParseUpstream, Rejects) {
  for (const char* bad : {"999.1.1.1", "1.1.1.1:0", "1.1.1.1:65536", "1.1.1.1:", "example.com", "[::1", "[::1]x", ""}) {
    EXPECT_FALSE(mw::parse_upstream(bad).has_value()) << bad;
  }
}

// ---- parse_listen ----

TEST(ParseListen, DefaultsToPort853) {
  const auto l = mw::parse_listen("0.0.0.0");
  ASSERT_TRUE(l.has_value()) << l.error();
  EXPECT_SHOW_EQ(l->host, "0.0.0.0");
  EXPECT_SHOW_EQ(l->port, 853);
}

TEST(ParseListen, AcceptsTheSameFormsAsUpstream) {
  const auto v4 = mw::parse_listen("127.0.0.1:8853");
  ASSERT_TRUE(v4.has_value()) << v4.error();
  EXPECT_SHOW_EQ(v4->host, "127.0.0.1");
  EXPECT_SHOW_EQ(v4->port, 8853);

  const auto v6 = mw::parse_listen("[::]:853");
  ASSERT_TRUE(v6.has_value()) << v6.error();
  EXPECT_SHOW_EQ(v6->host, "::");
  EXPECT_SHOW_EQ(v6->port, 853);

  const auto bare = mw::parse_listen("::");
  ASSERT_TRUE(bare.has_value()) << bare.error();
  EXPECT_SHOW_EQ(bare->host, "::");
  EXPECT_SHOW_EQ(bare->port, 853);
}

TEST(ParseListen, Rejects) {
  for (const char* bad : {"999.1.1.1", "0.0.0.0:0", "0.0.0.0:65536", "0.0.0.0:", "localhost", "[::", ""}) {
    EXPECT_FALSE(mw::parse_listen(bad).has_value()) << bad;
  }
}

TEST(ParseListen, ErrorsSayListen) {
  const auto l = mw::parse_listen("0.0.0.0:x");
  ASSERT_FALSE(l.has_value());
  EXPECT_SHOW_EQ(l.error(), "listen '0.0.0.0:x' has an invalid port (1-65535)");
  EXPECT_SHOW_EQ(mw::parse_upstream("0.0.0.0:x").error(), "upstream '0.0.0.0:x' has an invalid port (1-65535)");
}

// ---- parse_config ----

TEST(ParseConfig, RecursiveWithNothingElseIsAllDefaults) {
  const auto cfg = mw::parse_config("mode = recursive\n");
  ASSERT_TRUE(cfg.has_value()) << cfg.error();
  EXPECT_SHOW_EQ(cfg->mode, mw::Mode::Recursive);
  EXPECT_SHOW_EQ(cfg->upstreams.size(), 0u);
  EXPECT_SHOW_EQ(cfg->records_file.empty(), true);
  EXPECT_SHOW_EQ(cfg->workers, 4u);
  EXPECT_SHOW_EQ(cfg->queue_capacity, 256u);
  EXPECT_SHOW_EQ(cfg->request_timeout.count(), 2500);
  EXPECT_SHOW_EQ(cfg->lb_policy, mw::LbPolicy::LeastOutstanding);
  EXPECT_SHOW_EQ(cfg->failure_threshold, 5u);
  EXPECT_SHOW_EQ(cfg->cooldown.count(), 5000);
  EXPECT_SHOW_EQ(cfg->rate_limit_qps, 0.0);
  EXPECT_SHOW_EQ(cfg->rate_limit_burst, 0.0);
  EXPECT_SHOW_EQ(cfg->log_level, mw::LogLevel::Info);
}

TEST(ParseConfig, ReadsEveryKey) {
  const auto cfg = mw::parse_config(R"(
# comment
  mode = Forwarding
upstreams = 1.1.1.1, [2606:4700::1111]:53 ,8.8.8.8:5353
records_file = zones/local.txt
workers = 8
queue_capacity = 1000
request_timeout_ms = 1500
lb_policy = POWER_OF_TWO
failure_threshold = 3
cooldown_ms = 250
rate_limit_qps = 12.5
rate_limit_burst = 20
log_level = Debug
)");
  ASSERT_TRUE(cfg.has_value()) << cfg.error();
  EXPECT_SHOW_EQ(cfg->mode, mw::Mode::Forwarding);
  ASSERT_SHOW_EQ(cfg->upstreams.size(), 3u);
  EXPECT_SHOW_EQ(cfg->upstreams[0], (mw::Upstream{"1.1.1.1", 53}));
  EXPECT_SHOW_EQ(cfg->upstreams[1], (mw::Upstream{"2606:4700::1111", 53}));
  EXPECT_SHOW_EQ(cfg->upstreams[2], (mw::Upstream{"8.8.8.8", 5353}));
  EXPECT_SHOW_EQ(cfg->records_file.string(), "zones/local.txt");
  EXPECT_SHOW_EQ(cfg->workers, 8u);
  EXPECT_SHOW_EQ(cfg->queue_capacity, 1000u);
  EXPECT_SHOW_EQ(cfg->request_timeout.count(), 1500);
  EXPECT_SHOW_EQ(cfg->lb_policy, mw::LbPolicy::PowerOfTwo);
  EXPECT_SHOW_EQ(cfg->failure_threshold, 3u);
  EXPECT_SHOW_EQ(cfg->cooldown.count(), 250);
  EXPECT_SHOW_EQ(cfg->rate_limit_qps, 12.5);
  EXPECT_SHOW_EQ(cfg->rate_limit_burst, 20.0);
  EXPECT_SHOW_EQ(cfg->log_level, mw::LogLevel::Debug);
}

TEST(ParseConfig, ExampleFileParses) {
  // CMake compiles with absolute paths, so the repo root is two levels above this file
  const auto root = std::filesystem::path(__FILE__).parent_path().parent_path();
  std::ifstream in(root / "config" / "middleware.example.conf");
  ASSERT_TRUE(in.good());
  const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  const auto cfg = mw::parse_config(text);
  EXPECT_TRUE(cfg.has_value()) << cfg.error();
}

TEST(ParseConfig, ErrorsNameTheLine) {
  EXPECT_TRUE(error_on_line("mode = recursive\n# c\n\nworker = 4\n", 4)); // unknown key
  EXPECT_TRUE(error_on_line("mode = recursive\nworkers = 4\nworkers = 5\n", 3));
  EXPECT_TRUE(error_on_line("mode = recursive\nworkers = 0\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nworkers = 65\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nworkers = 4x\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nlb_policy = random\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nworkers 4\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\n = 4\n", 2));
  EXPECT_TRUE(error_on_line("mode = sideways\n", 1));
  EXPECT_TRUE(error_on_line("mode = recursive\nrequest_timeout_ms = 49\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\ncooldown_ms = 99\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nfailure_threshold = 0\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nrate_limit_qps = -1\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nupstreams = 1.1.1.1,,8.8.8.8\n", 2));
  EXPECT_TRUE(error_on_line("mode = recursive\nlog_level = loud\n", 2));
}

TEST(ParseConfig, UnknownKeyMessage) {
  const auto cfg = mw::parse_config("mode = recursive\nworker = 4\n");
  ASSERT_FALSE(cfg.has_value());
  EXPECT_SHOW_EQ(cfg.error(), "line 2: unknown key 'worker'");
}

TEST(ParseConfig, ForwardingNeedsUpstreams) {
  const auto cfg = mw::parse_config("mode = forwarding\n");
  ASSERT_FALSE(cfg.has_value());
  EXPECT_SHOW_EQ(cfg.error().rfind("line", 0) == 0, false); // cross field: no line number
}

TEST(ParseConfig, QpsNeedsBurst) {
  EXPECT_FALSE(mw::parse_config("mode = recursive\nrate_limit_qps = 10\n").has_value());
  EXPECT_FALSE(mw::parse_config("mode = recursive\nrate_limit_qps = 10\nrate_limit_burst = 0.5\n").has_value());
  EXPECT_TRUE(mw::parse_config("mode = recursive\nrate_limit_qps = 10\nrate_limit_burst = 1\n").has_value());
}

TEST(ParseConfig, BlockAndFrontEndDefaults) {
  const auto cfg = mw::parse_config("mode = recursive\n");
  ASSERT_TRUE(cfg.has_value()) << cfg.error();
  EXPECT_SHOW_EQ(cfg->block_rate_limit_strikes, 0u);
  EXPECT_SHOW_EQ(cfg->block_protocol_strikes, 0u);
  EXPECT_SHOW_EQ(cfg->block_window.count(), 10000);
  EXPECT_SHOW_EQ(cfg->block_duration.count(), 300000);
  EXPECT_SHOW_EQ(cfg->block_max_entries, 100000u);
  EXPECT_SHOW_EQ(cfg->listen.host, "0.0.0.0");
  EXPECT_SHOW_EQ(cfg->listen.port, 853);
  EXPECT_SHOW_EQ(cfg->tls_cert.empty(), true);
  EXPECT_SHOW_EQ(cfg->tls_key.empty(), true);
  EXPECT_SHOW_EQ(cfg->max_connections, 1000u);
  EXPECT_SHOW_EQ(cfg->max_connections_per_source, 32u);
  EXPECT_SHOW_EQ(cfg->idle_timeout.count(), 10000);
  EXPECT_SHOW_EQ(cfg->blocked_domains_file.empty(), true);
}

TEST(ParseConfig, ReadsBlockAndFrontEndKeys) {
  const auto cfg = mw::parse_config(R"(
mode = recursive
rate_limit_qps = 100
rate_limit_burst = 50
block_rate_limit_strikes = 5
block_protocol_strikes = 20
block_window_ms = 30000
block_duration_ms = 600000
block_max_entries = 5000
listen = [::]:8853
tls_cert = certs/server.pem
tls_key = certs/server.key
max_connections = 250
max_connections_per_source = 8
idle_timeout_ms = 15000
blocked_domains_file = policy/blocked.txt
)");
  ASSERT_TRUE(cfg.has_value()) << cfg.error();
  EXPECT_SHOW_EQ(cfg->block_rate_limit_strikes, 5u);
  EXPECT_SHOW_EQ(cfg->block_protocol_strikes, 20u);
  EXPECT_SHOW_EQ(cfg->block_window.count(), 30000);
  EXPECT_SHOW_EQ(cfg->block_duration.count(), 600000);
  EXPECT_SHOW_EQ(cfg->block_max_entries, 5000u);
  EXPECT_SHOW_EQ(cfg->listen.host, "::");
  EXPECT_SHOW_EQ(cfg->listen.port, 8853);
  EXPECT_SHOW_EQ(cfg->tls_cert.string(), "certs/server.pem");
  EXPECT_SHOW_EQ(cfg->tls_key.string(), "certs/server.key");
  EXPECT_SHOW_EQ(cfg->max_connections, 250u);
  EXPECT_SHOW_EQ(cfg->max_connections_per_source, 8u);
  EXPECT_SHOW_EQ(cfg->idle_timeout.count(), 15000);
  EXPECT_SHOW_EQ(cfg->blocked_domains_file.string(), "policy/blocked.txt");
}

TEST(ParseConfig, BlockAndFrontEndRanges) {
  const auto ok = [](const std::string& line) { return mw::parse_config("mode = recursive\n" + line + "\n").has_value(); };
  for (const char* line : {"block_window_ms = 100", "block_window_ms = 3600000", "block_duration_ms = 1000", "block_duration_ms = 604800000",
                           "block_max_entries = 1", "block_max_entries = 10000000", "max_connections = 1", "max_connections = 100000",
                           "idle_timeout_ms = 1000", "idle_timeout_ms = 300000", "block_protocol_strikes = 0",
                           "max_connections_per_source = 0", "max_connections_per_source = 100000"}) {
    EXPECT_SHOW_EQ_AS(line, ok(line), true);
  }
  for (const char* line : {"block_window_ms = 99", "block_window_ms = 3600001", "block_duration_ms = 999", "block_duration_ms = 604800001",
                           "block_max_entries = 0", "block_max_entries = 10000001", "max_connections = 0", "max_connections = 100001",
                           "idle_timeout_ms = 999", "idle_timeout_ms = 300001", "block_protocol_strikes = -1", "block_rate_limit_strikes = 3x",
                           "listen = localhost:853", "max_connections_per_source = 100001", "max_connections_per_source = -1"}) {
    EXPECT_TRUE(error_on_line("mode = recursive\n" + std::string(line) + "\n", 2)) << line;
  }
}

TEST(ParseConfig, ProtocolThresholdMustBeHigher) {
  const std::string base = "mode = recursive\nrate_limit_qps = 10\nrate_limit_burst = 5\nblock_rate_limit_strikes = 5\n";
  EXPECT_SHOW_EQ_AS("protocol 6 > rate limit 5", mw::parse_config(base + "block_protocol_strikes = 6\n").has_value(), true);
  EXPECT_SHOW_EQ_AS("protocol 0 (off)", mw::parse_config(base + "block_protocol_strikes = 0\n").has_value(), true);

  const auto equal = mw::parse_config(base + "block_protocol_strikes = 5\n");
  ASSERT_FALSE(equal.has_value());
  EXPECT_SHOW_EQ(equal.error(), "block_protocol_strikes must be greater than block_rate_limit_strikes");
  EXPECT_SHOW_EQ_AS("protocol 4 < rate limit 5", mw::parse_config(base + "block_protocol_strikes = 4\n").has_value(), false);
}

TEST(ParseConfig, RateLimitStrikesWithLimiterOffAreAccepted) {
  // rate_limit_qps = 0 is the limiter's off switch; the block setting stays for when it is switched back on
  const auto cfg = mw::parse_config("mode = recursive\nrate_limit_qps = 0\nblock_rate_limit_strikes = 5\nblock_protocol_strikes = 20\n");
  ASSERT_TRUE(cfg.has_value()) << cfg.error();
  EXPECT_SHOW_EQ(cfg->block_rate_limit_strikes, 5u);
}

TEST(ParseConfig, TlsCertAndKeyGoTogether) {
  EXPECT_FALSE(mw::parse_config("mode = recursive\ntls_cert = a.pem\n").has_value());
  EXPECT_FALSE(mw::parse_config("mode = recursive\ntls_key = a.key\n").has_value());
  const auto only_cert = mw::parse_config("mode = recursive\ntls_cert = a.pem\n");
  EXPECT_SHOW_EQ(only_cert.error(), "tls_cert and tls_key must be set together");
  EXPECT_TRUE(mw::parse_config("mode = recursive\ntls_cert = a.pem\ntls_key = a.key\n").has_value());
}

// ---- load_config ----

TEST(LoadConfig, MissingFileIsAnError) {
  EXPECT_FALSE(mw::load_config("/definitely/not/here.conf").has_value());
}

TEST(LoadConfig, ChecksRecordsFileExists) {
  support::TempDir dir;
  const std::string records = dir.write("records.txt", "");

  const std::string ok = dir.write("ok.conf", "mode = recursive\nrecords_file = " + records + "\n");
  const auto loaded = mw::load_config(ok);
  EXPECT_TRUE(loaded.has_value()) << loaded.error();

  const std::string bad = dir.write("bad.conf", "mode = recursive\nrecords_file = " + (dir.path() / "nope.txt").string() + "\n");
  EXPECT_FALSE(mw::load_config(bad).has_value());
}

TEST(LoadConfig, ChecksTlsAndBlockedDomainsFilesExist) {
  support::TempDir dir;
  const std::string cert = dir.write("server.pem", "");
  const std::string key = dir.write("server.key", "");
  const std::string domains = dir.write("blocked.txt", "");
  const std::string missing = (dir.path() / "nope").string();

  const std::string ok = dir.write("ok.conf", "mode = recursive\ntls_cert = " + cert + "\ntls_key = " + key + "\nblocked_domains_file = " + domains + "\n");
  const auto loaded = mw::load_config(ok);
  EXPECT_TRUE(loaded.has_value()) << loaded.error();

  const std::string no_cert = dir.write("c.conf", "mode = recursive\ntls_cert = " + missing + "\ntls_key = " + key + "\n");
  EXPECT_SHOW_EQ(mw::load_config(no_cert).error(), "tls_cert '" + missing + "' does not exist");

  const std::string no_key = dir.write("k.conf", "mode = recursive\ntls_cert = " + cert + "\ntls_key = " + missing + "\n");
  EXPECT_SHOW_EQ(mw::load_config(no_key).error(), "tls_key '" + missing + "' does not exist");

  const std::string no_domains = dir.write("d.conf", "mode = recursive\nblocked_domains_file = " + missing + "\n");
  EXPECT_SHOW_EQ(mw::load_config(no_domains).error(), "blocked_domains_file '" + missing + "' does not exist");
}
