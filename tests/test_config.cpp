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
