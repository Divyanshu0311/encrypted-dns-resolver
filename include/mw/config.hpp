#pragma once
#include<cstddef>
#include<cstdint>
#include<expected>
#include<filesystem>
#include<optional>
#include<string>
#include<string_view>
#include<vector>

#include "mw/logger.hpp"
#include "mw/types.hpp"

// Will hold: mw::Config

namespace mw {

enum class Mode : uint8_t {
  Forwarding,
  Recursive
};

struct Upstream {
  std::string host;
  uint16_t port = 53;
  bool tls = false;     // DNS-over-TLS (RFC 7858) instead of plain DNS
  std::string tls_name; // the name its certificate must carry; empty: the certificate must list host instead

  bool operator==(const Upstream&) const = default;
};

struct ListenAddress {
  std::string host = "0.0.0.0";
  uint16_t port = 853;

  bool operator==(const ListenAddress&) const = default;
};

struct Config {
  Mode mode = Mode::Forwarding;
  std::vector<Upstream> upstreams;         // must be non-empty in forwarding mode
  std::filesystem::path upstream_ca_file;  // CAs that tls:// upstreams' certificates must chain to; empty: the system's
  std::filesystem::path records_file;      // empty means no local records
  std::size_t workers = 4;                 // 1-64
  std::size_t queue_capacity = 256;        // 1-100000
  Ms request_timeout{2500};                // 50-30000
  LbPolicy lb_policy = LbPolicy::LeastOutstanding;
  uint32_t failure_threshold = 5;          // >= 1
  Ms cooldown{5000};                       // >= 100
  double rate_limit_qps = 0;               // 0 disables the limiter
  double rate_limit_burst = 0;             // >= 1 when qps > 0
  uint32_t block_rate_limit_strikes = 0;   // 0 disables; needs rate_limit_qps > 0
  uint32_t block_protocol_strikes = 0;     // 0 disables; above block_rate_limit_strikes when both are set
  Ms block_window{10000};                  // 100-3600000
  Ms block_duration{300000};               // 1000-604800000 (a week)
  std::size_t block_max_entries = 100000;  // 1-10000000
  LogLevel log_level = LogLevel::Info;

  // front end
  ListenAddress listen;
  std::filesystem::path tls_cert;          // both or neither
  std::filesystem::path tls_key;
  std::size_t max_connections = 1000;      // 1-100000
  std::size_t max_connections_per_source = 32; // 0-100000, 0 means no limit. IPv4 per address, IPv6 per /64
  Ms idle_timeout{10000};                  // 1000-300000
  std::filesystem::path blocked_domains_file; // empty means no domain blocking

  // admin page (HTTP, no TLS: keep it on loopback)
  std::optional<ListenAddress> admin_listen;  // unset means no admin page
  std::filesystem::path admin_ui_dir = "gui"; // where index.html is served from
};

// 1.1.1.1, 1.1.1.1:53, [2606:4700::1111]:53 or a bare 2606:4700::1111. port defaults to 53.
// tls://1.1.1.1#cloudflare-dns.com is DNS-over-TLS, port 853 unless given, the certificate checked against the
// name after '#' (or, without one, against the IP address)
std::expected<Upstream, std::string> parse_upstream(std::string_view s);

// the form parse_upstream reads: "1.1.1.1:53", "tls://[2606:4700::1111]:853#cloudflare-dns.com"
std::string upstream_text(const Upstream& u);

// same forms as parse_upstream, port defaults to 853
std::expected<ListenAddress, std::string> parse_listen(std::string_view s);

// same forms, port defaults to 8080. "off" gives nullopt
std::expected<std::optional<ListenAddress>, std::string> parse_admin_listen(std::string_view s);

// parses `key = value` text only, touches no files. errors look like "line 7: unknown key 'worker'"
std::expected<Config, std::string> parse_config(std::string_view text);

// reads the file, parses it, then checks that every file path that is set exists
std::expected<Config, std::string> load_config(const std::filesystem::path& path);

} // namespace mw
