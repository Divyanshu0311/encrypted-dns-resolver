#pragma once
#include<cstddef>
#include<cstdint>
#include<expected>
#include<filesystem>
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

  bool operator==(const Upstream&) const = default;
};

struct Config {
  Mode mode = Mode::Forwarding;
  std::vector<Upstream> upstreams;         // must be non-empty in forwarding mode
  std::filesystem::path records_file;      // empty means no local records
  std::size_t workers = 4;                 // 1-64
  std::size_t queue_capacity = 256;        // 1-100000
  Ms request_timeout{2500};                // 50-30000
  LbPolicy lb_policy = LbPolicy::LeastOutstanding;
  uint32_t failure_threshold = 5;          // >= 1
  Ms cooldown{5000};                       // >= 100
  double rate_limit_qps = 0;               // 0 disables the limiter
  double rate_limit_burst = 0;             // >= 1 when qps > 0
  LogLevel log_level = LogLevel::Info;
};

// 1.1.1.1, 1.1.1.1:53, [2606:4700::1111]:53 or a bare 2606:4700::1111. port defaults to 53
std::expected<Upstream, std::string> parse_upstream(std::string_view s);

// parses `key = value` text only, touches no files. errors look like "line 7: unknown key 'worker'"
std::expected<Config, std::string> parse_config(std::string_view text);

// reads the file, parses it, then checks records_file exists if it is set
std::expected<Config, std::string> load_config(const std::filesystem::path& path);

} // namespace mw
