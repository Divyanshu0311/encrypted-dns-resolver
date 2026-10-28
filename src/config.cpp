#include "mw/config.hpp"
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include<charconv>
#include<format>
#include<fstream>
#include<sstream>
#include<unordered_set>

#include "utils.hpp"

namespace mw {
namespace {

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
    s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
    s.remove_suffix(1);
  return s;
}

// the whole value must be consumed, "4x" is not 4
template<typename T>
std::optional<T> parse_number(std::string_view s) {
  T value{};
  auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
  if (ec != std::errc() || end != s.data() + s.size() || s.empty())
    return std::nullopt;
  return value;
}

bool is_ip(const std::string& host) {
  unsigned char buf[sizeof(in6_addr)];
  return inet_pton(AF_INET, host.c_str(), buf) == 1 || inet_pton(AF_INET6, host.c_str(), buf) == 1;
}

// parses an integer and checks lo <= value <= hi
std::expected<long long, std::string> int_in_range(std::string_view key, std::string_view value, long long lo, long long hi) {
  auto n = parse_number<long long>(value);
  if (!n)
    return std::unexpected(std::format("{} must be an integer, got '{}'", key, value));
  if (*n < lo || *n > hi) {
    if (hi == std::numeric_limits<long long>::max())
      return std::unexpected(std::format("{} must be at least {}, got {}", key, lo, *n));
    return std::unexpected(std::format("{} must be between {} and {}, got {}", key, lo, hi, *n));
  }
  return *n;
}

std::expected<double, std::string> non_negative_double(std::string_view key, std::string_view value) {
  auto d = parse_number<double>(value);
  if (!d)
    return std::unexpected(std::format("{} must be a number, got '{}'", key, value));
  if (*d < 0)
    return std::unexpected(std::format("{} must be >= 0, got {}", key, value));
  return *d;
}

struct HostPort {
  std::string host;
  uint16_t port;
};

// `what` names the value in errors, e.g. "upstream '1.2.3.4:x' has an invalid port"
std::expected<HostPort, std::string> parse_host_port(std::string_view s, uint16_t default_port, std::string_view what) {
  s = trim(s);
  std::string host;
  std::string_view port_text;

  if (!s.empty() && s.front() == '[') {
    // [v6]:port
    auto close = s.find(']');
    if (close == std::string_view::npos)
      return std::unexpected(std::format("{} '{}' is missing ']'", what, s));
    host = std::string(s.substr(1, close - 1));
    auto rest = s.substr(close + 1);
    if (!rest.empty()) {
      if (rest.front() != ':')
        return std::unexpected(std::format("{} '{}' has junk after ']'", what, s));
      port_text = rest.substr(1);
      if (port_text.empty())
        return std::unexpected(std::format("{} '{}' has an empty port", what, s));
    }
  }
  else if (std::count(s.begin(), s.end(), ':') > 1) {
    // bare v6, no port possible
    host = std::string(s);
  }
  else {
    auto colon = s.find(':');
    host = std::string(s.substr(0, colon));
    if (colon != std::string_view::npos) {
      port_text = s.substr(colon + 1);
      if (port_text.empty())
        return std::unexpected(std::format("{} '{}' has an empty port", what, s));
    }
  }

  if (!is_ip(host))
    return std::unexpected(std::format("{} '{}' is not an IPv4 or IPv6 address", what, s));

  HostPort result{host, default_port};
  if (!port_text.empty()) {
    auto port = parse_number<unsigned>(port_text);
    if (!port || *port < 1 || *port > 65535)
      return std::unexpected(std::format("{} '{}' has an invalid port (1-65535)", what, s));
    result.port = static_cast<uint16_t>(*port);
  }
  return result;
}

std::expected<std::vector<Upstream>, std::string> parse_upstream_list(std::string_view value) {
  std::vector<Upstream> upstreams;
  if (value.empty())
    return upstreams;
  while (true) {
    auto comma = value.find(',');
    auto item = trim(value.substr(0, comma));
    if (item.empty())
      return std::unexpected("upstreams has an empty entry");
    auto upstream = parse_upstream(item);
    if (!upstream)
      return std::unexpected(upstream.error());
    upstreams.push_back(*upstream);
    if (comma == std::string_view::npos)
      break;
    value.remove_prefix(comma + 1);
  }
  return upstreams;
}

// applies one `key = value` line to cfg. returns the problem, without the line number
std::expected<void, std::string> apply(Config& cfg, std::string_view key, std::string_view value) {
  std::string lower = utils::lower(std::string(value)); // enum values are case insensitive

  if (key == "mode") {
    if (lower == "forwarding")
      cfg.mode = Mode::Forwarding;
    else if (lower == "recursive")
      cfg.mode = Mode::Recursive;
    else
      return std::unexpected(std::format("mode must be forwarding or recursive, got '{}'", value));
  }
  else if (key == "upstreams") {
    auto list = parse_upstream_list(value);
    if (!list)
      return std::unexpected(list.error());
    cfg.upstreams = std::move(*list);
  }
  else if (key == "records_file") {
    cfg.records_file = std::string(value);
  }
  else if (key == "workers") {
    auto n = int_in_range(key, value, 1, 64);
    if (!n)
      return std::unexpected(n.error());
    cfg.workers = static_cast<std::size_t>(*n);
  }
  else if (key == "queue_capacity") {
    auto n = int_in_range(key, value, 1, 100000);
    if (!n)
      return std::unexpected(n.error());
    cfg.queue_capacity = static_cast<std::size_t>(*n);
  }
  else if (key == "request_timeout_ms") {
    auto n = int_in_range(key, value, 50, 30000);
    if (!n)
      return std::unexpected(n.error());
    cfg.request_timeout = Ms(*n);
  }
  else if (key == "lb_policy") {
    if (lower == "round_robin")
      cfg.lb_policy = LbPolicy::RoundRobin;
    else if (lower == "least_outstanding")
      cfg.lb_policy = LbPolicy::LeastOutstanding;
    else if (lower == "power_of_two")
      cfg.lb_policy = LbPolicy::PowerOfTwo;
    else
      return std::unexpected(std::format("lb_policy must be round_robin, least_outstanding or power_of_two, got '{}'", value));
  }
  else if (key == "failure_threshold") {
    auto n = int_in_range(key, value, 1, std::numeric_limits<uint32_t>::max());
    if (!n)
      return std::unexpected(n.error());
    cfg.failure_threshold = static_cast<uint32_t>(*n);
  }
  else if (key == "cooldown_ms") {
    auto n = int_in_range(key, value, 100, std::numeric_limits<long long>::max());
    if (!n)
      return std::unexpected(n.error());
    cfg.cooldown = Ms(*n);
  }
  else if (key == "rate_limit_qps") {
    auto d = non_negative_double(key, value);
    if (!d)
      return std::unexpected(d.error());
    cfg.rate_limit_qps = *d;
  }
  else if (key == "rate_limit_burst") {
    auto d = non_negative_double(key, value);
    if (!d)
      return std::unexpected(d.error());
    cfg.rate_limit_burst = *d;
  }
  else if (key == "block_rate_limit_strikes") {
    auto n = int_in_range(key, value, 0, std::numeric_limits<uint32_t>::max());
    if (!n)
      return std::unexpected(n.error());
    cfg.block_rate_limit_strikes = static_cast<uint32_t>(*n);
  }
  else if (key == "block_protocol_strikes") {
    auto n = int_in_range(key, value, 0, std::numeric_limits<uint32_t>::max());
    if (!n)
      return std::unexpected(n.error());
    cfg.block_protocol_strikes = static_cast<uint32_t>(*n);
  }
  else if (key == "block_window_ms") {
    auto n = int_in_range(key, value, 100, 3600000);
    if (!n)
      return std::unexpected(n.error());
    cfg.block_window = Ms(*n);
  }
  else if (key == "block_duration_ms") {
    auto n = int_in_range(key, value, 1000, 604800000);
    if (!n)
      return std::unexpected(n.error());
    cfg.block_duration = Ms(*n);
  }
  else if (key == "block_max_entries") {
    auto n = int_in_range(key, value, 1, 10000000);
    if (!n)
      return std::unexpected(n.error());
    cfg.block_max_entries = static_cast<std::size_t>(*n);
  }
  else if (key == "log_level") {
    if (lower == "debug")
      cfg.log_level = LogLevel::Debug;
    else if (lower == "info")
      cfg.log_level = LogLevel::Info;
    else if (lower == "warn")
      cfg.log_level = LogLevel::Warn;
    else if (lower == "error")
      cfg.log_level = LogLevel::Error;
    else
      return std::unexpected(std::format("log_level must be debug, info, warn or error, got '{}'", value));
  }
  else if (key == "listen") {
    auto listen = parse_listen(value);
    if (!listen)
      return std::unexpected(listen.error());
    cfg.listen = std::move(*listen);
  }
  else if (key == "tls_cert") {
    cfg.tls_cert = std::string(value);
  }
  else if (key == "tls_key") {
    cfg.tls_key = std::string(value);
  }
  else if (key == "max_connections") {
    auto n = int_in_range(key, value, 1, 100000);
    if (!n)
      return std::unexpected(n.error());
    cfg.max_connections = static_cast<std::size_t>(*n);
  }
  else if (key == "max_connections_per_source") {
    auto n = int_in_range(key, value, 0, 100000);
    if (!n)
      return std::unexpected(n.error());
    cfg.max_connections_per_source = static_cast<std::size_t>(*n);
  }
  else if (key == "idle_timeout_ms") {
    auto n = int_in_range(key, value, 1000, 300000);
    if (!n)
      return std::unexpected(n.error());
    cfg.idle_timeout = Ms(*n);
  }
  else if (key == "blocked_domains_file") {
    cfg.blocked_domains_file = std::string(value);
  }
  else if (key == "admin_listen") {
    auto admin = parse_admin_listen(value);
    if (!admin)
      return std::unexpected(admin.error());
    cfg.admin_listen = std::move(*admin);
  }
  else if (key == "admin_ui_dir") {
    cfg.admin_ui_dir = std::string(value);
  }
  else {
    return std::unexpected(std::format("unknown key '{}'", key));
  }
  return {};
}

} // namespace

std::expected<Upstream, std::string> parse_upstream(std::string_view s) {
  auto hp = parse_host_port(s, 53, "upstream");
  if (!hp)
    return std::unexpected(hp.error());
  return Upstream{std::move(hp->host), hp->port};
}

std::expected<ListenAddress, std::string> parse_listen(std::string_view s) {
  auto hp = parse_host_port(s, 853, "listen");
  if (!hp)
    return std::unexpected(hp.error());
  return ListenAddress{std::move(hp->host), hp->port};
}

std::expected<std::optional<ListenAddress>, std::string> parse_admin_listen(std::string_view s) {
  if (utils::lower(std::string(s)) == "off")
    return std::nullopt;
  auto hp = parse_host_port(s, 8080, "admin_listen");
  if (!hp)
    return std::unexpected(hp.error());
  return ListenAddress{std::move(hp->host), hp->port};
}

std::expected<Config, std::string> parse_config(std::string_view text) {
  Config cfg;
  std::unordered_set<std::string> seen;
  std::size_t line_no = 0;

  while (!text.empty()) {
    auto nl = text.find('\n');
    std::string_view line = trim(text.substr(0, nl));
    text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
    line_no++;

    if (line.empty() || line.front() == '#')
      continue;

    auto eq = line.find('=');
    if (eq == std::string_view::npos)
      return std::unexpected(std::format("line {}: expected 'key = value'", line_no));
    auto key = trim(line.substr(0, eq));
    auto value = trim(line.substr(eq + 1));
    if (key.empty())
      return std::unexpected(std::format("line {}: empty key", line_no));
    if (!seen.insert(std::string(key)).second)
      return std::unexpected(std::format("line {}: duplicate key '{}'", line_no, key));

    auto applied = apply(cfg, key, value);
    if (!applied)
      return std::unexpected(std::format("line {}: {}", line_no, applied.error()));
  }

  // cross field checks, no line number
  if (cfg.mode == Mode::Forwarding && cfg.upstreams.empty())
    return std::unexpected("forwarding mode needs at least one upstream");
  if (cfg.rate_limit_qps > 0 && cfg.rate_limit_burst < 1)
    return std::unexpected("rate_limit_burst must be at least 1 when rate_limit_qps > 0");
  // rate_limit_strikes with qps 0 is fine: the limiter is switched off, so those strikes just never happen
  if (cfg.block_rate_limit_strikes > 0 && cfg.block_protocol_strikes > 0 && cfg.block_protocol_strikes <= cfg.block_rate_limit_strikes)
    return std::unexpected("block_protocol_strikes must be greater than block_rate_limit_strikes");
  if (cfg.tls_cert.empty() != cfg.tls_key.empty())
    return std::unexpected("tls_cert and tls_key must be set together");

  return cfg;
}

std::expected<Config, std::string> load_config(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return std::unexpected(std::format("cannot read config file '{}'", path.string()));
  std::ostringstream buf;
  buf << in.rdbuf();
  if (in.bad())
    return std::unexpected(std::format("cannot read config file '{}'", path.string()));

  auto cfg = parse_config(buf.str());
  if (!cfg)
    return cfg;

  const std::pair<std::string_view, const std::filesystem::path*> files[] = {
      {"records_file", &cfg->records_file},
      {"tls_cert", &cfg->tls_cert},
      {"tls_key", &cfg->tls_key},
      {"blocked_domains_file", &cfg->blocked_domains_file},
  };
  for (const auto& [key, path] : files) {
    std::error_code ec;
    if (!path->empty() && !std::filesystem::exists(*path, ec))
      return std::unexpected(std::format("{} '{}' does not exist", key, path->string()));
  }
  return cfg;
}

} // namespace mw
