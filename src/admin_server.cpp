#include "mw/admin_server.hpp"
#include<algorithm>
#include<array>
#include<atomic>
#include<cctype>
#include<cerrno>
#include<cstdint>
#include<chrono>
#include<cmath>
#include<condition_variable>
#include<cstring>
#include<filesystem>
#include<format>
#include<fstream>
#include<functional>
#include<future>
#include<map>
#include<mutex>
#include<random>
#include<sstream>
#include<string_view>
#include<thread>
#include<unordered_map>
#include<vector>

#include<arpa/inet.h>
#include<netinet/in.h>
#include<poll.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<unistd.h>

#include "IP.hpp"
#include "backend/ForwardingResolver.hpp"
#include "backend/RecursiveResolver.hpp"
#include "backend/Upstream.hpp"
#include "mw/logger.hpp"

namespace mw {
namespace {

using SysClock = std::chrono::system_clock;

// ---- JSON ----

std::string json_string(std::string_view s) {
  std::string out = "\"";
  for (unsigned char c : s) {
    switch (c) {
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n"; break;
    case '\r': out += "\\r"; break;
    case '\t': out += "\\t"; break;
    default:
      // control characters, and bytes above ASCII read as Latin-1 so the output stays valid UTF-8
      if (c < 0x20 || c >= 0x7F)
        out += std::format("\\u{:04x}", static_cast<unsigned>(c));
      else
        out += static_cast<char>(c);
    }
  }
  out += '"';
  return out;
}

std::string json_number(double v) {
  if (!std::isfinite(v))
    return "null";
  return std::format("{:.3f}", v);
}

std::string json_array(const std::vector<std::string>& items) {
  std::string out = "[";
  for (std::size_t i = 0; i < items.size(); i++) {
    if (i != 0)
      out += ',';
    out += items[i];
  }
  return out + "]";
}

class JsonObject {
  private:
    std::string out_ = "{";
    bool first_ = true;

    void key(std::string_view k) {
      if (!first_)
        out_ += ',';
      first_ = false;
      out_ += json_string(k);
      out_ += ':';
    }

  public:
    JsonObject& raw(std::string_view k, std::string_view json) {
      key(k);
      out_ += json;
      return *this;
    }
    JsonObject& str(std::string_view k, std::string_view v) { return raw(k, json_string(v)); }
    JsonObject& num(std::string_view k, double v) { return raw(k, json_number(v)); }
    JsonObject& integer(std::string_view k, uint64_t v) { return raw(k, std::to_string(v)); }
    JsonObject& boolean(std::string_view k, bool v) { return raw(k, v ? "true" : "false"); }
    std::string done() { return out_ + "}"; }
};

std::string json_counts(const std::map<std::string, uint64_t>& counts) {
  JsonObject o;
  for (const auto& [k, v] : counts)
    o.integer(k, v);
  return o.done();
}

// ---- names ----

const char* rcode_name(Rcode rc) {
  static constexpr const char* names[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
                                          "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI"};
  auto i = static_cast<std::size_t>(rc);
  return i < std::size(names) ? names[i] : "OTHER";
}

std::string type_name(RecordType type) {
  switch (type) {
  case RecordType::A: return "A";
  case RecordType::NS: return "NS";
  case RecordType::CNAME: return "CNAME";
  case RecordType::SOA: return "SOA";
  case RecordType::PTR: return "PTR";
  case RecordType::MX: return "MX";
  case RecordType::TXT: return "TXT";
  case RecordType::AAAA: return "AAAA";
  case RecordType::SRV: return "SRV";
  case RecordType::DS: return "DS";
  case RecordType::RRSIG: return "RRSIG";
  case RecordType::DNSKEY: return "DNSKEY";
  case RecordType::SVCB: return "SVCB";
  case RecordType::HTTPS: return "HTTPS";
  case RecordType::CAA: return "CAA";
  case RecordType::ANY: return "ANY";
  default: return std::format("TYPE{}", static_cast<unsigned>(type));
  }
}

const char* transport_name(Transport t) {
  switch (t) {
  case Transport::Udp: return "udp";
  case Transport::Tcp: return "tcp";
  case Transport::Dot: return "dot";
  }
  return "?";
}

const char* breaker_name(BreakerState b) {
  switch (b) {
  case BreakerState::Closed: return "closed";
  case BreakerState::Open: return "open";
  case BreakerState::HalfOpen: return "half-open";
  }
  return "?";
}

const char* policy_name(LbPolicy p) {
  switch (p) {
  case LbPolicy::RoundRobin: return "round_robin";
  case LbPolicy::LeastOutstanding: return "least_outstanding";
  case LbPolicy::PowerOfTwo: return "power_of_two";
  }
  return "?";
}

uint32_t u32_at(const std::vector<uint8_t>& d, std::size_t pos) {
  return static_cast<uint32_t>(d[pos]) << 24 | static_cast<uint32_t>(d[pos + 1]) << 16 | static_cast<uint32_t>(d[pos + 2]) << 8 | d[pos + 3];
}

std::size_t wire_size(const DomainName& name) {
  return static_cast<std::vector<uint8_t>>(name).size();
}

// rdata the way dig prints it, or RFC 3597's \# form for types we don't know
std::string rdata_text(const ResourceRecord& r) {
  const auto& d = r.rdata;
  try {
    switch (r.type) {
    case RecordType::A:
    case RecordType::AAAA:
      if (d.size() == 4 || d.size() == 16)
        return std::string(types::IP(d));
      break;
    case RecordType::CNAME:
    case RecordType::NS:
    case RecordType::PTR:
    case RecordType::DNAME:
      return std::string(DomainName(d, 0));
    case RecordType::MX:
      if (d.size() > 2)
        return std::format("{} {}", d[0] << 8 | d[1], std::string(DomainName(d, 2)));
      break;
    case RecordType::SOA: {
      DomainName mname(d, 0);
      std::size_t pos = wire_size(mname);
      DomainName rname(d, pos);
      pos += wire_size(rname);
      if (pos + 20 == d.size())
        return std::format("{} {} {}", std::string(mname), std::string(rname), u32_at(d, pos));
      break;
    }
    case RecordType::TXT: {
      std::string out;
      for (std::size_t pos = 0; pos < d.size();) {
        std::size_t len = d[pos];
        if (pos + 1 + len > d.size())
          break;
        if (!out.empty())
          out += ' ';
        out += '"';
        out.append(reinterpret_cast<const char*>(&d[pos + 1]), len);
        out += '"';
        pos += 1 + len;
      }
      return out;
    }
    default:
      break;
    }
  }
  catch (const std::exception&) {
  }
  std::string hex;
  for (uint8_t b : d)
    hex += std::format("{:02x}", b);
  return std::format("\\# {} {}", d.size(), hex);
}

std::string records_json(const std::vector<ResourceRecord>& records) {
  std::vector<std::string> items;
  for (const auto& r : records)
    items.push_back(JsonObject()
                        .str("name", std::string(r.name))
                        .str("type", type_name(r.type))
                        .integer("ttl", r.ttl)
                        .str("data", rdata_text(r))
                        .done());
  return json_array(items);
}

std::string result_json(std::string_view name, RecordType type, std::string_view via, const ResolveResult& r, double latency_ms) {
  return JsonObject()
      .str("name", name)
      .str("type", type_name(type))
      .str("via", via)
      .str("rcode", rcode_name(r.rcode))
      .num("latency_ms", latency_ms)
      .str("served_by", r.served_by)
      .raw("answers", records_json(r.answer))
      .raw("authority", records_json(r.authority))
      .done();
}

// nearest-rank percentile of an unsorted sample. NaN when empty
double percentile(std::vector<double> v, double p) {
  if (v.empty())
    return std::nan("");
  auto k = static_cast<std::size_t>(std::ceil(p * static_cast<double>(v.size()))) - 1;
  k = std::min(k, v.size() - 1);
  std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(k), v.end());
  return v[k];
}

// popular names for the cache-friendly load test
constexpr const char* kPopularNames[] = {
    "google.com",    "youtube.com",   "facebook.com",  "wikipedia.org", "amazon.com",   "instagram.com", "linkedin.com",  "reddit.com",
    "netflix.com",   "microsoft.com", "apple.com",     "github.com",    "twitter.com",  "x.com",         "whatsapp.com",  "zoom.us",
    "stackoverflow.com", "bing.com",  "yahoo.com",     "cloudflare.com", "openai.com",  "anthropic.com", "mozilla.org",   "ubuntu.com",
    "python.org",    "cppreference.com", "nytimes.com", "bbc.co.uk",    "cnn.com",      "spotify.com",   "twitch.tv",     "discord.com",
    "dropbox.com",   "adobe.com",     "paypal.com",    "ebay.com",      "imdb.com",     "quora.com",     "medium.com",    "flipkart.com"};

// ---- HTTP ----

struct Request {
  std::string method;
  std::string path;
  std::unordered_map<std::string, std::string> params;
  std::string host;
};

struct Response {
  int status = 200;
  std::string content_type = "application/json";
  std::string body;
};

Response json_response(std::string body, int status = 200) {
  return Response{status, "application/json", std::move(body)};
}

Response error_response(int status, std::string_view message) {
  return json_response(JsonObject().str("error", message).done(), status);
}

int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

std::string url_decode(std::string_view s) {
  std::string out;
  for (std::size_t i = 0; i < s.size(); i++) {
    if (s[i] == '+')
      out += ' ';
    else if (s[i] == '%' && i + 2 < s.size() && hex_value(s[i + 1]) >= 0 && hex_value(s[i + 2]) >= 0) {
      out += static_cast<char>(hex_value(s[i + 1]) * 16 + hex_value(s[i + 2]));
      i += 2;
    }
    else
      out += s[i];
  }
  return out;
}

// the request line and headers; the body (if any) is ignored, every parameter is in the query string
std::optional<Request> read_request(int fd) {
  std::string data;
  char buf[4096];
  while (data.find("\r\n\r\n") == std::string::npos) {
    if (data.size() > 16384)
      return std::nullopt;
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0)
      return std::nullopt;
    data.append(buf, static_cast<std::size_t>(n));
  }

  std::istringstream in(data.substr(0, data.find("\r\n\r\n")));
  std::string line;
  std::getline(in, line);
  std::istringstream first(line);
  std::string target;
  Request req;
  first >> req.method >> target;
  if (req.method.empty() || target.empty() || target[0] != '/')
    return std::nullopt;

  auto q = target.find('?');
  req.path = url_decode(std::string_view(target).substr(0, q));
  if (q != std::string::npos) {
    std::string_view rest = std::string_view(target).substr(q + 1);
    while (!rest.empty()) {
      auto amp = rest.find('&');
      auto pair = rest.substr(0, amp);
      auto eq = pair.find('=');
      if (!pair.empty())
        req.params[url_decode(pair.substr(0, eq))] = eq == std::string_view::npos ? "" : url_decode(pair.substr(eq + 1));
      if (amp == std::string_view::npos)
        break;
      rest.remove_prefix(amp + 1);
    }
  }

  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    auto colon = line.find(':');
    if (colon != std::string::npos && utils::lower(line.substr(0, colon)) == "host") {
      auto value = line.substr(colon + 1);
      value.erase(0, value.find_first_not_of(' '));
      req.host = utils::lower(value);
    }
  }
  return req;
}

void send_response(int fd, const Response& r) {
  const char* reason = r.status == 200 ? "OK" : r.status == 400 ? "Bad Request" : r.status == 403 ? "Forbidden" : r.status == 404 ? "Not Found"
                     : r.status == 405 ? "Method Not Allowed" : r.status == 409 ? "Conflict" : r.status == 504 ? "Gateway Timeout"
                                                                                                                : "Internal Server Error";
  std::string out = std::format("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                                r.status, reason, r.content_type, r.body.size());
  out += r.body;
  std::string_view rest = out;
  while (!rest.empty()) {
    ssize_t n = ::send(fd, rest.data(), rest.size(), MSG_NOSIGNAL);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return;
    rest.remove_prefix(static_cast<std::size_t>(n));
  }
}

// the host part of a Host header: "localhost:8080" -> "localhost", "[::1]:8080" -> "::1"
std::string host_only(std::string_view host) {
  if (!host.empty() && host.front() == '[') {
    auto close = host.find(']');
    return std::string(host.substr(1, close == std::string_view::npos ? std::string_view::npos : close - 1));
  }
  return std::string(host.substr(0, host.find(':')));
}

bool is_loopback_host(const std::string& host) {
  return host == "localhost" || host.starts_with("127.") || host == "::1";
}

std::optional<uint64_t> number_param(const Request& req, const std::string& key, uint64_t fallback, uint64_t lo, uint64_t hi) {
  auto it = req.params.find(key);
  if (it == req.params.end() || it->second.empty())
    return fallback;
  uint64_t v = 0;
  for (char c : it->second) {
    if (c < '0' || c > '9' || v > hi)
      return std::nullopt;
    v = v * 10 + static_cast<uint64_t>(c - '0');
  }
  if (v < lo || v > hi)
    return std::nullopt;
  return v;
}

std::string param(const Request& req, const std::string& key, std::string fallback = {}) {
  auto it = req.params.find(key);
  return it == req.params.end() || it->second.empty() ? fallback : it->second;
}

// a resolver the lookup test can pick directly, outside the middleware, with a cache of its own so
// "cold" and "warm" mean the same thing for every resolver being compared
struct Lab {
  std::string id;
  std::string label;
  std::mutex mutex; // resolvers aren't thread safe
  std::unique_ptr<backend::Cache> cache = std::make_unique<backend::Cache>();
  std::unique_ptr<backend::Resolver> resolver;
};

struct LoadState {
  bool running = false;
  std::string names;
  uint64_t requested = 0;
  uint64_t concurrency = 0;
  uint64_t sent = 0;
  uint64_t done = 0;
  SteadyClock::time_point started{};
  SteadyClock::time_point finished{};
  std::map<std::string, uint64_t> rcodes;
  std::map<std::string, uint64_t> served_by;
  std::vector<double> latencies;
};

// the Traffic test: a steady stream of queries until it is stopped
struct TrafficState {
  bool running = false;
  double rate = 0;
  std::string names;
  uint64_t sent = 0;
  uint64_t done = 0;
  uint64_t dropped = 0; // not sent: too many were still unanswered
  SteadyClock::time_point started{};
  SteadyClock::time_point finished{};
  std::map<std::string, uint64_t> served_by;
};

// the Abuse test: one client sending at a steady rate for a few seconds
struct AbuseState {
  bool running = false;
  std::string client;
  double rate = 0;
  uint64_t seconds = 0;
  uint64_t sent = 0;
  SteadyClock::time_point started{};
  SteadyClock::time_point finished{};
  std::vector<std::array<uint64_t, 3>> timeline; // per second: answered, rate limited, refused as blocked
  double first_blocked_s = -1;
};

// "upstream 1.1.1.1:53" and "upstream 8.8.8.8:53" count as one, and so do the recursive variants
std::string served_label(const ResolveResult& r) {
  if (r.served_by.starts_with("upstream "))
    return r.served_by.ends_with(" over TLS") ? "upstream over TLS" : "upstream";
  if (r.served_by.starts_with("recursive"))
    return "recursive";
  return r.served_by.empty() ? "?" : r.served_by;
}

} // namespace

struct AdminServer::Impl : std::enable_shared_from_this<Impl> {
  const Config config;
  Middleware& middleware;
  const Admission& admission;
  const ResolverShared shared;
  const SysClock::time_point started_at = SysClock::now();
  std::vector<std::unique_ptr<Lab>> labs;

  int listen_fd = -1;
  std::thread accept_thread;
  std::atomic<bool> stopping{false};

  // request and load test threads still running
  std::mutex active_mutex;
  std::condition_variable active_cv;
  int active = 0;

  std::mutex load_mutex;
  LoadState load;
  std::atomic<bool> cancel_load{false};

  std::mutex traffic_mutex;
  TrafficState traffic;
  std::atomic<bool> cancel_traffic{false};

  std::mutex abuse_mutex;
  AbuseState abuse;
  std::atomic<bool> cancel_abuse{false};

  // most queries a paced test keeps unanswered at once
  static constexpr uint64_t kMaxInFlight = 20000;

  Impl(Config cfg, Middleware& m, const Admission& a, ResolverShared s) : config(std::move(cfg)), middleware(m), admission(a), shared(std::move(s)) {
    // make_factory configured it, unless the middleware runs a stub (tests, load_gen)
    if (!shared.upstream_tls->configured())
      if (auto ok = shared.upstream_tls->configure(config.upstream_ca_file); !ok)
        warn("admin page: DNS-over-TLS upstreams will fail: {}", ok.error());
    std::vector<backend::Endpoint> upstreams;
    for (const auto& u : config.upstreams) {
      try {
        upstreams.push_back({types::IP(u.host), u.port, u.tls ? shared.upstream_tls : nullptr, u.tls_name});
      }
      catch (const std::runtime_error&) {
      }
    }
    for (auto& e : public_upstreams(shared.upstream_tls)) {
      if (std::ranges::none_of(upstreams, [&](const auto& u) { return upstream_id(u) == upstream_id(e); }))
        upstreams.push_back(std::move(e));
    }
    for (const auto& u : upstreams) {
      auto lab = std::make_unique<Lab>();
      lab->id = upstream_id(u);
      lab->label = "Forward to " + upstream_label(u);
      // a cold TLS upstream needs the TCP and TLS handshakes before the question
      lab->resolver = std::make_unique<backend::ForwardingResolver>(std::vector{u}, *lab->cache, Ms(u.tls ? 3000 : 1500));
      labs.push_back(std::move(lab));
    }
    auto lab = std::make_unique<Lab>();
    lab->id = "recursive";
    lab->label = "Recursive from the root servers";
    backend::RecursiveOptions opts;
    opts.total_timeout = Ms(5000);
    lab->resolver = std::make_unique<backend::RecursiveResolver>(*lab->cache, opts);
    labs.push_back(std::move(lab));
  }

  ~Impl() {
    if (listen_fd >= 0)
      ::close(listen_fd);
  }

  // counts a thread as running from before it starts, so stop() can't miss it
  void enter() {
    std::lock_guard<std::mutex> lock(active_mutex);
    active++;
  }
  void leave() {
    std::lock_guard<std::mutex> lock(active_mutex);
    if (--active == 0)
      active_cv.notify_all();
  }

  void accept_loop() {
    while (!stopping.load()) {
      pollfd p{listen_fd, POLLIN, 0};
      if (::poll(&p, 1, 200) <= 0)
        continue;
      int fd = ::accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
      if (fd < 0)
        continue;
      timeval tv{10, 0};
      ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      enter();
      try {
        std::thread([self = shared_from_this(), fd] {
          self->serve(fd);
          ::close(fd);
          self->leave();
        }).detach();
      }
      catch (const std::system_error&) {
        ::close(fd);
        leave();
      }
    }
  }

  void serve(int fd) {
    auto req = read_request(fd);
    if (!req)
      return;
    Response res;
    try {
      res = route(*req);
    }
    catch (const std::exception& e) {
      res = error_response(500, e.what());
    }
    send_response(fd, res);
  }

  Response route(const Request& req) {
    auto host = host_only(req.host);
    if (!is_loopback_host(host) && !(config.admin_listen && host == config.admin_listen->host))
      return error_response(403, "the admin page only answers on a loopback address");

    const bool get = req.method == "GET";
    const bool post = req.method == "POST";
    if (req.path == "/api/status" && get)
      return json_response(status_json());
    if (req.path == "/api/metrics" && get)
      return json_response(metrics_json());
    if (req.path == "/api/queries" && get)
      return queries(req);
    if (req.path == "/api/lookup" && get)
      return lookup(req);
    if (req.path == "/api/load" && post)
      return start_load(req);
    if (req.path == "/api/load" && get)
      return json_response(load_json());
    if (req.path == "/api/traffic" && post)
      return start_traffic(req);
    if (req.path == "/api/traffic/stop" && post) {
      cancel_traffic = true;
      return json_response(traffic_json());
    }
    if (req.path == "/api/abuse" && post)
      return start_abuse(req);
    if (req.path == "/api/abuse/stop" && post) {
      cancel_abuse = true;
      return json_response(abuse_json());
    }
    if (req.path == "/api/unblock" && post)
      return unblock(req);
    if (req.path == "/api/resolver" && post)
      return switch_resolver(req);
    if (req.path == "/api/faults" && post)
      return faults(req);
    if (req.path == "/api/cache/flush" && post)
      return flush();
    if (req.path == "/api/tls/probe" && post)
      return tls_probe(req);
    if (req.path.starts_with("/api/"))
      return error_response(get || post ? 404 : 405, "no such endpoint");
    if (get)
      return static_file(req.path);
    return error_response(405, "method not allowed");
  }

  Response static_file(const std::string& path) {
    std::string file = path == "/" ? "index.html" : path.substr(1);
    if (file.empty() || file.find("..") != std::string::npos || !std::ranges::all_of(file, [](char c) {
          return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_';
        }))
      return error_response(404, "not found");
    std::ifstream in(config.admin_ui_dir / file, std::ios::binary);
    if (!in)
      return error_response(404, std::format("{} not found in admin_ui_dir '{}'", file, config.admin_ui_dir.string()));
    std::ostringstream buf;
    buf << in.rdbuf();
    auto ext = std::filesystem::path(file).extension().string();
    std::string type = ext == ".html" ? "text/html; charset=utf-8" : ext == ".js" ? "text/javascript" : ext == ".css" ? "text/css"
                     : ext == ".svg"  ? "image/svg+xml"            : "application/octet-stream";
    return Response{200, type, buf.str()};
  }

  std::string status_json() {
    std::vector<std::string> upstreams, lab_items;
    for (const auto& u : config.upstreams)
      upstreams.push_back(json_string(upstream_text(u)));
    for (const auto& lab : labs)
      lab_items.push_back(JsonObject().str("id", lab->id).str("label", lab->label).done());
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(SysClock::now() - started_at).count();
    return JsonObject()
        .str("mode", config.mode == Mode::Forwarding ? "forwarding" : "recursive")
        .raw("upstreams", json_array(upstreams))
        .str("upstream_ca_file", config.upstream_ca_file.string())
        .str("records_file", config.records_file.string())
        .str("blocked_domains_file", config.blocked_domains_file.string())
        .integer("blocked_domains", admission.blocked_count())
        .integer("workers", config.workers)
        .integer("queue_capacity", config.queue_capacity)
        .str("lb_policy", policy_name(config.lb_policy))
        .integer("request_timeout_ms", static_cast<uint64_t>(config.request_timeout.count()))
        .integer("failure_threshold", config.failure_threshold)
        .integer("cooldown_ms", static_cast<uint64_t>(config.cooldown.count()))
        .num("rate_limit_qps", config.rate_limit_qps)
        .num("rate_limit_burst", config.rate_limit_burst)
        .integer("block_rate_limit_strikes", config.block_rate_limit_strikes)
        .integer("block_duration_ms", static_cast<uint64_t>(config.block_duration.count()))
        .str("listen", std::format("{}:{}", config.listen.host, config.listen.port))
        .integer("uptime_s", static_cast<uint64_t>(uptime))
        .raw("labs", json_array(lab_items))
        .raw("resolvers", resolvers_json())
        .str("active_resolver", active_resolver().id)
        .done();
  }

  std::string resolvers_json() {
    std::vector<std::string> items;
    for (const auto& c : shared.resolvers->choices)
      items.push_back(JsonObject().str("id", c.id).str("label", c.label).done());
    return json_array(items);
  }

  // empty id and label when the server runs a stub (tests, load_gen)
  ResolverChoice active_resolver() {
    const auto& choices = shared.resolvers->choices;
    if (choices.empty())
      return {};
    return choices[std::min(shared.resolvers->active.load(), choices.size() - 1)];
  }

  std::string metrics_json() {
    auto s = middleware.metrics_snapshot();

    JsonObject rcodes;
    for (std::size_t i = 0; i < kRcodeSlots; i++)
      rcodes.integer(i + 1 == kRcodeSlots ? "OTHER" : rcode_name(static_cast<Rcode>(i)), s.replies_by_rcode[i]);

    std::vector<std::string> buckets;
    for (std::size_t i = 0; i < kLatencyBuckets; i++) {
      JsonObject b;
      if (i < Metrics::kBucketUpperMs.size())
        b.integer("le_ms", static_cast<uint64_t>(Metrics::kBucketUpperMs[i]));
      else
        b.raw("le_ms", "null");
      buckets.push_back(b.integer("count", s.latency_buckets[i]).done());
    }

    std::vector<std::string> workers;
    for (const auto& w : middleware.worker_stats())
      workers.push_back(JsonObject()
                            .integer("id", w.id)
                            .integer("outstanding", w.outstanding)
                            .num("ewma_ms", w.ewma_ms)
                            .integer("consecutive_failures", w.consecutive_failures)
                            .integer("total_calls", w.total_calls)
                            .integer("total_failures", w.total_failures)
                            .integer("breaker_trips", w.breaker_trips)
                            .str("breaker", breaker_name(w.breaker))
                            .done());

    auto c = shared.cache->stats();
    return JsonObject()
        .integer("time_ms", static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(SysClock::now().time_since_epoch()).count()))
        .integer("received", s.received)
        .integer("total_replies", s.total_replies)
        .integer("rate_limited", s.rate_limited)
        .integer("overload", s.overload)
        .integer("timeouts", s.timeouts)
        .integer("coalesced", s.coalesced)
        .integer("resolver_exceptions", s.resolver_exceptions)
        .raw("rcodes", rcodes.done())
        .raw("latency", JsonObject().num("p50_ms", s.p50_ms).num("p95_ms", s.p95_ms).num("p99_ms", s.p99_ms).raw("buckets", json_array(buckets)).done())
        .raw("cache", JsonObject().integer("rrsets", c.rrsets).integer("records", c.records).integer("hits", c.hits).integer("misses", c.misses).done())
        .integer("blocked_queries", s.blocked_queries)
        .integer("blocks_started", s.blocks_started)
        .integer("domain_refusals", s.domain_refusals)
        .integer("blocked_sources", middleware.blocked_sources())
        .raw("workers", json_array(workers))
        .num("fault_rate", shared.faults->fail_rate.load())
        .str("active_resolver", active_resolver().id)
        .raw("load", load_json())
        .raw("traffic", traffic_json())
        .raw("abuse", abuse_json())
        .raw("upstream_tls", upstream_tls_json())
        .done();
  }

  // the evidence that DNS-over-TLS upstreams have their certificates checked
  std::string upstream_tls_json() {
    auto t = shared.upstream_tls->stats();
    return JsonObject()
        .integer("queries", t.queries)
        .integer("handshakes", t.handshakes)
        .integer("reused", t.reused)
        .integer("rejected", t.rejected)
        .integer("failed", t.failed)
        .str("last_peer", t.last_peer)
        .str("last_subject", t.last_subject)
        .str("last_issuer", t.last_issuer)
        .str("last_rejected_peer", t.last_rejected_peer)
        .str("last_rejection", t.last_rejection)
        .done();
  }

  // one TLS handshake with ip:port, the certificate checked against name (or, without one, the IP address)
  Response tls_probe(const Request& req) {
    backend::Endpoint e{types::IP("127.0.0.1"), 853, shared.upstream_tls, ""};
    try {
      e.address = types::IP(param(req, "ip"));
    }
    catch (const std::exception&) {
      return error_response(400, "ip must be an IPv4 or IPv6 address");
    }
    auto port = number_param(req, "port", 853, 1, 65535);
    if (!port)
      return error_response(400, "port must be between 1 and 65535");
    e.port = static_cast<uint16_t>(*port);
    e.tls_name = utils::lower(param(req, "name"));
    if (!std::ranges::all_of(e.tls_name, [](char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-'; }))
      return error_response(400, "name must be a host name");

    auto p = shared.upstream_tls->probe(e, Ms(3000));
    info("admin page TLS probe of {}: {}", p.peer, p.verified ? "certificate accepted" : p.error);
    return json_response(JsonObject()
                             .str("peer", p.peer)
                             .str("checked_against", e.tls_name.empty() ? "IP address " + std::string(e.address) : "name " + e.tls_name)
                             .boolean("connected", p.connected)
                             .boolean("verified", p.verified)
                             .str("error", p.error)
                             .str("protocol", p.protocol)
                             .str("cipher", p.cipher)
                             .str("subject", p.subject)
                             .str("issuer", p.issuer)
                             .str("not_after", p.not_after)
                             .num("handshake_ms", p.handshake_ms)
                             .done());
  }

  Response queries(const Request& req) {
    auto after = number_param(req, "after", 0, 0, UINT64_MAX / 10);
    if (!after)
      return error_response(400, "after must be a number");
    std::vector<std::string> items;
    for (const auto& e : middleware.recent_queries(*after))
      items.push_back(JsonObject()
                          .integer("seq", e.seq)
                          .integer("time_ms", static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(e.when.time_since_epoch()).count()))
                          .str("client", e.client)
                          .str("transport", transport_name(e.transport))
                          .str("name", e.name)
                          .str("type", type_name(e.type))
                          .str("rcode", rcode_name(e.rcode))
                          .num("latency_ms", e.latency_ms)
                          .str("served_by", e.served_by)
                          .raw("answers", records_json(e.answer))
                          .done());
    return json_response(JsonObject().raw("queries", json_array(items)).done());
  }

  Response lookup(const Request& req) {
    std::string name = param(req, "name");
    auto type = types::record_type_from_string(utils::upper(param(req, "type", "A")));
    std::string via = param(req, "via", "server");
    if (name.empty())
      return error_response(400, "name is missing");
    if (!type)
      return error_response(400, "unknown record type");

    DomainName dn;
    try {
      dn = DomainName(name);
      dn.absolute = true;
    }
    catch (const std::exception& e) {
      return error_response(400, std::format("bad name: {}", e.what()));
    }

    if (via == "server")
      return through_middleware(name, *type);

    auto lab = std::ranges::find(labs, via, &Lab::id);
    if (lab == labs.end())
      return error_response(400, "unknown resolver");
    std::lock_guard<std::mutex> lock((*lab)->mutex);
    auto start = SteadyClock::now();
    auto result = (*lab)->resolver->resolve(dn, *type, RecordClass::IN);
    double ms = std::chrono::duration<double, std::milli>(SteadyClock::now() - start).count();
    return json_response(result_json(std::string(dn), *type, (*lab)->label, result, ms));
  }

  std::string server_label() {
    auto active = active_resolver();
    return active.label.empty() ? "This server" : "This server: " + active.label;
  }

  // the same path a DNS-over-TLS query takes after the front end has decoded it
  Response through_middleware(const std::string& name, RecordType type) {
    if (admission.refuses(types::DnsQuery{0, true, name, type, false, false})) {
      middleware.record_domain_refusal(name, type, ClientInfo{"127.0.0.1", 0, Transport::Tcp});
      return json_response(result_json(name, type, server_label(), error_result(Rcode::Refused, "blocked domain"), 0));
    }

    auto promise = std::make_shared<std::promise<ResolveResult>>();
    auto future = promise->get_future();
    auto start = SteadyClock::now();
    middleware.submit(name, type, ClientInfo{"127.0.0.1", 0, Transport::Tcp}, [promise](ResolveResult r) { promise->set_value(std::move(r)); });
    if (future.wait_for(config.request_timeout + Ms(2000)) != std::future_status::ready)
      return error_response(504, "no answer from the middleware");
    double ms = std::chrono::duration<double, std::milli>(SteadyClock::now() - start).count();
    return json_response(result_json(name, type, server_label(), future.get(), ms));
  }

  std::string load_json() {
    std::unique_lock<std::mutex> lock(load_mutex);
    if (load.requested == 0)
      return JsonObject().boolean("running", false).integer("requested", 0).done();
    auto latencies = load.latencies;
    auto end = load.running ? SteadyClock::now() : load.finished;
    double elapsed = std::chrono::duration<double>(end - load.started).count();
    JsonObject o;
    o.boolean("running", load.running)
        .str("names", load.names)
        .integer("requested", load.requested)
        .integer("concurrency", load.concurrency)
        .integer("sent", load.sent)
        .integer("done", load.done)
        .num("elapsed_s", elapsed)
        .num("qps", elapsed > 0 ? static_cast<double>(load.done) / elapsed : 0)
        .raw("rcodes", json_counts(load.rcodes))
        .raw("served_by", json_counts(load.served_by));
    lock.unlock();
    return o.num("p50_ms", percentile(latencies, 0.50))
        .num("p95_ms", percentile(latencies, 0.95))
        .num("p99_ms", percentile(latencies, 0.99))
        .num("max_ms", latencies.empty() ? std::nan("") : *std::ranges::max_element(latencies))
        .done();
  }

  Response start_load(const Request& req) {
    auto count = number_param(req, "count", 2000, 1, 200000);
    auto concurrency = number_param(req, "concurrency", 100, 1, 5000);
    std::string names = param(req, "names", "popular");
    if (!count || !concurrency)
      return error_response(400, "count must be 1-200000 and concurrency 1-5000");
    if (names != "popular" && names != "unique")
      return error_response(400, "names must be popular or unique");
    // every unique name is a real question to the upstreams: keep that polite
    if (names == "unique")
      *count = std::min<uint64_t>(*count, 5000);

    {
      std::lock_guard<std::mutex> lock(load_mutex);
      if (load.running)
        return error_response(409, "a load test is already running");
      load = LoadState{};
      load.running = true;
      load.names = names;
      load.requested = *count;
      load.concurrency = *concurrency;
      load.started = SteadyClock::now();
      load.latencies.reserve(*count);
    }
    cancel_load = false;
    enter();
    try {
      std::thread([self = shared_from_this(), count = *count, concurrency = *concurrency, unique = names == "unique"] {
        self->run_load(count, concurrency, unique);
        self->leave();
      }).detach();
    }
    catch (const std::system_error& e) {
      std::lock_guard<std::mutex> lock(load_mutex);
      load.running = false;
      leave();
      return error_response(500, e.what());
    }
    return json_response(load_json());
  }

  void run_load(uint64_t count, uint64_t concurrency, bool unique) {
    struct Window {
      std::mutex mutex;
      std::condition_variable cv;
      uint64_t outstanding = 0;
    };
    auto window = std::make_shared<Window>();
    std::mt19937_64 rng{std::random_device{}()};

    for (uint64_t i = 0; i < count && !cancel_load.load(); i++) {
      {
        std::unique_lock<std::mutex> lock(window->mutex);
        window->cv.wait(lock, [&] { return window->outstanding < concurrency; });
        window->outstanding++;
      }
      std::string name = unique ? std::format("{:x}-{}.example.com", rng() & 0xFFFFFF, i) : kPopularNames[rng() % std::size(kPopularNames)];
      // 1000 benchmark-range clients (RFC 2544), so the per-client rate limiter sees ordinary users
      std::string client = std::format("198.18.{}.{}", (i / 250) % 4, i % 250 + 1);
      {
        std::lock_guard<std::mutex> lock(load_mutex);
        load.sent++;
      }
      auto start = SteadyClock::now();
      middleware.submit(name, RecordType::A, ClientInfo{client, 0, Transport::Udp, true}, [self = shared_from_this(), window, start](ResolveResult r) {
        double ms = std::chrono::duration<double, std::milli>(SteadyClock::now() - start).count();
        {
          std::lock_guard<std::mutex> lock(self->load_mutex);
          self->load.done++;
          self->load.rcodes[rcode_name(r.rcode)]++;
          self->load.served_by[served_label(r)]++;
          self->load.latencies.push_back(ms);
        }
        std::lock_guard<std::mutex> lock(window->mutex);
        window->outstanding--;
        window->cv.notify_all();
      });
    }

    std::unique_lock<std::mutex> lock(window->mutex);
    window->cv.wait(lock, [&] { return window->outstanding == 0; });
    std::lock_guard<std::mutex> load_lock(load_mutex);
    load.running = false;
    load.finished = SteadyClock::now();
  }

  // calls send(i, done) `rate` times a second until cancel is set or limit has passed (zero: no limit), then
  // waits for every done(). a query that would put more than kMaxInFlight unanswered is dropped instead, so a
  // slow upstream can't pile up work. returns how many were dropped
  uint64_t run_paced(double rate, SteadyClock::duration limit, const std::atomic<bool>& cancel,
                     const std::function<void(uint64_t, std::function<void()>)>& send) {
    struct Flight {
      std::mutex mutex;
      std::condition_variable cv;
      uint64_t n = 0;
    };
    auto flight = std::make_shared<Flight>();
    std::function<void()> done = [flight] {
      std::lock_guard<std::mutex> lock(flight->mutex);
      if (--flight->n == 0)
        flight->cv.notify_all();
    };

    const auto start = SteadyClock::now();
    uint64_t next = 0, dropped = 0;
    while (!cancel.load() && !stopping.load()) {
      auto elapsed = SteadyClock::now() - start;
      if (limit.count() > 0 && elapsed >= limit)
        break;
      auto due = static_cast<uint64_t>(rate * std::chrono::duration<double>(elapsed).count()) + 1;
      for (; next < due; next++) {
        {
          std::lock_guard<std::mutex> lock(flight->mutex);
          if (flight->n >= kMaxInFlight) {
            dropped++;
            continue;
          }
          flight->n++;
        }
        send(next, done);
      }
      std::this_thread::sleep_for(Ms(5));
    }
    std::unique_lock<std::mutex> lock(flight->mutex);
    flight->cv.wait(lock, [&] { return flight->n == 0; });
    return dropped;
  }

  // runs fn on its own thread, counted as active so stop() waits for it
  template<class Fn>
  std::optional<Response> spawn(Fn fn) {
    enter();
    try {
      std::thread([self = shared_from_this(), fn = std::move(fn)]() mutable {
        fn(*self);
        self->leave();
      }).detach();
    }
    catch (const std::system_error& e) {
      leave();
      return error_response(500, e.what());
    }
    return std::nullopt;
  }

  std::string traffic_json() {
    std::lock_guard<std::mutex> lock(traffic_mutex);
    if (traffic.started == SteadyClock::time_point{})
      return JsonObject().boolean("running", false).integer("sent", 0).done();
    auto end = traffic.running ? SteadyClock::now() : traffic.finished;
    return JsonObject()
        .boolean("running", traffic.running)
        .num("rate", traffic.rate)
        .str("names", traffic.names)
        .integer("sent", traffic.sent)
        .integer("done", traffic.done)
        .integer("dropped", traffic.dropped)
        .num("elapsed_s", std::chrono::duration<double>(end - traffic.started).count())
        .raw("served_by", json_counts(traffic.served_by))
        .done();
  }

  Response start_traffic(const Request& req) {
    auto rate = number_param(req, "rate", 500, 1, 20000);
    std::string names = param(req, "names", "mixed");
    if (!rate)
      return error_response(400, "rate must be 1-20000 queries a second");
    if (names != "popular" && names != "mixed" && names != "unique")
      return error_response(400, "names must be popular, mixed or unique");
    // every unique name is a real question to the upstreams: keep that polite
    if (names == "unique")
      *rate = std::min<uint64_t>(*rate, 200);
    {
      std::lock_guard<std::mutex> lock(traffic_mutex);
      if (traffic.running)
        return error_response(409, "traffic is already running");
      traffic = TrafficState{};
      traffic.running = true;
      traffic.rate = static_cast<double>(*rate);
      traffic.names = names;
      traffic.started = SteadyClock::now();
    }
    cancel_traffic = false;
    if (auto failed = spawn([rate = *rate, names](Impl& self) { self.run_traffic(static_cast<double>(rate), names); })) {
      std::lock_guard<std::mutex> lock(traffic_mutex);
      traffic.running = false;
      return *failed;
    }
    return json_response(traffic_json());
  }

  void run_traffic(double rate, const std::string& names) {
    std::mt19937_64 rng{std::random_device{}()};
    // ten minutes at most, in case nobody presses Stop
    auto dropped = run_paced(rate, std::chrono::minutes(10), cancel_traffic, [&](uint64_t i, std::function<void()> done) {
      // mixed: one name in ten is new, the way real traffic is mostly names someone asked for recently
      bool unique = names == "unique" || (names == "mixed" && rng() % 10 == 0);
      std::string name = unique ? std::format("{:x}-{}.example.com", rng() & 0xFFFFFF, i) : kPopularNames[rng() % std::size(kPopularNames)];
      std::string client = std::format("198.18.{}.{}", (i / 250) % 4, i % 250 + 1);
      {
        std::lock_guard<std::mutex> lock(traffic_mutex);
        traffic.sent++;
      }
      middleware.submit(name, RecordType::A, ClientInfo{client, 0, Transport::Udp, true}, [self = shared_from_this(), done](ResolveResult r) {
        {
          std::lock_guard<std::mutex> lock(self->traffic_mutex);
          self->traffic.done++;
          self->traffic.served_by[served_label(r)]++;
        }
        done();
      });
    });
    std::lock_guard<std::mutex> lock(traffic_mutex);
    traffic.running = false;
    traffic.dropped = dropped;
    traffic.finished = SteadyClock::now();
  }

  std::string abuse_json() {
    std::lock_guard<std::mutex> lock(abuse_mutex);
    JsonObject o;
    o.num("rate_limit_qps", config.rate_limit_qps)
        .num("rate_limit_burst", config.rate_limit_burst)
        .integer("block_rate_limit_strikes", config.block_rate_limit_strikes)
        .integer("block_window_ms", static_cast<uint64_t>(config.block_window.count()))
        .integer("block_duration_ms", static_cast<uint64_t>(config.block_duration.count()));
    if (abuse.client.empty())
      return o.boolean("running", false).done();
    auto end = abuse.running ? SteadyClock::now() : abuse.finished;
    double elapsed = std::chrono::duration<double>(end - abuse.started).count();
    auto seconds_seen = std::min<std::size_t>(abuse.timeline.size(), static_cast<std::size_t>(elapsed) + 1);
    std::vector<std::string> timeline;
    for (std::size_t i = 0; i < seconds_seen; i++)
      timeline.push_back(std::format("[{},{},{}]", abuse.timeline[i][0], abuse.timeline[i][1], abuse.timeline[i][2]));
    o.boolean("running", abuse.running)
        .str("client", abuse.client)
        .num("rate", abuse.rate)
        .integer("seconds", abuse.seconds)
        .integer("sent", abuse.sent)
        .num("elapsed_s", elapsed)
        .boolean("blocked_now", middleware.is_blocked(abuse.client))
        .raw("timeline", json_array(timeline));
    if (abuse.first_blocked_s >= 0)
      o.num("first_blocked_s", abuse.first_blocked_s);
    else
      o.raw("first_blocked_s", "null");
    return o.done();
  }

  Response start_abuse(const Request& req) {
    std::string client = param(req, "client", "203.0.113.66");
    auto rate = number_param(req, "rate", 2000, 1, 20000);
    auto seconds = number_param(req, "seconds", 10, 1, 60);
    if (!rate || !seconds)
      return error_response(400, "rate must be 1-20000 and seconds 1-60");
    try {
      types::IP check(client);
    }
    catch (const std::runtime_error&) {
      return error_response(400, "client must be an IP address");
    }
    {
      std::lock_guard<std::mutex> lock(abuse_mutex);
      if (abuse.running)
        return error_response(409, "an abuse test is already running");
      abuse = AbuseState{};
      abuse.running = true;
      abuse.client = client;
      abuse.rate = static_cast<double>(*rate);
      abuse.seconds = *seconds;
      abuse.timeline.assign(*seconds, {0, 0, 0});
      abuse.started = SteadyClock::now();
    }
    cancel_abuse = false;
    if (auto failed = spawn([client, rate = *rate, seconds = *seconds](Impl& self) { self.run_abuse(client, static_cast<double>(rate), seconds); })) {
      std::lock_guard<std::mutex> lock(abuse_mutex);
      abuse.running = false;
      return *failed;
    }
    return json_response(abuse_json());
  }

  void run_abuse(const std::string& client, double rate, uint64_t seconds) {
    const auto start = SteadyClock::now();
    run_paced(rate, std::chrono::seconds(seconds), cancel_abuse, [&](uint64_t, std::function<void()> done) {
      const double at = std::chrono::duration<double>(SteadyClock::now() - start).count();
      const auto slot = std::min<std::size_t>(static_cast<std::size_t>(at), seconds - 1);
      {
        std::lock_guard<std::mutex> lock(abuse_mutex);
        abuse.sent++;
      }
      middleware.submit("example.com", RecordType::A, ClientInfo{client, 0, Transport::Udp, true}, [self = shared_from_this(), done, slot, at](ResolveResult r) {
        {
          std::lock_guard<std::mutex> lock(self->abuse_mutex);
          const std::size_t kind = r.served_by == "rate limited" ? 1 : r.served_by == "client blocked" ? 2 : 0;
          self->abuse.timeline[slot][kind]++;
          if (kind == 2 && self->abuse.first_blocked_s < 0)
            self->abuse.first_blocked_s = at;
        }
        done();
      });
    });
    std::lock_guard<std::mutex> lock(abuse_mutex);
    abuse.running = false;
    abuse.finished = SteadyClock::now();
  }

  Response unblock(const Request& req) {
    std::string client = param(req, "client", "203.0.113.66");
    return json_response(JsonObject().str("client", client).boolean("was_blocked", middleware.unblock(client)).done());
  }

  Response switch_resolver(const Request& req) {
    if (shared.resolvers->choices.empty())
      return error_response(400, "this server's resolver can't be switched");
    auto index = shared.resolvers->find(param(req, "id"));
    if (!index)
      return error_response(400, "unknown resolver");
    shared.resolvers->active = *index;
    // otherwise the next answers would still come from what the old resolver cached
    shared.cache->clear();
    const auto& choice = shared.resolvers->choices[*index];
    info("admin page switched the resolver to {}", choice.label);
    return json_response(JsonObject().str("active_resolver", choice.id).str("label", choice.label).done());
  }

  Response faults(const Request& req) {
    std::string value = param(req, "fail_rate", "0");
    double rate = 0;
    try {
      std::size_t used = 0;
      rate = std::stod(value, &used);
      if (used != value.size())
        throw std::invalid_argument(value);
    }
    catch (const std::exception&) {
      return error_response(400, "fail_rate must be a number");
    }
    if (!(rate >= 0 && rate <= 1))
      return error_response(400, "fail_rate must be between 0 and 1");
    shared.faults->fail_rate.store(rate);
    warn("admin page set the injected failure rate to {}", rate);
    return json_response(JsonObject().num("fail_rate", rate).done());
  }

  Response flush() {
    shared.cache->clear();
    for (auto& lab : labs) {
      std::lock_guard<std::mutex> lock(lab->mutex);
      lab->cache->clear();
    }
    info("admin page flushed the caches");
    return json_response(JsonObject().boolean("flushed", true).done());
  }
};

AdminServer::AdminServer(Config config, Middleware& middleware, const Admission& admission, ResolverShared shared)
    : impl_(std::make_shared<Impl>(std::move(config), middleware, admission, std::move(shared))) {}

AdminServer::~AdminServer() {
  stop();
}

std::expected<uint16_t, std::string> AdminServer::start() {
  if (!impl_->config.admin_listen)
    return std::unexpected("admin_listen is not set");
  const auto& addr = *impl_->config.admin_listen;

  sockaddr_storage ss{};
  socklen_t len = 0;
  try {
    types::IP ip(addr.host);
    if (auto v4 = ip.to_ipv4()) {
      auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
      sa->sin_family = AF_INET;
      sa->sin_port = htons(addr.port);
      sa->sin_addr = *v4;
      len = sizeof(sockaddr_in);
    }
    else {
      auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
      sa->sin6_family = AF_INET6;
      sa->sin6_port = htons(addr.port);
      sa->sin6_addr = *ip.to_ipv6();
      len = sizeof(sockaddr_in6);
    }
  }
  catch (const std::runtime_error&) {
    return std::unexpected(std::format("admin_listen host '{}' is not an IP address", addr.host));
  }

  int fd = ::socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return std::unexpected(std::format("admin socket: {}", std::strerror(errno)));
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (::bind(fd, reinterpret_cast<sockaddr*>(&ss), len) != 0 || ::listen(fd, 64) != 0) {
    auto err = std::format("admin page cannot listen on {}:{}: {}", addr.host, addr.port, std::strerror(errno));
    ::close(fd);
    return std::unexpected(err);
  }
  sockaddr_storage bound{};
  socklen_t bound_len = sizeof(bound);
  ::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_len);
  uint16_t port = ntohs(bound.ss_family == AF_INET ? reinterpret_cast<sockaddr_in*>(&bound)->sin_port : reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);

  impl_->listen_fd = fd;
  impl_->accept_thread = std::thread([impl = impl_] { impl->accept_loop(); });
  info("admin page on http://{}:{}/", addr.host.find(':') == std::string::npos ? addr.host : "[" + addr.host + "]", port);
  return port;
}

void AdminServer::stop() {
  if (impl_->stopping.exchange(true))
    return;
  if (impl_->accept_thread.joinable())
    impl_->accept_thread.join();
  impl_->cancel_load = true;
  impl_->cancel_traffic = true;
  impl_->cancel_abuse = true;
  // requests reference the middleware, so they have to finish before it goes away
  std::unique_lock<std::mutex> lock(impl_->active_mutex);
  impl_->active_cv.wait(lock, [&] { return impl_->active == 0; });
}

} // namespace mw
