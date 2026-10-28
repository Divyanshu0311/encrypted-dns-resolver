#include "mw/admin_server.hpp"
#include<algorithm>
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

// waits for a known number of callbacks, which may run on any thread
class Countdown {
  private:
    std::mutex mutex_;
    std::condition_variable cv_;
    uint64_t left_;

  public:
    explicit Countdown(uint64_t n) : left_(n) {}
    void tick() {
      std::lock_guard<std::mutex> lock(mutex_);
      if (left_ > 0 && --left_ == 0)
        cv_.notify_all();
    }
    bool wait_for(std::chrono::milliseconds timeout) {
      std::unique_lock<std::mutex> lock(mutex_);
      return cv_.wait_for(lock, timeout, [this] { return left_ == 0; });
    }
};

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

  Impl(Config cfg, Middleware& m, const Admission& a, ResolverShared s) : config(std::move(cfg)), middleware(m), admission(a), shared(std::move(s)) {
    std::vector<backend::Endpoint> upstreams;
    for (const auto& u : config.upstreams) {
      try {
        upstreams.push_back({types::IP(u.host), u.port});
      }
      catch (const std::runtime_error&) {
      }
    }
    for (const char* extra : {"1.1.1.1", "8.8.8.8", "9.9.9.9"}) {
      backend::Endpoint e{types::IP(std::string(extra)), 53};
      if (std::ranges::none_of(upstreams, [&](const auto& u) { return u.address == e.address && u.port == e.port; }))
        upstreams.push_back(e);
    }
    for (const auto& u : upstreams) {
      auto lab = std::make_unique<Lab>();
      lab->id = std::format("upstream:{}:{}", std::string(u.address), u.port);
      lab->label = std::format("Forward to {}", std::string(u.address));
      lab->resolver = std::make_unique<backend::ForwardingResolver>(std::vector{u}, *lab->cache, Ms(1500));
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
    if (req.path == "/api/flood" && post)
      return flood(req);
    if (req.path == "/api/faults" && post)
      return faults(req);
    if (req.path == "/api/cache/flush" && post)
      return flush();
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
      upstreams.push_back(json_string(std::format("{}:{}", u.host, u.port)));
    for (const auto& lab : labs)
      lab_items.push_back(JsonObject().str("id", lab->id).str("label", lab->label).done());
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(SysClock::now() - started_at).count();
    return JsonObject()
        .str("mode", config.mode == Mode::Forwarding ? "forwarding" : "recursive")
        .raw("upstreams", json_array(upstreams))
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
        .done();
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
        .raw("workers", json_array(workers))
        .num("fault_rate", shared.faults->fail_rate.load())
        .raw("load", load_json())
        .done();
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

  // the same path a DNS-over-TLS query takes after the front end has decoded it
  Response through_middleware(const std::string& name, RecordType type) {
    if (admission.refuses(types::DnsQuery{0, true, name, type, false, false})) {
      const auto refused = error_result(Rcode::Refused, "blocked domain");
      middleware.log_reply(name, type, ClientInfo{"127.0.0.1", 0, Transport::Tcp}, refused);
      return json_response(result_json(name, type, "this server", refused, 0));
    }

    auto promise = std::make_shared<std::promise<ResolveResult>>();
    auto future = promise->get_future();
    auto start = SteadyClock::now();
    middleware.submit(name, type, ClientInfo{"127.0.0.1", 0, Transport::Tcp}, [promise](ResolveResult r) { promise->set_value(std::move(r)); });
    if (future.wait_for(config.request_timeout + Ms(2000)) != std::future_status::ready)
      return error_response(504, "no answer from the middleware");
    double ms = std::chrono::duration<double, std::milli>(SteadyClock::now() - start).count();
    return json_response(result_json(name, type, "this server", future.get(), ms));
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
          // "upstream 1.1.1.1:53" and "upstream 8.8.8.8:53" are counted as one
          std::string label = r.served_by.starts_with("upstream ") ? "upstream" : r.served_by.starts_with("recursive") ? "recursive" : r.served_by;
          self->load.served_by[label.empty() ? "?" : label]++;
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

  Response flood(const Request& req) {
    std::string client = param(req, "client", "203.0.113.66");
    auto count = number_param(req, "count", 2000, 1, 50000);
    if (!count)
      return error_response(400, "count must be 1-50000");
    try {
      types::IP check(client);
    }
    catch (const std::runtime_error&) {
      return error_response(400, "client must be an IP address");
    }

    struct Tally {
      std::mutex mutex;
      std::map<std::string, uint64_t> rcodes;
      std::map<std::string, uint64_t> served_by;
    };
    auto tally = std::make_shared<Tally>();
    auto countdown = std::make_shared<Countdown>(*count);
    const bool blocked_before = middleware.is_blocked(client);
    auto start = SteadyClock::now();
    for (uint64_t i = 0; i < *count; i++) {
      middleware.submit("example.com", RecordType::A, ClientInfo{client, 0, Transport::Udp, true}, [tally, countdown](ResolveResult r) {
        {
          std::lock_guard<std::mutex> lock(tally->mutex);
          tally->rcodes[rcode_name(r.rcode)]++;
          std::string label = r.served_by.starts_with("upstream ") ? "upstream" : r.served_by;
          tally->served_by[label.empty() ? "?" : label]++;
        }
        countdown->tick();
      });
    }
    bool finished = countdown->wait_for(config.request_timeout + Ms(2000));
    double ms = std::chrono::duration<double, std::milli>(SteadyClock::now() - start).count();

    std::lock_guard<std::mutex> lock(tally->mutex);
    return json_response(JsonObject()
                             .str("client", client)
                             .integer("sent", *count)
                             .boolean("all_answered", finished)
                             .num("elapsed_ms", ms)
                             .boolean("blocked_before", blocked_before)
                             .boolean("blocked_after", middleware.is_blocked(client))
                             .num("rate_limit_qps", config.rate_limit_qps)
                             .num("rate_limit_burst", config.rate_limit_burst)
                             .integer("block_rate_limit_strikes", config.block_rate_limit_strikes)
                             .integer("block_duration_ms", static_cast<uint64_t>(config.block_duration.count()))
                             .raw("rcodes", json_counts(tally->rcodes))
                             .raw("served_by", json_counts(tally->served_by))
                             .done());
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
  // requests reference the middleware, so they have to finish before it goes away
  std::unique_lock<std::mutex> lock(impl_->active_mutex);
  impl_->active_cv.wait(lock, [&] { return impl_->active == 0; });
}

} // namespace mw
