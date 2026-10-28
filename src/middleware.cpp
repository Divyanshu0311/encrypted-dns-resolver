#include "mw/middleware.hpp"
#include<optional>
#include<stdexcept>
#include<string>
#include<thread>
#include<utility>

#include "mw/logger.hpp"

namespace mw {
namespace {

// the key name: absolute, so "example.com" and "Example.COM." coalesce together.
// nullopt for a name DomainName rejects (empty label, label > 63, name > 255)
std::optional<DomainName> to_key_name(std::string_view name) {
  if (name.empty())
    name = ".";
  try {
    DomainName dn{std::string(name)};
    dn.absolute = true;
    return dn;
  }
  catch (const std::exception&) {
    return std::nullopt;
  }
}

BlockPolicy block_policy(const Config& c) {
  return BlockPolicy{.rate_limit_strikes = c.block_rate_limit_strikes,
                     .protocol_strikes = c.block_protocol_strikes,
                     .window = c.block_window,
                     .duration = c.block_duration,
                     .max_entries = c.block_max_entries};
}

// fails open: a strike lost to an exception simply doesn't count
void strike_and_log(BlockList& list, std::string_view ip, Offence offence, Ms duration) noexcept {
  try {
    if (list.strike(ip, offence))
      warn("blocking {} for {} ms: too many {}", ip, duration.count(), offence == Offence::RateLimited ? "rate-limited queries" : "protocol errors");
  }
  catch (...) {
  }
}

} // namespace

Middleware::Middleware(Config config, ResolverFactory factory, Clock clock)
    : config_(std::move(config)), clock_(std::move(clock)), limiter_(config_.rate_limit_qps, config_.rate_limit_burst, clock_),
      blocklist_(block_policy(config_), clock_), timer_(metrics_) {
  set_log_level(config_.log_level);

  WorkerTuning tuning;
  tuning.failure_threshold = config_.failure_threshold;
  tuning.cooldown = config_.cooldown;

  std::vector<Worker*> raw;
  for (std::size_t i = 0; i < config_.workers; i++) {
    auto resolver = factory(); // a throwing factory propagates
    if (!resolver)
      throw std::runtime_error("resolver factory returned null");
    workers_.push_back(std::make_unique<Worker>(i, std::move(resolver), config_.queue_capacity,
                                                [this](const QueryKey& k, ResolveResult r) { on_complete(k, std::move(r)); }, tuning, metrics_,
                                                clock_));
    raw.push_back(workers_.back().get());
  }
  lb_ = std::make_unique<LoadBalancer>(std::move(raw), config_.lb_policy, clock_);
}

Middleware::~Middleware() {
  stop(Ms{0});
}

void Middleware::start() {
  if (started_.exchange(true))
    return;
  for (auto& w : workers_)
    w->start();
  info("middleware started with {} workers", workers_.size());
  if (config_.block_rate_limit_strikes > 0 && !limiter_.enabled())
    info("rate limiter is off, so rate-limit blocking stays inactive until rate_limit_qps > 0");
}

void Middleware::submit(std::string_view name, RecordType type, ClientInfo client, ResultCallback cb) noexcept {
  std::shared_ptr<Responder> r;
  bool leader = false;
  std::optional<QueryKey> key;
  try {
    metrics_.on_received();

    if (!started_.load() || stopping_.load()) {
      reply_now(cb, Rcode::ServFail);
      return;
    }
    // the front end should have dropped a blocked source already; this covers callers that didn't
    if (is_blocked(client.address)) {
      reply_now(cb, Rcode::Refused);
      return;
    }
    if (!limiter_.allow(client.address)) {
      metrics_.on_rate_limited();
      strike_and_log(blocklist_, client.address, Offence::RateLimited, config_.block_duration);
      reply_now(cb, Rcode::Refused);
      return;
    }
    auto norm = to_key_name(name);
    if (!norm) {
      reply_now(cb, Rcode::FormErr);
      return;
    }

    key = QueryKey{std::move(*norm), type};
    r = std::make_shared<Responder>(*key, std::move(client), std::move(cb), clock_(), metrics_, clock_);

    auto deadline = clock_() + config_.request_timeout;
    timer_.schedule(deadline, r);

    if (!inflight_.attach(*key, r)) {
      metrics_.on_coalesced(); // someone is already resolving this one
      return;
    }
    leader = true;

    if (!lb_->submit(Job{*key, deadline})) {
      metrics_.on_overload();
      for (auto& w : inflight_.take(*key))
        w->fail(Rcode::ServFail);
    }
  }
  catch (...) {
    // before the responder exists cb is still ours; after, the responder owns it
    if (leader) {
      for (auto& w : inflight_.take(*key))
        w->fail(Rcode::ServFail);
    }
    if (r)
      r->fail(Rcode::ServFail);
    else if (cb)
      reply_now(cb, Rcode::ServFail);
  }
}

void Middleware::stop(Ms drain_timeout) {
  if (stopping_.exchange(true))
    return;

  // real time here, clock_ may be a fake in tests
  auto give_up = SteadyClock::now() + drain_timeout;
  while (inflight_.size() != 0 && SteadyClock::now() < give_up)
    std::this_thread::sleep_for(Ms{10});

  for (auto& w : workers_)
    w->stop();
  for (auto& r : inflight_.take_all())
    r->fail(Rcode::ServFail);
  timer_.stop();
}

bool Middleware::is_blocked(std::string_view ip) const noexcept {
  try {
    return blocklist_.is_blocked(ip);
  }
  catch (...) {
    return false;
  }
}

void Middleware::report_abuse(std::string_view ip) noexcept {
  strike_and_log(blocklist_, ip, Offence::Protocol, config_.block_duration);
}

MetricsSnapshot Middleware::metrics_snapshot() const {
  return metrics_.snapshot();
}

std::vector<WorkerStats> Middleware::worker_stats() const {
  std::vector<WorkerStats> stats;
  for (auto& w : workers_)
    stats.push_back(w->stats());
  return stats;
}

void Middleware::on_complete(const QueryKey& key, ResolveResult r) {
  for (auto& w : inflight_.take(key))
    w->complete(r); // each one gets a copy
}

void Middleware::reply_now(ResultCallback& cb, Rcode rc) noexcept {
  metrics_.record_reply(rc, Ms{0});
  if (!cb)
    return;
  try {
    cb(error_result(rc));
  }
  catch (...) {
  }
}

} // namespace mw
