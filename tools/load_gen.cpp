// load_gen: hammers Middleware::submit() directly, no network. prints throughput, the metrics
// report and a per worker table. exit 0 when every query got exactly one callback, 1 when a
// reply went missing, 2 for bad arguments
#include<array>
#include<atomic>
#include<charconv>
#include<chrono>
#include<cstdio>
#include<cstdlib>
#include<format>
#include<iostream>
#include<random>
#include<string>
#include<string_view>
#include<thread>
#include<vector>

#include "mw/config.hpp"
#include "mw/middleware.hpp"
#include "mw/resolver_factory.hpp"

namespace {

struct Options {
  std::size_t threads = 8;
  std::size_t queries = 100000;
  double dup_ratio = 0.3;
  std::size_t workers = 4;
  mw::LbPolicy policy = mw::LbPolicy::LeastOutstanding;
  long long timeout_ms = 2500;
  std::size_t queue = 256;
  long long stub_delay_ms = 5;
  double stub_fail_rate = 0;
  double stub_throw_rate = 0;
  double qps = 0; // per thread, 0 = as fast as possible
  // tighter than the server defaults (5 / 5000 ms) so a short run shows the breaker working
  uint32_t failure_threshold = 3;
  long long cooldown_ms = 200;
};

void usage() {
  std::cerr << "usage: load_gen [--threads N] [--queries N] [--dup-ratio R] [--workers N]\n"
               "                [--policy round_robin|least_outstanding|power_of_two]\n"
               "                [--timeout-ms N] [--queue N] [--stub-delay-ms N]\n"
               "                [--stub-fail-rate R] [--stub-throw-rate R] [--qps R]\n"
               "                [--failure-threshold N] [--cooldown-ms N]\n";
}

template<typename T>
bool parse(std::string_view s, T& out) {
  auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
  return ec == std::errc() && end == s.data() + s.size() && !s.empty();
}

bool parse_args(int argc, char** argv, Options& o) {
  for (int i = 1; i < argc; i += 2) {
    std::string_view key = argv[i];
    if (i + 1 >= argc)
      return false;
    std::string_view v = argv[i + 1];
    bool ok;
    if (key == "--threads")
      ok = parse(v, o.threads) && o.threads >= 1;
    else if (key == "--queries")
      ok = parse(v, o.queries);
    else if (key == "--dup-ratio")
      ok = parse(v, o.dup_ratio) && o.dup_ratio >= 0 && o.dup_ratio <= 1;
    else if (key == "--workers")
      ok = parse(v, o.workers) && o.workers >= 1 && o.workers <= 64;
    else if (key == "--policy") {
      ok = true;
      if (v == "round_robin")
        o.policy = mw::LbPolicy::RoundRobin;
      else if (v == "least_outstanding")
        o.policy = mw::LbPolicy::LeastOutstanding;
      else if (v == "power_of_two")
        o.policy = mw::LbPolicy::PowerOfTwo;
      else
        ok = false;
    }
    else if (key == "--timeout-ms")
      ok = parse(v, o.timeout_ms) && o.timeout_ms >= 1;
    else if (key == "--queue")
      ok = parse(v, o.queue) && o.queue >= 1;
    else if (key == "--stub-delay-ms")
      ok = parse(v, o.stub_delay_ms) && o.stub_delay_ms >= 0;
    else if (key == "--stub-fail-rate")
      ok = parse(v, o.stub_fail_rate) && o.stub_fail_rate >= 0 && o.stub_fail_rate <= 1;
    else if (key == "--stub-throw-rate")
      ok = parse(v, o.stub_throw_rate) && o.stub_throw_rate >= 0 && o.stub_throw_rate <= 1;
    else if (key == "--qps")
      ok = parse(v, o.qps) && o.qps >= 0;
    else if (key == "--failure-threshold")
      ok = parse(v, o.failure_threshold) && o.failure_threshold >= 1;
    else if (key == "--cooldown-ms")
      ok = parse(v, o.cooldown_ms) && o.cooldown_ms >= 1;
    else
      ok = false;
    if (!ok)
      return false;
  }
  return true;
}

const char* breaker_name(mw::BreakerState s) {
  switch (s) {
  case mw::BreakerState::Closed: return "closed";
  case mw::BreakerState::Open: return "open";
  case mw::BreakerState::HalfOpen: return "half-open";
  }
  return "?";
}

} // namespace

int main(int argc, char** argv) {
  Options o;
  if (!parse_args(argc, argv, o)) {
    usage();
    return 2;
  }

  mw::Config cfg;
  cfg.mode = mw::Mode::Recursive; // no upstreams needed
  cfg.workers = o.workers;
  cfg.queue_capacity = o.queue;
  cfg.request_timeout = mw::Ms(o.timeout_ms);
  cfg.lb_policy = o.policy;
  cfg.failure_threshold = o.failure_threshold;
  cfg.cooldown = mw::Ms(o.cooldown_ms);
  cfg.log_level = mw::LogLevel::Error; // breaker chatter would drown the report

  mw::StubOptions stub;
  stub.delay = mw::Ms(o.stub_delay_ms);
  stub.failure_rate = o.stub_fail_rate;
  stub.throw_rate = o.stub_throw_rate;

  mw::Middleware middleware(cfg, mw::make_factory(cfg, stub));
  middleware.start();

  std::array<std::atomic<uint64_t>, 7> by_rcode{};
  std::atomic<uint64_t> completed{0};
  std::atomic<std::size_t> next_unique{0};

  auto started = std::chrono::steady_clock::now();
  std::vector<std::jthread> clients;
  for (std::size_t t = 0; t < o.threads; t++) {
    std::size_t share = o.queries / o.threads + (t < o.queries % o.threads ? 1 : 0);
    clients.emplace_back([&, t, share] {
      std::mt19937 rng(static_cast<uint32_t>(1000 + t));
      std::uniform_real_distribution<double> coin(0.0, 1.0);
      std::uniform_int_distribution<int> hot(0, 9);
      mw::ClientInfo client{std::format("10.0.0.{}", t), 0, mw::Transport::Udp};
      auto gap = o.qps > 0 ? std::chrono::duration<double>(1.0 / o.qps) : std::chrono::duration<double>(0);
      auto next = std::chrono::steady_clock::now();

      for (std::size_t i = 0; i < share; i++) {
        std::string name;
        if (coin(rng) < o.dup_ratio)
          name = std::format("hot{}.test.", hot(rng));
        else
          name = std::format("host{}.test.", next_unique.fetch_add(1));
        auto type = coin(rng) < 0.8 ? mw::RecordType::A : mw::RecordType::AAAA;

        middleware.submit(name, type, client, [&](mw::ResolveResult r) {
          std::size_t slot = static_cast<std::size_t>(r.rcode);
          by_rcode[slot < 6 ? slot : 6].fetch_add(1);
          completed.fetch_add(1);
        });

        if (o.qps > 0) {
          next += std::chrono::duration_cast<std::chrono::steady_clock::duration>(gap);
          std::this_thread::sleep_until(next);
        }
      }
    });
  }
  clients.clear(); // joins

  auto limit = started + std::chrono::seconds(30);
  while (completed.load() < o.queries && std::chrono::steady_clock::now() < limit)
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  uint64_t done = completed.load();

  middleware.stop(mw::Ms{1000});

  std::cout << std::format("queries     {}\ncompleted   {}\nwall time   {:.3f} s\nthroughput  {:.0f} queries/s\n\n", o.queries, done, seconds,
                           seconds > 0 ? static_cast<double>(done) / seconds : 0.0);
  std::cout << mw::format_snapshot(middleware.metrics_snapshot()) << "\n";
  std::cout << std::format("{:>6} {:>10} {:>10} {:>10} {:>8} {:>10}\n", "worker", "calls", "failures", "ewma ms", "trips", "breaker");
  for (const auto& w : middleware.worker_stats())
    std::cout << std::format("{:>6} {:>10} {:>10} {:>10.2f} {:>8} {:>10}\n", w.id, w.total_calls, w.total_failures, w.ewma_ms, w.breaker_trips,
                             breaker_name(w.breaker));

  // after stop() every submit must have been answered exactly once
  uint64_t final_count = completed.load();
  if (done != o.queries || final_count != o.queries) {
    std::cerr << std::format("lost or duplicated replies: {} callbacks for {} queries\n", final_count, o.queries);
    return 1;
  }
  return 0;
}
