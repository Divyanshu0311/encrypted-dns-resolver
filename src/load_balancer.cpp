#include "mw/load_balancer.hpp"
#include<algorithm>
#include<random>
#include<stdexcept>
#include<utility>

namespace mw {
namespace {

// fewer outstanding, then lower ewma, then lower id
bool less_loaded(const Worker* a, const Worker* b) {
  if (a->outstanding() != b->outstanding())
    return a->outstanding() < b->outstanding();
  if (a->ewma_ms() != b->ewma_ms())
    return a->ewma_ms() < b->ewma_ms();
  return a->id() < b->id();
}

std::mt19937& rng() {
  thread_local std::mt19937 gen{std::random_device{}()};
  return gen;
}

} // namespace

LoadBalancer::LoadBalancer(std::vector<Worker*> workers, LbPolicy policy, Clock clock) : workers_(std::move(workers)), policy_(policy), clock_(std::move(clock)) {
  if (workers_.empty())
    throw std::invalid_argument("LoadBalancer needs at least one worker");
  if (std::find(workers_.begin(), workers_.end(), nullptr) != workers_.end())
    throw std::invalid_argument("LoadBalancer got a null worker");
}

Worker* LoadBalancer::pick() {
  auto candidates = ranked(clock_());
  return candidates.empty() ? nullptr : candidates.front();
}

bool LoadBalancer::submit(const Job& job) {
  for (Worker* w : ranked(clock_())) {
    if (w->try_submit(job))
      return true;
  }
  return false;
}

std::vector<Worker*> LoadBalancer::ranked(TimePoint now) {
  std::vector<Worker*> out;
  std::size_t n = workers_.size();

  if (policy_ == LbPolicy::RoundRobin) {
    std::size_t start = rr_.fetch_add(1, std::memory_order_relaxed) % n;
    for (std::size_t i = 0; i < n && out.size() < 2; i++) {
      Worker* w = workers_[(start + i) % n];
      if (w->accepting(now))
        out.push_back(w);
    }
    return out;
  }

  std::vector<Worker*> open;
  for (Worker* w : workers_) {
    if (w->accepting(now))
      open.push_back(w);
  }
  if (open.size() <= 1)
    return open;

  if (policy_ == LbPolicy::LeastOutstanding) {
    std::partial_sort(open.begin(), open.begin() + 2, open.end(), less_loaded);
    return {open[0], open[1]};
  }

  // PowerOfTwo: two distinct random ones, the less loaded wins
  std::uniform_int_distribution<std::size_t> first(0, open.size() - 1);
  std::uniform_int_distribution<std::size_t> second(0, open.size() - 2);
  std::size_t i = first(rng());
  std::size_t j = second(rng());
  if (j >= i)
    j++;
  Worker* a = open[i];
  Worker* b = open[j];
  if (b->outstanding() < a->outstanding())
    std::swap(a, b);
  return {a, b};
}

} // namespace mw
