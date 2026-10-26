#include "mw/inflight_table.hpp"
#include<utility>

namespace mw {

bool InFlightTable::attach(const QueryKey& key, std::shared_ptr<Responder> r) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto [it, inserted] = map_.try_emplace(key);
  it->second.push_back(std::move(r));
  return inserted;
}

std::vector<std::shared_ptr<Responder>> InFlightTable::take(const QueryKey& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = map_.find(key);
  if (it == map_.end())
    return {};
  auto waiters = std::move(it->second);
  map_.erase(it);
  return waiters;
}

std::vector<std::shared_ptr<Responder>> InFlightTable::take_all() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::shared_ptr<Responder>> all;
  for (auto& [key, waiters] : map_) {
    for (auto& w : waiters)
      all.push_back(std::move(w));
  }
  map_.clear();
  return all;
}

std::size_t InFlightTable::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return map_.size();
}

} // namespace mw
