#include "mw/block_list.hpp"
#include<algorithm>
#include<exception>
#include<mutex>
#include<stdexcept>
#include<utility>
#include<vector>

#include "IP.hpp"

namespace mw {
namespace {

// ::ffff:a.b.c.d, what a dual-stack socket reports for an IPv4 client
bool is_v4_mapped(const std::vector<uint8_t>& b) {
  return std::all_of(b.begin(), b.begin() + 10, [](uint8_t x) { return x == 0; }) && b[10] == 0xff && b[11] == 0xff;
}

} // namespace

BlockList::BlockList(BlockPolicy policy, Clock clock) : policy_(policy), clock_(std::move(clock)) {
  if (policy_.window <= Ms{0})
    throw std::invalid_argument("BlockList window must be > 0");
  if (policy_.duration <= Ms{0})
    throw std::invalid_argument("BlockList duration must be > 0");
  if (policy_.max_entries == 0)
    throw std::invalid_argument("BlockList max_entries must be >= 1");
}

std::optional<std::string> BlockList::key_for(std::string_view ip) {
  std::vector<uint8_t> bytes;
  try {
    bytes = types::IP(std::string(ip));
  }
  catch (const std::exception&) {
    return std::nullopt;
  }
  // 4-byte and 8-byte keys can never collide
  if (bytes.size() == 16 && is_v4_mapped(bytes))
    return std::string(bytes.begin() + 12, bytes.end());
  if (bytes.size() == 16)
    return std::string(bytes.begin(), bytes.begin() + 8);
  return std::string(bytes.begin(), bytes.end());
}

bool BlockList::is_blocked(std::string_view ip) const {
  auto key = key_for(ip);
  if (!key)
    return false;

  TimePoint now = clock_();
  std::shared_lock lock(mutex_);
  auto it = entries_.find(*key);
  return it != entries_.end() && it->second.blocked_until > now;
}

bool BlockList::strike(std::string_view ip, Offence offence) {
  const uint32_t limit = offence == Offence::RateLimited ? policy_.rate_limit_strikes : policy_.protocol_strikes;
  if (limit == 0)
    return false;
  auto key = key_for(ip);
  if (!key)
    return false;

  TimePoint now = clock_();
  std::unique_lock lock(mutex_);

  if (++strikes_since_sweep_ >= kSweepEvery) {
    strikes_since_sweep_ = 0;
    sweep(now);
  }

  auto it = entries_.find(*key);
  if (it == entries_.end()) {
    // full: drop the newcomer rather than evict anyone, so existing blocks always stand
    if (entries_.size() >= policy_.max_entries)
      return false;
    it = entries_.emplace(std::move(*key), Entry{0, 0, now, TimePoint{}}).first;
  }

  Entry& e = it->second;
  if (e.blocked_until > now)
    return false;
  if (now - e.window_start > policy_.window) {
    e.rate_limit_strikes = 0;
    e.protocol_strikes = 0;
    e.window_start = now;
  }

  uint32_t& count = offence == Offence::RateLimited ? e.rate_limit_strikes : e.protocol_strikes;
  if (++count < limit)
    return false;

  e.blocked_until = now + policy_.duration;
  e.rate_limit_strikes = 0;
  e.protocol_strikes = 0;
  return true;
}

std::size_t BlockList::tracked_sources() const {
  std::shared_lock lock(mutex_);
  return entries_.size();
}

void BlockList::sweep(TimePoint now) {
  std::erase_if(entries_, [&](const auto& entry) {
    const Entry& e = entry.second;
    return e.blocked_until <= now && now - e.window_start > policy_.window;
  });
}

} // namespace mw
