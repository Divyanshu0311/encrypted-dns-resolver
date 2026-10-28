#include "mw/query_log.hpp"
#include<algorithm>

namespace mw {

void QueryLog::add(QueryLogEntry entry) noexcept {
  try {
    if (entry.answer.size() > kAnswersKept)
      entry.answer.resize(kAnswersKept);
    std::lock_guard<std::mutex> lock(mutex_);
    entry.seq = next_seq_++;
    entries_.push_back(std::move(entry));
    while (entries_.size() > capacity_)
      entries_.pop_front();
  }
  catch (...) {
  }
}

std::vector<QueryLogEntry> QueryLog::since(uint64_t after, std::size_t limit) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto first = std::ranges::upper_bound(entries_, after, {}, &QueryLogEntry::seq);
  auto count = static_cast<std::size_t>(entries_.end() - first);
  if (count > limit)
    first += static_cast<std::ptrdiff_t>(count - limit);
  return {first, entries_.end()};
}

} // namespace mw
