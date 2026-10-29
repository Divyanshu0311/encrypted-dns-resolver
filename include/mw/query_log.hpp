#pragma once
#include<chrono>
#include<cstddef>
#include<cstdint>
#include<deque>
#include<mutex>
#include<string>
#include<vector>

#include "mw/types.hpp"

// Will hold: mw::QueryLog (the last few hundred queries, for the admin page)

namespace mw {

struct QueryLogEntry {
  uint64_t seq = 0; // 1, 2, 3, ... in the order the replies went out
  std::chrono::system_clock::time_point when;
  std::string client;
  Transport transport = Transport::Udp;
  std::string name;
  RecordType type = RecordType::A;
  Rcode rcode = Rcode::NoError;
  double latency_ms = 0;
  std::string served_by;
  std::vector<ResourceRecord> answer; // the first few records only
};

// thread safe ring buffer, oldest entries drop off the front
class QueryLog {
  private:
    mutable std::mutex mutex_;
    std::deque<QueryLogEntry> entries_;
    const std::size_t capacity_;
    uint64_t next_seq_ = 1;

  public:
    static constexpr std::size_t kAnswersKept = 4;

    explicit QueryLog(std::size_t capacity = 500) : capacity_(capacity) {}

    // fills in seq. never throws past a failed allocation, which it swallows
    void add(QueryLogEntry entry) noexcept;

    // entries with seq > after, oldest first, at most limit of the newest
    std::vector<QueryLogEntry> since(uint64_t after, std::size_t limit = 200) const;
};

} // namespace mw
