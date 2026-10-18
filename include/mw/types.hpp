#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>

#include "mw/resolver_interface.hpp"

// Will hold: shared value types used across the middleware.

namespace mw {
  enum class Transport : uint8_t {
    Udp,
    Tcp
  };
  enum class LbPolicy : uint8_t {
    RoundRobin,
    LeastOutstanding,
    PowerOfTwo
  };
struct ClientInfo {
  std::string address;
  uint16_t port = 0;
  Transport transport = Transport::Udp;
};

// called exactly once per submit()
using ResultCallback = std::move_only_function<void(ResolveResult)>;

struct QueryKey {
  std::string name; // normalized
  RecordType type;

  bool operator==(const QueryKey&) const = default;
};
struct QueryKeyHash {
  std::size_t operator()(const QueryKey& key) const noexcept {
    std::size_t h1 = std::hash<std::string>{}(key.name);
    std::size_t h2 = std::hash<std::underlying_type_t<RecordType>>{}(
        static_cast<std::underlying_type_t<RecordType>>(key.type));
    return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
  }
};

using SteadyClock = std::chrono::steady_clock;
using TimePoint = SteadyClock::time_point;
using Ms = std::chrono::milliseconds;
using Clock = std::function<TimePoint()>;

inline Clock steady_clock_fn() {
  return [] { return SteadyClock::now(); };
}

} // namespace mw
