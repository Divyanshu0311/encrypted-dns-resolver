#pragma once
#include<chrono>
#include<cstddef>
#include<cstdint>
#include<functional>
#include<memory>
#include<string>
#include<type_traits>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/Resolver.hpp"

// Will hold: shared value types used across the middleware.

namespace mw {

// record types, rcodes and results are Arnav's types:: ones, so the backend and the
// middleware speak the same language. aliased here so the middleware can say mw::Rcode.
using RecordType = types::RecordType;
using RecordClass = types::RecordClass;
using Rcode = types::Rcode;
using ResourceRecord = types::ResourceRecord;
using ResolveResult = types::ResolveResult;
using DomainName = types::DomainName;

// every worker owns one backend::Resolver chain. each call returns a new, independent chain
using ResolverFactory = std::function<std::unique_ptr<backend::Resolver>()>;

// result with just an rcode and no records
inline ResolveResult error_result(Rcode rc) {
  return ResolveResult{rc, {}, {}, {}};
}

enum class Transport : uint8_t {
  Udp,
  Tcp
};

// here and not in load_balancer.hpp so config.hpp can use it
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
  DomainName name; // absolute; compares and hashes case-insensitively
  RecordType type;

  bool operator==(const QueryKey&) const = default;
};

struct QueryKeyHash {
  std::size_t operator()(const QueryKey& key) const noexcept {
    std::size_t h1 = std::hash<DomainName>{}(key.name);
    std::size_t h2 = std::hash<std::underlying_type_t<RecordType>>{}(static_cast<std::underlying_type_t<RecordType>>(key.type));
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
