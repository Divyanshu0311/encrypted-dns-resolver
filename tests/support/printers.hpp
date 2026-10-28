#pragma once

// Test-only gtest printers so failures show names and fields instead of raw bytes.
// Each lives in the namespace of the type it prints (types:: for Arnav's record types,
// mw:: for ours) so gtest finds it by argument-dependent lookup.

#include "mw/config.hpp"
#include "mw/types.hpp"
#include "mw/worker.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <ostream>
#include <string>

namespace types {

inline void PrintTo(RecordType type, std::ostream* os) {
  switch (type) {
  case RecordType::A: *os << "A"; return;
  case RecordType::NS: *os << "NS"; return;
  case RecordType::CNAME: *os << "CNAME"; return;
  case RecordType::SOA: *os << "SOA"; return;
  case RecordType::PTR: *os << "PTR"; return;
  case RecordType::MX: *os << "MX"; return;
  case RecordType::TXT: *os << "TXT"; return;
  case RecordType::AAAA: *os << "AAAA"; return;
  case RecordType::ANY: *os << "ANY"; return;
  default: break;
  }
  *os << "TYPE" << static_cast<std::uint16_t>(type);
}

inline void PrintTo(Rcode rcode, std::ostream* os) {
  switch (rcode) {
  case Rcode::NoError: *os << "NoError"; return;
  case Rcode::FormErr: *os << "FormErr"; return;
  case Rcode::ServFail: *os << "ServFail"; return;
  case Rcode::NXDomain: *os << "NXDomain"; return;
  case Rcode::NotImp: *os << "NotImp"; return;
  case Rcode::Refused: *os << "Refused"; return;
  default: break;
  }
  *os << "RCODE" << static_cast<int>(rcode);
}

inline void PrintTo(const DomainName& name, std::ostream* os) {
  *os << ::testing::PrintToString(static_cast<std::string>(name));
}

inline void PrintTo(const ResourceRecord& rr, std::ostream* os) {
  static constexpr char hex[] = "0123456789abcdef";
  *os << "{";
  PrintTo(rr.name, os);
  *os << " ";
  PrintTo(rr.type, os);
  *os << " class=" << static_cast<int>(rr.rclass) << " ttl=" << rr.ttl << " rdata=[";
  for (std::size_t i = 0; i < rr.rdata.size(); ++i) {
    const auto b = static_cast<unsigned>(rr.rdata[i]);
    *os << (i == 0 ? "" : " ") << hex[b >> 4] << hex[b & 0xf];
  }
  *os << "]}";
}

inline void PrintTo(const ResolveResult& result, std::ostream* os) {
  *os << "{rcode=";
  PrintTo(result.rcode, os);
  *os << " answer=" << result.answer.size() << " authority=" << result.authority.size()
      << " additional=" << result.additional.size() << "}";
}

} // namespace types

namespace mw {

inline void PrintTo(Transport transport, std::ostream* os) {
  switch (transport) {
  case Transport::Udp: *os << "Udp"; return;
  case Transport::Tcp: *os << "Tcp"; return;
  case Transport::Dot: *os << "Dot"; return;
  }
  *os << "Transport(" << static_cast<int>(transport) << ")";
}

inline void PrintTo(LbPolicy policy, std::ostream* os) {
  switch (policy) {
  case LbPolicy::RoundRobin: *os << "RoundRobin"; return;
  case LbPolicy::LeastOutstanding: *os << "LeastOutstanding"; return;
  case LbPolicy::PowerOfTwo: *os << "PowerOfTwo"; return;
  }
  *os << "LbPolicy(" << static_cast<int>(policy) << ")";
}

inline void PrintTo(BreakerState state, std::ostream* os) {
  switch (state) {
  case BreakerState::Closed: *os << "Closed"; return;
  case BreakerState::Open: *os << "Open"; return;
  case BreakerState::HalfOpen: *os << "HalfOpen"; return;
  }
  *os << "BreakerState(" << static_cast<int>(state) << ")";
}

inline void PrintTo(Mode mode, std::ostream* os) {
  *os << (mode == Mode::Forwarding ? "Forwarding" : "Recursive");
}

inline void PrintTo(LogLevel level, std::ostream* os) {
  switch (level) {
  case LogLevel::Debug: *os << "Debug"; return;
  case LogLevel::Info: *os << "Info"; return;
  case LogLevel::Warn: *os << "Warn"; return;
  case LogLevel::Error: *os << "Error"; return;
  }
  *os << "LogLevel(" << static_cast<int>(level) << ")";
}

inline void PrintTo(const Upstream& u, std::ostream* os) {
  *os << ::testing::PrintToString(u.host) << ":" << u.port;
}

inline void PrintTo(const QueryKey& key, std::ostream* os) {
  *os << "{";
  types::PrintTo(key.name, os);
  *os << " ";
  types::PrintTo(key.type, os);
  *os << "}";
}

inline void PrintTo(const ClientInfo& info, std::ostream* os) {
  *os << "{" << ::testing::PrintToString(info.address) << " port=" << info.port << " ";
  PrintTo(info.transport, os);
  *os << "}";
}

} // namespace mw
