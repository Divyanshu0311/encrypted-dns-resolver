#pragma once

// Test-only gtest printers so failures show names and fields instead of raw bytes.
// They live in namespace mw so gtest finds them by argument-dependent lookup.

#include "mw/resolver_interface.hpp"
#include "mw/types.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <ostream>

namespace mw {

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
  }
  *os << "RCODE" << static_cast<int>(rcode);
}

inline void PrintTo(Transport transport, std::ostream* os) {
  switch (transport) {
  case Transport::Udp: *os << "Udp"; return;
  case Transport::Tcp: *os << "Tcp"; return;
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

inline void PrintTo(const ResourceRecord& rr, std::ostream* os) {
  static constexpr char hex[] = "0123456789abcdef";
  *os << "{" << ::testing::PrintToString(rr.name) << " ";
  PrintTo(rr.type, os);
  *os << " class=" << rr.rclass << " ttl=" << rr.ttl << " rdata=[";
  for (std::size_t i = 0; i < rr.rdata.size(); ++i) {
    const auto b = static_cast<unsigned>(rr.rdata[i]);
    *os << (i == 0 ? "" : " ") << hex[b >> 4] << hex[b & 0xf];
  }
  *os << "]}";
}

inline void PrintTo(const ResolveResult& result, std::ostream* os) {
  *os << "{rcode=";
  PrintTo(result.rcode, os);
  *os << " answers=" << ::testing::PrintToString(result.answers)
      << " authority=" << ::testing::PrintToString(result.authority) << "}";
}

inline void PrintTo(const QueryKey& key, std::ostream* os) {
  *os << "{" << ::testing::PrintToString(key.name) << " ";
  PrintTo(key.type, os);
  *os << "}";
}

inline void PrintTo(const ClientInfo& info, std::ostream* os) {
  *os << "{" << ::testing::PrintToString(info.address) << " port=" << info.port << " ";
  PrintTo(info.transport, os);
  *os << "}";
}

} // namespace mw
