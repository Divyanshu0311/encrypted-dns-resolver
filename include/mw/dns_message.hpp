#pragma once
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mw/resolver_interface.hpp"

namespace mw {

struct DnsQuery {
  uint16_t id = 0;
  bool recursion_desired = false;
  std::string name;
  RecordType type = RecordType::A;
  bool has_edns = false;
  bool wants_padding = false;

  bool operator==(const DnsQuery &) const = default;
};

struct ParseError {
  Rcode rcode = Rcode::FormErr;
  std::optional<uint16_t> id;

  bool operator==(const ParseError &) const = default;
};

std::expected<DnsQuery, ParseError> parse_query(std::span<const std::byte> wire);
std::vector<std::byte> encode_response(const DnsQuery &query, const ResolveResult &result);
std::vector<std::byte> encode_error(uint16_t id, Rcode rcode);

} // namespace mw
