#pragma once
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mw/types.hpp"

namespace mw {

    struct DnsQuery {
        uint16_t id            = 0;
        bool recursion_desired = false;
        std::string name;
        RecordType type    = RecordType::A;
        bool has_edns      = false;
        bool wants_padding = false;

        bool operator==(const DnsQuery&) const = default;
    };

    struct ParseError {
        Rcode rcode = Rcode::FormErr;
        std::optional<uint16_t> id;
        // EDNS version above 0: the reply is BADVERS (16), which has no Rcode value, so rcode is unused
        bool bad_edns_version = false;

        bool operator==(const ParseError&) const = default;
    };

    std::expected<DnsQuery, ParseError> parse_query(std::span<const std::byte> wire);
    std::vector<std::byte> encode_response(const DnsQuery& query, const ResolveResult& result);
    std::vector<std::byte> encode_error(uint16_t id, Rcode rcode);
    std::vector<std::byte> encode_bad_version(uint16_t id);
    // the reply for a rejected query, or nullopt when there is no ID to reply to
    std::optional<std::vector<std::byte>> encode_parse_error(const ParseError& error);

} // namespace mw
