#ifndef TYPES_DNS_MESSAGE_HPP
#define TYPES_DNS_MESSAGE_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"

namespace types {

    // ---- server side: queries from clients, replies to them ----

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

    // ---- client side: queries to upstream servers, their replies ----

    struct DnsResponse {
        uint16_t id         = 0;
        bool truncated      = false;
        bool authoritative  = false;
        DomainName question; // root when the reply carries no question
        RecordType qtype    = RecordType::A;
        RecordClass qclass  = RecordClass::IN;
        bool has_question   = false;
        ResolveResult result; // the OPT record is left out of additional
    };

    // the block size RFC 8467 recommends for padding queries
    inline constexpr std::size_t kQueryPaddingBlock = 128;

    // one question plus an OPT record advertising a 1232 byte UDP buffer. pad_block > 0 adds an EDNS Padding
    // option making the query a multiple of pad_block bytes, which also asks the server to pad its reply
    std::vector<std::byte> encode_query(uint16_t id, const DomainName& name, RecordType type, RecordClass rclass, bool recursion_desired,
                                        std::size_t pad_block = 0);

    // nullopt for a query or a malformed message. names inside the rdata of the RFC 1035 types (and SRV, RP, ...)
    // are decompressed, so the records can be copied into another message. rcodes above 11 come back as ServFail
    std::optional<DnsResponse> parse_response(std::span<const std::byte> wire);

} // namespace types

#endif
