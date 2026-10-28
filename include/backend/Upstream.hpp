#ifndef BACKEND_UPSTREAM_HPP
#define BACKEND_UPSTREAM_HPP

#include <chrono>
#include <cstdint>
#include <optional>

#include "DomainName.hpp"
#include "IP.hpp"
#include "Records.hpp"
#include "dns_message.hpp"

namespace backend {
    struct Endpoint {
        types::IP address;
        uint16_t port = 53;
    };

    // Asks one server one question over UDP, again over TCP if the reply comes back truncated. Replies whose ID or
    // question don't match are ignored (they may be spoofed) and the wait goes on. nullopt on timeout, a network
    // error or a malformed reply. Blocks for at most timeout per transport.
    std::optional<types::DnsResponse> query_server(const Endpoint& server, const types::DomainName& name, const types::RecordType type,
                                                   const types::RecordClass rclass, const bool recursion_desired, const std::chrono::milliseconds timeout);
} // namespace backend

#endif
