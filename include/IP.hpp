#ifndef TYPES_IP_HPP
#define TYPES_IP_HPP

#ifdef _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#endif
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "DomainName.hpp"

namespace types {
    class IP {
    private:
        std::vector<uint8_t> addr;
        bool ipv6;

    public:
        IP();

        IP(const std::vector<uint8_t> bytes);

        IP(const std::string& repr);

        IP(const in_addr& ipv4_addr);

        IP(const in6_addr& ipv6_addr);

        bool is_ipv6() const noexcept { return ipv6; }

        operator std::vector<uint8_t>() const;

        std::optional<in_addr> to_ipv4() const;

        std::optional<in6_addr> to_ipv6() const;

        operator std::string() const;

        operator DomainName() const;

        bool operator==(const IP&) const noexcept = default;
        bool operator!=(const IP&) const noexcept = default;
    };
} // namespace types

#endif
