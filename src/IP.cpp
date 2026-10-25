#include <sstream>
#include <stdexcept>

#include "IP.hpp"

namespace types {
    IP::IP() : addr(4), ipv6(false) {}

    IP::IP(const std::vector<uint8_t> bytes) : addr(bytes) {
        if (bytes.size() == 4)
            ipv6 = false;
        else if (bytes.size() == 16)
            ipv6 = true;
        else
            throw std::runtime_error("IP: Incorrect length");
    }

    IP::IP(const std::string& repr) {
        in_addr ipv4_addr;
        in6_addr ipv6_addr;
        if (inet_pton(AF_INET, &repr[0], &ipv4_addr) > 0) {
            ipv6 = false;
            addr = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ipv4_addr), reinterpret_cast<const uint8_t*>(&ipv4_addr) + 4);
        } else if (inet_pton(AF_INET6, &repr[0], &ipv6_addr) > 0) {
            ipv6 = true;
            addr = std::vector(ipv6_addr.s6_addr, ipv6_addr.s6_addr + 16);
        } else {
            throw std::runtime_error("IP: Invalid representation");
        }
    }

    IP::IP(const in_addr& ipv4_addr) {
        ipv6 = false;
        addr = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ipv4_addr), reinterpret_cast<const uint8_t*>(&ipv4_addr) + 4);
    }

    IP::IP(const in6_addr& ipv6_addr) {
        ipv6 = true;
        addr = std::vector(ipv6_addr.s6_addr, ipv6_addr.s6_addr + 16);
    }

    IP::operator std::vector<uint8_t>() const {
        return addr;
    }

    std::optional<in_addr> IP::to_ipv4() const {
        if (ipv6) return std::nullopt;
        return *(reinterpret_cast<const in_addr*>(&addr[0]));
    }

    std::optional<in6_addr> IP::to_ipv6() const {
        if (!ipv6) return std::nullopt;
        return *(reinterpret_cast<const in6_addr*>(&addr[0]));
    }

    IP::operator std::string() const {
        char repr[40];
        if (ipv6)
            inet_ntop(AF_INET6, &addr[0], repr, sizeof(repr));
        else
            inet_ntop(AF_INET, &addr[0], repr, sizeof(repr));
        return std::string(repr);
    }

    IP::operator DomainName() const {
        if (ipv6) {
            std::stringstream name_stream;
            name_stream << std::hex;
            for (auto it = addr.rbegin(); it < addr.rend(); it++) {
                name_stream << ((*it) & 0x0f) << '.' << (((*it) & 0xf0) >> 4) << '.';
            }
            name_stream << "ip6.arpa.";
            return DomainName(name_stream.str());
        } else {
            return DomainName(std::to_string(addr[3]) + "." + std::to_string(addr[2]) + "." + std::to_string(addr[1]) + "." + std::to_string(addr[0]) + "." +
                              "in-addr.arpa.");
        }
    }
} // namespace types
