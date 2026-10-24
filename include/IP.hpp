#ifndef TYPES_IP_HPP
#define TYPES_IP_HPP


#ifdef _WIN32
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#endif
#include <cstddef>
#include <cstdint>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "DomainName.hpp"

namespace types {
    class IP {
    private:
        std::vector<uint8_t> addr;
        bool ipv6;

    public:
        IP(bool ipv6 = false) : ipv6(ipv6) {
            if (ipv6)
                addr = std::vector<uint8_t>(16, 0);
            else
                addr = std::vector<uint8_t>(4, 0);
        }

        IP(const std::vector<uint8_t> bytes) : addr(bytes) {
            if (bytes.size() == 4)
                ipv6 = false;
            else if (bytes.size() == 16)
                ipv6 = true;
            else
                throw std::runtime_error("IP: Incorrect length");
        }

        IP(const std::string& repr) {
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

        IP(const char* repr) : IP(std::string(repr)) {}

        IP(const in_addr& ipv4_addr) {
            ipv6 = false;
            addr = std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(&ipv4_addr), reinterpret_cast<const uint8_t*>(&ipv4_addr) + 4);
        }

        IP(const in6_addr& ipv6_addr) {
            ipv6 = true;
            addr = std::vector(ipv6_addr.s6_addr, ipv6_addr.s6_addr + 16);
        }

        bool is_ipv6() const noexcept { return ipv6; }

        std::vector<uint8_t> to_bytes() const noexcept { return addr; }

        std::optional<in_addr> to_ipv4() const noexcept {
            if (ipv6) return std::nullopt;
            return *(reinterpret_cast<const in_addr*>(&addr[0]));
        }

        std::optional<in6_addr> to_ipv6() const noexcept {
            if (!ipv6) return std::nullopt;
            return *(reinterpret_cast<const in6_addr*>(&addr[0]));
        }

        std::string to_string() const noexcept {
            char repr[40];
            if (ipv6)
                inet_ntop(AF_INET6, &addr[0], repr, sizeof(repr));
            else
                inet_ntop(AF_INET, &addr[0], repr, sizeof(repr));
            return std::string(repr);
        }

        DomainName to_domain() {
            if (ipv6) {
                std::stringstream name_stream;
                name_stream << std::hex;
                for (auto it = addr.rbegin(); it < addr.rend(); it++) {
                    name_stream << ((*it) & 0x0f) << '.' << (((*it) & 0xf0) >> 4) << '.';
                }
                name_stream << "ip6.arpa.";
                return DomainName(name_stream.str());
            } else {
                return DomainName(std::to_string(addr[3]) + "." + std::to_string(addr[2]) + "." + std::to_string(addr[1]) + "." + std::to_string(addr[0]) +
                                  "." + "in-addr.arpa.");
            }
        }

        bool operator==(const IP&) const noexcept = default;
        bool operator!=(const IP&) const noexcept = default;
    };
} // namespace types

#endif
