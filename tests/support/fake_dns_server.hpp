#ifndef TESTS_SUPPORT_FAKE_DNS_SERVER_HPP
#define TESTS_SUPPORT_FAKE_DNS_SERVER_HPP

// A DNS server on a loopback address for the resolver tests. It answers over UDP and TCP (same port) with
// whatever the test's handler returns, and counts what it was asked.

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "IP.hpp"
#include "Records.hpp"
#include "dns_message.hpp"

namespace support {
    class FakeDnsServer {
    public:
        // the datagrams (or, over TCP, messages) to send back. empty: stay silent, the client times out
        using Handler = std::function<std::vector<std::vector<std::byte>>(const types::DnsQuery& query, bool tcp)>;

        // port 0 picks a free one
        explicit FakeDnsServer(Handler handler, std::string address = "127.0.0.1", uint16_t port = 0) : handler_(std::move(handler)), address_(address) {
            udp_ = bind_socket(SOCK_DGRAM, port);
            port_ = bound_port(udp_);
            tcp_ = bind_socket(SOCK_STREAM, port_);
            if (::listen(tcp_, 16) != 0) throw std::runtime_error("FakeDnsServer: listen failed");
            thread_ = std::thread([this] { run(); });
        }

        ~FakeDnsServer() {
            stop_ = true;
            thread_.join();
            ::close(udp_);
            ::close(tcp_);
        }

        FakeDnsServer(const FakeDnsServer&)            = delete;
        FakeDnsServer& operator=(const FakeDnsServer&) = delete;

        uint16_t port() const { return port_; }
        types::IP ip() const { return types::IP(address_); }
        int udp_queries() const { return udp_queries_.load(); }
        int tcp_queries() const { return tcp_queries_.load(); }

        // the usual reply: the question echoed, the result's sections, rcode
        static std::vector<std::vector<std::byte>> reply(const types::DnsQuery& query, const types::ResolveResult& result) {
            return { types::encode_response(query, result) };
        }

        // a reply with the TC (truncated) bit set and no records
        static std::vector<std::vector<std::byte>> truncated(const types::DnsQuery& query) {
            auto wire = types::encode_response(query, types::ResolveResult{});
            wire[2] |= std::byte{ 0x02 };
            return { wire };
        }

    private:
        Handler handler_;
        std::string address_;
        int udp_      = -1;
        int tcp_      = -1;
        uint16_t port_ = 0;
        std::atomic<bool> stop_{ false };
        std::atomic<int> udp_queries_{ 0 };
        std::atomic<int> tcp_queries_{ 0 };
        std::thread thread_;

        int bind_socket(int type, uint16_t port) {
            int fd = ::socket(AF_INET, type | SOCK_CLOEXEC, 0);
            if (fd < 0) throw std::runtime_error("FakeDnsServer: socket failed");
            int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(port);
            ::inet_pton(AF_INET, address_.c_str(), &addr.sin_addr);
            if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
                ::close(fd);
                throw std::runtime_error("FakeDnsServer: cannot bind " + address_ + ":" + std::to_string(port) + ": " + std::strerror(errno));
            }
            return fd;
        }

        static uint16_t bound_port(int fd) {
            sockaddr_in addr{};
            socklen_t len = sizeof(addr);
            ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
            return ntohs(addr.sin_port);
        }

        void run() {
            while (!stop_) {
                pollfd fds[2] = { { udp_, POLLIN, 0 }, { tcp_, POLLIN, 0 } };
                if (::poll(fds, 2, 20) <= 0) continue;
                if (fds[0].revents & POLLIN) serve_udp();
                if (fds[1].revents & POLLIN) serve_tcp();
            }
        }

        void serve_udp() {
            std::vector<std::byte> buf(65535);
            sockaddr_storage from{};
            socklen_t from_len = sizeof(from);
            ssize_t n          = ::recvfrom(udp_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
            if (n <= 0) return;
            auto query = types::parse_query(std::span(buf.data(), static_cast<std::size_t>(n)));
            if (!query) return;
            udp_queries_++;
            for (const auto& out : handler_(*query, false))
                ::sendto(udp_, out.data(), out.size(), 0, reinterpret_cast<sockaddr*>(&from), from_len);
        }

        void serve_tcp() {
            int fd = ::accept(tcp_, nullptr, nullptr);
            if (fd < 0) return;
            timeval tv{ 1, 0 };
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            uint8_t len_bytes[2];
            if (::recv(fd, len_bytes, 2, MSG_WAITALL) == 2) {
                std::vector<std::byte> msg(static_cast<std::size_t>(len_bytes[0] << 8 | len_bytes[1]));
                if (::recv(fd, msg.data(), msg.size(), MSG_WAITALL) == static_cast<ssize_t>(msg.size())) {
                    if (auto query = types::parse_query(msg)) {
                        tcp_queries_++;
                        for (const auto& out : handler_(*query, true)) {
                            uint8_t prefix[2] = { static_cast<uint8_t>(out.size() >> 8), static_cast<uint8_t>(out.size() & 0xFF) };
                            ::send(fd, prefix, 2, MSG_NOSIGNAL);
                            ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
                        }
                    }
                }
            }
            ::close(fd);
        }
    };

    // a port on 127.0.0.1 with nothing listening: UDP to it fails fast with ECONNREFUSED
    inline uint16_t closed_port() {
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
        ::close(fd);
        return ntohs(addr.sin_port);
    }

    inline types::ResourceRecord record(const std::string& name, types::RecordType type, std::vector<uint8_t> rdata, uint32_t ttl = 300) {
        return types::ResourceRecord{ types::DomainName(name), type, types::RecordClass::IN, ttl, std::move(rdata) };
    }

    inline types::ResourceRecord a_record(const std::string& name, const std::string& ip, uint32_t ttl = 300) {
        return record(name, types::RecordType::A, types::IP(ip), ttl);
    }

    inline types::ResourceRecord name_record(const std::string& name, types::RecordType type, const std::string& target, uint32_t ttl = 300) {
        return record(name, type, static_cast<std::vector<uint8_t>>(types::DomainName(target)), ttl);
    }

    // a minimal SOA: mname, rname, then five zero counters
    inline types::ResourceRecord soa_record(const std::string& zone) {
        std::vector<uint8_t> rdata = types::DomainName("ns." + zone);
        std::vector<uint8_t> rname = types::DomainName("admin." + zone);
        rdata.insert(rdata.end(), rname.begin(), rname.end());
        rdata.resize(rdata.size() + 20, 0);
        return record(zone, types::RecordType::SOA, std::move(rdata));
    }

    inline types::ResolveResult result(types::Rcode rcode, std::vector<types::ResourceRecord> answer = {}, std::vector<types::ResourceRecord> authority = {},
                                       std::vector<types::ResourceRecord> additional = {}) {
        types::ResolveResult r;
        r.rcode      = rcode;
        r.answer     = std::move(answer);
        r.authority  = std::move(authority);
        r.additional = std::move(additional);
        return r;
    }
} // namespace support

#endif
