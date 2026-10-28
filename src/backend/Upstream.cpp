#include <array>
#include <cerrno>
#include <cstring>
#include <random>
#include <span>
#include <vector>

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "backend/Upstream.hpp"
#include "utils.hpp"

namespace backend {
    namespace {
        using Clock = std::chrono::steady_clock;

        class Socket : utils::immovable {
        private:
            int fd;

        public:
            explicit Socket(int fd) : fd(fd) {}
            ~Socket() {
                if (fd >= 0) ::close(fd);
            }
            int get() const noexcept { return fd; }
        };

        socklen_t to_sockaddr(const Endpoint& server, sockaddr_storage& out) {
            std::memset(&out, 0, sizeof(out));
            if (auto ipv4 = server.address.to_ipv4()) {
                auto* addr       = reinterpret_cast<sockaddr_in*>(&out);
                addr->sin_family = AF_INET;
                addr->sin_port   = htons(server.port);
                addr->sin_addr   = *ipv4;
                return sizeof(sockaddr_in);
            }
            auto* addr        = reinterpret_cast<sockaddr_in6*>(&out);
            addr->sin6_family = AF_INET6;
            addr->sin6_port   = htons(server.port);
            addr->sin6_addr   = *server.address.to_ipv6();
            return sizeof(sockaddr_in6);
        }

        bool retryable(int err) {
            return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
        }

        // true once fd is ready for events (or has an error the next call will report), false at the deadline
        bool wait_for(int fd, short events, Clock::time_point deadline) {
            while (true) {
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
                if (left <= 0) return false;
                pollfd p{ fd, events, 0 };
                const int n = ::poll(&p, 1, static_cast<int>(left));
                if (n > 0) return true;
                if (n == 0 || errno != EINTR) return false;
            }
        }

        uint16_t random_id() {
            thread_local std::mt19937 rng{ std::random_device{}() };
            return static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 0xFFFF)(rng));
        }

        struct Question {
            uint16_t id;
            const types::DomainName& name;
            types::RecordType type;
            types::RecordClass rclass;

            bool answered_by(const types::DnsResponse& response) const {
                return response.id == id && response.has_question && response.question == name && response.qtype == type && response.qclass == rclass;
            }
        };

        std::optional<types::DnsResponse> over_udp(const sockaddr_storage& addr, socklen_t addr_len, std::span<const std::byte> query, const Question& question,
                                                   Clock::time_point deadline) {
            Socket sock(::socket(addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (sock.get() < 0) return std::nullopt;
            // connected: the kernel drops datagrams from anyone else, and reports port unreachable as ECONNREFUSED
            if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) return std::nullopt;
            if (::send(sock.get(), query.data(), query.size(), 0) != static_cast<ssize_t>(query.size())) return std::nullopt;

            std::vector<std::byte> buffer(65535);
            while (wait_for(sock.get(), POLLIN, deadline)) {
                const ssize_t n = ::recv(sock.get(), buffer.data(), buffer.size(), 0);
                if (n < 0) {
                    if (retryable(errno)) continue;
                    return std::nullopt;
                }
                auto response = types::parse_response(std::span(buffer.data(), static_cast<std::size_t>(n)));
                if (response && question.answered_by(*response)) return response;
                // anything else may be a spoofing attempt: keep waiting for the real answer
            }
            return std::nullopt;
        }

        bool send_all(int fd, std::span<const std::byte> data, Clock::time_point deadline) {
            while (!data.empty()) {
                if (!wait_for(fd, POLLOUT, deadline)) return false;
                const ssize_t n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
                if (n < 0) {
                    if (retryable(errno)) continue;
                    return false;
                }
                data = data.subspan(static_cast<std::size_t>(n));
            }
            return true;
        }

        bool recv_all(int fd, std::span<std::byte> out, Clock::time_point deadline) {
            while (!out.empty()) {
                if (!wait_for(fd, POLLIN, deadline)) return false;
                const ssize_t n = ::recv(fd, out.data(), out.size(), 0);
                if (n == 0) return false;
                if (n < 0) {
                    if (retryable(errno)) continue;
                    return false;
                }
                out = out.subspan(static_cast<std::size_t>(n));
            }
            return true;
        }

        std::optional<types::DnsResponse> over_tcp(const sockaddr_storage& addr, socklen_t addr_len, std::span<const std::byte> query, const Question& question,
                                                   Clock::time_point deadline) {
            Socket sock(::socket(addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
            if (sock.get() < 0) return std::nullopt;
            if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), addr_len) != 0) {
                if (errno != EINPROGRESS) return std::nullopt;
                if (!wait_for(sock.get(), POLLOUT, deadline)) return std::nullopt;
                int err       = 0;
                socklen_t len = sizeof(err);
                if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) return std::nullopt;
            }

            // RFC 1035 section 4.2.2: every message on a stream is prefixed with its two byte length
            std::vector<std::byte> framed;
            framed.reserve(query.size() + 2);
            framed.push_back(static_cast<std::byte>(query.size() >> 8));
            framed.push_back(static_cast<std::byte>(query.size() & 0xFF));
            framed.insert(framed.end(), query.begin(), query.end());
            if (!send_all(sock.get(), framed, deadline)) return std::nullopt;

            std::array<std::byte, 2> length_bytes;
            if (!recv_all(sock.get(), length_bytes, deadline)) return std::nullopt;
            const std::size_t length = std::to_integer<std::size_t>(length_bytes[0]) << 8 | std::to_integer<std::size_t>(length_bytes[1]);
            std::vector<std::byte> buffer(length);
            if (!recv_all(sock.get(), buffer, deadline)) return std::nullopt;

            auto response = types::parse_response(buffer);
            if (!response || response->truncated || !question.answered_by(*response)) return std::nullopt;
            return response;
        }
    } // namespace

    std::optional<types::DnsResponse> query_server(const Endpoint& server, const types::DomainName& name, const types::RecordType type,
                                                   const types::RecordClass rclass, const bool recursion_desired, const std::chrono::milliseconds timeout) {
        sockaddr_storage addr;
        const socklen_t addr_len = to_sockaddr(server, addr);
        const Question question{ random_id(), name, type, rclass };
        const auto query = types::encode_query(question.id, name, type, rclass, recursion_desired);

        auto response = over_udp(addr, addr_len, query, question, Clock::now() + timeout);
        if (!response || !response->truncated) return response;
        // the server is up and has more to say than fits in a datagram
        return over_tcp(addr, addr_len, query, question, Clock::now() + timeout);
    }
} // namespace backend
