#ifndef BACKEND_UPSTREAM_HPP
#define BACKEND_UPSTREAM_HPP

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "DomainName.hpp"
#include "IP.hpp"
#include "Records.hpp"
#include "dns_message.hpp"
#include "utils.hpp"

namespace backend {
    struct Endpoint;

    // The client side of DNS-over-TLS (RFC 7858), shared by every upstream that uses it. Certificates are always
    // checked: the chain against the trusted CAs, and the name (or, without one, the IP address) against the
    // certificate. When that fails the query fails; it never falls back to plain DNS. Connections that answered
    // are kept open for the next query, so most queries skip the TCP and TLS handshakes. Thread safe.
    class TlsClient : utils::immovable {
    public:
        using TimePoint = std::chrono::steady_clock::time_point;

        // running totals, for the admin page: the evidence that certificates are being checked
        struct Stats {
            uint64_t queries    = 0; // answered over TLS
            uint64_t handshakes = 0; // completed, so a certificate was accepted
            uint64_t reused     = 0; // queries sent on a connection kept from an earlier one
            uint64_t rejected   = 0; // handshakes stopped because the certificate failed a check
            uint64_t failed     = 0; // everything else: no connection, not TLS, timed out, a bad answer
            std::string last_peer;   // the last server whose certificate was accepted, "1.1.1.1:853 (cloudflare-dns.com)"
            std::string last_subject; // and that certificate's subject and issuer
            std::string last_issuer;
            std::string last_rejected_peer; // the last one refused, and why ("hostname mismatch")
            std::string last_rejection;
        };

        // one handshake, without a query: what the server presented and what we made of it
        struct Probe {
            bool connected = false; // TCP connected (a TLS alert can still follow)
            bool verified  = false; // handshake done and the certificate accepted
            std::string peer;       // as in Stats::last_peer
            std::string error;      // why not verified, empty when it was
            std::string protocol;   // "TLSv1.3"
            std::string cipher;     // "TLS_AES_256_GCM_SHA384"
            std::string subject;    // of the certificate presented, also when it was rejected
            std::string issuer;
            std::string not_after;  // "Jan  1 00:00:00 2027 GMT"
            double handshake_ms = 0;
        };

        TlsClient();
        ~TlsClient();

        // loads the trusted CAs: ca_file (PEM, one or more certificates) or, when empty, the system's store.
        // call once, before the first query. a client never configured fails every query
        std::expected<void, std::string> configure(const std::filesystem::path& ca_file = {});
        bool configured() const;

        Stats stats() const;

        // a fresh handshake with server (never a kept connection), counted in stats like any other
        Probe probe(const Endpoint& server, std::chrono::milliseconds timeout);

        // for query_server: sends query to server over TLS and returns the first reply, if matches accepts it.
        // nullopt on a rejected certificate, a network error, a malformed or unexpected reply, or at the deadline
        std::optional<types::DnsResponse> exchange(const Endpoint& server, std::span<const std::byte> query,
                                                   const std::function<bool(const types::DnsResponse&)>& matches, TimePoint deadline);

    private:
        struct Connection;
        struct State;
        std::unique_ptr<State> state;

        std::unique_ptr<Connection> connect(const Endpoint& server, TimePoint deadline, Probe& out);
    };

    struct Endpoint {
        types::IP address;
        uint16_t port = 53;
        // set: DNS-over-TLS through this client (the port is then usually 853). null: plain DNS, UDP then TCP
        std::shared_ptr<TlsClient> tls;
        // the name the server's certificate must be issued to, also sent as SNI. empty: the certificate must list
        // the IP address instead
        std::string tls_name;
    };

    // "1.1.1.1:53", "[2606:4700::1111]:853 (cloudflare-dns.com)"
    std::string endpoint_label(const Endpoint& server);

    // Asks one server one question. Plain: over UDP, again over TCP if the reply comes back truncated. With tls
    // set: over TLS only. Replies whose ID or question don't match are ignored (they may be spoofed) and the wait
    // goes on. nullopt on timeout, a network error or a malformed reply. Blocks for at most timeout per transport.
    std::optional<types::DnsResponse> query_server(const Endpoint& server, const types::DomainName& name, const types::RecordType type,
                                                   const types::RecordClass rclass, const bool recursion_desired, const std::chrono::milliseconds timeout);
} // namespace backend

#endif
