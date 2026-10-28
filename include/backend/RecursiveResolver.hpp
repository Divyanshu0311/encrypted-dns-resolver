#ifndef BACKEND_RECURSIVERESOLVER_HPP
#define BACKEND_RECURSIVERESOLVER_HPP

#include <chrono>
#include <cstdint>
#include <utility>
#include <vector>

#include "DomainName.hpp"
#include "IP.hpp"
#include "Records.hpp"
#include "backend/Cache.hpp"
#include "backend/Resolver.hpp"

namespace backend {
    struct RecursiveOptions {
        std::vector<types::IP> roots;                     // empty: the 13 root servers (IPv4), unless the cache holds root hints
        uint16_t port                          = 53;      // every server is asked on this port (tests change it)
        std::chrono::milliseconds server_timeout{ 800 };  // per server asked
        std::chrono::milliseconds total_timeout{ 3000 };  // per question from the client, sub-lookups included
        int max_queries                        = 64;      // servers asked per question from the client
    };

    // Walks down from the root servers, following referrals and CNAMEs. A server's records are only trusted for
    // names inside the zone it was asked about, so a referral can't plant answers for someone else's domain.
    // Only IPv4 name server addresses are used. Not thread safe: every worker owns one, the cache is what they share.
    class RecursiveResolver : public Resolver {
    private:
        using Clock = std::chrono::steady_clock;

        struct Budget {
            Clock::time_point deadline;
            int queries_left;
        };

        Cache& cache;
        RecursiveOptions options;

        std::pair<types::DomainName, std::vector<types::IP>> closest_servers(const types::DomainName& name, const types::RecordClass rclass);

        std::vector<types::IP> addresses_of(const types::DomainName& host, const int depth, Budget& budget);

        types::ResolveResult resolve_impl(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass, const int depth,
                                          Budget& budget);

    public:
        RecursiveResolver(Cache& cache, RecursiveOptions options = {});

        // recurse = false answers from the cache only, REFUSED otherwise
        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                     const bool recurse = true) override;
    };
} // namespace backend

#endif
