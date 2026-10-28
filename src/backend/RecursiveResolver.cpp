#include <algorithm>
#include <random>
#include <stdexcept>

#include "IP.hpp"
#include "backend/RecursiveResolver.hpp"
#include "backend/Upstream.hpp"

namespace backend {
    namespace {
        constexpr int kMaxDepth = 8; // CNAME hops plus name server lookups, nested

        // a.root-servers.net to m.root-servers.net
        const char* const kRootServers[] = { "198.41.0.4",   "170.247.170.2", "192.33.4.12",   "199.7.91.13",  "192.203.230.10",
                                             "192.5.5.241",  "192.112.36.4",  "198.97.190.53", "192.36.148.17", "192.58.128.30",
                                             "193.0.14.129", "199.7.83.42",   "202.12.27.33" };

        types::ResolveResult make_result(types::Rcode rcode, std::vector<types::ResourceRecord> answer = {}, std::vector<types::ResourceRecord> authority = {}) {
            types::ResolveResult result;
            result.rcode     = rcode;
            result.answer    = std::move(answer);
            result.authority = std::move(authority);
            return result;
        }

        types::ResolveResult servfail() {
            return make_result(types::Rcode::ServFail);
        }

        std::vector<types::IP> ipv4_addresses(const std::vector<types::ResourceRecord>& records) {
            std::vector<types::IP> out;
            for (const auto& record : records)
                if (record.type == types::RecordType::A && record.rdata.size() == 4) out.emplace_back(record.rdata);
            return out;
        }

        std::optional<types::DomainName> name_in_rdata(const types::ResourceRecord& record) {
            try {
                return types::DomainName(record.rdata, 0);
            } catch (const std::runtime_error&) {
                return std::nullopt;
            }
        }

        // spreads the load, and keeps one dead server from being asked first every time
        void shuffle(std::vector<types::IP>& servers) {
            thread_local std::mt19937 rng{ std::random_device{}() };
            std::ranges::shuffle(servers, rng);
        }
    } // namespace

    RecursiveResolver::RecursiveResolver(Cache& cache, RecursiveOptions options) : cache(cache), options(std::move(options)) {
        if (this->options.roots.empty())
            for (const char* root : kRootServers) this->options.roots.emplace_back(std::string(root));
    }

    std::pair<types::DomainName, std::vector<types::IP>> RecursiveResolver::closest_servers(const types::DomainName& name, const types::RecordClass rclass) {
        for (types::DomainName zone = name;; zone = zone.parent()) {
            std::vector<types::IP> servers;
            for (const auto& ns : cache.find(zone, types::RecordType::NS, rclass))
                if (auto host = name_in_rdata(ns)) servers.append_range(ipv4_addresses(cache.find(*host, types::RecordType::A, types::RecordClass::IN)));
            if (!servers.empty()) return { zone, servers };
            if (zone.get_labels().empty()) break;
        }
        return { types::DomainName("."), options.roots };
    }

    std::vector<types::IP> RecursiveResolver::addresses_of(const types::DomainName& host, const int depth, Budget& budget) {
        return ipv4_addresses(resolve_impl(host, types::RecordType::A, types::RecordClass::IN, depth, budget).answer);
    }

    types::ResolveResult RecursiveResolver::resolve_impl(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                         const int depth, Budget& budget) {
        if (depth > kMaxDepth) return servfail();
        if (auto cached = cache.find_answer(name, type, rclass)) return *cached;

        auto [zone, servers] = closest_servers(name, rclass);
        shuffle(servers);
        while (!servers.empty()) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(budget.deadline - Clock::now());
            if (budget.queries_left <= 0 || left.count() <= 0) return servfail();
            --budget.queries_left;

            const types::IP server = servers.front();
            auto response          = query_server(Endpoint{ server, options.port }, name, type, rclass, false, std::min(options.server_timeout, left));
            // unreachable, broken or lame: try the zone's next server
            if (!response || (response->result.rcode != types::Rcode::NoError && response->result.rcode != types::Rcode::NXDomain)) {
                servers.erase(servers.begin());
                continue;
            }
            const types::ResolveResult& reply = response->result;

            // the answer, possibly behind CNAMEs, as far as it stays inside the zone this server is authoritative for
            std::vector<types::ResourceRecord> chain;
            types::DomainName current = name;
            for (int hops = 0; hops <= kMaxDepth && zone.is_ancestor_of(current); ++hops) {
                auto own = type == types::RecordType::ANY ? types::find_records(reply.answer, current, rclass)
                                                          : types::find_records(reply.answer, current, type, rclass);
                if (!own.empty()) {
                    chain.append_range(own);
                    cache.update(chain);
                    return make_result(reply.rcode, chain);
                }
                const auto cname = types::find_records(reply.answer, current, types::RecordType::CNAME, rclass);
                if (cname.empty() || type == types::RecordType::CNAME) break;
                const auto target = name_in_rdata(cname.front());
                if (!target) return servfail();
                chain.push_back(cname.front());
                current = *target;
            }
            if (!chain.empty()) {
                // the chain leaves this zone: look the rest up on its own
                cache.update(chain);
                auto rest = resolve_impl(current, type, rclass, depth + 1, budget);
                rest.answer.insert(rest.answer.begin(), chain.begin(), chain.end());
                return rest;
            }

            if (reply.rcode == types::Rcode::NXDomain) return make_result(types::Rcode::NXDomain, {}, reply.authority);

            // a referral to a zone between this one and the name
            std::vector<types::ResourceRecord> delegation;
            for (const auto& record : reply.authority) {
                if (record.type != types::RecordType::NS || record.rclass != rclass) continue;
                if (!record.name.is_ancestor_of(name) || !zone.is_ancestor_of(record.name) || record.name == zone) continue;
                if (delegation.empty() || record.name == delegation.front().name) delegation.push_back(record);
            }
            if (!delegation.empty()) {
                cache.update(delegation);
                std::vector<types::ResourceRecord> glue;
                for (const auto& ns : delegation) {
                    const auto host = name_in_rdata(ns);
                    // glue outside this server's zone could point anywhere, so it is ignored
                    if (host && zone.is_ancestor_of(*host)) glue.append_range(types::find_records(reply.additional, *host, types::RecordType::A));
                }
                cache.update(glue);

                std::vector<types::IP> next = ipv4_addresses(glue);
                for (std::size_t i = 0; i < delegation.size() && next.empty(); ++i)
                    if (auto host = name_in_rdata(delegation[i])) next = addresses_of(*host, depth + 1, budget);

                zone    = delegation.front().name;
                servers = std::move(next);
                shuffle(servers);
                continue;
            }

            // no data of that type: the server says so with its zone's SOA, or answers authoritatively
            std::vector<types::ResourceRecord> soa;
            for (const auto& record : reply.authority)
                if (record.type == types::RecordType::SOA && zone.is_ancestor_of(record.name)) soa.push_back(record);
            if (!soa.empty() || response->authoritative) return make_result(types::Rcode::NoError, {}, soa);

            servers.erase(servers.begin()); // lame: neither an answer nor a referral
        }
        return servfail();
    }

    types::ResolveResult RecursiveResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                    const bool recurse) {
        if (!recurse) {
            if (auto cached = cache.find_answer(name, type, rclass)) return *cached;
            auto refused      = make_result(types::Rcode::Refused);
            refused.served_by = "not in cache, recursion not desired";
            return refused;
        }
        Budget budget{ Clock::now() + options.total_timeout, options.max_queries };
        auto result = resolve_impl(name, type, rclass, 0, budget);
        const int asked = options.max_queries - budget.queries_left;
        if (asked > 0) result.served_by = "recursive, " + std::to_string(asked) + (asked == 1 ? " server asked" : " servers asked");
        return result;
    }
} // namespace backend
