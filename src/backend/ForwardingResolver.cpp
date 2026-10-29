#include <algorithm>
#include <stdexcept>
#include <string>

#include "backend/ForwardingResolver.hpp"

namespace backend {
    namespace {
        // the answer records that belong to the question: its own and those of the CNAME chain it starts.
        // anything else the upstream put in is not cached, so a bad upstream can't plant unrelated names
        std::vector<types::ResourceRecord> chain_records(const std::vector<types::ResourceRecord>& answer, const types::DomainName& name) {
            std::vector<types::ResourceRecord> chain;
            types::DomainName current = name;
            for (int hops = 0; hops <= 8; ++hops) {
                auto here = types::find_records(answer, current);
                if (here.empty()) break;
                chain.insert(chain.end(), here.begin(), here.end());
                const auto cname = std::ranges::find(here, types::RecordType::CNAME, &types::ResourceRecord::type);
                if (cname == here.end()) break;
                try {
                    current = types::DomainName(cname->rdata, 0);
                } catch (const std::runtime_error&) {
                    break;
                }
            }
            return chain;
        }
    } // namespace

    ForwardingResolver::ForwardingResolver(std::vector<Endpoint> resolvers, Cache& cache, std::chrono::milliseconds timeout,
                                           std::shared_ptr<std::atomic<std::size_t>> preferred)
        : resolvers(std::move(resolvers)), cache(cache), timeout(timeout), preferred(std::move(preferred)) {
        if (this->resolvers.empty()) throw std::invalid_argument("ForwardingResolver: no upstream resolvers");
    }

    types::ResolveResult ForwardingResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                     const bool recurse) {
        if (auto cached = cache.find_answer(name, type, rclass)) return *cached;
        if (!recurse) {
            types::ResolveResult failed;
            failed.rcode = types::Rcode::Refused;
            failed.served_by = "recursion not desired";
            return failed;
        }

        const std::size_t first = preferred->load(std::memory_order_relaxed);
        for (std::size_t attempt = 0; attempt < resolvers.size(); ++attempt) {
            const std::size_t index = (first + attempt) % resolvers.size();
            auto response           = query_server(resolvers[index], name, type, rclass, recurse, timeout);
            // SERVFAIL and REFUSED are the upstream's problem, another one may do better
            if (!response || response->result.rcode == types::Rcode::ServFail || response->result.rcode == types::Rcode::Refused) continue;

            preferred->store(index, std::memory_order_relaxed);
            if (response->result.rcode == types::Rcode::NoError) cache.update(chain_records(response->result.answer, name));
            response->result.served_by = "upstream " + endpoint_label(resolvers[index]) + (resolvers[index].tls ? " over TLS" : "");
            return std::move(response->result);
        }
        types::ResolveResult failed;
        failed.rcode     = types::Rcode::ServFail;
        failed.served_by = "no upstream answered";
        return failed;
    }

} // namespace backend
