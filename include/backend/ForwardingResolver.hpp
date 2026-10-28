#ifndef BACKEND_FORWARDINGRESOLVER_HPP
#define BACKEND_FORWARDINGRESOLVER_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <vector>

#include "backend/Cache.hpp"
#include "backend/Resolver.hpp"
#include "backend/Upstream.hpp"

namespace backend {
    // Sends each question to upstream resolvers (1.1.1.1 and the like) and caches the answers. Not thread safe:
    // every worker owns one, the cache is what they share.
    class ForwardingResolver : public Resolver {
    private:
        std::vector<Endpoint> resolvers;
        Cache& cache;
        std::chrono::milliseconds timeout;
        // the upstream that answered last, asked first. shared between resolvers given the same one, so a dead
        // upstream costs one timeout in total rather than one per worker
        std::shared_ptr<std::atomic<std::size_t>> preferred;

    public:
        // timeout is per upstream: a question that every upstream ignores takes resolvers.size() * timeout
        ForwardingResolver(std::vector<Endpoint> resolvers, Cache& cache, std::chrono::milliseconds timeout = std::chrono::milliseconds(1000),
                           std::shared_ptr<std::atomic<std::size_t>> preferred = std::make_shared<std::atomic<std::size_t>>(0));

        // ServFail when no upstream gives a usable answer
        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                     const bool recurse = true) override;
    };
} // namespace backend

#endif
