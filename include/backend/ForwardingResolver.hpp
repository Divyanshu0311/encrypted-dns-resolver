#ifndef BACKEND_FORWARDINGRESOLVER_HPP
#define BACKEND_FORWARDINGRESOLVER_HPP

#include <stdexcept>
#include <vector>

#include "Cache.hpp"
#include "IP.hpp"
#include "Resolver.hpp"

namespace backend {
    class ForwardingResolver : public Resolver {
    private:
        std::vector<types::IP> resolvers;
        Cache& cache;

    public:
        ForwardingResolver(std::vector<types::IP> resolvers, Cache& cache) : resolvers(resolvers), cache(cache) {}

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {}
    };
} // namespace backend

#endif
