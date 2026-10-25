#ifndef BACKEND_FORWARDINGRESOLVER_HPP
#define BACKEND_FORWARDINGRESOLVER_HPP

#include <vector>

#include "IP.hpp"
#include "backend/Cache.hpp"
#include "backend/Resolver.hpp"

namespace backend {
    class ForwardingResolver : public Resolver {
    private:
        std::vector<types::IP> resolvers;
        Cache& cache;

    public:
        ForwardingResolver(std::vector<types::IP> resolvers, Cache& cache);

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                     const bool recurse = true) override;
    };
} // namespace backend

#endif
