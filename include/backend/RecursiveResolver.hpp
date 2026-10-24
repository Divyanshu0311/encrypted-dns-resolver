#ifndef BACKEND_RECURSIVERESOLVER_HPP
#define BACKEND_RECURSIVERESOLVER_HPP

#include <stdexcept>
#include <vector>

#include "IP.hpp"
#include "Resolver.hpp"

namespace backend {
    class RecursiveResolver : public Resolver {
    private:
        Cache& cache;

    public:
        RecursiveResolver(Cache& cache) : cache(cache) {}

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {}
    };
} // namespace backend

#endif
