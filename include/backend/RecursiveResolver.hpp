#ifndef BACKEND_RECURSIVERESOLVER_HPP
#define BACKEND_RECURSIVERESOLVER_HPP

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/Cache.hpp"
#include "backend/Resolver.hpp"

namespace backend {
    class RecursiveResolver : public Resolver {
    private:
        Cache& cache;

    public:
        RecursiveResolver(Cache& cache);

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                     const bool recurse = true) override;
    };
} // namespace backend

#endif
