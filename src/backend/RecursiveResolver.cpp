#include "backend/RecursiveResolver.hpp"
#include "IP.hpp"

namespace backend {
    RecursiveResolver::RecursiveResolver(Cache& cache) : cache(cache) {}

    types::ResolveResult RecursiveResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                    const bool recurse) {}
} // namespace backend
