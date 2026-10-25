#include "backend/ForwardingResolver.hpp"

namespace backend {

    ForwardingResolver::ForwardingResolver(std::vector<types::IP> resolvers, Cache& cache) : resolvers(resolvers), cache(cache) {}

    types::ResolveResult ForwardingResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                     const bool recurse) {}

} // namespace backend
