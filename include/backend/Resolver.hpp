#ifndef BACKEND_RESOLVER_HPP
#define BACKEND_RESOLVER_HPP

#include "Records.hpp"
#include "utils.hpp"

namespace backend {
    class Resolver : utils::immovable {
    public:
        virtual types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) = 0;
    };

} // namespace backend

#endif
