#ifndef BACKEND_RESOLVER_HPP
#define BACKEND_RESOLVER_HPP

#include "Records.hpp"
#include "utils.hpp"

namespace backend {
    class Resolver : utils::immovable {
    public:
        virtual types::ResolveResult resolve(types::DomainName name, types::RecordType type) = 0;
    };

} // namespace backend

#endif
