#ifndef BACKEND_HOSTSFILERESOLVER_HPP
#define BACKEND_HOSTSFILERESOLVER_HPP

#include <string>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/Resolver.hpp"

namespace backend {
    class HostsFileResolver : public Resolver {
    private:
        std::vector<types::ResourceRecord> records;
        Resolver* fallback;

    public:
        HostsFileResolver(const std::string& hosts_file, Resolver* fallback);

        HostsFileResolver(const char* hosts_file, Resolver* fallback);

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                     const bool recurse = true) override;
    };
} // namespace backend

#endif
