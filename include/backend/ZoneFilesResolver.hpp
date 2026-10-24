#ifndef BACKEND_ZONEFILESRESOLVER_HPP
#define BACKEND_ZONEFILESRESOLVER_HPP

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "IP.hpp"
#include "Resolver.hpp"

namespace backend {
    class ZoneFilesResolver : public Resolver {
    private:
        std::vector<types::ResourceRecord> records;
        Resolver* fallback;

    public:
        ZoneFilesResolver(const std::vector<std::string>& zone_files, Resolver* fallback) : fallback(fallback) {}

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {}
    };
} // namespace backend

#endif
