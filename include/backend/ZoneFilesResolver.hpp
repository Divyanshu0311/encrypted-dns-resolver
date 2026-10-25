#ifndef BACKEND_ZONEFILESRESOLVER_HPP
#define BACKEND_ZONEFILESRESOLVER_HPP

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/Resolver.hpp"

namespace backend {
    struct ZoneFile {
        types::DomainName origin;
        std::string path;
    };

    struct ZoneKey {
        types::DomainName name;
        types::RecordClass rclass;
        bool operator==(const ZoneKey&) const noexcept = default;
    };
} // namespace backend

namespace std {
    template<>
    struct hash<backend::ZoneKey> {
        size_t operator()(const backend::ZoneKey& k) const noexcept;
    };
} // namespace std

namespace backend {

    class ZoneFilesResolver : public Resolver {
    private:
        std::unordered_map<ZoneKey, std::vector<types::ResourceRecord>> records;
        Resolver* fallback;

        std::optional<std::vector<types::ResourceRecord>> get_zone(const types::DomainName& name, const types::RecordClass rclass);

        static bool node_exists(const std::vector<types::ResourceRecord>& zone, const types::DomainName& node);

        static types::ResolveResult make_negative(const types::ResourceRecord& soa, const types::Rcode rcode);

        static void add_additional(const std::vector<types::ResourceRecord>& zone, const std::vector<types::ResourceRecord>& source,
                                   std::vector<types::ResourceRecord>& out);

        types::ResolveResult answer_node(const std::vector<types::ResourceRecord>& zone, const std::vector<types::ResourceRecord>& node,
                                         const types::ResourceRecord& soa, const types::DomainName& owner, const types::DomainName& name,
                                         const types::RecordType type, const types::RecordClass rclass, const bool synthesized, const bool recurse,
                                         const int depth);

        types::ResolveResult resolve_impl(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass, const bool recurse,
                                          const int depth);

    public:
        ZoneFilesResolver(const std::vector<ZoneFile>& zone_files, Resolver* fallback);

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                     const bool recurse = true) override;
    };
} // namespace backend

#endif
