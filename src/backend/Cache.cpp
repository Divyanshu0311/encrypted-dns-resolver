#include "backend/Cache.hpp"
#include "backend/ZoneFile.hpp"

namespace backend {

    std::vector<types::ResourceRecord> Cache::find(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {}

    bool Cache::update(const std::vector<types::ResourceRecord>& records) {}

    bool Cache::update(const types::ResolveResult& result) {
        update(result.answer);
        update(result.authority);
        update(result.additional);
    }

    bool Cache::add_root_hints(const std::string& root_hints_file) {
        update(records_from_zone_file(types::DomainName("."), root_hints_file));
    }

} // namespace backend
