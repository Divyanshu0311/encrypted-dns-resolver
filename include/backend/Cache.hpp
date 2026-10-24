#ifndef BACKEND_CACHE_HPP
#define BACKEND_CACHE_HPP

#include <ctime>
#include <shared_mutex>
#include <vector>

#include "Records.hpp"

namespace Backend {
    struct CacheRecord {
        types::DomainName name;
        types::RecordType type;
        types::RecordClass rclass = types::RecordClass::IN;
        std::time_t expiry;
        std::vector<uint8_t> rdata;
    };

    class Cache {
    private:
        std::vector<CacheRecord> records;
        mutable std::shared_mutex mutex;

    public:
        Cache() = default;

        bool add_root_hints(const std::string& root_hints_file) {}

        bool add_root_hints(const char* root_hints_file) { return add_root_hints(std::string(root_hints_file)); }

        std::vector<types::ResourceRecord> find(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {}

        bool update(const std::vector<types::ResourceRecord>& records) {}

        bool update(const types::ResolveResult& result) {
            update(result.answer);
            update(result.authority);
            update(result.additional);
        }
    };
} // namespace Backend

#endif
