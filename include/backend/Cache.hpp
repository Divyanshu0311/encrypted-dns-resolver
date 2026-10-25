#ifndef BACKEND_CACHE_HPP
#define BACKEND_CACHE_HPP

#include <cstdint>
#include <ctime>
#include <shared_mutex>
#include <string>
#include <vector>

#include "Records.hpp"
#include "utils.hpp"

namespace backend {
    struct CacheRecord {
        types::DomainName name;
        types::RecordType type;
        types::RecordClass rclass = types::RecordClass::IN;
        std::time_t expiry;
        std::vector<uint8_t> rdata;
    };

    class Cache : utils::immovable {
    private:
        std::vector<CacheRecord> records;
        mutable std::shared_mutex mutex;

    public:
        Cache() = default;

        std::vector<types::ResourceRecord> find(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass);

        bool update(const std::vector<types::ResourceRecord>& records);

        bool update(const types::ResolveResult& result);

        bool add_root_hints(const std::string& root_hints_file);
    };
} // namespace backend

#endif
