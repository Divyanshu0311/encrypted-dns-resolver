#ifndef BACKEND_CACHE_HPP
#define BACKEND_CACHE_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <limits>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
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

    struct CacheKey {
        types::DomainName name;
        types::RecordType type;
        types::RecordClass rclass;
        bool operator==(const CacheKey&) const noexcept = default;
    };

    struct CacheStats {
        std::size_t rrsets  = 0;
        std::size_t records = 0;
        uint64_t hits       = 0; // find_answer calls that were answered
        uint64_t misses     = 0;
    };

    struct CacheKeyHash {
        std::size_t operator()(const CacheKey& key) const noexcept;
    };

    // Thread safe: one cache is shared by every worker's resolver chain. Records are kept per RRset (name, type,
    // class), and an update replaces the whole RRset, so a stale record never mixes with fresh ones.
    class Cache : utils::immovable {
    public:
        using Clock = std::function<std::time_t()>;

    private:
        std::unordered_map<CacheKey, std::vector<CacheRecord>, CacheKeyHash> records;
        std::size_t size = 0; // records over every RRset
        const std::size_t max_records;
        const Clock clock;
        mutable std::shared_mutex mutex;
        std::atomic<uint64_t> hits{ 0 };
        std::atomic<uint64_t> misses{ 0 };

        bool insert(const std::vector<types::ResourceRecord>& records, const bool pinned);

        std::optional<types::ResolveResult> find_chain(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass);

    public:
        static constexpr std::time_t kPinned = std::numeric_limits<std::time_t>::max(); // root hints never expire

        explicit Cache(std::size_t max_records = 100000, Clock clock = [] { return std::time(nullptr); });

        // unexpired records of that RRset, their TTL lowered to the time left
        std::vector<types::ResourceRecord> find(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass);

        // the cached answer to a question: follows CNAMEs (at most 8) and is nullopt unless the chain ends at records of type
        std::optional<types::ResolveResult> find_answer(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass);

        // records with a TTL of 0 are skipped. true if anything was stored
        bool update(const std::vector<types::ResourceRecord>& records);

        bool update(const types::ResolveResult& result);

        // the zone file that lists the root servers (named.root). its records never expire
        bool add_root_hints(const std::string& root_hints_file);

        // drops everything but the root hints
        void clear();

        CacheStats stats() const;
    };
} // namespace backend

#endif
