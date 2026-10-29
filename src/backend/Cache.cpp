#include <algorithm>
#include <exception>
#include <mutex>
#include <stdexcept>

#include "backend/Cache.hpp"
#include "backend/ZoneFile.hpp"

std::size_t backend::CacheKeyHash::operator()(const CacheKey& key) const noexcept {
    const std::size_t kind = static_cast<std::size_t>(key.type) << 16 | static_cast<std::size_t>(key.rclass);
    return std::hash<types::DomainName>{}(key.name) ^ (kind * 0x9e3779b97f4a7c15ULL);
}

namespace backend {

    Cache::Cache(std::size_t max_records, Clock clock) : max_records(max_records), clock(std::move(clock)) {}

    bool Cache::insert(const std::vector<types::ResourceRecord>& new_records, const bool pinned) {
        const std::time_t now = clock();

        // group into RRsets first, so each one replaces its old copy exactly once
        std::unordered_map<CacheKey, std::vector<CacheRecord>, CacheKeyHash> rrsets;
        for (const auto& record : new_records) {
            if (!pinned && record.ttl == 0) continue;
            auto& rrset = rrsets[CacheKey{ record.name, record.type, record.rclass }];
            if (std::ranges::any_of(rrset, [&](const CacheRecord& r) { return r.rdata == record.rdata; })) continue;
            rrset.push_back(CacheRecord{ record.name, record.type, record.rclass, pinned ? kPinned : now + record.ttl, record.rdata });
        }

        std::unique_lock lock(mutex);
        bool stored = false;
        for (auto& [key, rrset] : rrsets) {
            // RFC 2181 section 5.2: the records of an RRset share one TTL, so the set expires with its lowest
            const std::time_t expiry = std::ranges::min(rrset, {}, &CacheRecord::expiry).expiry;
            for (auto& record : rrset) record.expiry = expiry;

            if (auto old = records.find(key); old != records.end()) {
                if (old->second.front().expiry == kPinned && !pinned) continue; // answers never override the root hints
                size -= old->second.size();
                records.erase(old);
            }
            if (size + rrset.size() > max_records) {
                // expired RRsets first, then everything but the root hints
                for (const bool keep_live : { true, false }) {
                    std::erase_if(records, [&](const auto& entry) {
                        const std::time_t e = entry.second.front().expiry;
                        const bool drop     = keep_live ? e <= now : e != kPinned;
                        if (drop) size -= entry.second.size();
                        return drop;
                    });
                    if (size + rrset.size() <= max_records) break;
                }
                if (size + rrset.size() > max_records) continue;
            }
            size += rrset.size();
            records.emplace(key, std::move(rrset));
            stored = true;
        }
        return stored;
    }

    std::vector<types::ResourceRecord> Cache::find(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {
        const std::time_t now = clock();
        std::shared_lock lock(mutex);
        std::vector<types::ResourceRecord> found;
        const auto it = records.find(CacheKey{ name, type, rclass });
        if (it == records.end() || it->second.front().expiry <= now) return found;
        for (const auto& record : it->second) {
            const auto left = static_cast<uint32_t>(std::min<std::time_t>(record.expiry - now, 0x7FFFFFFF));
            found.push_back(types::ResourceRecord{ record.name, record.type, record.rclass, left, record.rdata });
        }
        return found;
    }

    std::optional<types::ResolveResult> Cache::find_answer(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {
        auto answer = find_chain(name, type, rclass);
        (answer ? hits : misses).fetch_add(1, std::memory_order_relaxed);
        return answer;
    }

    std::optional<types::ResolveResult> Cache::find_chain(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {
        types::ResolveResult result;
        result.served_by = "cache";
        types::DomainName current = name;
        for (int hops = 0; hops <= 8; ++hops) {
            auto found = find(current, type, rclass);
            if (!found.empty()) {
                result.answer.insert(result.answer.end(), found.begin(), found.end());
                return result;
            }
            if (type == types::RecordType::CNAME || type == types::RecordType::ANY) return std::nullopt;
            const auto cname = find(current, types::RecordType::CNAME, rclass);
            if (cname.empty()) return std::nullopt;
            result.answer.push_back(cname.front());
            try {
                current = types::DomainName(cname.front().rdata, 0);
            } catch (const std::runtime_error&) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    bool Cache::update(const std::vector<types::ResourceRecord>& records) {
        return insert(records, false);
    }

    bool Cache::update(const types::ResolveResult& result) {
        const bool answer     = update(result.answer);
        const bool authority  = update(result.authority);
        const bool additional = update(result.additional);
        return answer || authority || additional;
    }

    void Cache::clear() {
        std::unique_lock lock(mutex);
        std::erase_if(records, [](const auto& entry) { return entry.second.front().expiry != kPinned; });
        size = 0;
        for (const auto& entry : records) size += entry.second.size();
    }

    CacheStats Cache::stats() const {
        std::shared_lock lock(mutex);
        return CacheStats{ records.size(), size, hits.load(std::memory_order_relaxed), misses.load(std::memory_order_relaxed) };
    }

    bool Cache::add_root_hints(const std::string& root_hints_file) {
        std::vector<types::ResourceRecord> hints;
        try {
            hints = records_from_zone_file(types::DomainName("."), root_hints_file);
        } catch (const std::exception&) {
            return false;
        }
        return insert(hints, true);
    }

} // namespace backend
