#include <algorithm>
#include <stdexcept>

#include "backend/ZoneFile.hpp"
#include "backend/ZoneFilesResolver.hpp"

std::size_t std::hash<backend::ZoneKey>::operator()(const backend::ZoneKey& k) const noexcept {
    return hash<types::DomainName>{}(k.name) ^ (static_cast<size_t>(k.rclass) * 0x9e3779b97f4a7c15ULL);
}

namespace backend {

    std::optional<std::vector<types::ResourceRecord>> ZoneFilesResolver::get_zone(const types::DomainName& name, const types::RecordClass rclass) {
        std::size_t labels_matched = 0;
        std::optional<std::vector<types::ResourceRecord>> result;
        for (const auto& group : records)
            if (group.first.name.is_ancestor_of(name) && (group.first.rclass == rclass))
                if (group.first.name.get_labels().size() > labels_matched) {
                    result         = group.second;
                    labels_matched = group.first.name.get_labels().size();
                }
        return result;
    }

    bool ZoneFilesResolver::node_exists(const std::vector<types::ResourceRecord>& zone, const types::DomainName& node) {
        return std::ranges::any_of(zone, [&](const types::ResourceRecord& record) { return record.name.is_descendent_of(node); });
    }

    types::ResolveResult ZoneFilesResolver::make_negative(const types::ResourceRecord& soa, const types::Rcode rcode) {
        types::ResolveResult res;
        res.rcode = rcode;
        res.authority.push_back(soa);
        return res;
    }

    void ZoneFilesResolver::add_additional(const std::vector<types::ResourceRecord>& zone, const std::vector<types::ResourceRecord>& source,
                                           std::vector<types::ResourceRecord>& out) {
        for (const auto& record : source) {
            std::size_t offset = 0;
            switch (record.type) {
            case types::RecordType::NS:
                offset = 0;
                break;
            case types::RecordType::MX:
                offset = 2;
                break; // skip preference
            case types::RecordType::SRV:
                offset = 6;
                break; // skip priority, weight, port
            default:
                continue;
            }
            if (record.rdata.size() <= offset) continue;
            try {
                types::DomainName target(record.rdata, offset);
                for (const types::RecordType t : { types::RecordType::A, types::RecordType::AAAA }) {
                    auto glue = types::find_records(zone, target, t);
                    out.append_range(glue);
                }
            } catch (const std::runtime_error&) {
                // Malformed rdata: skip glue.
            }
        }
    }

    types::ResolveResult ZoneFilesResolver::answer_node(const std::vector<types::ResourceRecord>& zone, const std::vector<types::ResourceRecord>& node,
                                                        const types::ResourceRecord& soa, const types::DomainName& owner, const types::DomainName& name,
                                                        const types::RecordType type, const types::RecordClass rclass, const bool synthesized,
                                                        const bool recurse, const int depth) {
        auto relabel = [&](types::ResourceRecord record) {
            if (synthesized) record.name = name;
            return record;
        };

        // CNAME handling: applies to every query type except CNAME and ANY.
        if (type != types::RecordType::CNAME && type != types::RecordType::ANY) {
            for (const auto& record : node) {
                if (record.type != types::RecordType::CNAME) continue;

                types::ResolveResult res;
                res.answer.push_back(relabel(record));

                // CNAME loop / overly long chain
                if (depth >= 8) {
                    res.rcode = types::Rcode::ServFail;
                    return res;
                }

                try {
                    types::DomainName target(record.rdata, 0);
                    types::ResolveResult sub;

                    if (get_zone(target, rclass).has_value())
                        sub = resolve_impl(target, type, rclass, recurse, depth + 1);
                    else if (fallback)
                        sub = fallback->resolve(target, type, rclass, recurse);

                    if (sub.rcode == types::Rcode::Refused) return res;

                    res.rcode = sub.rcode;
                    // insert() rather than append_range(): append_range needs GCC 15
                    res.answer.insert(res.answer.end(), sub.answer.begin(), sub.answer.end());
                    res.authority  = sub.authority;
                    res.additional = sub.additional;
                } catch (const std::runtime_error&) {
                    res.rcode = types::Rcode::ServFail;
                }
                return res;
            }
        }

        types::ResolveResult res;
        for (const types::ResourceRecord& r : types::find_records(node, owner, type)) res.answer.push_back(relabel(r));


        if (res.answer.empty()) return make_negative(soa, types::Rcode::NoError); // NODATA
        add_additional(zone, res.answer, res.additional);
        return res;
    }

    types::ResolveResult ZoneFilesResolver::resolve_impl(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                         const bool recurse, const int depth) {
        auto zone_opt = get_zone(name, rclass);
        if (!zone_opt.has_value()) {
            if (fallback) return fallback->resolve(name, type, rclass, recurse);
            types::ResolveResult result;
            result.rcode = types::Rcode::Refused;
            return result;
        }
        const std::vector<types::ResourceRecord>& zone = *zone_opt;

        // The constructor guarantees exactly one SOA, which also gives us the apex.
        const types::ResourceRecord* soa = nullptr;
        for (const auto& record : zone)
            if (record.type == types::RecordType::SOA) {
                soa = &record;
                break;
            }
        if (!soa) {
             types::ResolveResult result;
            result.rcode = types::Rcode::ServFail;
            return result;
        }
        const types::DomainName apex = soa->name;

        // Delegation: look for a zone cut between the apex (exclusive) and the name (inclusive)
        std::vector<types::DomainName> chain;
        for (types::DomainName cur = name; cur != apex; cur = cur.parent()) {
            chain.push_back(cur);
            if (cur.get_labels().empty()) break; // Safety
        }
        for (auto it = chain.rbegin(); it != chain.rend(); it++) {
            auto ns = types::find_records(zone, *it, types::RecordType::NS);
            if (ns.empty()) continue;
            if (*it == name && type == types::RecordType::DS) continue; // DS lives on the parent side of the cut

            types::ResolveResult res;
            res.authority = ns;
            add_additional(zone, ns, res.additional);
            return res; // Referral
        }

        // Exact match
        const std::vector<types::ResourceRecord> node = types::find_records(zone, name);
        if (!node.empty()) return answer_node(zone, node, *soa, name, name, type, rclass, false, recurse, depth);

        // Empty non-terminal: descendants exist but nothing at the name itself
        if (node_exists(zone, name)) return make_negative(*soa, types::Rcode::NoError);

        // Wildcard at the closest encloser
        types::DomainName encloser = name.parent();
        while (encloser != apex && !node_exists(zone, encloser)) {
            if (encloser.get_labels().empty()) break;
            encloser = encloser.parent();
        }
        const types::DomainName wildcard                       = types::DomainName("*") + encloser;
        const std::vector<types::ResourceRecord> wildcard_node = types::find_records(zone, wildcard);
        if (!wildcard_node.empty()) return answer_node(zone, wildcard_node, *soa, wildcard, name, type, rclass, true, recurse, depth);

        // The name does not exist
        return make_negative(*soa, types::Rcode::NXDomain);
    }

    ZoneFilesResolver::ZoneFilesResolver(const std::vector<ZoneFile>& zone_files, Resolver* fallback) : fallback(fallback) {
        for (const auto& zone_file : zone_files) {
            auto file_records = backend::records_from_zone_file(zone_file.origin, zone_file.path);

            std::vector<types::ResourceRecord> soa_records;
            for (const auto& record : file_records)
                if (record.type == types::RecordType::SOA) soa_records.push_back(record);

            if (soa_records.empty()) throw std::runtime_error("ZoneFilesResolver: " + zone_file.path + ": No SOA records");
            if (soa_records.size() != 1) throw std::runtime_error("ZoneFilesResolver: " + zone_file.path + ": Too many SOA records");

            auto apex   = soa_records[0].name;
            auto rclass = soa_records[0].rclass;
            for (const auto& record : file_records)
                if (record.rclass != rclass) throw std::runtime_error("ZoneFilesResolver: Multiple record classes");

            ZoneKey key{ apex, rclass };
            if (records.find(key) != records.end())
                throw std::runtime_error("ZoneFilesResolver: " + static_cast<std::string>(apex) + " defined multiple times in same class");
            records[key] = file_records;
        }
    }

    types::ResolveResult ZoneFilesResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                    const bool recurse) {
        return resolve_impl(name, type, rclass, recurse, 0);
    }
} // namespace backend
