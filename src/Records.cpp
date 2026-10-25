#include <ranges>
#include <unordered_map>

#include "Records.hpp"
#include "utils.hpp"

namespace types {
    std::optional<RecordType> record_type_from_string(const std::string& name) {
#define DNS_E(name)                                                                                                                                            \
    {                                                                                                                                                          \
        #name, RecordType::name                                                                                                                                \
    }
        static std::unordered_map<std::string, RecordType> table = {
            DNS_E(A),          DNS_E(NS),         DNS_E(MD),     DNS_E(MF),       DNS_E(CNAME),
            DNS_E(SOA),        DNS_E(MB),         DNS_E(MG),     DNS_E(MR),       { "NULL", RecordType::NULL_RR },
            DNS_E(NULL_RR),    DNS_E(WKS),        DNS_E(PTR),    DNS_E(HINFO),    DNS_E(MINFO),
            DNS_E(MX),         DNS_E(TXT),        DNS_E(RP),     DNS_E(AFSDB),    DNS_E(X25),
            DNS_E(ISDN),       DNS_E(RT),         DNS_E(NSAP),   DNS_E(NSAP_PTR), { "NSAP-PTR", RecordType::NSAP_PTR },
            DNS_E(SIG),        DNS_E(KEY),        DNS_E(PX),     DNS_E(GPOS),     DNS_E(AAAA),
            DNS_E(LOC),        DNS_E(NXT),        DNS_E(EID),    DNS_E(NIMLOC),   DNS_E(SRV),
            DNS_E(ATMA),       DNS_E(NAPTR),      DNS_E(KX),     DNS_E(CERT),     DNS_E(A6),
            DNS_E(DNAME),      DNS_E(SINK),       DNS_E(APL),    DNS_E(DS),       DNS_E(SSHFP),
            DNS_E(IPSECKEY),   DNS_E(RRSIG),      DNS_E(NSEC),   DNS_E(DNSKEY),   DNS_E(DHCID),
            DNS_E(NSEC3),      DNS_E(NSEC3PARAM), DNS_E(TLSA),   DNS_E(SMIMEA),   DNS_E(HIP),
            DNS_E(NINFO),      DNS_E(RKEY),       DNS_E(TALINK), DNS_E(CDS),      DNS_E(CDNSKEY),
            DNS_E(OPENPGPKEY), DNS_E(CSYNC),      DNS_E(ZONEMD), DNS_E(SVCB),     DNS_E(HTTPS),
            DNS_E(DSYNC),      DNS_E(HHIT),       DNS_E(BRID),   DNS_E(SPF),      DNS_E(UINFO),
            DNS_E(UID),        DNS_E(GID),        DNS_E(UNSPEC), DNS_E(NID),      DNS_E(L32),
            DNS_E(L64),        DNS_E(LP),         DNS_E(EUI48),  DNS_E(EUI64),    DNS_E(NXNAME),
            DNS_E(TKEY),       DNS_E(TSIG),       DNS_E(MAILB),  DNS_E(MAILA),    DNS_E(ANY),
            DNS_E(URI),        DNS_E(CAA),        DNS_E(AVC),    DNS_E(DOA),      DNS_E(AMTRELAY),
            DNS_E(RESINFO),    DNS_E(WALLET),     DNS_E(CLA),    DNS_E(IPN),      DNS_E(TA),
            DNS_E(DLV),
        };
#undef DNS_E
        std::optional<RecordType> value;
        auto it = table.find(utils::upper(name));
        if (it != table.end()) value = it->second;
        return value;
    }

    std::optional<RecordClass> record_class_from_string(const std::string& name) {
        std::string uname = utils::upper(name);
        if (uname == "IN") return RecordClass::IN;
        if (uname == "CS") return RecordClass::CS;
        if (uname == "CH") return RecordClass::CH;
        if (uname == "HS") return RecordClass::HS;
        return std::nullopt;
    }

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name) {
        return records | std::views::filter([&](const types::ResourceRecord& record) { return (record.name == name); }) | std::ranges::to<std::vector>();
    }

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name, const RecordClass rclass) {
        return records | std::views::filter([&](const types::ResourceRecord& record) { return (record.name == name) && (record.rclass == rclass); }) |
               std::ranges::to<std::vector>();
    }

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name, const RecordType type) {
        if (type == RecordType::ANY)
            return records | std::views::filter([&](const types::ResourceRecord& record) {
                       return (record.name == name) && ((record.type == RecordType::A) || (record.type == RecordType::AAAA) ||
                                                        (record.type == RecordType::MX) || (record.type == RecordType::CNAME));
                   }) |
                   std::ranges::to<std::vector>();

        return records | std::views::filter([&](const types::ResourceRecord& record) { return (record.name == name) && (record.type == type); }) |
               std::ranges::to<std::vector>();
    }

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name, const RecordType type,
                                             const RecordClass rclass) {
        if (type == RecordType::ANY)
            return records | std::views::filter([&](const types::ResourceRecord& record) {
                       return (record.name == name) &&
                              ((record.type == RecordType::A) || (record.type == RecordType::AAAA) || (record.type == RecordType::MX) ||
                               (record.type == RecordType::CNAME)) &&
                              (record.rclass == rclass);
                   }) |
                   std::ranges::to<std::vector>();

        return records | std::views::filter([&](const types::ResourceRecord& record) {
                   return (record.name == name) && (record.type == type) && (record.rclass == rclass);
               }) |
               std::ranges::to<std::vector>();
    }
} // namespace types
