#ifndef TYPES_RECORDS_HPP
#define TYPES_RECORDS_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "DomainName.hpp"

#undef IN

namespace types {
    enum class RecordType : uint16_t {
        A          = 1,     // IPv4 address
        NS         = 2,     // Authoritative name server
        MD         = 3,     // Mail destination (obsolete)
        MF         = 4,     // Mail forwarder (obsolete)
        CNAME      = 5,     // Canonical name
        SOA        = 6,     // Start of authority
        MB         = 7,     // Mailbox (experimental)
        MG         = 8,     // Mail group member (experimental)
        MR         = 9,     // Mail rename (experimental)
        NULL_RR    = 10,    // Null RR (named NULL_RR to avoid the NULL macro)
        WKS        = 11,    // Well-known services
        PTR        = 12,    // Pointer
        HINFO      = 13,    // Host information
        MINFO      = 14,    // Mailbox/mail list information
        MX         = 15,    // Mail exchange
        TXT        = 16,    // Text strings
        RP         = 17,    // Responsible person
        AFSDB      = 18,    // AFS database
        X25        = 19,    // X.25 PSDN address
        ISDN       = 20,    // ISDN address
        RT         = 21,    // Route through
        NSAP       = 22,    // NSAP address
        NSAP_PTR   = 23,    // NSAP pointer
        SIG        = 24,    // Security signature
        KEY        = 25,    // Security key
        PX         = 26,    // X.400 mail mapping
        GPOS       = 27,    // Geographical position
        AAAA       = 28,    // IPv6 address
        LOC        = 29,    // Location information
        NXT        = 30,    // Next domain (obsolete)
        EID        = 31,    // Endpoint identifier
        NIMLOC     = 32,    // Nimrod locator
        SRV        = 33,    // Service locator
        ATMA       = 34,    // ATM address
        NAPTR      = 35,    // Naming authority pointer
        KX         = 36,    // Key exchanger
        CERT       = 37,    // Certificate
        A6         = 38,    // IPv6 address (historic)
        DNAME      = 39,    // Delegation name
        SINK       = 40,    // Kitchen sink
        APL        = 42,    // Address prefix list
        DS         = 43,    // Delegation signer
        SSHFP      = 44,    // SSH key fingerprint
        IPSECKEY   = 45,    // IPsec key
        RRSIG      = 46,    // DNSSEC signature
        NSEC       = 47,    // Next secure record
        DNSKEY     = 48,    // DNS key
        DHCID      = 49,    // DHCP identifier
        NSEC3      = 50,    // NSEC version 3
        NSEC3PARAM = 51,    // NSEC3 parameters
        TLSA       = 52,    // TLSA certificate association
        SMIMEA     = 53,    // S/MIME cert association
        HIP        = 55,    // Host identity protocol
        NINFO      = 56,    // NINFO
        RKEY       = 57,    // RKEY
        TALINK     = 58,    // Trust anchor link
        CDS        = 59,    // Child DS
        CDNSKEY    = 60,    // Child DNSKEY
        OPENPGPKEY = 61,    // OpenPGP public key
        CSYNC      = 62,    // Child-to-parent synchronization
        ZONEMD     = 63,    // Zone message digest
        SVCB       = 64,    // Service binding
        HTTPS      = 65,    // HTTPS service binding
        DSYNC      = 66,    // Delegation synchronization
        HHIT       = 67,    // Hierarchical HIT
        BRID       = 68,    // Broadcast remote ID
        SPF        = 99,    // Sender policy framework (obsolete)
        UINFO      = 100,   // IANA-reserved
        UID        = 101,   // IANA-reserved
        GID        = 102,   // IANA-reserved
        UNSPEC     = 103,   // IANA-reserved
        NID        = 104,   // Node identifier
        L32        = 105,   // 32-bit locator
        L64        = 106,   // 64-bit locator
        LP         = 107,   // Locator pointer
        EUI48      = 108,   // 48-bit MAC address
        EUI64      = 109,   // 64-bit MAC address
        NXNAME     = 128,   // NXDOMAIN indicator for compact denial of existence
        TKEY       = 249,   // Transaction key
        TSIG       = 250,   // Transaction signature
        MAILB      = 253,   // Mailbox-related records (QTYPE)
        MAILA      = 254,   // Mail agent RRs (obsolete QTYPE)
        ANY        = 255,   // Wildcard
        URI        = 256,   // Uniform resource identifier
        CAA        = 257,   // Certification authority authorization
        AVC        = 258,   // Application visibility and control
        DOA        = 259,   // Digital object architecture
        AMTRELAY   = 260,   // Automatic multicast tunneling relay
        RESINFO    = 261,   // Resolver information as key/value pairs
        WALLET     = 262,   // Public wallet address
        CLA        = 263,   // BP convergence layer adapter
        IPN        = 264,   // BP node number
        TA         = 32768, // DNSSEC trust authorities
        DLV        = 32769  // DNSSEC lookaside validation (obsolete)
    };

    std::optional<RecordType> record_type_from_string(const std::string& name);

    enum class Rcode : uint8_t {
        NoError   = 0,  // No error
        FormErr   = 1,  // Format error
        ServFail  = 2,  // Server failure
        NXDomain  = 3,  // Non-existent domain
        NotImp    = 4,  // Not implemented
        Refused   = 5,  // Query refused
        YXDomain  = 6,  // Name exists when it should not (RFC 2136)
        YXRRSet   = 7,  // RR set exists when it should not (RFC 2136)
        NXRRSet   = 8,  // RR set that should exist does not (RFC 2136)
        NotAuth   = 9,  // Server not authoritative / not authorized (RFC 2136, 8945)
        NotZone   = 10, // Name not in zone (RFC 2136)
        DSOTypeNI = 11, // DSO-TYPE not implemented (RFC 8490)
    };

    enum class RecordClass : uint16_t {
        IN = 1, // Internet
        CS = 2, // CSNET (Obsolete)
        CH = 3, // CHAOS
        HS = 4, // Hesiod
    };

    std::optional<RecordClass> record_class_from_string(const std::string& name);

    struct ResourceRecord {
        DomainName name;
        RecordType type;
        RecordClass rclass = RecordClass::IN;
        uint32_t ttl       = 0;
        std::vector<uint8_t> rdata;
    };

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name);

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name, const RecordClass rclass);

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name, const RecordType type);

    std::vector<ResourceRecord> find_records(const std::vector<ResourceRecord>& records, const DomainName& name, const RecordType type,
                                             const RecordClass rclass);

    struct ResolveResult {
        Rcode rcode = Rcode::NoError;
        std::vector<ResourceRecord> answer;
        std::vector<ResourceRecord> authority;
        std::vector<ResourceRecord> additional;
    };
} // namespace types

#endif
