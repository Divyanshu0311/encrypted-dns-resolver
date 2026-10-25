#include <gtest/gtest.h>

#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"

using types::RecordClass;
using types::RecordType;

namespace {
    types::ResourceRecord make_rr(const char* name, RecordType type, RecordClass rclass = RecordClass::IN) {
        types::ResourceRecord rr;
        rr.name   = types::DomainName(name);
        rr.type   = type;
        rr.rclass = rclass;
        return rr;
    }

    std::vector<types::ResourceRecord> sample() {
        return {
            make_rr("example.com.", RecordType::A),
            make_rr("example.com.", RecordType::AAAA),
            make_rr("example.com.", RecordType::MX),
            make_rr("example.com.", RecordType::TXT),
            make_rr("example.com.", RecordType::A, RecordClass::CH),
            make_rr("www.example.com.", RecordType::CNAME),
            make_rr("other.org.", RecordType::A),
        };
    }
} // namespace

// ---- String lookups -----------------------------------------------------------

TEST(Records, RecordTypeFromString) {
    auto a = types::record_type_from_string("A");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(*a, RecordType::A);

    auto mx = types::record_type_from_string("MX");
    ASSERT_TRUE(mx.has_value());
    EXPECT_EQ(*mx, RecordType::MX);
}

TEST(Records, RecordTypeFromStringIsCaseInsensitive) {
    auto r = types::record_type_from_string("aaaa");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, RecordType::AAAA);
}

TEST(Records, RecordTypeSpecialSpellings) {
    auto null_rr = types::record_type_from_string("null");
    ASSERT_TRUE(null_rr.has_value());
    EXPECT_EQ(*null_rr, RecordType::NULL_RR);

    auto nsap_ptr = types::record_type_from_string("nsap-ptr");
    ASSERT_TRUE(nsap_ptr.has_value());
    EXPECT_EQ(*nsap_ptr, RecordType::NSAP_PTR);
}

TEST(Records, RecordTypeFromUnknownString) {
    EXPECT_FALSE(types::record_type_from_string("BOGUS").has_value());
    EXPECT_FALSE(types::record_type_from_string("").has_value());
}

TEST(Records, RecordClassFromString) {
    auto in = types::record_class_from_string("in");
    ASSERT_TRUE(in.has_value());
    EXPECT_EQ(*in, RecordClass::IN);

    auto ch = types::record_class_from_string("CH");
    ASSERT_TRUE(ch.has_value());
    EXPECT_EQ(*ch, RecordClass::CH);

    EXPECT_FALSE(types::record_class_from_string("XX").has_value());
}

TEST(Records, EnumValuesMatchWireCodes) {
    EXPECT_EQ(static_cast<int>(RecordType::A), 1);
    EXPECT_EQ(static_cast<int>(RecordType::AAAA), 28);
    EXPECT_EQ(static_cast<int>(RecordType::ANY), 255);
    EXPECT_EQ(static_cast<int>(RecordClass::IN), 1);
    EXPECT_EQ(static_cast<int>(types::Rcode::NXDomain), 3);
}

TEST(Records, ResourceRecordDefaults) {
    types::ResourceRecord rr;
    EXPECT_EQ(rr.rclass, RecordClass::IN);
    EXPECT_EQ(rr.ttl, 0u);
    EXPECT_TRUE(rr.rdata.empty());
}

TEST(Records, ResolveResultDefaults) {
    types::ResolveResult res;
    EXPECT_EQ(res.rcode, types::Rcode::NoError);
    EXPECT_TRUE(res.answer.empty());
    EXPECT_TRUE(res.authority.empty());
    EXPECT_TRUE(res.additional.empty());
}

// ---- find_records ----------------------------------------------------------------

TEST(FindRecords, ByNameOnly) {
    auto found = types::find_records(sample(), types::DomainName("example.com."));
    EXPECT_EQ(found.size(), 5u);
}

TEST(FindRecords, ByNameIsCaseInsensitive) {
    auto found = types::find_records(sample(), types::DomainName("EXAMPLE.com."));
    EXPECT_EQ(found.size(), 5u);
}

TEST(FindRecords, NoMatch) {
    EXPECT_TRUE(types::find_records(sample(), types::DomainName("missing.example.")).empty());
}

TEST(FindRecords, ByNameAndClass) {
    auto in = types::find_records(sample(), types::DomainName("example.com."), RecordClass::IN);
    EXPECT_EQ(in.size(), 4u);

    auto ch = types::find_records(sample(), types::DomainName("example.com."), RecordClass::CH);
    EXPECT_EQ(ch.size(), 1u);
}

TEST(FindRecords, ByNameAndType) {
    auto found = types::find_records(sample(), types::DomainName("example.com."), RecordType::A);
    // Class is not filtered here, so both the IN and the CH record match.
    EXPECT_EQ(found.size(), 2u);
}

TEST(FindRecords, AnyReturnsOnlyAddressMailAndAlias) {
    auto found = types::find_records(sample(), types::DomainName("example.com."), RecordType::ANY);
    // A (IN), A (CH), AAAA, MX. TXT is excluded.
    EXPECT_EQ(found.size(), 4u);
    for (const auto& rr : found) EXPECT_NE(rr.type, RecordType::TXT);
}

TEST(FindRecords, AnyIncludesCname) {
    auto found = types::find_records(sample(), types::DomainName("www.example.com."), RecordType::ANY);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].type, RecordType::CNAME);
}

TEST(FindRecords, ByNameTypeAndClass) {
    auto found = types::find_records(sample(), types::DomainName("example.com."), RecordType::A, RecordClass::CH);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].rclass, RecordClass::CH);
}

TEST(FindRecords, AnyWithClassFilter) {
    auto found = types::find_records(sample(), types::DomainName("example.com."), RecordType::ANY, RecordClass::IN);
    // A, AAAA, MX in class IN
    EXPECT_EQ(found.size(), 3u);
}
