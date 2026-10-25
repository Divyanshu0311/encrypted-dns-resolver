#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/ZoneFilesResolver.hpp"
#include "support/temp_dir.hpp"

using types::Rcode;
using types::RecordClass;
using types::RecordType;

namespace {
    using Bytes = std::vector<uint8_t>;

    Bytes wire(const char* name) {
        types::DomainName d(name);
        return d;
    }

    class MockResolver : public backend::Resolver {
    public:
        int calls = 0;
        types::DomainName last_name;
        RecordType last_type = RecordType::A;
        types::ResolveResult result;

        types::ResolveResult resolve(const types::DomainName& name, const RecordType type, const RecordClass, const bool = true) override {
            ++calls;
            last_name = name;
            last_type = type;
            return result;
        }
    };

    const char* const kZone = R"z($TTL 300
@       IN SOA  ns1 admin 1 7200 3600 1209600 300
@       IN NS   ns1
@       IN NS   ns2.other.net.
@       IN A    192.0.2.1
@       IN MX   10 mail
ns1     IN A    192.0.2.53
mail    IN A    192.0.2.25
mail    IN AAAA 2001:db8::25
www     IN CNAME @
alias   IN CNAME www
ext     IN CNAME target.elsewhere.org.
loop1   IN CNAME loop2
loop2   IN CNAME loop1
*.wild  IN A    192.0.2.99
a.b.c   IN A    192.0.2.100
sub     IN NS   ns.sub
ns.sub  IN A    192.0.2.77
)z";

    const char* const kMinimalZone = R"z($TTL 60
@   IN SOA ns admin 1 1 1 1 60
@   IN NS  ns
)z";

    class ZoneFilesResolverTest : public ::testing::Test {
    protected:
        support::TempDir dir;
        MockResolver fallback;
        std::unique_ptr<backend::ZoneFilesResolver> resolver;

        void SetUp() override { resolver = load("example.com.", kZone); }

        std::unique_ptr<backend::ZoneFilesResolver> load(const char* origin, const std::string& text, backend::Resolver* fb = nullptr,
                                                         const std::string& file = "zone.db") {
            std::vector<backend::ZoneFile> files{ { types::DomainName(origin), dir.write(file, text) } };
            return std::make_unique<backend::ZoneFilesResolver>(files, fb);
        }

        types::ResolveResult query(const char* name, RecordType type, RecordClass rclass = RecordClass::IN) {
            return resolver->resolve(types::DomainName(name), type, rclass);
        }

        static void expect_negative(const types::ResolveResult& r, Rcode rcode) {
            EXPECT_EQ(r.rcode, rcode);
            EXPECT_TRUE(r.answer.empty());
            ASSERT_EQ(r.authority.size(), 1u);
            EXPECT_EQ(r.authority[0].type, RecordType::SOA);
        }
    };
} // namespace

// ---- Positive answers --------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, AnswersFromApex) {
    auto r = query("example.com.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, Bytes({ 192, 0, 2, 1 }));
    EXPECT_TRUE(r.authority.empty());
}

TEST_F(ZoneFilesResolverTest, AnswersFromSubdomain) {
    auto r = query("ns1.example.com.", RecordType::A);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].rdata, Bytes({ 192, 0, 2, 53 }));
}

TEST_F(ZoneFilesResolverTest, LookupIsCaseInsensitive) {
    auto r = query("NS1.Example.COM.", RecordType::A);
    EXPECT_EQ(r.answer.size(), 1u);
}

TEST_F(ZoneFilesResolverTest, ApexNsIsAnsweredAuthoritativelyWithGlue) {
    auto r = query("example.com.", RecordType::NS);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    EXPECT_EQ(r.answer.size(), 2u);
    EXPECT_TRUE(r.authority.empty());
    // Only ns1 is in the zone; ns2.other.net. has no glue.
    ASSERT_EQ(r.additional.size(), 1u);
    EXPECT_EQ(r.additional[0].rdata, Bytes({ 192, 0, 2, 53 }));
}

TEST_F(ZoneFilesResolverTest, MxAnswerIncludesAddressesInAdditional) {
    auto r = query("example.com.", RecordType::MX);
    ASSERT_EQ(r.answer.size(), 1u);
    ASSERT_EQ(r.additional.size(), 2u);
    EXPECT_EQ(r.additional[0].type, RecordType::A);
    EXPECT_EQ(r.additional[1].type, RecordType::AAAA);
}

// ---- CNAME ---------------------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, CnameQueryReturnsOnlyTheCname) {
    auto r = query("www.example.com.", RecordType::CNAME);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[0].rdata, wire("example.com."));
}

TEST_F(ZoneFilesResolverTest, CnameIsFollowedInsideTheZone) {
    auto r = query("www.example.com.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 2u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[1].type, RecordType::A);
    EXPECT_EQ(r.answer[1].rdata, Bytes({ 192, 0, 2, 1 }));
}

TEST_F(ZoneFilesResolverTest, CnameChain) {
    auto r = query("alias.example.com.", RecordType::A);
    ASSERT_EQ(r.answer.size(), 3u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[1].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[2].type, RecordType::A);
}

TEST_F(ZoneFilesResolverTest, CnameLoopIsServFail) {
    EXPECT_EQ(query("loop1.example.com.", RecordType::A).rcode, Rcode::ServFail);
}

TEST_F(ZoneFilesResolverTest, CnameToExternalNameWithoutFallbackReturnsOnlyTheCname) {
    auto r = query("ext.example.com.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
}

TEST_F(ZoneFilesResolverTest, CnameToExternalNameAsksFallback) {
    types::ResourceRecord a;
    a.name  = types::DomainName("target.elsewhere.org.");
    a.type  = RecordType::A;
    a.rdata = { 203, 0, 113, 5 };
    fallback.result.answer.push_back(a);
    resolver = load("example.com.", kZone, &fallback);

    auto r = query("ext.example.com.", RecordType::A);
    EXPECT_EQ(fallback.calls, 1);
    EXPECT_TRUE(fallback.last_name == types::DomainName("target.elsewhere.org."));
    EXPECT_EQ(fallback.last_type, RecordType::A);
    ASSERT_EQ(r.answer.size(), 2u);
    EXPECT_EQ(r.answer[0].type, RecordType::CNAME);
    EXPECT_EQ(r.answer[1].rdata, Bytes({ 203, 0, 113, 5 }));
}

TEST_F(ZoneFilesResolverTest, CnameWithRefusingFallbackKeepsTheCname) {
    fallback.result.rcode = Rcode::Refused;
    resolver              = load("example.com.", kZone, &fallback);

    auto r = query("ext.example.com.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    EXPECT_EQ(r.answer.size(), 1u);
}

// ---- Negative answers ----------------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, NoDataWhenNameExistsButTypeDoesNot) {
    expect_negative(query("ns1.example.com.", RecordType::AAAA), Rcode::NoError);
}

TEST_F(ZoneFilesResolverTest, NxDomainForMissingName) {
    expect_negative(query("missing.example.com.", RecordType::A), Rcode::NXDomain);
}

TEST_F(ZoneFilesResolverTest, EmptyNonTerminalIsNoDataNotNxDomain) {
    // a.b.c exists, so b.c and c exist implicitly.
    expect_negative(query("c.example.com.", RecordType::A), Rcode::NoError);
    expect_negative(query("b.c.example.com.", RecordType::A), Rcode::NoError);
}

TEST_F(ZoneFilesResolverTest, NoWildcardMeansNxDomainBelowExistingBranch) {
    expect_negative(query("x.b.c.example.com.", RecordType::A), Rcode::NXDomain);
}

// ---- Wildcards ---------------------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, WildcardSynthesizesRecordForQueriedName) {
    auto r = query("foo.wild.example.com.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_TRUE(r.answer[0].name == types::DomainName("foo.wild.example.com."));
    EXPECT_EQ(r.answer[0].rdata, Bytes({ 192, 0, 2, 99 }));
}

TEST_F(ZoneFilesResolverTest, WildcardMatchesSeveralLabelsDeep) {
    auto r = query("a.b.wild.example.com.", RecordType::A);
    ASSERT_EQ(r.answer.size(), 1u);
    EXPECT_TRUE(r.answer[0].name == types::DomainName("a.b.wild.example.com."));
}

TEST_F(ZoneFilesResolverTest, WildcardWithWrongTypeIsNoData) {
    expect_negative(query("foo.wild.example.com.", RecordType::AAAA), Rcode::NoError);
}

// ---- Delegation ------------------------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, ReferralForNameBelowZoneCut) {
    auto r = query("www.sub.example.com.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::NoError);
    EXPECT_TRUE(r.answer.empty());
    ASSERT_EQ(r.authority.size(), 1u);
    EXPECT_EQ(r.authority[0].type, RecordType::NS);
    EXPECT_EQ(r.authority[0].rdata, wire("ns.sub.example.com."));
    ASSERT_EQ(r.additional.size(), 1u);
    EXPECT_EQ(r.additional[0].rdata, Bytes({ 192, 0, 2, 77 }));
}

TEST_F(ZoneFilesResolverTest, ReferralAtTheCutItself) {
    auto r = query("sub.example.com.", RecordType::A);
    EXPECT_TRUE(r.answer.empty());
    ASSERT_EQ(r.authority.size(), 1u);
    EXPECT_EQ(r.authority[0].type, RecordType::NS);
}

TEST_F(ZoneFilesResolverTest, GlueBelowTheCutIsReferredNotAnswered) {
    auto r = query("ns.sub.example.com.", RecordType::A);
    EXPECT_TRUE(r.answer.empty());
    ASSERT_EQ(r.authority.size(), 1u);
    EXPECT_EQ(r.authority[0].type, RecordType::NS);
}

TEST_F(ZoneFilesResolverTest, DsAtTheCutIsNotReferred) {
    // DS lives on the parent side, so the parent answers (NODATA here, there is no DS).
    expect_negative(query("sub.example.com.", RecordType::DS), Rcode::NoError);
}

// ---- Out-of-zone and class handling ----------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, OutOfZoneWithoutFallbackIsRefused) {
    auto r = query("www.other.org.", RecordType::A);
    EXPECT_EQ(r.rcode, Rcode::Refused);
    EXPECT_TRUE(r.answer.empty());
}

TEST_F(ZoneFilesResolverTest, OutOfZoneUsesFallback) {
    fallback.result.rcode = Rcode::NXDomain;
    resolver              = load("example.com.", kZone, &fallback);

    auto r = query("www.other.org.", RecordType::A);
    EXPECT_EQ(fallback.calls, 1);
    EXPECT_TRUE(fallback.last_name == types::DomainName("www.other.org."));
    EXPECT_EQ(r.rcode, Rcode::NXDomain);
}

TEST_F(ZoneFilesResolverTest, InZoneNamesNeverReachTheFallback) {
    resolver = load("example.com.", kZone, &fallback);
    query("example.com.", RecordType::A);
    query("missing.example.com.", RecordType::A);
    EXPECT_EQ(fallback.calls, 0);
}

TEST_F(ZoneFilesResolverTest, NameThatOnlySharesASuffixStringIsOutOfZone) {
    EXPECT_EQ(query("notexample.com.", RecordType::A).rcode, Rcode::Refused);
}

TEST_F(ZoneFilesResolverTest, WrongClassIsRefused) {
    EXPECT_EQ(query("example.com.", RecordType::A, RecordClass::CH).rcode, Rcode::Refused);
}

// ---- Multiple zones ----------------------------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, MostSpecificZoneWins) {
    const std::string parent = std::string(kMinimalZone) + "ns IN A 10.0.0.53\nwww.sub IN A 10.0.0.2\n";
    const std::string child  = std::string(kMinimalZone) + "ns IN A 10.0.1.53\nwww IN A 10.0.0.1\n";

    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), dir.write("parent.db", parent) },
                                          { types::DomainName("sub.example.com."), dir.write("child.db", child) } };
    backend::ZoneFilesResolver multi(files, nullptr);

    auto from_child = multi.resolve(types::DomainName("www.sub.example.com."), RecordType::A, RecordClass::IN);
    ASSERT_EQ(from_child.answer.size(), 1u);
    EXPECT_EQ(from_child.answer[0].rdata, Bytes({ 10, 0, 0, 1 }));

    auto from_parent = multi.resolve(types::DomainName("ns.example.com."), RecordType::A, RecordClass::IN);
    ASSERT_EQ(from_parent.answer.size(), 1u);
    EXPECT_EQ(from_parent.answer[0].rdata, Bytes({ 10, 0, 0, 53 }));
}

TEST_F(ZoneFilesResolverTest, SameNameInDifferentClassesAreSeparateZones) {
    const std::string in_zone = std::string(kMinimalZone) + "www IN A 10.0.0.1\n";
    const std::string ch_zone = "@ 60 CH SOA ns admin 1 1 1 1 60\nwww 60 CH A 10.9.9.9\n";

    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), dir.write("in.db", in_zone) },
                                          { types::DomainName("example.com."), dir.write("ch.db", ch_zone) } };
    backend::ZoneFilesResolver multi(files, nullptr);

    auto in = multi.resolve(types::DomainName("www.example.com."), RecordType::A, RecordClass::IN);
    auto ch = multi.resolve(types::DomainName("www.example.com."), RecordType::A, RecordClass::CH);
    ASSERT_EQ(in.answer.size(), 1u);
    ASSERT_EQ(ch.answer.size(), 1u);
    EXPECT_EQ(in.answer[0].rdata, Bytes({ 10, 0, 0, 1 }));
    EXPECT_EQ(ch.answer[0].rdata, Bytes({ 10, 9, 9, 9 }));
}

// ---- Construction errors -------------------------------------------------------------------------------------------

TEST_F(ZoneFilesResolverTest, ZoneWithoutSoaIsRejected) {
    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), dir.write("nosoa.db", "$TTL 60\nwww IN A 1.2.3.4\n") } };
    try {
        backend::ZoneFilesResolver r(files, nullptr);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("No SOA"), std::string::npos) << e.what();
    }
}

TEST_F(ZoneFilesResolverTest, ZoneWithTwoSoasIsRejected) {
    const std::string text = std::string(kMinimalZone) + "@ IN SOA ns2 admin 2 1 1 1 60\n";
    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), dir.write("twosoa.db", text) } };
    try {
        backend::ZoneFilesResolver r(files, nullptr);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("Too many SOA"), std::string::npos) << e.what();
    }
}

TEST_F(ZoneFilesResolverTest, MixedClassesInOneZoneFileAreRejected) {
    const std::string text = std::string(kMinimalZone) + "www 60 CH A 10.0.0.1\n";
    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), dir.write("mixed.db", text) } };
    try {
        backend::ZoneFilesResolver r(files, nullptr);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("Multiple record classes"), std::string::npos) << e.what();
    }
}

TEST_F(ZoneFilesResolverTest, DuplicateZoneIsRejected) {
    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), dir.write("one.db", kMinimalZone) },
                                          { types::DomainName("example.com."), dir.write("two.db", kMinimalZone) } };
    try {
        backend::ZoneFilesResolver r(files, nullptr);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("multiple times"), std::string::npos) << e.what();
    }
}

TEST_F(ZoneFilesResolverTest, MissingZoneFileIsRejected) {
    std::vector<backend::ZoneFile> files{ { types::DomainName("example.com."), (dir.path() / "nope.db").string() } };
    EXPECT_THROW(backend::ZoneFilesResolver(files, nullptr), std::runtime_error);
}

TEST_F(ZoneFilesResolverTest, NoZonesRefusesEverything) {
    backend::ZoneFilesResolver empty({}, nullptr);
    EXPECT_EQ(empty.resolve(types::DomainName("example.com."), RecordType::A, RecordClass::IN).rcode, Rcode::Refused);
}
