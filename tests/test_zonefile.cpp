#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/ZoneFile.hpp"
#include "support/temp_dir.hpp"

using types::RecordClass;
using types::RecordType;

namespace {
    using Bytes = std::vector<uint8_t>;

    std::string str(const types::DomainName& d) {
        return d;
    }

    Bytes wire(const char* name) {
        types::DomainName d(name);
        return d;
    }

    Bytes u8(unsigned v) {
        return Bytes{ static_cast<uint8_t>(v) };
    }

    Bytes u16(unsigned v) {
        return { static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v) };
    }

    Bytes u32(uint32_t v) {
        return { static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v) };
    }

    Bytes raw(const std::string& s) {
        return Bytes(s.begin(), s.end());
    }

    // length-prefixed character-string
    Bytes lp(const std::string& s) {
        Bytes b{ static_cast<uint8_t>(s.size()) };
        b.insert(b.end(), s.begin(), s.end());
        return b;
    }

    Bytes cat(std::initializer_list<Bytes> parts) {
        Bytes out;
        for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
        return out;
    }

    class ZoneFileTest : public ::testing::Test {
    protected:
        support::TempDir dir;

        std::vector<types::ResourceRecord> parse_file(const std::string& path, const char* origin = "example.com.") {
            return backend::records_from_zone_file(types::DomainName(origin), path);
        }

        std::vector<types::ResourceRecord> parse(const std::string& text, const char* origin = "example.com.") {
            return parse_file(dir.write("zone.db", text), origin);
        }

        // Parses a single record line (a default TTL is supplied) and returns it.
        types::ResourceRecord one(const std::string& line) {
            auto records = parse("$TTL 60\n" + line + "\n");
            if (records.size() != 1) throw std::runtime_error("expected exactly one record, got " + std::to_string(records.size()));
            return records[0];
        }

        std::string error_of(const std::string& text) {
            try {
                parse(text);
            } catch (const std::runtime_error& e) {
                return e.what();
            }
            return "<no exception>";
        }

        void expect_error(const std::string& text, const std::string& needle) {
            const std::string msg = error_of(text);
            EXPECT_NE(msg.find(needle), std::string::npos) << "zone text: " << text << "\nmessage:   " << msg << "\nexpected to contain: " << needle;
        }
    };
} // namespace

// ---- Basic records and owner handling ------------------------------------------------

TEST_F(ZoneFileTest, ParsesARecord) {
    auto records = parse("$TTL 300\nwww IN A 192.0.2.1\n");
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(str(records[0].name), "www.example.com.");
    EXPECT_EQ(records[0].type, RecordType::A);
    EXPECT_EQ(records[0].rclass, RecordClass::IN);
    EXPECT_EQ(records[0].ttl, 300u);
    EXPECT_EQ(records[0].rdata, Bytes({ 192, 0, 2, 1 }));
}

TEST_F(ZoneFileTest, ParsesAAAARecord) {
    auto r = one("host IN AAAA 2001:db8::1");
    EXPECT_EQ(r.type, RecordType::AAAA);
    ASSERT_EQ(r.rdata.size(), 16u);
    EXPECT_EQ(r.rdata[0], 0x20);
    EXPECT_EQ(r.rdata[1], 0x01);
    EXPECT_EQ(r.rdata[2], 0x0d);
    EXPECT_EQ(r.rdata[3], 0xb8);
    EXPECT_EQ(r.rdata[15], 0x01);
}

TEST_F(ZoneFileTest, EmptyFileHasNoRecords) {
    EXPECT_TRUE(parse("").empty());
    EXPECT_TRUE(parse("; only a comment\n\n   \n").empty());
}

TEST_F(ZoneFileTest, AtSignIsOrigin) {
    EXPECT_EQ(str(one("@ IN A 1.2.3.4").name), "example.com.");
}

TEST_F(ZoneFileTest, AbsoluteOwnerIsNotExtended) {
    EXPECT_EQ(str(one("other.org. IN A 1.2.3.4").name), "other.org.");
}

TEST_F(ZoneFileTest, RelativeOwnerGetsOrigin) {
    EXPECT_EQ(str(one("a.b IN A 1.2.3.4").name), "a.b.example.com.");
}

TEST_F(ZoneFileTest, OwnerStartingWithDigitIsNotATtl) {
    auto r = one("1 60 IN A 1.2.3.4");
    EXPECT_EQ(str(r.name), "1.example.com.");
    EXPECT_EQ(r.ttl, 60u);
}

TEST_F(ZoneFileTest, WildcardOwner) {
    EXPECT_EQ(str(one("*.wild IN A 1.2.3.4").name), "*.wild.example.com.");
}

TEST_F(ZoneFileTest, LeadingWhitespaceReusesPreviousOwner) {
    auto records = parse("$TTL 60\nwww IN A 192.0.2.1\n    IN A 192.0.2.2\n\tIN AAAA ::1\n");
    ASSERT_EQ(records.size(), 3u);
    EXPECT_EQ(str(records[1].name), "www.example.com.");
    EXPECT_EQ(str(records[2].name), "www.example.com.");
}

TEST_F(ZoneFileTest, BlankIndentedLinesDoNotAffectOwnerInheritance) {
    auto records = parse("$TTL 60\nwww IN A 192.0.2.1\n   \n   ; indented comment\n    IN A 192.0.2.2\n");
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[1].name), "www.example.com.");
}

TEST_F(ZoneFileTest, KeywordsAreCaseInsensitive) {
    auto records = parse("$ttl 60\nwww in a 1.2.3.4\n");
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].type, RecordType::A);
    EXPECT_EQ(records[0].rclass, RecordClass::IN);
}

TEST_F(ZoneFileTest, CommentsBlankLinesAndCrlf) {
    auto records = parse("; header\r\n\r\n$TTL 60 ; default\r\nwww IN A 1.2.3.4 ; trailing\r\n\r\nmail IN A 1.2.3.5\r\n");
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[1].name), "mail.example.com.");
}

TEST_F(ZoneFileTest, LastLineWithoutNewline) {
    EXPECT_EQ(parse("$TTL 60\nwww IN A 1.2.3.4").size(), 1u);
}

// ---- Class ---------------------------------------------------------------------------------

TEST_F(ZoneFileTest, ClassDefaultsToIN) {
    EXPECT_EQ(one("www A 1.2.3.4").rclass, RecordClass::IN);
}

TEST_F(ZoneFileTest, ClassIsInheritedFromPreviousRecord) {
    auto records = parse("$TTL 60\na CH TXT \"x\"\nb TXT \"y\"\nc IN TXT \"z\"\nd TXT \"w\"\n");
    ASSERT_EQ(records.size(), 4u);
    EXPECT_EQ(records[0].rclass, RecordClass::CH);
    EXPECT_EQ(records[1].rclass, RecordClass::CH);
    EXPECT_EQ(records[2].rclass, RecordClass::IN);
    EXPECT_EQ(records[3].rclass, RecordClass::IN);
}

TEST_F(ZoneFileTest, TtlAndClassInEitherOrder) {
    auto a = one("www 120 IN A 1.2.3.4");
    auto b = one("www IN 120 A 1.2.3.4");
    EXPECT_EQ(a.ttl, 120u);
    EXPECT_EQ(b.ttl, 120u);
    EXPECT_EQ(a.rclass, RecordClass::IN);
    EXPECT_EQ(b.rclass, RecordClass::IN);
}

// ---- TTL ---------------------------------------------------------------------------------

TEST_F(ZoneFileTest, TtlFormats) {
    const std::vector<std::pair<std::string, uint32_t>> cases = {
        { "0", 0 },
        { "300", 300 },
        { "30s", 30 },
        { "2m", 120 },
        { "2M", 120 },
        { "1h", 3600 },
        { "1d", 86400 },
        { "1w", 604800 },
        { "1h30m", 5400 },
        { "1w2d3h4m5s", 604800 + 172800 + 10800 + 240 + 5 },
        { "4294967295", 4294967295u },
    };
    for (const auto& [text, expected] : cases) {
        SCOPED_TRACE(text);
        EXPECT_EQ(one("www " + text + " IN A 1.2.3.4").ttl, expected);
    }
}

TEST_F(ZoneFileTest, InvalidTtls) {
    expect_error("www 10x IN A 1.2.3.4\n", "TTL");
    expect_error("www 4294967296 IN A 1.2.3.4\n", "out of range");
    expect_error("$TTL abc\n", "TTL");
    expect_error("$TTL 99999999999\n", "out of range");
}

TEST_F(ZoneFileTest, ExplicitTtlBeatsDefaultTtl) {
    auto records = parse("$TTL 300\na 60 IN A 1.2.3.4\nb IN A 1.2.3.5\n");
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].ttl, 60u);
    EXPECT_EQ(records[1].ttl, 300u);
}

TEST_F(ZoneFileTest, PreviousExplicitTtlIsReusedWithoutDefault) {
    auto records = parse("a 60 IN A 1.2.3.4\nb IN A 1.2.3.5\n");
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[1].ttl, 60u);
}

TEST_F(ZoneFileTest, FirstRecordWithoutAnyTtlThrows) {
    expect_error("www IN A 1.2.3.4\n", "no TTL");
}

TEST_F(ZoneFileTest, SoaMinimumIsFallbackTtl) {
    auto records = parse("@ IN SOA ns1 admin 1 7200 3600 1209600 900\n");
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].ttl, 900u);
}

// ---- Directives ----------------------------------------------------------------------------

TEST_F(ZoneFileTest, OriginDirectiveAbsolute) {
    auto records = parse("$TTL 60\n$ORIGIN sub.example.com.\nwww IN A 1.1.1.1\n@ IN A 2.2.2.2\n");
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[0].name), "www.sub.example.com.");
    EXPECT_EQ(str(records[1].name), "sub.example.com.");
}

TEST_F(ZoneFileTest, RelativeOriginIsRejected) {
    expect_error("$ORIGIN sub\n", "absolute");
    expect_error("$ORIGIN @\n", "absolute");
    expect_error("$ORIGIN sub.example.com\n", "absolute");
}

TEST_F(ZoneFileTest, RootOriginIsAccepted) {
    auto records = parse("$TTL 60\n$ORIGIN .\nwww IN A 1.1.1.1\n");
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(str(records[0].name), "www.");
}

TEST_F(ZoneFileTest, RdataNamesUseCurrentOrigin) {
    auto records = parse("$TTL 60\n$ORIGIN sub.example.com.\nalias IN CNAME target\n");
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records[0].rdata, wire("target.sub.example.com."));
}

TEST_F(ZoneFileTest, UnknownOrMalformedDirectives) {
    expect_error("$BOGUS x\n", "directive");
    expect_error("$TTL\n", "directive");
    expect_error("$ORIGIN a b c\n", "directive");
}

// ---- Multi-line records ------------------------------------------------------------------------

TEST_F(ZoneFileTest, ParenthesesSpanLinesAndAllowComments) {
    auto records = parse(R"z(@ IN SOA ns1 admin (
        1        ; serial
        7200 3600 1209600
        300 )     ; minimum
www 60 IN A 1.2.3.4
)z");
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].type, RecordType::SOA);
    EXPECT_EQ(records[0].ttl, 300u);
    EXPECT_EQ(records[1].type, RecordType::A);
}

TEST_F(ZoneFileTest, UnbalancedParentheses) {
    expect_error("www 60 IN A 1.2.3.4 )\n", "unbalanced");
    expect_error("www 60 IN A ( 1.2.3.4\n", "unbalanced");
}

// ---- RDATA encodings ------------------------------------------------------------------------------

TEST_F(ZoneFileTest, NameBasedRecords) {
    EXPECT_EQ(one("@ IN NS ns1").rdata, wire("ns1.example.com."));
    EXPECT_EQ(one("@ IN NS ns2.other.net.").rdata, wire("ns2.other.net."));
    EXPECT_EQ(one("www IN CNAME @").rdata, wire("example.com."));
    EXPECT_EQ(one("1 IN PTR host").rdata, wire("host.example.com."));
}

TEST_F(ZoneFileTest, MxRecord) {
    auto r = one("@ IN MX 10 mail");
    EXPECT_EQ(r.type, RecordType::MX);
    EXPECT_EQ(r.rdata, cat({ u16(10), wire("mail.example.com.") }));
}

TEST_F(ZoneFileTest, MxPreferenceOutOfRange) {
    expect_error("@ 60 IN MX 65536 mail\n", "out of range");
}

TEST_F(ZoneFileTest, SrvRecord) {
    auto r = one("_sip._tcp IN SRV 10 60 5060 sip");
    EXPECT_EQ(str(r.name), "_sip._tcp.example.com.");
    EXPECT_EQ(r.rdata, cat({ u16(10), u16(60), u16(5060), wire("sip.example.com.") }));
}

TEST_F(ZoneFileTest, SoaRecord) {
    auto r = one("@ IN SOA ns1 admin 2024010101 7200 3600 1209600 300");
    EXPECT_EQ(r.type, RecordType::SOA);
    EXPECT_EQ(r.rdata, cat({ wire("ns1.example.com."), wire("admin.example.com."), u32(2024010101), u32(7200), u32(3600), u32(1209600), u32(300) }));
}

TEST_F(ZoneFileTest, SoaTimesAcceptUnits) {
    auto r = one("@ IN SOA ns1 admin 1 1h 15m 1w 5m");
    EXPECT_EQ(r.rdata, cat({ wire("ns1.example.com."), wire("admin.example.com."), u32(1), u32(3600), u32(900), u32(604800), u32(300) }));
}

TEST_F(ZoneFileTest, TxtRecord) {
    EXPECT_EQ(one("t IN TXT \"hello world\"").rdata, lp("hello world"));
    EXPECT_EQ(one("t IN TXT plain").rdata, lp("plain"));
    EXPECT_EQ(one("t IN TXT \"\"").rdata, u8(0));
}

TEST_F(ZoneFileTest, TxtEscapesAndSpecialCharacters) {
    EXPECT_EQ(one(R"(t IN TXT "a\"b")").rdata, lp("a\"b"));
    EXPECT_EQ(one(R"(t IN TXT "\065BC")").rdata, lp("ABC"));
    EXPECT_EQ(one(R"(t IN TXT "a;b")").rdata, lp("a;b"));     // ';' inside quotes is not a comment
    EXPECT_EQ(one(R"d(t IN TXT "a(b)")d").rdata, lp("a(b)")); // parentheses inside quotes are literal
}

TEST_F(ZoneFileTest, TxtLimits) {
    EXPECT_EQ(one("t IN TXT \"" + std::string(255, 'a') + "\"").rdata.size(), 256u);
    expect_error("t 60 IN TXT \"" + std::string(256, 'a') + "\"\n", "255");
    expect_error("t 60 IN TXT \"unterminated\n", "unterminated");
}

TEST_F(ZoneFileTest, HinfoRecord) {
    EXPECT_EQ(one("h IN HINFO \"INTEL-386\" Unix").rdata, cat({ lp("INTEL-386"), lp("Unix") }));
}

TEST_F(ZoneFileTest, CaaRecord) {
    EXPECT_EQ(one("@ IN CAA 0 issue \"letsencrypt.org\"").rdata, cat({ u8(0), lp("issue"), raw("letsencrypt.org") }));
}

TEST_F(ZoneFileTest, HexAndBase64Records) {
    EXPECT_EQ(one("ex IN DS 12345 8 2 ABCD").rdata, cat({ u16(12345), u8(8), u8(2), Bytes({ 0xAB, 0xCD }) }));
    EXPECT_EQ(one("ex IN DS 12345 8 2 AB CD").rdata, cat({ u16(12345), u8(8), u8(2), Bytes({ 0xAB, 0xCD }) })); // split hex
    EXPECT_EQ(one("ex IN SSHFP 1 1 deadbeef").rdata, cat({ u8(1), u8(1), Bytes({ 0xDE, 0xAD, 0xBE, 0xEF }) }));
    EXPECT_EQ(one("ex IN TLSA 3 1 1 0a0B").rdata, cat({ u8(3), u8(1), u8(1), Bytes({ 0x0A, 0x0B }) }));
    EXPECT_EQ(one("ex IN DNSKEY 257 3 8 AQID").rdata, cat({ u16(257), u8(3), u8(8), Bytes({ 1, 2, 3 }) }));
}

TEST_F(ZoneFileTest, InvalidEncodedData) {
    expect_error("ex 60 IN DS 1 8 2 abc\n", "odd length");
    expect_error("ex 60 IN DS 1 8 2 zz\n", "hex");
    expect_error("ex 60 IN DNSKEY 257 3 8 !!!\n", "base64");
}

// ---- Generic (RFC 3597) syntax --------------------------------------------------------------------

TEST_F(ZoneFileTest, GenericSyntaxForUnknownType) {
    auto r = one(R"(x IN TYPE999 \# 3 0a0b0c)");
    EXPECT_EQ(static_cast<uint16_t>(r.type), 999);
    EXPECT_EQ(r.rdata, Bytes({ 0x0A, 0x0B, 0x0C }));
}

TEST_F(ZoneFileTest, GenericSyntaxForKnownType) {
    auto r = one(R"(x IN A \# 4 7f 00 00 01)");
    EXPECT_EQ(r.type, RecordType::A);
    EXPECT_EQ(r.rdata, Bytes({ 127, 0, 0, 1 }));
}

TEST_F(ZoneFileTest, GenericSyntaxEmptyRdata) {
    EXPECT_TRUE(one(R"(x IN TYPE999 \# 0)").rdata.empty());
}

TEST_F(ZoneFileTest, TypeMnemonicIsCaseInsensitive) {
    EXPECT_EQ(static_cast<uint16_t>(one(R"(x IN type999 \# 1 ff)").type), 999);
}

TEST_F(ZoneFileTest, GenericSyntaxErrors) {
    expect_error("x 60 IN TYPE999 \\# 2 0a0b0c\n", "length mismatch");
    expect_error("x 60 IN TYPE999 \\# 1 abc\n", "odd length");
    expect_error("x 60 IN TYPE70000 \\# 0\n", "out of range");
}

// ---- Errors ----------------------------------------------------------------------------------------

TEST_F(ZoneFileTest, MalformedRecords) {
    const std::vector<std::pair<std::string, std::string>> cases = {
        { "www 60 IN\n", "missing record type" },           { "www 60 IN MX 10\n", "missing RDATA" },
        { "www 60 IN A 1.2.3.4 5.6.7.8\n", "extra field" }, { "www 60 IN A ::1\n", "address family" },
        { "www 60 IN AAAA 1.2.3.4\n", "address family" },   { "www 60 IN A 999.1.1.1\n", "Invalid" },
        { "www 60 IN BOGUS x\n", "unknown record type" },   { "www 60 IN LOC 1 2 3\n", "unsupported record type" },
        { "bad..name 60 IN A 1.2.3.4\n", "empty label" },   { "    60 IN A 1.2.3.4\n", "no owner" },
    };
    for (const auto& [text, needle] : cases) {
        SCOPED_TRACE(text);
        expect_error(text, needle);
    }
}

TEST_F(ZoneFileTest, ErrorMessageHasFileAndLineNumber) {
    const std::string msg = error_of("$TTL 60\nwww IN A 1.2.3.4\nbad IN A 1.2.3.4.5\n");
    EXPECT_NE(msg.find("zone.db"), std::string::npos) << msg;
    EXPECT_NE(msg.find("line 3"), std::string::npos) << msg;
}

TEST_F(ZoneFileTest, ErrorLineNumberIsTheFirstTokensLine) {
    const std::string msg = error_of("$TTL 60\nwww IN A (\n  1.2.3.4.5 )\n");
    EXPECT_NE(msg.find("line 2"), std::string::npos) << msg;
}

TEST_F(ZoneFileTest, MissingFileThrows) {
    EXPECT_THROW(parse_file((dir.path() / "nope.db").string()), std::runtime_error);
}

// ---- $INCLUDE --------------------------------------------------------------------------------------

TEST_F(ZoneFileTest, IncludeInsertsRecordsInOrder) {
    dir.write("child.zone", "inc IN A 2.2.2.2\n");
    const std::string main = dir.write("main.zone", "$TTL 60\n$INCLUDE child.zone\nwww IN A 1.1.1.1\n");

    auto records = parse_file(main);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[0].name), "inc.example.com.");
    EXPECT_EQ(str(records[1].name), "www.example.com.");
}

TEST_F(ZoneFileTest, IncludeIsRelativeToIncludingFile) {
    dir.write("sub/b.zone", "b IN A 3.3.3.3\n");
    dir.write("sub/a.zone", "a IN A 2.2.2.2\n$INCLUDE b.zone\n");
    const std::string main = dir.write("main.zone", "$TTL 60\n$INCLUDE sub/a.zone\n");

    auto records = parse_file(main);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[0].name), "a.example.com.");
    EXPECT_EQ(str(records[1].name), "b.example.com.");
}

TEST_F(ZoneFileTest, IncludeWithOriginAppliesOnlyToThatFile) {
    dir.write("child.zone", "inc IN A 2.2.2.2\n");
    const std::string main = dir.write("main.zone", "$TTL 60\n$INCLUDE child.zone other.example.\nwww IN A 1.1.1.1\n");

    auto records = parse_file(main);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[0].name), "inc.other.example.");
    EXPECT_EQ(str(records[1].name), "www.example.com.");
}

TEST_F(ZoneFileTest, IncludeWithRelativeOriginIsRejected) {
    dir.write("child.zone", "inc IN A 2.2.2.2\n");
    const std::string main = dir.write("main.zone", "$TTL 60\n$INCLUDE child.zone other\n");
    try {
        parse_file(main);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("absolute"), std::string::npos) << e.what();
    }
}

TEST_F(ZoneFileTest, OriginChangeInsideIncludeDoesNotLeak) {
    dir.write("child.zone", "$ORIGIN leak.example.\nx IN A 2.2.2.2\n");
    const std::string main = dir.write("main.zone", "$TTL 60\n$INCLUDE child.zone\nwww IN A 1.1.1.1\n");

    auto records = parse_file(main);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(str(records[0].name), "x.leak.example.");
    EXPECT_EQ(str(records[1].name), "www.example.com.");
}

TEST_F(ZoneFileTest, MissingIncludeThrows) {
    expect_error("$INCLUDE does-not-exist.zone\n", "cannot open $INCLUDE");
}

TEST_F(ZoneFileTest, RecursiveIncludeIsRejected) {
    const std::string path = dir.write("loop.zone", "$INCLUDE loop.zone\n");
    try {
        parse_file(path);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("nested too deeply"), std::string::npos) << e.what();
    }
}

TEST_F(ZoneFileTest, ErrorInsideIncludeNamesTheIncludedFile) {
    dir.write("child.zone", "bad IN A not-an-ip\n");
    const std::string main = dir.write("main.zone", "$TTL 60\n$INCLUDE child.zone\n");
    try {
        parse_file(main);
        FAIL() << "expected an exception";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("child.zone"), std::string::npos) << e.what();
    }
}
