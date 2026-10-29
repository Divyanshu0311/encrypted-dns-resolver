#include "dns_message.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using types::DnsQuery;
using types::ParseError;
using types::Rcode;
using types::RecordType;
using types::ResolveResult;
using types::ResourceRecord;

namespace {

    constexpr uint16_t kId               = 0x1234;
    constexpr uint16_t kRecursionDesired = 0x0100;
    constexpr uint16_t kTypeA            = 1;
    constexpr uint16_t kTypeAaaa         = 28;
    constexpr uint16_t kTypeHttps        = 65;
    constexpr uint16_t kTypeOpt          = 41;
    constexpr uint16_t kClassIn          = 1;
    constexpr uint16_t kClassChaos       = 3;

    class Packet {
    public:
        Packet& u8(uint8_t value) {
            bytes_.push_back(std::byte{ value });
            return *this;
        }

        Packet& u16(uint16_t value) {
            u8(static_cast<uint8_t>(value >> 8));
            return u8(static_cast<uint8_t>(value & 0xFF));
        }

        Packet& header(uint16_t flags, uint16_t questions, uint16_t answers, uint16_t authority, uint16_t additional) {
            return u16(kId).u16(flags).u16(questions).u16(answers).u16(authority).u16(additional);
        }

        Packet& query_header(uint16_t additional = 0) { return header(kRecursionDesired, 1, 0, 0, additional); }

        Packet& label(std::string_view text) {
            u8(static_cast<uint8_t>(text.size()));
            for (char c : text) {
                u8(static_cast<uint8_t>(c));
            }
            return *this;
        }

        Packet& name(std::string_view dotted) {
            while (!dotted.empty()) {
                const auto dot = dotted.find('.');
                label(dotted.substr(0, dot));
                dotted = dot == std::string_view::npos ? std::string_view{} : dotted.substr(dot + 1);
            }
            return u8(0);
        }

        Packet& type_class(uint16_t type, uint16_t qclass) { return u16(type).u16(qclass); }

        Packet& opt(uint8_t version, std::initializer_list<uint8_t> data) {
            u8(0).u16(kTypeOpt).u16(1232).u8(0).u8(version).u16(0);
            u16(static_cast<uint16_t>(data.size()));
            for (uint8_t b : data) {
                u8(b);
            }
            return *this;
        }

        std::expected<DnsQuery, ParseError> parse() const { return types::parse_query(bytes_); }

        std::optional<ParseError> parse_error() const {
            const auto result = parse();
            if (result) {
                return std::nullopt;
            }
            return result.error();
        }

        std::size_t size() const { return bytes_.size(); }

        const std::vector<std::byte>& bytes() const { return bytes_; }

    private:
        std::vector<std::byte> bytes_;
    };

    Packet valid_query() {
        return Packet().query_header().name("example.com").type_class(kTypeA, kClassIn);
    }

    ParseError rejected(Rcode rcode) {
        return ParseError{ rcode, kId };
    }

    ParseError no_reply() {
        return ParseError{ Rcode::FormErr, std::nullopt };
    }

} // namespace

TEST(DnsMessageParse, ParsesMinimalQuery) {
    const auto result = valid_query().parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, (DnsQuery{ kId, true, "example.com.", RecordType::A, false }));
}

TEST(DnsMessageParse, KeepsTheClientsCase) {
    const auto result = Packet().query_header().name("WWW.Example.COM").type_class(kTypeA, kClassIn).parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->name, "WWW.Example.COM.");
}

TEST(DnsMessageParse, ReadsRecursionDesiredFlag) {
    const auto result = Packet().header(0x0000, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn).parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->recursion_desired);
}

TEST(DnsMessageParse, ParsesRootName) {
    const auto result = Packet().query_header().name("").type_class(kTypeA, kClassIn).parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->name, ".");
}

TEST(DnsMessageParse, ParsesKnownRecordType) {
    const auto result = Packet().query_header().name("example.com").type_class(kTypeAaaa, kClassIn).parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, RecordType::AAAA);
}

TEST(DnsMessageParse, AcceptsDigStyleEdnsWithCookie) {
    const auto
        result = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(0, { 0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 }).parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->has_edns);
    EXPECT_FALSE(result->wants_padding);
}

TEST(DnsMessageParse, DetectsPaddingOption) {
    const auto result = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(0, { 0x00, 0x0c, 0x00, 0x04, 0, 0, 0, 0 }).parse();
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->has_edns);
    EXPECT_TRUE(result->wants_padding);
}

TEST(DnsMessageParse, DetectsPaddingAmongOtherOptions) {
    const auto cookie_then_padding = Packet()
                                         .query_header(1)
                                         .name("example.com")
                                         .type_class(kTypeA, kClassIn)
                                         .opt(0, { 0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x0c, 0x00, 0x00 })
                                         .parse();
    const auto padding_then_cookie = Packet()
                                         .query_header(1)
                                         .name("example.com")
                                         .type_class(kTypeA, kClassIn)
                                         .opt(0, { 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 })
                                         .parse();
    ASSERT_TRUE(cookie_then_padding.has_value());
    ASSERT_TRUE(padding_then_cookie.has_value());
    EXPECT_TRUE(cookie_then_padding->wants_padding);
    EXPECT_TRUE(padding_then_cookie->wants_padding);
}

TEST(DnsMessageParse, Check1_ShortHeaderCannotBeAnswered) {
    EXPECT_EQ(Packet().parse_error(), no_reply());

    Packet eleven_bytes;
    for (int i = 0; i < 11; ++i) {
        eleven_bytes.u8(0);
    }
    EXPECT_EQ(eleven_bytes.parse_error(), no_reply());

    EXPECT_EQ(Packet().query_header().parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check2_ResponseCannotBeAnswered) {
    const auto packet = Packet().header(0x8100, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), no_reply());
}

TEST(DnsMessageParse, Check3_NonStandardOpcodeIsNotImplemented) {
    const uint16_t update_opcode = 5 << 11;
    const auto packet            = Packet().header(update_opcode, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::NotImp));
}

TEST(DnsMessageParse, Check4_RejectsBadSectionCounts) {
    const auto with_counts = [](uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
        return Packet().header(kRecursionDesired, qd, an, ns, ar).name("example.com").type_class(kTypeA, kClassIn).parse_error();
    };
    EXPECT_EQ(with_counts(0, 0, 0, 0), rejected(Rcode::FormErr));
    EXPECT_EQ(with_counts(2, 0, 0, 0), rejected(Rcode::FormErr));
    EXPECT_EQ(with_counts(1, 1, 0, 0), rejected(Rcode::FormErr));
    EXPECT_EQ(with_counts(1, 0, 1, 0), rejected(Rcode::FormErr));
    EXPECT_EQ(with_counts(1, 0, 0, 2), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_RejectsTruncatedName) {
    EXPECT_EQ(Packet().query_header().u8(7).u8('e').u8('x').parse_error(), rejected(Rcode::FormErr));
    EXPECT_EQ(Packet().query_header().label("example").parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_RejectsCompressionPointer) {
    const auto packet = Packet().query_header().u8(0xC0).u8(0x0C).type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_RejectsReservedLabelTypes) {
    for (uint8_t length_byte : std::initializer_list<uint8_t>{ 0x40, 0x80 }) {
        const auto packet = Packet().query_header().u8(length_byte).u8(0).type_class(kTypeA, kClassIn);
        EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr)) << "length byte " << int{ length_byte };
    }
}

TEST(DnsMessageParse, Check5_EnforcesLabelLengthLimit) {
    const std::string at_limit(63, 'a');
    const std::string over_limit(64, 'a');
    EXPECT_EQ(Packet().query_header().name(at_limit).type_class(kTypeA, kClassIn).parse_error(), std::nullopt);
    EXPECT_EQ(Packet().query_header().name(over_limit).type_class(kTypeA, kClassIn).parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_EnforcesWireNameLengthLimit) {
    const std::string label63(63, 'a');
    const std::string three_labels = label63 + "." + label63 + "." + label63 + ".";
    Packet at_limit                = Packet().query_header().name(three_labels + std::string(61, 'a'));
    Packet over_limit              = Packet().query_header().name(three_labels + std::string(62, 'a'));
    ASSERT_EQ(at_limit.size(), 12u + 255u);
    EXPECT_EQ(at_limit.type_class(kTypeA, kClassIn).parse_error(), std::nullopt);
    EXPECT_EQ(over_limit.type_class(kTypeA, kClassIn).parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_RejectsDotInsideLabel) {
    const auto packet = Packet().query_header().label("a.b").u8(0).type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check6_RejectsInvalidCharacters) {
    for (std::string_view bad : { "a*b.com", "a b.com" }) {
        const auto packet = Packet().query_header().name(bad).type_class(kTypeA, kClassIn);
        EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr)) << bad;
    }
}

TEST(DnsMessageParse, Check7_RejectsMissingTypeOrClass) {
    EXPECT_EQ(Packet().query_header().name("example.com").parse_error(), rejected(Rcode::FormErr));
    EXPECT_EQ(Packet().query_header().name("example.com").u16(kTypeA).parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check7_NonInternetClassIsNotImplemented) {
    const auto packet = Packet().query_header().name("version.bind").type_class(kTypeA, kClassChaos);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::NotImp));
}

TEST(DnsMessageParse, Check7_UnknownTypeIsNotImplemented) {
    const auto packet = Packet().query_header().name("example.com").type_class(kTypeHttps, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::NotImp));
}

TEST(DnsMessageParse, Check8_RejectsMissingAdditionalRecord) {
    const auto packet = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8_RejectsNonOptAdditionalRecord) {
    const auto packet = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).u8(0).u16(kTypeA).u16(kClassIn).u16(0).u16(0).u16(0);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8_UnsupportedEdnsVersionIsBadVers) {
    const auto packet = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(1, {});
    EXPECT_EQ(packet.parse_error(), (ParseError{ Rcode::NoError, kId, true }));
}

TEST(DnsMessageParse, Check8_BrokenQueryIsFormErrWhateverItsVersion) {
    const auto packet = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(1, {}).u8(0);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8_RejectsOptDataPastEnd) {
    const auto packet = Packet()
                            .query_header(1)
                            .name("example.com")
                            .type_class(kTypeA, kClassIn)
                            .u8(0)
                            .u16(kTypeOpt)
                            .u16(1232)
                            .u8(0)
                            .u8(0)
                            .u16(0)
                            .u16(12)
                            .u16(0x000a)
                            .u16(0x0008);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8b_OptionCannotOverrunOptData) {
    const auto packet = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(0, { 0x00, 0x0c, 0x00, 0x08, 0, 0 }).u8(0).u8(0);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8b_RejectsHalfOptionHeader) {
    const auto packet = Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(0, { 0x00, 0x0c });
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check9_RejectsTrailingBytes) {
    EXPECT_EQ(valid_query().u8(0).parse_error(), rejected(Rcode::FormErr));
}

namespace {

    constexpr std::size_t kExampleAnswerSize = 56;
    constexpr std::size_t kOptSize           = 11;

    uint16_t u16_at(const std::vector<std::byte>& wire, std::size_t offset) {
        return static_cast<uint16_t>(std::to_integer<uint16_t>(wire.at(offset)) << 8 | std::to_integer<uint16_t>(wire.at(offset + 1)));
    }

    DnsQuery example_query(bool has_edns = false, bool wants_padding = false) {
        return DnsQuery{ kId, true, "example.com.", RecordType::A, has_edns, wants_padding };
    }

    ResourceRecord a_record(std::string name = "example.com.") {
        return ResourceRecord{ std::move(name), RecordType::A, types::RecordClass::IN, 300, { 93, 184, 215, 14 } };
    }

    ResolveResult answer(std::vector<ResourceRecord> records) {
        return ResolveResult{ Rcode::NoError, std::move(records), {}, {} };
    }

} // namespace

TEST(DnsMessageEncode, EncodesAnswerByteForByte) {
    const auto expected = Packet()
                              .header(0x8180, 1, 1, 0, 0)
                              .name("example.com")
                              .type_class(kTypeA, kClassIn)
                              .name("example.com")
                              .type_class(kTypeA, kClassIn)
                              .u16(0)
                              .u16(300)
                              .u16(4)
                              .u8(93)
                              .u8(184)
                              .u8(215)
                              .u8(14);
    EXPECT_EQ(types::encode_response(example_query(), answer({ a_record() })), expected.bytes());
}

TEST(DnsMessageEncode, CopiesRecursionDesiredAndSetsRecursionAvailable) {
    auto query = example_query();
    EXPECT_EQ(u16_at(types::encode_response(query, answer({})), 2), 0x8180);
    query.recursion_desired = false;
    EXPECT_EQ(u16_at(types::encode_response(query, answer({})), 2), 0x8080);
}

TEST(DnsMessageEncode, PutsRcodeInFlags) {
    const auto wire = types::encode_response(example_query(), ResolveResult{ Rcode::NXDomain });
    EXPECT_EQ(u16_at(wire, 2) & 0xF, 3);
    EXPECT_EQ(u16_at(wire, 4), 1);
    EXPECT_EQ(u16_at(wire, 6), 0);
}

TEST(DnsMessageEncode, CountsAuthorityRecords) {
    const ResourceRecord soa{ std::string("com."), RecordType::SOA, types::RecordClass::IN, 900, { 0 } };
    const auto wire = types::encode_response(example_query(), ResolveResult{ Rcode::NXDomain, {}, { soa }, {} });
    EXPECT_EQ(u16_at(wire, 6), 0);
    EXPECT_EQ(u16_at(wire, 8), 1);
}

TEST(DnsMessageEncode, RecordNameWithOrWithoutTrailingDotEncodesTheSame) {
    EXPECT_EQ(types::encode_response(example_query(), answer({ a_record("example.com") })),
              types::encode_response(example_query(), answer({ a_record("example.com.") })));
}

TEST(DnsMessageEncode, AddsOptRecordOnlyWhenClientSentEdns) {
    const auto without = types::encode_response(example_query(false), answer({ a_record() }));
    const auto with    = types::encode_response(example_query(true), answer({ a_record() }));

    EXPECT_EQ(without.size(), kExampleAnswerSize);
    EXPECT_EQ(u16_at(without, 10), 0);

    ASSERT_EQ(with.size(), kExampleAnswerSize + kOptSize);
    EXPECT_EQ(u16_at(with, 10), 1);
    const std::vector<std::byte> opt(with.begin() + kExampleAnswerSize, with.end());
    EXPECT_EQ(opt, Packet().u8(0).u16(kTypeOpt).u16(1232).u8(0).u8(0).u16(0).u16(0).bytes());
}

TEST(DnsMessageEncode, PadsToBlockSizeWhenClientPadded) {
    const auto wire = types::encode_response(example_query(true, true), answer({ a_record() }));
    ASSERT_EQ(wire.size(), 468u);

    const std::size_t option_offset = kExampleAnswerSize + kOptSize;
    EXPECT_EQ(u16_at(wire, option_offset - 2), 401);
    EXPECT_EQ(u16_at(wire, option_offset), 12);
    EXPECT_EQ(u16_at(wire, option_offset + 2), 397);
    EXPECT_TRUE(std::all_of(wire.begin() + option_offset + 4, wire.end(), [](std::byte b) { return b == std::byte{ 0 }; }));
}

TEST(DnsMessageEncode, PadsLargeRepliesToNextBlock) {
    const auto wire = types::encode_response(example_query(true, true), answer(std::vector<ResourceRecord>(20, a_record())));
    EXPECT_GT(wire.size(), 468u);
    EXPECT_EQ(wire.size() % 468, 0u);
}

TEST(DnsMessageEncode, FallsBackToServFailWhenRecordCannotBeEncoded) {
    const auto expected = Packet().header(0x8182, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn);
    // DomainName already rejects bad names, so make the record unencodable with oversized rdata
    auto huge = a_record();
    huge.rdata.assign(70000, 0);
    EXPECT_EQ(types::encode_response(example_query(), answer({ huge })), expected.bytes());
}

TEST(DnsMessageEncode, EchoesTheQuestionInTheClientsCase) {
    auto query          = example_query();
    query.name          = "ExAmPlE.CoM.";
    const auto expected = Packet().header(0x8180, 1, 0, 0, 0).name("ExAmPlE.CoM").type_class(kTypeA, kClassIn);
    EXPECT_EQ(types::encode_response(query, answer({})), expected.bytes());
}

TEST(DnsMessageEncode, EncodesAdditionalRecordsBeforeOpt) {
    const ResourceRecord glue{ std::string("ns.example.com."), RecordType::A, types::RecordClass::IN, 60, { 192, 0, 2, 1 } };
    const ResolveResult result{ Rcode::NoError, { a_record() }, {}, { glue } };

    const auto without_edns = types::encode_response(example_query(false), result);
    EXPECT_EQ(u16_at(without_edns, 10), 1);
    const auto glue_bytes = Packet().name("ns.example.com").type_class(kTypeA, kClassIn).u16(0).u16(60).u16(4).u8(192).u8(0).u8(2).u8(1).bytes();
    ASSERT_EQ(without_edns.size(), kExampleAnswerSize + glue_bytes.size());
    EXPECT_TRUE(std::equal(glue_bytes.begin(), glue_bytes.end(), without_edns.begin() + kExampleAnswerSize));

    const auto with_edns = types::encode_response(example_query(true), result);
    EXPECT_EQ(u16_at(with_edns, 10), 2);
    ASSERT_EQ(with_edns.size(), kExampleAnswerSize + glue_bytes.size() + kOptSize);
    EXPECT_EQ(u16_at(with_edns, kExampleAnswerSize + glue_bytes.size() + 1), kTypeOpt);
}

TEST(DnsMessageEncode, BadVersIsHeaderPlusOpt) {
    const auto expected = Packet()
                              .header(0x8080, 0, 0, 0, 1)
                              .u8(0)
                              .u16(kTypeOpt)
                              .u16(1232)
                              .u8(1) // extended rcode: 16 >> 4
                              .u8(0) // version we support
                              .u16(0)
                              .u16(0);
    EXPECT_EQ(types::encode_bad_version(kId), expected.bytes());
}

TEST(DnsMessageEncode, EncodeParseErrorPicksTheRightReply) {
    EXPECT_EQ(types::encode_parse_error(ParseError{ Rcode::FormErr, kId }), types::encode_error(kId, Rcode::FormErr));
    EXPECT_EQ(types::encode_parse_error(ParseError{ Rcode::NotImp, kId }), types::encode_error(kId, Rcode::NotImp));
    EXPECT_EQ(types::encode_parse_error(ParseError{ Rcode::NoError, kId, true }), types::encode_bad_version(kId));
    EXPECT_EQ(types::encode_parse_error(ParseError{ Rcode::FormErr, std::nullopt }), std::nullopt);
}

TEST(DnsMessageEncode, EncodeErrorIsBareHeader) {
    EXPECT_EQ(types::encode_error(kId, Rcode::FormErr), Packet().header(0x8081, 0, 0, 0, 0).bytes());
    EXPECT_EQ(u16_at(types::encode_error(kId, Rcode::NotImp), 2), 0x8084);
}

TEST(DnsMessageEncode, ReplyEchoesParsedQuestion) {
    const Packet query_packet = valid_query();
    const auto query          = query_packet.parse();
    ASSERT_TRUE(query.has_value());

    const auto wire  = types::encode_response(*query, answer({ a_record() }));
    const auto& sent = query_packet.bytes();
    EXPECT_EQ(u16_at(wire, 0), kId);
    EXPECT_TRUE(std::equal(sent.begin() + 12, sent.end(), wire.begin() + 12));
}

// ---- client side: encode_query / parse_response ----

TEST(DnsMessageUpstream, EncodedQueryParsesBack) {
    const auto wire  = types::encode_query(kId, types::DomainName("www.example.com."), RecordType::AAAA, types::RecordClass::IN, true);
    const auto query = types::parse_query(wire);
    ASSERT_TRUE(query.has_value());
    EXPECT_EQ(query->id, kId);
    EXPECT_EQ(query->name, "www.example.com.");
    EXPECT_EQ(query->type, RecordType::AAAA);
    EXPECT_TRUE(query->recursion_desired);
    EXPECT_TRUE(query->has_edns);
}

TEST(DnsMessageUpstream, QueryIsNotPaddedByDefault) {
    const auto wire  = types::encode_query(kId, types::DomainName("example.com."), RecordType::A, types::RecordClass::IN, true);
    const auto query = types::parse_query(wire);
    ASSERT_TRUE(query.has_value());
    EXPECT_FALSE(query->wants_padding);
}

TEST(DnsMessageUpstream, PaddedQueriesAllHaveTheBlockSize) {
    // names of very different lengths must not be told apart by size
    for (const char* name : { "a.io.", "example.com.", "a-much-longer-name-that-changes-the-message-size.example.org." }) {
        const auto wire = types::encode_query(kId, types::DomainName(name), RecordType::A, types::RecordClass::IN, true, types::kQueryPaddingBlock);
        EXPECT_EQ(wire.size(), types::kQueryPaddingBlock) << name;
        const auto query = types::parse_query(wire);
        ASSERT_TRUE(query.has_value()) << name;
        EXPECT_TRUE(query->wants_padding) << name; // also asks the server to pad its reply (RFC 7830)
        EXPECT_EQ(query->name, name);
    }
}

TEST(DnsMessageUpstream, QueryWithoutRecursionDesired) {
    const auto wire = types::encode_query(kId, types::DomainName("example.com."), RecordType::A, types::RecordClass::IN, false);
    EXPECT_EQ(u16_at(wire, 2), 0x0000);
}

TEST(DnsMessageUpstream, ResponseRoundTripsThroughEncodeResponse) {
    const auto query = valid_query().parse();
    ASSERT_TRUE(query.has_value());
    const ResourceRecord ns{ std::string("example.com."), RecordType::NS, types::RecordClass::IN, 900,
                             static_cast<std::vector<uint8_t>>(types::DomainName("ns.example.com.")) };
    const ResourceRecord glue{ std::string("ns.example.com."), RecordType::A, types::RecordClass::IN, 60, { 192, 0, 2, 1 } };
    const auto wire = types::encode_response(*query, ResolveResult{ Rcode::NoError, { a_record() }, { ns }, { glue } });

    const auto response = types::parse_response(wire);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->id, kId);
    EXPECT_TRUE(response->has_question);
    EXPECT_EQ(response->question, types::DomainName("example.com."));
    EXPECT_EQ(response->qtype, RecordType::A);
    EXPECT_FALSE(response->truncated);
    EXPECT_EQ(response->result.rcode, Rcode::NoError);
    ASSERT_EQ(response->result.answer.size(), 1u);
    EXPECT_EQ(response->result.answer[0].rdata, (std::vector<uint8_t>{ 93, 184, 215, 14 }));
    EXPECT_EQ(response->result.answer[0].ttl, 300u);
    ASSERT_EQ(response->result.authority.size(), 1u);
    EXPECT_EQ(response->result.authority[0].rdata, ns.rdata);
    ASSERT_EQ(response->result.additional.size(), 1u); // the OPT record is left out
    EXPECT_EQ(response->result.additional[0].name, glue.name);
}

TEST(DnsMessageUpstream, CompressedNamesInRdataAreExpanded) {
    // www.example.com CNAME pointing at "cdn" + a pointer back to example.com in the question
    const auto wire = Packet()
                          .header(0x8180, 1, 1, 0, 0)
                          .name("www.example.com")
                          .type_class(5, kClassIn)
                          .u16(0xC00C) // owner: the question name
                          .type_class(5, kClassIn)
                          .u16(0)
                          .u16(60)
                          .u16(6)
                          .label("cdn")
                          .u16(0xC010) // -> example.com inside the question
                          .bytes();
    const auto response = types::parse_response(wire);
    ASSERT_TRUE(response.has_value());
    ASSERT_EQ(response->result.answer.size(), 1u);
    EXPECT_EQ(response->result.answer[0].name, types::DomainName("www.example.com."));
    EXPECT_EQ(response->result.answer[0].rdata, static_cast<std::vector<uint8_t>>(types::DomainName("cdn.example.com.")));
}

TEST(DnsMessageUpstream, QueriesAreNotResponses) {
    EXPECT_FALSE(types::parse_response(valid_query().bytes()).has_value());
}

TEST(DnsMessageUpstream, TruncatedReplyKeepsHeaderAndQuestion) {
    // claims an answer that isn't there: fine, because TC says the rest is missing
    const auto wire     = Packet().header(0x8380, 1, 1, 0, 0).name("example.com").type_class(kTypeA, kClassIn).bytes();
    const auto response = types::parse_response(wire);
    ASSERT_TRUE(response.has_value());
    EXPECT_TRUE(response->truncated);
    EXPECT_TRUE(response->result.answer.empty());
}

TEST(DnsMessageUpstream, RecordRunningPastTheEndIsRejected) {
    const auto wire = Packet()
                          .header(0x8180, 1, 1, 0, 0)
                          .name("example.com")
                          .type_class(kTypeA, kClassIn)
                          .u16(0xC00C)
                          .type_class(kTypeA, kClassIn)
                          .u16(0)
                          .u16(60)
                          .u16(4) // rdlength 4, but only 2 bytes follow
                          .u8(1)
                          .u8(2)
                          .bytes();
    EXPECT_FALSE(types::parse_response(wire).has_value());
}

TEST(DnsMessageUpstream, RcodeAndAuthoritativeFlag) {
    const auto wire     = Packet().header(0x8483, 1, 0, 0, 0).name("nope.example").type_class(kTypeA, kClassIn).bytes();
    const auto response = types::parse_response(wire);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->result.rcode, Rcode::NXDomain);
    EXPECT_TRUE(response->authoritative);
}

TEST(DnsMessageUpstream, CompressionLoopIsRejected) {
    const auto wire = Packet().header(0x8180, 1, 0, 0, 0).u16(0xC00C).type_class(kTypeA, kClassIn).bytes();
    EXPECT_FALSE(types::parse_response(wire).has_value());
}
