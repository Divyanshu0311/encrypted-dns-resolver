#include "mw/dns_message.hpp"

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

using mw::DnsQuery;
using mw::ParseError;
using mw::Rcode;
using mw::RecordType;
using mw::ResolveResult;
using mw::ResourceRecord;

namespace {

constexpr uint16_t kId = 0x1234;
constexpr uint16_t kRecursionDesired = 0x0100;
constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAaaa = 28;
constexpr uint16_t kTypeHttps = 65;
constexpr uint16_t kTypeOpt = 41;
constexpr uint16_t kClassIn = 1;
constexpr uint16_t kClassChaos = 3;

class Packet {
public:
  Packet &u8(uint8_t value) {
    bytes_.push_back(std::byte{value});
    return *this;
  }

  Packet &u16(uint16_t value) {
    u8(static_cast<uint8_t>(value >> 8));
    return u8(static_cast<uint8_t>(value & 0xFF));
  }

  Packet &header(uint16_t flags, uint16_t questions, uint16_t answers, uint16_t authority,
                 uint16_t additional) {
    return u16(kId).u16(flags).u16(questions).u16(answers).u16(authority).u16(additional);
  }

  Packet &query_header(uint16_t additional = 0) {
    return header(kRecursionDesired, 1, 0, 0, additional);
  }

  Packet &label(std::string_view text) {
    u8(static_cast<uint8_t>(text.size()));
    for (char c : text) {
      u8(static_cast<uint8_t>(c));
    }
    return *this;
  }

  Packet &name(std::string_view dotted) {
    while (!dotted.empty()) {
      const auto dot = dotted.find('.');
      label(dotted.substr(0, dot));
      dotted = dot == std::string_view::npos ? std::string_view{} : dotted.substr(dot + 1);
    }
    return u8(0);
  }

  Packet &type_class(uint16_t type, uint16_t qclass) { return u16(type).u16(qclass); }

  Packet &opt(uint8_t version, std::initializer_list<uint8_t> data) {
    u8(0).u16(kTypeOpt).u16(1232).u8(0).u8(version).u16(0);
    u16(static_cast<uint16_t>(data.size()));
    for (uint8_t b : data) {
      u8(b);
    }
    return *this;
  }

  std::expected<DnsQuery, ParseError> parse() const { return mw::parse_query(bytes_); }

  std::optional<ParseError> parse_error() const {
    const auto result = parse();
    if (result) {
      return std::nullopt;
    }
    return result.error();
  }

  std::size_t size() const { return bytes_.size(); }

  const std::vector<std::byte> &bytes() const { return bytes_; }

private:
  std::vector<std::byte> bytes_;
};

Packet valid_query() {
  return Packet().query_header().name("example.com").type_class(kTypeA, kClassIn);
}

ParseError rejected(Rcode rcode) { return ParseError{rcode, kId}; }

ParseError no_reply() { return ParseError{Rcode::FormErr, std::nullopt}; }

} // namespace

TEST(DnsMessageParse, ParsesMinimalQuery) {
  const auto result = valid_query().parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, (DnsQuery{kId, true, "example.com.", RecordType::A, false}));
}

TEST(DnsMessageParse, NormalizesName) {
  const auto result =
      Packet().query_header().name("WWW.Example.COM").type_class(kTypeA, kClassIn).parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->name, "www.example.com.");
}

TEST(DnsMessageParse, ReadsRecursionDesiredFlag) {
  const auto result =
      Packet().header(0x0000, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn).parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(result->recursion_desired);
}

TEST(DnsMessageParse, ParsesRootName) {
  const auto result = Packet().query_header().name("").type_class(kTypeA, kClassIn).parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->name, ".");
}

TEST(DnsMessageParse, ParsesKnownRecordType) {
  const auto result =
      Packet().query_header().name("example.com").type_class(kTypeAaaa, kClassIn).parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->type, RecordType::AAAA);
}

TEST(DnsMessageParse, AcceptsDigStyleEdnsWithCookie) {
  const auto result = Packet()
                          .query_header(1)
                          .name("example.com")
                          .type_class(kTypeA, kClassIn)
                          .opt(0, {0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8})
                          .parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->has_edns);
  EXPECT_FALSE(result->wants_padding);
}

TEST(DnsMessageParse, DetectsPaddingOption) {
  const auto result = Packet()
                          .query_header(1)
                          .name("example.com")
                          .type_class(kTypeA, kClassIn)
                          .opt(0, {0x00, 0x0c, 0x00, 0x04, 0, 0, 0, 0})
                          .parse();
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result->has_edns);
  EXPECT_TRUE(result->wants_padding);
}

TEST(DnsMessageParse, DetectsPaddingAmongOtherOptions) {
  const auto cookie_then_padding =
      Packet()
          .query_header(1)
          .name("example.com")
          .type_class(kTypeA, kClassIn)
          .opt(0, {0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x0c, 0x00, 0x00})
          .parse();
  const auto padding_then_cookie =
      Packet()
          .query_header(1)
          .name("example.com")
          .type_class(kTypeA, kClassIn)
          .opt(0, {0x00, 0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8})
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
  const auto packet =
      Packet().header(0x8100, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn);
  EXPECT_EQ(packet.parse_error(), no_reply());
}

TEST(DnsMessageParse, Check3_NonStandardOpcodeIsNotImplemented) {
  const uint16_t update_opcode = 5 << 11;
  const auto packet =
      Packet().header(update_opcode, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn);
  EXPECT_EQ(packet.parse_error(), rejected(Rcode::NotImp));
}

TEST(DnsMessageParse, Check4_RejectsBadSectionCounts) {
  const auto with_counts = [](uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
    return Packet()
        .header(kRecursionDesired, qd, an, ns, ar)
        .name("example.com")
        .type_class(kTypeA, kClassIn)
        .parse_error();
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
  for (uint8_t length_byte : std::initializer_list<uint8_t>{0x40, 0x80}) {
    const auto packet = Packet().query_header().u8(length_byte).u8(0).type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr)) << "length byte " << int{length_byte};
  }
}

TEST(DnsMessageParse, Check5_EnforcesLabelLengthLimit) {
  const std::string at_limit(63, 'a');
  const std::string over_limit(64, 'a');
  EXPECT_EQ(Packet().query_header().name(at_limit).type_class(kTypeA, kClassIn).parse_error(),
            std::nullopt);
  EXPECT_EQ(Packet().query_header().name(over_limit).type_class(kTypeA, kClassIn).parse_error(),
            rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_EnforcesWireNameLengthLimit) {
  const std::string label63(63, 'a');
  const std::string three_labels = label63 + "." + label63 + "." + label63 + ".";
  Packet at_limit = Packet().query_header().name(three_labels + std::string(61, 'a'));
  Packet over_limit = Packet().query_header().name(three_labels + std::string(62, 'a'));
  ASSERT_EQ(at_limit.size(), 12u + 255u);
  EXPECT_EQ(at_limit.type_class(kTypeA, kClassIn).parse_error(), std::nullopt);
  EXPECT_EQ(over_limit.type_class(kTypeA, kClassIn).parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check5_RejectsDotInsideLabel) {
  const auto packet = Packet().query_header().label("a.b").u8(0).type_class(kTypeA, kClassIn);
  EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check6_RejectsInvalidCharacters) {
  for (std::string_view bad : {"a*b.com", "a b.com"}) {
    const auto packet = Packet().query_header().name(bad).type_class(kTypeA, kClassIn);
    EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr)) << bad;
  }
}

TEST(DnsMessageParse, Check7_RejectsMissingTypeOrClass) {
  EXPECT_EQ(Packet().query_header().name("example.com").parse_error(), rejected(Rcode::FormErr));
  EXPECT_EQ(Packet().query_header().name("example.com").u16(kTypeA).parse_error(),
            rejected(Rcode::FormErr));
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
  const auto packet = Packet()
                          .query_header(1)
                          .name("example.com")
                          .type_class(kTypeA, kClassIn)
                          .u8(0)
                          .u16(kTypeA)
                          .u16(kClassIn)
                          .u16(0)
                          .u16(0)
                          .u16(0);
  EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8_RejectsUnsupportedEdnsVersion) {
  const auto packet =
      Packet().query_header(1).name("example.com").type_class(kTypeA, kClassIn).opt(1, {});
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
  const auto packet = Packet()
                          .query_header(1)
                          .name("example.com")
                          .type_class(kTypeA, kClassIn)
                          .opt(0, {0x00, 0x0c, 0x00, 0x08, 0, 0})
                          .u8(0)
                          .u8(0);
  EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check8b_RejectsHalfOptionHeader) {
  const auto packet = Packet()
                          .query_header(1)
                          .name("example.com")
                          .type_class(kTypeA, kClassIn)
                          .opt(0, {0x00, 0x0c});
  EXPECT_EQ(packet.parse_error(), rejected(Rcode::FormErr));
}

TEST(DnsMessageParse, Check9_RejectsTrailingBytes) {
  EXPECT_EQ(valid_query().u8(0).parse_error(), rejected(Rcode::FormErr));
}

namespace {

constexpr std::size_t kExampleAnswerSize = 56;
constexpr std::size_t kOptSize = 11;

uint16_t u16_at(const std::vector<std::byte> &wire, std::size_t offset) {
  return static_cast<uint16_t>(std::to_integer<uint16_t>(wire.at(offset)) << 8 |
                               std::to_integer<uint16_t>(wire.at(offset + 1)));
}

DnsQuery example_query(bool has_edns = false, bool wants_padding = false) {
  return DnsQuery{kId, true, "example.com.", RecordType::A, has_edns, wants_padding};
}

ResourceRecord a_record(std::string name = "example.com.") {
  return ResourceRecord{std::move(name), RecordType::A, mw::RecordClass::IN, 300, {93, 184, 215, 14}};
}

ResolveResult answer(std::vector<ResourceRecord> records) {
  return ResolveResult{Rcode::NoError, std::move(records), {}, {}};
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
  EXPECT_EQ(mw::encode_response(example_query(), answer({a_record()})), expected.bytes());
}

TEST(DnsMessageEncode, CopiesRecursionDesiredAndSetsRecursionAvailable) {
  auto query = example_query();
  EXPECT_EQ(u16_at(mw::encode_response(query, answer({})), 2), 0x8180);
  query.recursion_desired = false;
  EXPECT_EQ(u16_at(mw::encode_response(query, answer({})), 2), 0x8080);
}

TEST(DnsMessageEncode, PutsRcodeInFlags) {
  const auto wire = mw::encode_response(example_query(), mw::error_result(Rcode::NXDomain));
  EXPECT_EQ(u16_at(wire, 2) & 0xF, 3);
  EXPECT_EQ(u16_at(wire, 4), 1);
  EXPECT_EQ(u16_at(wire, 6), 0);
}

TEST(DnsMessageEncode, CountsAuthorityRecords) {
  const ResourceRecord soa{std::string("com."), RecordType::SOA, mw::RecordClass::IN, 900, {0}};
  const auto wire = mw::encode_response(example_query(), ResolveResult{Rcode::NXDomain, {}, {soa}, {}});
  EXPECT_EQ(u16_at(wire, 6), 0);
  EXPECT_EQ(u16_at(wire, 8), 1);
}

TEST(DnsMessageEncode, RecordNameWithOrWithoutTrailingDotEncodesTheSame) {
  EXPECT_EQ(mw::encode_response(example_query(), answer({a_record("example.com")})),
            mw::encode_response(example_query(), answer({a_record("example.com.")})));
}

TEST(DnsMessageEncode, AddsOptRecordOnlyWhenClientSentEdns) {
  const auto without = mw::encode_response(example_query(false), answer({a_record()}));
  const auto with = mw::encode_response(example_query(true), answer({a_record()}));

  EXPECT_EQ(without.size(), kExampleAnswerSize);
  EXPECT_EQ(u16_at(without, 10), 0);

  ASSERT_EQ(with.size(), kExampleAnswerSize + kOptSize);
  EXPECT_EQ(u16_at(with, 10), 1);
  const std::vector<std::byte> opt(with.begin() + kExampleAnswerSize, with.end());
  EXPECT_EQ(opt, Packet().u8(0).u16(kTypeOpt).u16(1232).u8(0).u8(0).u16(0).u16(0).bytes());
}

TEST(DnsMessageEncode, PadsToBlockSizeWhenClientPadded) {
  const auto wire = mw::encode_response(example_query(true, true), answer({a_record()}));
  ASSERT_EQ(wire.size(), 468u);

  const std::size_t option_offset = kExampleAnswerSize + kOptSize;
  EXPECT_EQ(u16_at(wire, option_offset - 2), 401);
  EXPECT_EQ(u16_at(wire, option_offset), 12);
  EXPECT_EQ(u16_at(wire, option_offset + 2), 397);
  EXPECT_TRUE(std::all_of(wire.begin() + option_offset + 4, wire.end(),
                          [](std::byte b) { return b == std::byte{0}; }));
}

TEST(DnsMessageEncode, PadsLargeRepliesToNextBlock) {
  const auto wire = mw::encode_response(example_query(true, true),
                                        answer(std::vector<ResourceRecord>(20, a_record())));
  EXPECT_GT(wire.size(), 468u);
  EXPECT_EQ(wire.size() % 468, 0u);
}

TEST(DnsMessageEncode, FallsBackToServFailWhenRecordCannotBeEncoded) {
  const auto expected =
      Packet().header(0x8182, 1, 0, 0, 0).name("example.com").type_class(kTypeA, kClassIn);
  // DomainName already rejects bad names, so make the record unencodable with oversized rdata
  auto huge = a_record();
  huge.rdata.assign(70000, 0);
  EXPECT_EQ(mw::encode_response(example_query(), answer({huge})), expected.bytes());
}

TEST(DnsMessageEncode, EncodeErrorIsBareHeader) {
  EXPECT_EQ(mw::encode_error(kId, Rcode::FormErr), Packet().header(0x8081, 0, 0, 0, 0).bytes());
  EXPECT_EQ(u16_at(mw::encode_error(kId, Rcode::NotImp), 2), 0x8084);
}

TEST(DnsMessageEncode, ReplyEchoesParsedQuestion) {
  const Packet query_packet = valid_query();
  const auto query = query_packet.parse();
  ASSERT_TRUE(query.has_value());

  const auto wire = mw::encode_response(*query, answer({a_record()}));
  const auto &sent = query_packet.bytes();
  EXPECT_EQ(u16_at(wire, 0), kId);
  EXPECT_TRUE(std::equal(sent.begin() + 12, sent.end(), wire.begin() + 12));
}
