#include "mw/dns_name.hpp"

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <ostream>
#include <string>
#include <vector>

namespace {

// Builds "<labels joined by '.'>." where each label is `label_len` copies of 'a'.
std::string make_name(std::size_t label_count, std::size_t label_len) {
  std::string name;
  for (std::size_t i = 0; i < label_count; ++i) {
    name.append(label_len, 'a');
    name.push_back('.');
  }
  return name;
}

struct NormalizeCase {
  std::string name;
  std::string input;
  std::string expected;
};

void PrintTo(const NormalizeCase& c, std::ostream* os) {
  *os << mw::test::describe(c.input);
}

struct IsValidCase {
  std::string name;
  std::string input;
  bool expected;
};

void PrintTo(const IsValidCase& c, std::ostream* os) {
  *os << mw::test::describe(c.input);
}

template <typename Case>
std::string case_name(const ::testing::TestParamInfo<Case>& info) {
  return info.param.name;
}

// ---- normalize ----

const std::vector<NormalizeCase> kNormalizeCases = {
    {"LowercasesAndAppendsDot", "Example.COM", "example.com."},
    {"AlreadyNormalizedIsUnchanged", "example.com.", "example.com."},
    {"EmptyBecomesRoot", "", "."},
    {"RootStaysRoot", ".", "."},
    {"AllUpperWithTrailingDot", "WWW.EXAMPLE.COM.", "www.example.com."},
    {"LeavesNonLetterAsciiUntouched", "A-1_b*.Z9", "a-1_b*.z9."},
    // 0xC3 0x89 is UTF-8 'É'; 0xC0 and 0xDE are Latin-1 capitals. None may be altered.
    {"LeavesHighBytesUntouched", "\xC3\x89\xC0\xDE" "AB", "\xC3\x89\xC0\xDE" "ab."},
    {"DoesNotValidateDoubleDot", "A..B", "a..b."},
    {"DoesNotValidateLeadingDot", ".A", ".a."},
    {"PreservesEmbeddedNul", std::string("A\0B", 3), std::string("a\0b.", 4)},
};

class Normalize : public ::testing::TestWithParam<NormalizeCase> {};

TEST_P(Normalize, Matches) {
  const auto& c = GetParam();
  EXPECT_SHOW_EQ_AS("normalize(" + mw::test::describe(c.input) + ")", mw::normalize(c.input),
                    c.expected);
}

INSTANTIATE_TEST_SUITE_P(DnsName, Normalize, ::testing::ValuesIn(kNormalizeCases),
                         case_name<NormalizeCase>);

TEST(DnsNameNormalize, UpperAndLowerCaseCoalesce) {
  EXPECT_SHOW_EQ(mw::normalize("Example.COM"), mw::normalize("example.com."));
}

// ---- is_valid ----

const std::vector<IsValidCase> kIsValidCases = {
    {"OrdinaryName", "example.com.", true},
    {"SingleLabel", "a.", true},
    {"ThreeLabels", "www.example.com.", true},
    {"Root", ".", true},
    {"Empty", "", false},
    {"MissingTrailingDot", "example.com", false},
    {"EmptyLabelInMiddle", "a..b.", false},
    {"LeadingDot", ".a.", false},
    {"OnlyDots", "..", false},
    {"EmptyLabelAtEnd", "a..", false},
    {"Label63Bytes", make_name(1, 63), true},
    {"Label64Bytes", make_name(1, 64), false},
    {"Label64BytesInMiddle", "a." + make_name(1, 64) + "com.", false},
    // 3 x 63-byte labels + 1 x 61-byte label, each with its dot: 3*64 + 62 = 254 bytes.
    {"Name254Bytes", make_name(3, 63) + std::string(61, 'a') + ".", true},
    {"Name255Bytes", make_name(3, 63) + std::string(62, 'a') + ".", false},
};

class IsValid : public ::testing::TestWithParam<IsValidCase> {};

TEST_P(IsValid, Matches) {
  const auto& c = GetParam();
  EXPECT_SHOW_EQ_AS("is_valid(" + mw::test::describe(c.input) + ")", mw::is_valid(c.input),
                    c.expected);
}

INSTANTIATE_TEST_SUITE_P(DnsName, IsValid, ::testing::ValuesIn(kIsValidCases),
                         case_name<IsValidCase>);

TEST(DnsNameIsValid, AcceptsOutputOfNormalize) {
  EXPECT_SHOW_EQ(mw::is_valid(mw::normalize("Example.COM")), true);
  EXPECT_SHOW_EQ(mw::is_valid(mw::normalize("")), true);
}

TEST(DnsNameIsValid, IsNoexcept) {
  static_assert(noexcept(mw::is_valid(std::string_view{})));
  SUCCEED();
}

} // namespace
