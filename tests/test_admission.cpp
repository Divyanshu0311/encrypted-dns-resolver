#include "mw/admission.hpp"

#include "support/show.hpp"
#include "support/temp_dir.hpp"

#include <gtest/gtest.h>

#include <string>

namespace {

    mw::DnsQuery query(const std::string& name, mw::RecordType type = mw::RecordType::A) {
        return mw::DnsQuery{ 0x1234, true, name, type, false, false };
    }

    mw::Admission parsed(const std::string& text) {
        auto admission = mw::Admission::parse(text);
        EXPECT_TRUE(admission.has_value()) << admission.error();
        return admission ? std::move(*admission) : mw::Admission{};
    }

} // namespace

TEST(Admission, DefaultRefusesNothing) {
    const mw::Admission admission;
    EXPECT_SHOW_EQ(admission.refuses(query("example.com.")), false);
    EXPECT_SHOW_EQ(admission.refuses(query(".")), false);
    EXPECT_SHOW_EQ(admission.blocked_count(), 0u);
}

TEST(Admission, RefusesTheNameAndEverythingUnderIt) {
    const auto admission = parsed("ads.example\n");
    EXPECT_SHOW_EQ(admission.refuses(query("ads.example.")), true);
    EXPECT_SHOW_EQ(admission.refuses(query("x.ads.example.")), true);
    EXPECT_SHOW_EQ(admission.refuses(query("a.b.ads.example.")), true);
    EXPECT_SHOW_EQ_AS("parent", admission.refuses(query("example.")), false);
    EXPECT_SHOW_EQ_AS("sibling", admission.refuses(query("news.example.")), false);
    EXPECT_SHOW_EQ_AS("shared suffix, different label", admission.refuses(query("badads.example.")), false);
}

TEST(Admission, IgnoresCaseAndTrailingDot) {
    const auto admission = parsed("Ads.Example.\n");
    EXPECT_SHOW_EQ(admission.refuses(query("ADS.example.")), true);
    EXPECT_SHOW_EQ(admission.refuses(query("x.aDs.ExAmPlE.")), true);
}

TEST(Admission, AppliesToEveryType) {
    const auto admission = parsed("ads.example\n");
    for (auto type : { mw::RecordType::A, mw::RecordType::AAAA, mw::RecordType::TXT, mw::RecordType::ANY }) {
        EXPECT_TRUE(admission.refuses(query("ads.example.", type)));
    }
}

TEST(Admission, LoneRootRefusesEveryQuery) {
    const auto admission = parsed(".\n");
    EXPECT_SHOW_EQ(admission.refuses(query("example.com.")), true);
    EXPECT_SHOW_EQ(admission.refuses(query(".")), true);
}

TEST(Admission, FileFormat) {
    const auto admission = parsed("# blocked names\n\n  ads.example   # tracker\n\ttrack.test\r\n# done");
    EXPECT_SHOW_EQ(admission.blocked_count(), 2u);
    EXPECT_SHOW_EQ(admission.refuses(query("ads.example.")), true);
    EXPECT_SHOW_EQ(admission.refuses(query("track.test.")), true);
}

TEST(Admission, BadLinesAreErrorsWithTheirLineNumber) {
    const auto two_names = mw::Admission::parse("ok.example\nads.example track.test\n");
    ASSERT_FALSE(two_names.has_value());
    EXPECT_SHOW_EQ(two_names.error(), "line 2: expected one name, got 'ads.example track.test'");

    const auto empty_label = mw::Admission::parse("\n\na..example\n");
    ASSERT_FALSE(empty_label.has_value());
    EXPECT_SHOW_EQ(empty_label.error().rfind("line 3:", 0), 0u);

    const auto long_label = mw::Admission::parse(std::string(64, 'a') + ".example\n");
    ASSERT_FALSE(long_label.has_value());
    EXPECT_SHOW_EQ(long_label.error().rfind("line 1:", 0), 0u);
}

TEST(Admission, Load) {
    support::TempDir dir;
    const auto good = mw::Admission::load(dir.write("blocked.txt", "ads.example\n"));
    ASSERT_TRUE(good.has_value()) << good.error();
    EXPECT_SHOW_EQ(good->refuses(query("x.ads.example.")), true);

    const auto none = mw::Admission::load("");
    ASSERT_TRUE(none.has_value());
    EXPECT_SHOW_EQ(none->blocked_count(), 0u);

    const auto missing = mw::Admission::load(dir.path() / "nope.txt");
    ASSERT_FALSE(missing.has_value());
    EXPECT_SHOW_EQ(missing.error().rfind("cannot read blocked_domains_file", 0), 0u);

    const auto bad = mw::Admission::load(dir.write("bad.txt", "a..b\n"));
    ASSERT_FALSE(bad.has_value());
    EXPECT_SHOW_EQ(bad.error().rfind("blocked_domains_file line 1:", 0), 0u);
}
