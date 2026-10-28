#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include "DomainName.hpp"

namespace {
    // DomainName converts implicitly to both std::string and std::vector<uint8_t>,
    // so these helpers keep gtest and the conversions unambiguous.
    std::string str(const types::DomainName& d) {
        return d;
    }

    std::vector<uint8_t> wire(const types::DomainName& d) {
        return d;
    }
} // namespace

// ---- Parsing from text -----------------------------------------------------

TEST(DomainName, ParsesAbsoluteName) {
    types::DomainName d("www.example.com.");
    EXPECT_TRUE(d.absolute);
    ASSERT_EQ(d.get_labels().size(), 3u);
    EXPECT_EQ(d.get_labels()[0], "www");
    EXPECT_EQ(d.get_labels()[1], "example");
    EXPECT_EQ(d.get_labels()[2], "com");
}

TEST(DomainName, NameWithoutTrailingDotIsRelative) {
    types::DomainName d("www.example.com");
    EXPECT_FALSE(d.absolute);
    EXPECT_EQ(d.get_labels().size(), 3u);
}

TEST(DomainName, RootName) {
    types::DomainName root(".");
    EXPECT_TRUE(root.absolute);
    EXPECT_TRUE(root.get_labels().empty());
    EXPECT_EQ(str(root), ".");
    EXPECT_EQ(wire(root), std::vector<uint8_t>({ 0 }));
}

TEST(DomainName, RejectsEmptyString) {
    EXPECT_THROW(types::DomainName(""), std::runtime_error);
}

TEST(DomainName, RejectsEmptyLabels) {
    EXPECT_THROW(types::DomainName("a..b."), std::runtime_error);
    EXPECT_THROW(types::DomainName(".com"), std::runtime_error);
}

TEST(DomainName, LabelLengthLimit) {
    EXPECT_NO_THROW(types::DomainName(std::string(63, 'a') + "."));
    EXPECT_THROW(types::DomainName(std::string(64, 'a') + "."), std::runtime_error);
}

TEST(DomainName, TotalLengthLimit) {
    std::string too_long;
    for (int i = 0; i < 100; ++i) too_long += "abc.";
    EXPECT_THROW(types::DomainName{ too_long }, std::runtime_error);
}

TEST(DomainName, EscapedDotStaysInsideLabel) {
    types::DomainName d("a\\.b.example.");
    ASSERT_EQ(d.get_labels().size(), 2u);
    EXPECT_EQ(d.get_labels()[0], "a.b");
    EXPECT_EQ(str(d), "a\\.b.example.");
}

TEST(DomainName, DecimalEscape) {
    types::DomainName d("\\065bc.com.");
    ASSERT_EQ(d.get_labels().size(), 2u);
    EXPECT_EQ(d.get_labels()[0], "Abc");
}

TEST(DomainName, RejectsBadEscapes) {
    EXPECT_THROW(types::DomainName("abc\\"), std::runtime_error);     // dangling backslash
    EXPECT_THROW(types::DomainName("a\\0"), std::runtime_error);      // incomplete \DDD
    EXPECT_THROW(types::DomainName("a\\0x1.b."), std::runtime_error); // non-digit in \DDD
    EXPECT_THROW(types::DomainName("a\\999.b."), std::runtime_error); // out of range
}

// ---- Text and wire output ----------------------------------------------------

TEST(DomainName, ToStringRoundTrip) {
    EXPECT_EQ(str(types::DomainName("www.example.com.")), "www.example.com.");
    EXPECT_EQ(str(types::DomainName("www.example.com")), "www.example.com");
}

TEST(DomainName, ToWireFormat) {
    const std::vector<uint8_t> expected = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    EXPECT_EQ(wire(types::DomainName("example.com.")), expected);
}

TEST(DomainName, RelativeNameHasNoTerminatingZero) {
    const std::vector<uint8_t> expected = { 3, 'w', 'w', 'w' };
    EXPECT_EQ(wire(types::DomainName("www")), expected);
}

// ---- Parsing from wire format ----------------------------------------------

TEST(DomainName, WireRoundTrip) {
    types::DomainName original("www.example.com.");
    types::DomainName parsed(wire(original), 0);
    EXPECT_TRUE(original == parsed);
}

TEST(DomainName, WireParsingHonorsStartOffset) {
    std::vector<uint8_t> msg = { 0xAA, 0xBB, 3, 'c', 'o', 'm', 0 };
    types::DomainName d(msg, 2);
    EXPECT_EQ(str(d), "com.");
}

TEST(DomainName, FollowsCompressionPointer) {
    // offset 0: "com."   offset 5: "www" + pointer to offset 0
    std::vector<uint8_t> msg = { 3, 'c', 'o', 'm', 0, 3, 'w', 'w', 'w', 0xC0, 0x00 };
    types::DomainName d(msg, 5);
    EXPECT_EQ(str(d), "www.com.");
}

TEST(DomainName, RejectsMalformedWire) {
    EXPECT_THROW(types::DomainName(std::vector<uint8_t>{}, 0), std::runtime_error);             // empty
    EXPECT_THROW(types::DomainName(std::vector<uint8_t>{ 3, 'a' }, 0), std::runtime_error);     // truncated label
    EXPECT_THROW(types::DomainName(std::vector<uint8_t>{ 0xC0 }, 0), std::runtime_error);       // truncated pointer
    EXPECT_THROW(types::DomainName(std::vector<uint8_t>{ 0x40, 0x00 }, 0), std::runtime_error); // reserved label type
    EXPECT_THROW(types::DomainName(std::vector<uint8_t>{ 0xC0, 0x00 }, 0), std::runtime_error); // pointer loop
}

// ---- Comparison ---------------------------------------------------------------

TEST(DomainName, EqualityIsCaseInsensitive) {
    EXPECT_TRUE(types::DomainName("Example.COM.") == types::DomainName("example.com."));
    EXPECT_FALSE(types::DomainName("Example.COM.") != types::DomainName("example.com."));
}

TEST(DomainName, DifferentNamesAreNotEqual) {
    EXPECT_TRUE(types::DomainName("example.com.") != types::DomainName("example.org."));
    EXPECT_TRUE(types::DomainName("a.example.com.") != types::DomainName("example.com."));
}

TEST(DomainName, AbsoluteAndRelativeAreNotEqual) {
    EXPECT_TRUE(types::DomainName("example.com.") != types::DomainName("example.com"));
}

// ---- Concatenation -------------------------------------------------------------

TEST(DomainName, AppendRelativeToAbsolute) {
    types::DomainName host("www");
    host += types::DomainName("example.com.");
    EXPECT_TRUE(host.absolute);
    EXPECT_EQ(str(host), "www.example.com.");
}

TEST(DomainName, OperatorPlus) {
    types::DomainName result = types::DomainName("*") + types::DomainName("example.com.");
    EXPECT_EQ(str(result), "*.example.com.");
}

TEST(DomainName, CannotAppendToAbsoluteName) {
    types::DomainName d("example.com.");
    EXPECT_THROW(d += types::DomainName("x."), std::runtime_error);
}

TEST(DomainName, AppendOverflowThrows) {
    types::DomainName left(std::string(60, 'a') + "." + std::string(60, 'b') + "." + std::string(60, 'c'));
    types::DomainName right(std::string(60, 'd') + "." + std::string(60, 'e') + ".");
    EXPECT_THROW(left += right, std::runtime_error);
}

// ---- Hierarchy -------------------------------------------------------------------

TEST(DomainName, IsAncestorOf) {
    types::DomainName zone("example.com.");
    EXPECT_TRUE(zone.is_ancestor_of(types::DomainName("www.example.com.")));
    EXPECT_TRUE(zone.is_ancestor_of(zone));
    EXPECT_FALSE(zone.is_ancestor_of(types::DomainName("example.org.")));
    EXPECT_FALSE(types::DomainName("www.example.com.").is_ancestor_of(zone));
}

TEST(DomainName, RootIsAncestorOfEverything) {
    EXPECT_TRUE(types::DomainName(".").is_ancestor_of(types::DomainName("www.example.com.")));
}

TEST(DomainName, IsDescendentOf) {
    types::DomainName zone("example.com.");
    EXPECT_TRUE(types::DomainName("www.example.com.").is_descendent_of(zone));
    EXPECT_TRUE(zone.is_descendent_of(zone));
    EXPECT_FALSE(zone.is_descendent_of(types::DomainName("www.example.com.")));
}

TEST(DomainName, HierarchyIsCaseInsensitive) {
    EXPECT_TRUE(types::DomainName("EXAMPLE.com.").is_ancestor_of(types::DomainName("www.Example.COM.")));
}

TEST(DomainName, HierarchyRequiresMatchingAbsoluteness) {
    EXPECT_FALSE(types::DomainName("example.com").is_ancestor_of(types::DomainName("www.example.com.")));
    EXPECT_FALSE(types::DomainName("www.example.com.").is_descendent_of(types::DomainName("example.com")));
}

TEST(DomainName, Parent) {
    EXPECT_EQ(str(types::DomainName("www.example.com.").parent()), "example.com.");
    EXPECT_EQ(str(types::DomainName("com.").parent()), ".");
}

TEST(DomainName, ParentOfRootIsRoot) {
    EXPECT_EQ(str(types::DomainName(".").parent()), ".");
}

// ---- Hashing -----------------------------------------------------------------------

TEST(DomainName, HashIsCaseInsensitive) {
    std::hash<types::DomainName> h;
    EXPECT_EQ(h(types::DomainName("Example.COM.")), h(types::DomainName("example.com.")));
}

TEST(DomainName, HashDiffersForDifferentNames) {
    std::hash<types::DomainName> h;
    EXPECT_NE(h(types::DomainName("example.com.")), h(types::DomainName("example.org.")));
}
