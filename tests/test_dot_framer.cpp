#include "mw/dot_framer.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

using mw::DotFramer;
using mw::FrameStatus;

namespace {

    std::vector<std::byte> bytes(std::initializer_list<uint8_t> values) {
        std::vector<std::byte> out;
        for (uint8_t v : values) {
            out.push_back(std::byte{ v });
        }
        return out;
    }

    std::vector<std::byte> message_of(std::size_t size, uint8_t fill) {
        return std::vector<std::byte>(size, std::byte{ fill });
    }

    std::vector<std::byte> framed(const std::vector<std::byte>& message) {
        return mw::frame(message).value();
    }

    std::vector<std::byte> concat(std::vector<std::byte> first, const std::vector<std::byte>& second) {
        first.insert(first.end(), second.begin(), second.end());
        return first;
    }

} // namespace

TEST(DotFramer, EmptyFramerNeedsMoreData) {
    DotFramer framer;
    std::vector<std::byte> out;
    EXPECT_EQ(framer.next(out), FrameStatus::NeedMoreData);
}

TEST(DotFramer, ExtractsOneMessageFromOneFeed) {
    const auto message = message_of(29, 0xAB);
    DotFramer framer;
    framer.feed(framed(message));

    std::vector<std::byte> out;
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, message);
    EXPECT_EQ(framer.next(out), FrameStatus::NeedMoreData);
}

TEST(DotFramer, ReassemblesMessageFedOneByteAtATime) {
    const auto message = message_of(29, 0xAB);
    const auto wire    = framed(message);
    DotFramer framer;
    std::vector<std::byte> out;

    for (std::size_t i = 0; i + 1 < wire.size(); ++i) {
        framer.feed(std::span(wire).subspan(i, 1));
        ASSERT_EQ(framer.next(out), FrameStatus::NeedMoreData) << "after byte " << i;
    }
    framer.feed(std::span(wire).last(1));
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, message);
}

TEST(DotFramer, ExtractsTwoMessagesFromOneFeed) {
    const auto first  = message_of(29, 0x01);
    const auto second = message_of(40, 0x02);
    DotFramer framer;
    framer.feed(concat(framed(first), framed(second)));

    std::vector<std::byte> out;
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, first);
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, second);
    EXPECT_EQ(framer.next(out), FrameStatus::NeedMoreData);
}

TEST(DotFramer, KeepsStartOfNextMessageUntilItCompletes) {
    const auto first       = message_of(29, 0x01);
    const auto second      = message_of(40, 0x02);
    const auto second_wire = framed(second);
    const std::vector<std::byte> head(second_wire.begin(), second_wire.begin() + 5);
    const std::vector<std::byte> tail(second_wire.begin() + 5, second_wire.end());

    DotFramer framer;
    framer.feed(concat(framed(first), head));
    std::vector<std::byte> out;
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, first);
    EXPECT_EQ(framer.next(out), FrameStatus::NeedMoreData);

    framer.feed(tail);
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, second);
}

TEST(DotFramer, ZeroLengthIsInvalidAndStaysInvalid) {
    DotFramer framer;
    framer.feed(concat(bytes({ 0x00, 0x00 }), framed(message_of(29, 0xAB))));

    std::vector<std::byte> out;
    EXPECT_EQ(framer.next(out), FrameStatus::Invalid);
    EXPECT_EQ(framer.next(out), FrameStatus::Invalid);

    framer.feed(framed(message_of(29, 0xAB)));
    EXPECT_EQ(framer.next(out), FrameStatus::Invalid);
}

TEST(DotFramer, DeliversMessagesBeforeAZeroLength) {
    const auto message = message_of(29, 0xAB);
    DotFramer framer;
    framer.feed(concat(framed(message), bytes({ 0x00, 0x00 })));

    std::vector<std::byte> out;
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, message);
    EXPECT_EQ(framer.next(out), FrameStatus::Invalid);
}

TEST(DotFramer, HandlesLargestMessage) {
    const auto message = message_of(65535, 0xCD);
    DotFramer framer;
    framer.feed(framed(message));

    std::vector<std::byte> out;
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out.size(), 65535u);
    EXPECT_EQ(out, message);
}

TEST(DotFramer, ReplacesPreviousContentsOfOutput) {
    const auto message = message_of(29, 0xAB);
    DotFramer framer;
    framer.feed(framed(message));

    std::vector<std::byte> out = message_of(500, 0xFF);
    ASSERT_EQ(framer.next(out), FrameStatus::Complete);
    EXPECT_EQ(out, message);
}

TEST(DotFrame, PrefixesBigEndianLength) {
    const auto wire = framed(message_of(300, 0xAB));
    ASSERT_EQ(wire.size(), 302u);
    EXPECT_EQ(wire[0], std::byte{ 0x01 });
    EXPECT_EQ(wire[1], std::byte{ 0x2C });
}

TEST(DotFrame, RejectsMessagesThatDoNotFitTheLengthPrefix) {
    EXPECT_TRUE(mw::frame(message_of(65535, 0)).has_value());
    EXPECT_FALSE(mw::frame(message_of(65536, 0)).has_value());
}
