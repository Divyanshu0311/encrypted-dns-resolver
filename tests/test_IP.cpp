#include <gtest/gtest.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "IP.hpp"

namespace {
    // IP converts implicitly to string, vector<uint8_t> and DomainName.
    std::string str(const types::IP& ip) {
        return ip;
    }

    std::vector<uint8_t> bytes(const types::IP& ip) {
        return ip;
    }

    std::string reverse_name(const types::IP& ip) {
        types::DomainName d = ip;
        return d;
    }
} // namespace

TEST(IP, DefaultIsZeroIPv4) {
    types::IP ip;
    EXPECT_FALSE(ip.is_ipv6());
    EXPECT_EQ(str(ip), "0.0.0.0");
}

TEST(IP, ParsesIPv4) {
    types::IP ip(std::string("192.168.1.1"));
    EXPECT_FALSE(ip.is_ipv6());
    EXPECT_EQ(bytes(ip), std::vector<uint8_t>({ 192, 168, 1, 1 }));
    EXPECT_EQ(str(ip), "192.168.1.1");
}

TEST(IP, ParsesIPv6) {
    types::IP ip(std::string("::1"));
    EXPECT_TRUE(ip.is_ipv6());
    ASSERT_EQ(bytes(ip).size(), 16u);
    EXPECT_EQ(bytes(ip)[15], 1);
    EXPECT_EQ(str(ip), "::1");
}

TEST(IP, IPv6TextRoundTrip) {
    EXPECT_EQ(str(types::IP(std::string("2001:db8::1"))), "2001:db8::1");
}

TEST(IP, RejectsInvalidText) {
    EXPECT_THROW(types::IP(std::string("not an ip")), std::runtime_error);
    EXPECT_THROW(types::IP(std::string("256.1.1.1")), std::runtime_error);
    EXPECT_THROW(types::IP(std::string("")), std::runtime_error);
}

TEST(IP, ConstructsFromBytes) {
    types::IP v4(std::vector<uint8_t>{ 10, 0, 0, 1 });
    EXPECT_FALSE(v4.is_ipv6());
    EXPECT_EQ(str(v4), "10.0.0.1");

    types::IP v6(std::vector<uint8_t>(16, 0));
    EXPECT_TRUE(v6.is_ipv6());
    EXPECT_EQ(str(v6), "::");
}

TEST(IP, RejectsWrongByteLength) {
    EXPECT_THROW(types::IP(std::vector<uint8_t>{ 1, 2, 3 }), std::runtime_error);
    EXPECT_THROW(types::IP(std::vector<uint8_t>{}), std::runtime_error);
}

TEST(IP, ConstructsFromInAddr) {
    in_addr a{};
    ASSERT_EQ(inet_pton(AF_INET, "10.1.2.3", &a), 1);
    types::IP ip(a);
    EXPECT_FALSE(ip.is_ipv6());
    EXPECT_EQ(str(ip), "10.1.2.3");
}

TEST(IP, ConstructsFromIn6Addr) {
    in6_addr a{};
    ASSERT_EQ(inet_pton(AF_INET6, "fe80::1", &a), 1);
    types::IP ip(a);
    EXPECT_TRUE(ip.is_ipv6());
    EXPECT_EQ(str(ip), "fe80::1");
}

TEST(IP, ToIPv4) {
    types::IP v4(std::string("192.0.2.1"));
    auto a = v4.to_ipv4();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->s_addr, htonl(0xC0000201));
    EXPECT_FALSE(v4.to_ipv6().has_value());
}

TEST(IP, ToIPv6) {
    types::IP v6(std::string("::1"));
    auto a = v6.to_ipv6();
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->s6_addr[15], 1);
    EXPECT_FALSE(v6.to_ipv4().has_value());
}

TEST(IP, Equality) {
    EXPECT_TRUE(types::IP(std::string("1.2.3.4")) == types::IP(std::string("1.2.3.4")));
    EXPECT_TRUE(types::IP(std::string("1.2.3.4")) != types::IP(std::string("1.2.3.5")));
    EXPECT_TRUE(types::IP(std::string("::1")) != types::IP(std::string("1.2.3.4")));
}

TEST(IP, ReverseNameIPv4) {
    EXPECT_EQ(reverse_name(types::IP(std::string("192.0.2.1"))), "1.2.0.192.in-addr.arpa.");
}

TEST(IP, ReverseNameIPv6) {
    // ::1 is 31 zero nibbles followed by a 1, written least-significant nibble first
    std::string expected = "1.";
    for (int i = 0; i < 31; ++i) expected += "0.";
    expected += "ip6.arpa.";
    EXPECT_EQ(reverse_name(types::IP(std::string("::1"))), expected);
}
