#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/HostsFileResolver.hpp"

namespace {
    std::vector<uint8_t> wire(const types::DomainName& d) {
        return d;
    }

    class MockResolver : public backend::Resolver {
    public:
        int calls = 0;
        types::ResolveResult result;

        types::ResolveResult resolve(const types::DomainName&, const types::RecordType, const types::RecordClass, const bool = true) override {
            ++calls;
            return result;
        }
    };

    class HostsFileResolverTest : public ::testing::Test {
    protected:
        std::filesystem::path path;

        void SetUp() override {
            const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
            path             = std::filesystem::temp_directory_path() / (std::string("hosts_") + info->test_suite_name() + "_" + info->name() + ".txt");
        }

        void TearDown() override {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }

        std::string write(const std::string& content) {
            {
                std::ofstream out(path);
                out << content;
            }
            return path.string();
        }
    };

    const char* const kHosts = "# a comment line\n"
                               "127.0.0.1 localhost local.test\n"
                               "::1 localhost\n"
                               "\n"
                               "192.0.2.10   host.example.com.   \n";
} // namespace

TEST_F(HostsFileResolverTest, ResolvesIPv4Address) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("localhost."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(res.rcode, types::Rcode::NoError);
    ASSERT_EQ(res.answer.size(), 1u);
    EXPECT_EQ(res.answer[0].type, types::RecordType::A);
    EXPECT_EQ(res.answer[0].rdata, std::vector<uint8_t>({ 127, 0, 0, 1 }));
}

TEST_F(HostsFileResolverTest, ResolvesIPv6Address) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("localhost."), types::RecordType::AAAA, types::RecordClass::IN);
    ASSERT_EQ(res.answer.size(), 1u);
    EXPECT_EQ(res.answer[0].type, types::RecordType::AAAA);
    EXPECT_EQ(res.answer[0].rdata.size(), 16u);
    EXPECT_EQ(res.answer[0].rdata[15], 1);
}

TEST_F(HostsFileResolverTest, MultipleNamesOnOneLine) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("local.test."), types::RecordType::A, types::RecordClass::IN);
    ASSERT_EQ(res.answer.size(), 1u);
    EXPECT_EQ(res.answer[0].rdata, std::vector<uint8_t>({ 127, 0, 0, 1 }));
}

TEST_F(HostsFileResolverTest, ToleratesTrailingWhitespaceAndBlankLines) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("host.example.com."), types::RecordType::A, types::RecordClass::IN);
    ASSERT_EQ(res.answer.size(), 1u);
    EXPECT_EQ(res.answer[0].rdata, std::vector<uint8_t>({ 192, 0, 2, 10 }));
}

TEST_F(HostsFileResolverTest, LookupIsCaseInsensitive) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("LOCALHOST."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(res.answer.size(), 1u);
}

TEST_F(HostsFileResolverTest, ReverseLookupReturnsAllNames) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("1.0.0.127.in-addr.arpa."), types::RecordType::PTR, types::RecordClass::IN);
    ASSERT_EQ(res.answer.size(), 2u);
    EXPECT_EQ(res.answer[0].rdata, wire(types::DomainName("localhost.")));
    EXPECT_EQ(res.answer[1].rdata, wire(types::DomainName("local.test.")));
}

TEST_F(HostsFileResolverTest, CommentsAreIgnored) {
    backend::HostsFileResolver resolver(write("#127.0.0.1 hidden\n127.0.0.1 visible\n"), nullptr);

    auto hidden = resolver.resolve(types::DomainName("hidden."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(hidden.rcode, types::Rcode::Refused);

    auto visible = resolver.resolve(types::DomainName("visible."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(visible.answer.size(), 1u);
}

TEST_F(HostsFileResolverTest, UnknownNameWithoutFallbackIsRefused) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("unknown.example."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(res.rcode, types::Rcode::Refused);
    EXPECT_TRUE(res.answer.empty());
}

TEST_F(HostsFileResolverTest, WrongTypeWithoutFallbackIsRefused) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("host.example.com."), types::RecordType::MX, types::RecordClass::IN);
    EXPECT_EQ(res.rcode, types::Rcode::Refused);
}

TEST_F(HostsFileResolverTest, NonInClassSkipsHostsFile) {
    backend::HostsFileResolver resolver(write(kHosts), nullptr);

    auto res = resolver.resolve(types::DomainName("localhost."), types::RecordType::A, types::RecordClass::CH);
    EXPECT_EQ(res.rcode, types::Rcode::Refused);
}

TEST_F(HostsFileResolverTest, FallbackUsedForUnknownNames) {
    MockResolver fallback;
    fallback.result.rcode = types::Rcode::NXDomain;
    backend::HostsFileResolver resolver(write(kHosts), &fallback);

    auto res = resolver.resolve(types::DomainName("unknown.example."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(fallback.calls, 1);
    EXPECT_EQ(res.rcode, types::Rcode::NXDomain);
}

TEST_F(HostsFileResolverTest, FallbackNotUsedWhenHostsFileAnswers) {
    MockResolver fallback;
    backend::HostsFileResolver resolver(write(kHosts), &fallback);

    auto res = resolver.resolve(types::DomainName("localhost."), types::RecordType::A, types::RecordClass::IN);
    EXPECT_EQ(fallback.calls, 0);
    EXPECT_EQ(res.answer.size(), 1u);
}

TEST_F(HostsFileResolverTest, MissingFileThrows) {
    EXPECT_THROW(backend::HostsFileResolver((path.parent_path() / "no_such_hosts_file").string(), nullptr), std::runtime_error);
}

TEST_F(HostsFileResolverTest, InvalidIpThrows) {
    const std::string p = write("notanip example.com\n");
    EXPECT_THROW(backend::HostsFileResolver(p, nullptr), std::runtime_error);
}

TEST_F(HostsFileResolverTest, InvalidDomainNameThrows) {
    const std::string p = write("127.0.0.1 a..b\n");
    EXPECT_THROW(backend::HostsFileResolver(p, nullptr), std::runtime_error);
}
