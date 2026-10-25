#ifndef TESTS_SUPPORT_TEMP_DIR_HPP
#define TESTS_SUPPORT_TEMP_DIR_HPP

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

namespace support {
    // Per-test scratch directory, removed on destruction.
    class TempDir {
    public:
        TempDir() {
            const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
            std::string name = std::string("dns_test_") + (info ? info->test_suite_name() : "none") + "_" + (info ? info->name() : "none");
            std::replace(name.begin(), name.end(), '/', '_'); // parameterized test names contain '/'
            root_ = std::filesystem::temp_directory_path() / name;
            std::error_code ec;
            std::filesystem::remove_all(root_, ec);
            std::filesystem::create_directories(root_);
        }

        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(root_, ec);
        }

        TempDir(const TempDir&)            = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::filesystem::path& path() const { return root_; }

        // Writes root/relative (creating subdirectories) and returns its full path.
        std::string write(const std::string& relative, const std::string& content) const {
            const std::filesystem::path p = root_ / relative;
            std::filesystem::create_directories(p.parent_path());
            std::ofstream out(p, std::ios::binary);
            out << content;
            return p.string();
        }

    private:
        std::filesystem::path root_;
    };
} // namespace support

#endif
