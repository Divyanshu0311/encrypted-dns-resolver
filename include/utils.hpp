#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
namespace utils {
    class immovable {
    public:
        immovable()                            = default;
        immovable(const immovable&)            = delete;
        immovable(immovable&&)                 = delete;
        immovable& operator=(const immovable&) = delete;
        immovable& operator=(immovable&&)      = delete;
    };

    static inline std::string lower(std::string s) {
        for (char& c : s)
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        return s;
    }

    static inline std::string upper(std::string s) {
        for (char& c : s)
            if (c >= 'a' && c <= 'z') c += 'A' - 'a';
        return s;
    }

    static inline bool is_digit(const char c) {
        return (c >= '0') && (c <= '9');
    }
} // namespace utils

#endif
