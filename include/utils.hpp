#ifndef UTILS_HPP
#define UTILS_HPP

namespace utils {
    class immovable {
    public:
        immovable()                            = default;
        immovable(const immovable&)            = delete;
        immovable(immovable&&)                 = delete;
        immovable& operator=(const immovable&) = delete;
        immovable& operator=(immovable&&)      = delete;
    };
} // namespace utils

#endif
