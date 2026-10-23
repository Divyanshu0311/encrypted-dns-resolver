#ifndef TYPES_DOMAINNAME_HPP
#define TYPES_DOMAINNAME_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace types {
    class DomainName {
    private:
        std::vector<std::string> labels;

    public:
        DomainName() = default;

        DomainName(const std::vector<uint8_t>& msg, std::size_t pos = 0, std::size_t* next = nullptr) {
            std::size_t size    = 0;
            std::size_t end_pos = 0;
            bool jumped         = false;
            std::size_t jumps   = 0;

            while (true) {
                if (pos >= msg.size()) throw std::runtime_error("DomainName: read past end of message");
                uint8_t len = msg[pos];

                if (len == 0) {
                    if (!jumped) end_pos = pos + 1;
                    break; // Done
                }

                if ((len & 0xC0) == 0xC0) {
                    // Compression pointer
                    if (pos + 1 >= msg.size()) throw std::runtime_error("DomainName: truncated compression pointer");
                    if (!jumped) end_pos = pos + 2;
                    jumped = true;
                    if (++jumps > 128) throw std::runtime_error("DomainName: too many compression pointers (loop?)");
                    pos = (static_cast<std::size_t>(len & 0x3F) << 8) | msg[pos + 1];
                    continue;
                }

                if ((len & 0xC0) != 0x00) throw std::runtime_error("DomainName: reserved label type");

                if ((size + len) > 254) throw std::runtime_error("DomainName: name too long");
                if ((pos + len + 1) > msg.size()) throw std::runtime_error("DomainName: read past end of message");

                labels.emplace_back(reinterpret_cast<const char*>(&msg[pos + 1]), len);

                pos += len + 1;
                size += len + 1;
            }
            if (next) *next = end_pos;
        }

        DomainName(const std::string& name) {
            if (name.empty()) throw std::runtime_error("DomainName: empty string");
            if (name == ".") return;

            std::string cur;
            std::size_t wire_len = 1;

            auto finish_label = [&]() {
                if (cur.empty()) throw std::runtime_error("DomainName: empty label");
                if (cur.size() > 63) throw std::runtime_error("DomainName: label too long");
                wire_len += cur.size() + 1; // length byte + data
                if (wire_len > 255) throw std::runtime_error("DomainName: name too long");
                labels.push_back(std::move(cur));
                cur.clear();
            };

            for (std::size_t i = 0; i < name.size(); ++i) {
                const char c = name[i];

                if (c == '.') {
                    finish_label(); // throws on empty label
                } else if (c == '\\') {
                    if (i + 1 >= name.size()) throw std::runtime_error("DomainName: dangling backslash");

                    const char n = name[i + 1];
                    if (n >= '0' && n <= '9') { // \DDD
                        if (i + 3 >= name.size()) throw std::runtime_error("DomainName: incomplete \\DDD escape");
                        const char d2 = name[i + 2];
                        const char d3 = name[i + 3];
                        if (d2 < '0' || d2 > '9' || d3 < '0' || d3 > '9') throw std::runtime_error("DomainName: invalid \\DDD escape");
                        const int value = (n - '0') * 100 + (d2 - '0') * 10 + (d3 - '0');
                        if (value > 255) throw std::runtime_error("DomainName: \\DDD escape out of range");
                        cur += static_cast<char>(value);
                        i += 3;
                    } else { // \. \\ \x ...
                        cur += n;
                        i += 1;
                    }
                } else {
                    cur += c;
                }
            }

            // Name without a trailing dot: the last label is still pending.
            // With a trailing dot, `cur` is empty here and everything was already added.
            if (!cur.empty()) finish_label();
        }

        DomainName(const char* name) : DomainName(std::string(name)) {}

        std::vector<uint8_t> to_bytes() const noexcept {
            std::vector<uint8_t> result;
            for (const std::string& label : labels) {
                result.push_back(static_cast<uint8_t>(label.size()));
                result.append_range(label);
            }
            result.push_back(0);

            return result;
        }

        std::string to_string() const noexcept {
            if (labels.empty()) // root domain
                return ".";

            std::string result;
            for (std::size_t i = 0; i < labels.size(); ++i) {
                if (i != 0) result += '.';

                for (const char c : labels[i]) {
                    if (c == '.' || c == '\\' || c == ' ') {
                        result += '\\';
                        result += c;
                    } else if (c <= 0x20 || c >= 0x7F) { // control, space, non-ASCII
                        result += '\\';
                        result += '0' + c / 100;
                        result += '0' + (c / 10) % 10;
                        result += '0' + c % 10;
                    } else {
                        result += c;
                    }
                }
            }
            result += '.';

            return result;
        }

        std::vector<std::string> get_labels() const noexcept { return labels; }

        bool operator==(const DomainName& name) const noexcept {
            if (labels.size() != name.labels.size()) return false;
            for (std::size_t i = 0; i < labels.size(); i++) {
                std::string a = labels[i], b = name.labels[i];
                auto lower = [](char c) -> char {
                    if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
                    return c;
                };
                std::transform(a.begin(), a.end(), a.begin(), lower);
                std::transform(b.begin(), b.end(), b.begin(), lower);
                if (a != b) return false;
            }
            return true;
        };

        bool operator!=(const DomainName& name) const noexcept { return !operator==(name); }

        DomainName& operator+=(const DomainName& name) {
            std::size_t len = 0;
            for (const std::string& label : labels) len += label.size();
            for (const std::string& label : name.labels) len += label.size();
            len += labels.size() + name.labels.size();
            if (len > 254)
                throw std::runtime_error("DomainName: length overflow after addition");
            else
                labels.append_range(name.labels);
            return *this;
        }
    };

    inline DomainName operator+(DomainName lhs, const DomainName& rhs) {
        lhs += rhs;
        return lhs;
    }

} // namespace types

namespace std {
    template<>
    struct hash<types::DomainName> {
        size_t operator()(const types::DomainName& domain_name) const noexcept {
            auto lower = [](char c) -> char {
                if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
                return c;
            };
            string name = domain_name.to_string();
            transform(name.begin(), name.end(), name.begin(), lower);
            return hash<string>{}(name);
        }
    };
} // namespace std

#endif
