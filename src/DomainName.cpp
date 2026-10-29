#include <algorithm>
#include <stdexcept>

#include "DomainName.hpp"
#include "utils.hpp"

namespace types {
    DomainName::DomainName(const std::vector<uint8_t>& msg, std::size_t pos, std::size_t* next_pos) {
        std::size_t size  = 0;
        std::size_t jumps = 0;
        std::size_t end_pos;
        bool jumped = false;

        absolute = true;

        while (true) {
            if (pos >= msg.size()) throw std::runtime_error("DomainName: read past end of message");
            uint8_t len = msg[pos];

            if (len == 0) {
                if (!jumped) end_pos = pos;
                break; // Done
            }

            if ((len & 0xC0) == 0xC0) {
                // Compression pointer
                if (pos + 1 >= msg.size()) throw std::runtime_error("DomainName: truncated compression pointer");
                if (++jumps > 128) throw std::runtime_error("DomainName: too many compression pointers (loop?)");
                if (!jumped) {
                    end_pos = pos + 1;
                    jumped  = true;
                }
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
        if (next_pos) *next_pos = end_pos + 1;
    }

    DomainName::DomainName(const std::string& name) {
        if (name.empty()) throw std::runtime_error("DomainName: empty string");

        absolute = true;
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
            const unsigned char c = name[i];

            if (c == '.') {
                finish_label(); // throws on empty label
            } else if (c == '\\') {
                if (i + 1 >= name.size()) throw std::runtime_error("DomainName: dangling backslash");

                const unsigned char n = name[i + 1];
                if (n >= '0' && n <= '9') { // \DDD
                    if (i + 3 >= name.size()) throw std::runtime_error("DomainName: incomplete \\DDD escape");
                    const unsigned char d2 = name[i + 2];
                    const unsigned char d3 = name[i + 3];
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
        if (!cur.empty()) {
            finish_label();
            absolute = false;
        }
    }

    DomainName::operator std::vector<uint8_t>() const {
        std::vector<uint8_t> result;
        for (const std::string& label : labels) {
            result.push_back(label.size());
            result.append_range(label);
        }
        if (absolute) result.push_back(0);

        return result;
    }

    DomainName::operator std::string() const {
        std::string result;

        for (std::size_t i = 0; i < labels.size(); ++i) {
            if (i != 0) result += '.';

            for (const unsigned char c : labels[i]) {
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
        if (absolute) result += '.';

        return result;
    }

    bool DomainName::operator==(const DomainName& name) const noexcept {
        if (absolute != name.absolute) return false;
        return std::ranges::equal(labels, name.labels, {}, utils::lower, utils::lower);
    }

    DomainName& DomainName::operator+=(const DomainName& name) {
        if (absolute) throw std::runtime_error("DomainName: Cannot append to absolute domain");
        std::size_t len = 0;
        for (const std::string& label : labels) len += label.size();
        for (const std::string& label : name.labels) len += label.size();
        len += labels.size() + name.labels.size();
        if (len > 254) throw std::runtime_error("DomainName: length overflow after addition");
        labels.append_range(name.labels);
        absolute = name.absolute;
        return *this;
    }

    bool DomainName::is_ancestor_of(const DomainName& name) const noexcept {
        if (absolute != name.absolute) return false;
        return std::ranges::ends_with(name.labels, labels, {}, utils::lower, utils::lower);
    }

    bool DomainName::is_descendent_of(const DomainName& name) const noexcept {
        if (absolute != name.absolute) return false;
        return std::ranges::ends_with(labels, name.labels, {}, utils::lower, utils::lower);
    }

    DomainName DomainName::parent() const {
        DomainName parent_name(*this);
        if (!parent_name.labels.empty()) parent_name.labels.erase(parent_name.labels.begin());
        return parent_name;
    }

} // namespace types

std::size_t std::hash<types::DomainName>::operator()(const types::DomainName& domain_name) const noexcept {
    return hash<string>{}(utils::lower(domain_name));
}
