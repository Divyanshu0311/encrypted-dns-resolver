#ifndef TYPES_DOMAINNAME_HPP
#define TYPES_DOMAINNAME_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace types {
    class DomainName {
    private:
        std::vector<std::string> labels;

    public:
        bool absolute = true;
        DomainName()  = default;

        DomainName(const std::vector<uint8_t>& msg, std::size_t pos = 0);

        DomainName(const std::string& name);

        operator std::vector<uint8_t>() const;

        operator std::string() const;

        const std::vector<std::string>& get_labels() const noexcept { return labels; }

        bool operator==(const DomainName& name) const noexcept;

        bool operator!=(const DomainName& name) const noexcept { return !operator==(name); }

        DomainName& operator+=(const DomainName& name);

        bool is_ancestor_of(const DomainName& name) const noexcept;

        bool is_descendent_of(const DomainName& name) const noexcept;

        DomainName parent() const noexcept;
    };

    DomainName operator+(DomainName lhs, const DomainName& rhs);

} // namespace types

namespace std {
    template<>
    struct hash<types::DomainName> {
        size_t operator()(const types::DomainName& domain_name) const noexcept;
    };
} // namespace std

#endif
