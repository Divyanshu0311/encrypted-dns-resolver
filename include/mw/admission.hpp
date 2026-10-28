#pragma once
#include <cstddef>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>

#include "mw/dns_message.hpp"
#include "mw/types.hpp"

namespace mw {

    // policy checks on a parsed query before it reaches the middleware. a hit is answered REFUSED;
    // the connection stays open and the source gets no strike
    class Admission {
    public:
        Admission() = default; // refuses nothing

        // one name per line, '#' starts a comment (also after a name), blank lines are skipped.
        // a name also covers every name under it, so a lone "." refuses every query
        static std::expected<Admission, std::string> parse(std::string_view text);

        // an empty path blocks nothing
        static std::expected<Admission, std::string> load(const std::filesystem::path& file);

        bool refuses(const DnsQuery& query) const;
        std::size_t blocked_count() const noexcept { return blocked_.size(); }

    private:
        std::unordered_set<DomainName> blocked_; // absolute names, compared case-insensitively
    };

} // namespace mw
