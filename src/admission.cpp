#include "mw/admission.hpp"

#include <exception>
#include <format>
#include <fstream>
#include <sstream>
#include <utility>

namespace mw {
    namespace {

        std::string_view trim(std::string_view s) {
            while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) {
                s.remove_prefix(1);
            }
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
                s.remove_suffix(1);
            }
            return s;
        }

    } // namespace

    std::expected<Admission, std::string> Admission::parse(std::string_view text) {
        Admission admission;
        std::size_t line_no = 0;
        while (!text.empty()) {
            const auto nl         = text.find('\n');
            std::string_view line = text.substr(0, nl);
            text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
            ++line_no;

            line = trim(line.substr(0, line.find('#')));
            if (line.empty()) {
                continue;
            }
            if (line.find_first_of(" \t") != std::string_view::npos) {
                return std::unexpected(std::format("line {}: expected one name, got '{}'", line_no, line));
            }
            try {
                DomainName name{ std::string(line) };
                name.absolute = true;
                admission.blocked_.insert(std::move(name));
            } catch (const std::exception& e) {
                return std::unexpected(std::format("line {}: '{}' is not a valid name ({})", line_no, line, e.what()));
            }
        }
        return admission;
    }

    std::expected<Admission, std::string> Admission::load(const std::filesystem::path& file) {
        if (file.empty()) {
            return Admission{};
        }
        std::ifstream in(file, std::ios::binary);
        if (!in) {
            return std::unexpected(std::format("cannot read blocked_domains_file '{}'", file.string()));
        }
        std::ostringstream buf;
        buf << in.rdbuf();
        auto admission = parse(buf.str());
        if (!admission) {
            return std::unexpected(std::format("blocked_domains_file {}", admission.error()));
        }
        return admission;
    }

    bool Admission::refuses(const types::DnsQuery& query) const {
        if (blocked_.empty()) {
            return false;
        }
        try {
            DomainName name{ query.name };
            name.absolute = true;
            // the name itself, then each parent up to and including the root
            while (true) {
                if (blocked_.contains(name)) {
                    return true;
                }
                if (name.get_labels().empty()) {
                    return false;
                }
                name = name.parent();
            }
        } catch (const std::exception&) {
            return false; // the parser only lets valid names through, so this is not expected
        }
    }

} // namespace mw
