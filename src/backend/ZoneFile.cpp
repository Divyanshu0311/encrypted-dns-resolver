#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "IP.hpp"
#include "backend/ZoneFile.hpp"
#include "utils.hpp"

namespace backend {
    static uint64_t parse_uint(const std::string& s, uint64_t max) {
        if (s.empty()) throw std::runtime_error("ZoneFile: expected a number");
        uint64_t v = 0;
        for (char c : s) {
            if (!utils::is_digit(c)) throw std::runtime_error("ZoneFile: expected a number, got '" + s + "'");
            v = v * 10 + (c - '0');
            if (v > max) throw std::runtime_error("ZoneFile: number out of range: " + s);
        }
        return v;
    }

    static uint32_t parse_ttl(const std::string& s) {
        uint64_t total = 0, cur = 0;
        bool have = false;
        for (char c : s) {
            if (utils::is_digit(c)) {
                cur  = cur * 10 + (c - '0');
                have = true;
            } else {
                uint64_t mult;
                switch (c | 0x20) {
                case 's':
                    mult = 1;
                    break;
                case 'm':
                    mult = 60;
                    break;
                case 'h':
                    mult = 3600;
                    break;
                case 'd':
                    mult = 86400;
                    break;
                case 'w':
                    mult = 604800;
                    break;
                default:
                    throw std::runtime_error("ZoneFile: invalid TTL '" + s + "'");
                }
                if (!have) throw std::runtime_error("ZoneFile: invalid TTL '" + s + "'");
                total += cur * mult;
                cur  = 0;
                have = false;
            }
            if (total > 0xFFFFFFFFull || cur > 0xFFFFFFFFull) throw std::runtime_error("ZoneFile: TTL out of range");
        }
        total += cur;
        if (total > 0xFFFFFFFFull) throw std::runtime_error("ZoneFile: TTL out of range");
        return total;
    }

    static std::string unescape(const std::string& tok) {
        std::string t = tok;
        if (!t.empty() && t[0] == '"') t = t.substr(1, t.size() >= 2 ? t.size() - 2 : 0);
        std::string out;
        for (std::size_t i = 0; i < t.size(); ++i) {
            if (t[i] != '\\') {
                out += t[i];
            } else if (i + 1 >= t.size()) {
                throw std::runtime_error("ZoneFile: dangling backslash");
            } else if (utils::is_digit(t[i + 1])) {
                if (i + 3 >= t.size() || !utils::is_digit(t[i + 2]) || !utils::is_digit(t[i + 3])) throw std::runtime_error("ZoneFile: invalid \\DDD escape");
                int v = (t[i + 1] - '0') * 100 + (t[i + 2] - '0') * 10 + (t[i + 3] - '0');
                if (v > 255) throw std::runtime_error("ZoneFile: \\DDD escape out of range");
                out += static_cast<char>(v);
                i += 3;
            } else {
                out += t[++i];
            }
        }
        return out;
    }

    static std::vector<uint8_t> decode_hex(const std::string& s) {
        if (s.size() % 2) throw std::runtime_error("ZoneFile: hex data has odd length");
        std::vector<uint8_t> out;
        auto val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::runtime_error("ZoneFile: invalid hex digit");
        };
        for (std::size_t i = 0; i < s.size(); i += 2) out.push_back(val(s[i]) * 16 + val(s[i + 1]));
        return out;
    }

    static std::vector<uint8_t> decode_base64(const std::string& s) {
        static const std::string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<uint8_t> out;
        uint32_t acc = 0;
        int bits     = 0;
        for (char c : s) {
            if (c == '=') break;
            std::size_t v = alpha.find(c);
            if (v == std::string::npos) throw std::runtime_error("ZoneFile: invalid base64 character");
            acc = (acc << 6) | static_cast<uint32_t>(v);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back((acc >> bits) & 0xFF);
            }
        }
        return out;
    }

    static inline types::DomainName resolve_name(const std::string& tok, const types::DomainName& origin) {
        if (tok == "@") return origin;
        types::DomainName name(tok);
        return name.absolute ? name : name + origin;
    }



    std::vector<types::ResourceRecord> records_from_zone_file(types::DomainName origin, const std::string& zone_file) {
        std::vector<types::ResourceRecord> records;
        std::optional<uint32_t> default_ttl, last_ttl;
        std::optional<types::DomainName> last_owner;
        types::RecordClass last_class = types::RecordClass::IN;

        std::string cur_file;
        std::filesystem::path cur_dir;
        int include_depth = 0;
        std::function<void(const std::string&)> parse_text;

        // Handle one logical line
        auto handle = [&](const std::vector<std::string>& tok, bool leading_ws) {
            // Directives
            if (tok[0][0] == '$') {
                std::string directive = utils::upper(tok[0]);
                if (directive == "$ORIGIN" && tok.size() == 2)
                    origin = resolve_name(tok[1], origin);
                else if (directive == "$TTL" && tok.size() == 2)
                    default_ttl = parse_ttl(tok[1]);
                else if (directive == "$INCLUDE" && (tok.size() == 2 || tok.size() == 3)) {
                    if (include_depth >= 10) throw std::runtime_error("ZoneFile: $INCLUDE nested too deeply");
                    std::filesystem::path p = cur_dir / unescape(tok[1]);
                    std::ifstream in(p, std::ios::binary);
                    if (!in) throw std::runtime_error("ZoneFile: cannot open $INCLUDE file '" + p.string() + "'");
                    std::stringstream ss;
                    ss << in.rdbuf();

                    // An origin given to $INCLUDE (and any $ORIGIN inside the file) only applies to that file
                    types::DomainName saved_origin  = origin;
                    std::string saved_file          = cur_file;
                    std::filesystem::path saved_dir = cur_dir;
                    if (tok.size() == 3) origin = resolve_name(tok[2], origin);
                    cur_file = p.string();
                    cur_dir  = p.parent_path();
                    ++include_depth;
                    parse_text(ss.str());
                    --include_depth;
                    origin   = saved_origin;
                    cur_file = saved_file;
                    cur_dir  = saved_dir;
                } else
                    throw std::runtime_error("ZoneFile: unsupported or malformed directive " + tok[0]);
                return;
            }

            // Owner
            std::size_t idx = 0;
            types::DomainName owner;
            if (leading_ws) {
                if (!last_owner) throw std::runtime_error("ZoneFile: no owner name and no previous record");
                owner = *last_owner;
            } else {
                owner = resolve_name(tok[idx++], origin);
            }
            last_owner = owner;

            // [ttl] [class] in either order
            std::optional<uint32_t> ttl;
            std::optional<types::RecordClass> rclass;
            while (idx < tok.size()) {
                if (!ttl && utils::is_digit(tok[idx][0]))
                    ttl = parse_ttl(tok[idx++]);
                else if (auto c = types::record_class_from_string(tok[idx]); c && !rclass) {
                    rclass = c;
                    ++idx;
                } else
                    break;
            }
            if (idx >= tok.size()) throw std::runtime_error("ZoneFile: missing record type");

            // type (mnemonic or TYPEnnn)
            types::RecordType type;
            {
                const std::string& t = tok[idx++];
                if (auto rt = types::record_type_from_string(t))
                    type = *rt;
                else if (utils::upper(t).starts_with("TYPE"))
                    type = static_cast<types::RecordType>(parse_uint(t.substr(4), 0xFFFF));
                else
                    throw std::runtime_error("ZoneFile: unknown record type '" + t + "'");
            }

            // rdata
            std::vector<std::string> r(tok.begin() + idx, tok.end());
            std::size_t p = 0;
            std::vector<uint8_t> rd;

            auto next = [&]() -> const std::string& {
                if (p >= r.size()) throw std::runtime_error("ZoneFile: missing RDATA field");
                return r[p++];
            };
            auto put = [&](uint64_t v, int bytes) {
                for (int s = (bytes - 1) * 8; s >= 0; s -= 8) rd.push_back((v >> s) & 0xFF);
            };
            auto num  = [&](int bytes) { put(parse_uint(next(), (bytes == 8 ? ~0ull : (1ull << (bytes * 8)) - 1)), bytes); };
            auto tm   = [&]() { put(parse_ttl(next()), 4); };
            auto name = [&]() {
                std::vector<uint8_t> b = resolve_name(next(), origin);
                rd.insert(rd.end(), b.begin(), b.end());
            };
            auto str = [&]() { // length-prefixed character-string
                std::string s = unescape(next());
                if (s.size() > 255) throw std::runtime_error("ZoneFile: character-string longer than 255 bytes");
                rd.push_back(s.size());
                rd.insert(rd.end(), s.begin(), s.end());
            };
            auto rest = [&]() {
                std::string s;
                while (p < r.size()) s += r[p++];
                return s;
            };
            auto bytes = [&](const std::vector<uint8_t>& b) { rd.insert(rd.end(), b.begin(), b.end()); };

            if (!r.empty() && r[0] == "\\#") { // RFC 3597 generic: \# <len> <hex>
                ++p;
                std::size_t len = parse_uint(next(), 0xFFFF);
                rd              = decode_hex(rest());
                if (rd.size() != len) throw std::runtime_error("ZoneFile: generic RDATA length mismatch");
            } else {
                switch (type) {
                case types::RecordType::A:
                case types::RecordType::AAAA: {
                    types::IP ip(next());
                    if (ip.is_ipv6() != (type == types::RecordType::AAAA)) throw std::runtime_error("ZoneFile: address family does not match record type");
                    bytes(ip);
                    break;
                }
                case types::RecordType::NS:
                case types::RecordType::CNAME:
                case types::RecordType::PTR:
                case types::RecordType::DNAME:
                case types::RecordType::MB:
                case types::RecordType::MD:
                case types::RecordType::MF:
                case types::RecordType::MG:
                case types::RecordType::MR:
                    name();
                    break;
                case types::RecordType::MX:
                case types::RecordType::AFSDB:
                case types::RecordType::RT:
                case types::RecordType::KX:
                    num(2);
                    name();
                    break;
                case types::RecordType::MINFO:
                case types::RecordType::RP:
                    name();
                    name();
                    break;
                case types::RecordType::SOA:
                    name();
                    name();
                    num(4); // serial
                    tm();
                    tm();
                    tm();
                    tm(); // refresh retry expire minimum
                    break;
                case types::RecordType::HINFO:
                    str();
                    str();
                    break;
                case types::RecordType::TXT:
                case types::RecordType::SPF:
                    str();
                    break;
                case types::RecordType::SRV:
                    num(2);
                    num(2);
                    num(2);
                    name();
                    break;
                case types::RecordType::CAA: {
                    num(1);
                    str(); // tag
                    std::string v = unescape(next());
                    rd.insert(rd.end(), v.begin(), v.end());
                    break;
                }
                case types::RecordType::SSHFP:
                    num(1);
                    num(1);
                    bytes(decode_hex(rest()));
                    break;
                case types::RecordType::DS:
                case types::RecordType::CDS:
                    num(2);
                    num(1);
                    num(1);
                    bytes(decode_hex(rest()));
                    break;
                case types::RecordType::DNSKEY:
                case types::RecordType::CDNSKEY:
                    num(2);
                    num(1);
                    num(1);
                    bytes(decode_base64(rest()));
                    break;
                case types::RecordType::TLSA:
                case types::RecordType::SMIMEA:
                    num(1);
                    num(1);
                    num(1);
                    bytes(decode_hex(rest()));
                    break;
                default:
                    throw std::runtime_error("ZoneFile: unsupported record type; use generic syntax: \\# <length> <hex>");
                }
                if (p < r.size()) throw std::runtime_error("ZoneFile: unexpected extra field '" + r[p] + "'");
            }

            // ---- TTL: explicit > $TTL > previous > SOA minimum
            uint32_t final_ttl;
            if (ttl) {
                final_ttl = *ttl;
                last_ttl  = final_ttl;
            } else if (default_ttl) {
                final_ttl = *default_ttl;
            } else if (last_ttl) {
                final_ttl = *last_ttl;
            } else if (type == types::RecordType::SOA) {
                std::size_t n = rd.size();
                final_ttl     = (uint32_t(rd[n - 4]) << 24) | (uint32_t(rd[n - 3]) << 16) | (uint32_t(rd[n - 2]) << 8) | rd[n - 1];
            } else {
                throw std::runtime_error("ZoneFile: no TTL specified and no default available");
            }

            if (rclass) last_class = *rclass;
            records.push_back(types::ResourceRecord{ owner, type, last_class, final_ttl, rd });
        };

        // tokenizer: splits text into logical lines (handles comments, quotes, parentheses)
        parse_text = [&](const std::string& text) {
            const std::string file = cur_file;
            std::vector<std::string> tokens;
            bool leading_ws = false, bol = true;
            int depth        = 0;
            std::size_t line = 1, tok_line = 1;

            auto flush = [&]() {
                if (!tokens.empty()) {
                    try {
                        handle(tokens, leading_ws);
                    } catch (const std::exception& e) {
                        throw std::runtime_error("ZoneFile: " + file + ": line " + std::to_string(tok_line) + ": " + e.what());
                    }
                }
                tokens.clear();
                leading_ws = false;
            };

            const std::size_t n = text.size();
            std::size_t i       = 0;
            while (i < n) {
                char c = text[i];
                if (c == '\n') {
                    ++line;
                    ++i;
                    if (depth == 0) {
                        flush();
                        bol = true;
                    }
                    continue;
                }
                if (bol) {
                    bol = false;
                    if (c == ' ' || c == '\t') leading_ws = true;
                }
                if (c == ' ' || c == '\t' || c == '\r') {
                    ++i;
                } else if (c == ';') {
                    while (i < n && text[i] != '\n') ++i;
                } else if (c == '(') {
                    ++depth;
                    ++i;
                } else if (c == ')') {
                    if (depth == 0) throw std::runtime_error("ZoneFile: " + file + ": line " + std::to_string(line) + ": unbalanced ')'");
                    --depth;
                    ++i;
                } else {
                    if (tokens.empty()) tok_line = line;
                    std::string t;
                    if (c == '"') { // quoted string; keep the quotes so the type can be told apart later
                        t += c;
                        ++i;
                        bool closed = false;
                        while (i < n) {
                            char d = text[i++];
                            t += d;
                            if (d == '\\' && i < n) {
                                t += text[i++];
                            } else if (d == '"') {
                                closed = true;
                                break;
                            } else if (d == '\n') {
                                ++line;
                            }
                        }
                        if (!closed) throw std::runtime_error("ZoneFile: " + file + ": line " + std::to_string(tok_line) + ": unterminated string");
                    } else {
                        while (i < n) {
                            char d = text[i];
                            if (d == '\\' && i + 1 < n) {
                                t += d;
                                t += text[i + 1];
                                i += 2;
                                continue;
                            }
                            if (d == ' ' || d == '\t' || d == '\r' || d == '\n' || d == ';' || d == '(' || d == ')' || d == '"') break;
                            t += d;
                            ++i;
                        }
                    }
                    tokens.push_back(t);
                }
            }
            if (depth != 0) throw std::runtime_error("ZoneFile: " + file + ": unbalanced '('");
            flush();
        };

        std::ifstream in(zone_file, std::ios::binary);
        if (!in) throw std::runtime_error("ZoneFile: cannot open zone file '" + zone_file + "'");
        std::stringstream ss;
        ss << in.rdbuf();
        cur_file = zone_file;
        cur_dir  = std::filesystem::path(zone_file).parent_path();
        parse_text(ss.str());

        return records;
    }
} // namespace backend
