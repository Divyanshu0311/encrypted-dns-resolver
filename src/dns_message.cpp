#include "dns_message.hpp"

#include <algorithm>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace types {
    namespace {

        constexpr std::size_t kHeaderSize        = 12;
        constexpr std::size_t kMaxLabelLength    = 63;
        constexpr std::size_t kMaxWireNameLength = 255;
        constexpr uint16_t kClassIn              = 1;
        constexpr uint16_t kTypeOpt              = 41;
        constexpr uint16_t kOptionPadding        = 12;
        constexpr std::size_t kMaxMessageSize    = 65535;
        constexpr std::size_t kMaxSectionCount   = 65535;
        constexpr uint16_t kEdnsUdpSize          = 1232;
        constexpr uint8_t kBadVersExtendedRcode  = 1; // BADVERS (16) >> 4
        constexpr std::size_t kPaddingBlockSize  = 468;

        constexpr uint16_t kFlagResponse           = 0x8000;
        constexpr uint16_t kFlagAuthoritative      = 0x0400;
        constexpr uint16_t kFlagTruncated          = 0x0200;
        constexpr uint16_t kFlagRecursionDesired   = 0x0100;
        constexpr uint16_t kFlagRecursionAvailable = 0x0080;

        class Reader {
        public:
            explicit Reader(std::span<const std::byte> data) : data_(data) {}

            std::size_t remaining() const { return data_.size() - pos_; }

            std::optional<uint8_t> u8() {
                if (remaining() < 1) {
                    return std::nullopt;
                }
                return std::to_integer<uint8_t>(data_[pos_++]);
            }

            std::optional<uint16_t> u16() {
                if (remaining() < 2) {
                    return std::nullopt;
                }
                const auto high = std::to_integer<uint16_t>(data_[pos_]);
                const auto low  = std::to_integer<uint16_t>(data_[pos_ + 1]);
                pos_ += 2;
                return static_cast<uint16_t>(high << 8 | low);
            }

            std::optional<std::span<const std::byte>> bytes(std::size_t count) {
                if (remaining() < count) {
                    return std::nullopt;
                }
                const auto out = data_.subspan(pos_, count);
                pos_ += count;
                return out;
            }

        private:
            std::span<const std::byte> data_;
            std::size_t pos_ = 0;
        };

        // letters, digits, '-' and '_' (used by SRV/DKIM-style names); anything else is FORMERR
        bool is_name_char(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        }

        std::optional<std::string> read_name(Reader& reader) {
            std::string name;
            std::size_t wire_length = 1;
            while (true) {
                const auto length = reader.u8();
                if (!length) {
                    return std::nullopt;
                }
                if (*length == 0) {
                    return name;
                }
                if (*length > kMaxLabelLength) {
                    return std::nullopt;
                }
                wire_length += 1 + *length;
                if (wire_length > kMaxWireNameLength) {
                    return std::nullopt;
                }
                const auto label = reader.bytes(*length);
                if (!label) {
                    return std::nullopt;
                }
                for (std::byte b : *label) {
                    const auto c = static_cast<char>(b);
                    if (!is_name_char(c)) {
                        return std::nullopt;
                    }
                    name.push_back(c);
                }
                name.push_back('.');
            }
        }

        std::optional<RecordType> to_record_type(uint16_t value) {
            const auto type = static_cast<RecordType>(value);
            switch (type) {
            case RecordType::A:
            case RecordType::NS:
            case RecordType::CNAME:
            case RecordType::SOA:
            case RecordType::PTR:
            case RecordType::MX:
            case RecordType::TXT:
            case RecordType::AAAA:
            case RecordType::ANY:
                return type;
            default:
                return std::nullopt;
            }
        }

        struct EdnsInfo {
            uint8_t version    = 0;
            bool wants_padding = false;
        };

        std::optional<EdnsInfo> read_opt_record(Reader& reader) {
            const auto root           = reader.u8();
            const auto type           = reader.u16();
            const auto udp_size       = reader.u16();
            const auto extended_rcode = reader.u8();
            const auto version        = reader.u8();
            const auto flags          = reader.u16();
            const auto data_length    = reader.u16();
            if (!root || !type || !udp_size || !extended_rcode || !version || !flags || !data_length) {
                return std::nullopt;
            }
            if (*root != 0 || *type != kTypeOpt) {
                return std::nullopt;
            }
            const auto data = reader.bytes(*data_length);
            if (!data) {
                return std::nullopt;
            }

            EdnsInfo info;
            info.version = *version;
            Reader options(*data);
            while (options.remaining() > 0) {
                const auto code   = options.u16();
                const auto length = options.u16();
                if (!code || !length || !options.bytes(*length)) {
                    return std::nullopt;
                }
                if (*code == kOptionPadding) {
                    info.wants_padding = true;
                }
            }
            return info;
        }

        class Writer {
        public:
            void u8(uint8_t value) { out_.push_back(std::byte{ value }); }

            void u16(uint16_t value) {
                u8(static_cast<uint8_t>(value >> 8));
                u8(static_cast<uint8_t>(value & 0xFF));
            }

            void u32(uint32_t value) {
                u16(static_cast<uint16_t>(value >> 16));
                u16(static_cast<uint16_t>(value & 0xFFFF));
            }

            void bytes(std::span<const std::byte> data) { out_.insert(out_.end(), data.begin(), data.end()); }

            std::size_t size() const { return out_.size(); }

            std::vector<std::byte> take() { return std::move(out_); }

        private:
            std::vector<std::byte> out_;
        };

        bool write_name(Writer& writer, std::string_view text) {
            if (text.empty() || text == ".") {
                writer.u8(0);
                return true;
            }
            if (text.back() == '.') {
                text.remove_suffix(1);
            }
            std::size_t wire_length = 1;
            std::size_t start       = 0;
            while (true) {
                const auto dot   = text.find('.', start);
                const auto label = text.substr(start, dot == std::string_view::npos ? dot : dot - start);
                if (label.empty() || label.size() > kMaxLabelLength) {
                    return false;
                }
                wire_length += 1 + label.size();
                if (wire_length > kMaxWireNameLength) {
                    return false;
                }
                writer.u8(static_cast<uint8_t>(label.size()));
                for (char c : label) {
                    writer.u8(static_cast<uint8_t>(c));
                }
                if (dot == std::string_view::npos) {
                    break;
                }
                start = dot + 1;
            }
            writer.u8(0);
            return true;
        }

        bool write_domain_name(Writer& writer, const DomainName& name) {
            std::size_t wire_length = 1;
            for (const auto& label : name.get_labels()) {
                if (label.empty() || label.size() > kMaxLabelLength) {
                    return false;
                }
                wire_length += 1 + label.size();
                if (wire_length > kMaxWireNameLength) {
                    return false;
                }
                writer.u8(static_cast<uint8_t>(label.size()));
                for (char c : label) {
                    writer.u8(static_cast<uint8_t>(c));
                }
            }
            writer.u8(0);
            return true;
        }

        bool write_record(Writer& writer, const ResourceRecord& record) {
            if (record.rdata.size() > kMaxMessageSize || !write_domain_name(writer, record.name)) {
                return false;
            }
            writer.u16(static_cast<uint16_t>(record.type));
            writer.u16(static_cast<uint16_t>(record.rclass));
            writer.u32(record.ttl);
            writer.u16(static_cast<uint16_t>(record.rdata.size()));
            writer.bytes(std::as_bytes(std::span(record.rdata)));
            return true;
        }

        // pad_block 0: no Padding option
        void write_opt_record(Writer& writer, std::size_t pad_block) {
            writer.u8(0);
            writer.u16(kTypeOpt);
            writer.u16(kEdnsUdpSize);
            writer.u8(0);
            writer.u8(0);
            writer.u16(0);

            const std::size_t unpadded = writer.size() + 2 + 4;
            const std::size_t padding  = pad_block == 0 ? 0 : (pad_block - unpadded % pad_block) % pad_block;
            if (pad_block == 0 || unpadded + padding > kMaxMessageSize) {
                writer.u16(0);
                return;
            }
            writer.u16(static_cast<uint16_t>(4 + padding));
            writer.u16(kOptionPadding);
            writer.u16(static_cast<uint16_t>(padding));
            for (std::size_t i = 0; i < padding; ++i) {
                writer.u8(0);
            }
        }

        uint16_t response_flags(bool recursion_desired, Rcode rcode) {
            uint16_t flags = kFlagResponse | kFlagRecursionAvailable | (static_cast<uint16_t>(rcode) & 0xF);
            if (recursion_desired) {
                flags |= kFlagRecursionDesired;
            }
            return flags;
        }

        std::optional<std::vector<std::byte>> try_encode(const DnsQuery& query, const ResolveResult& result) {
            const std::size_t additional_count = result.additional.size() + (query.has_edns ? 1 : 0);
            if (result.answer.size() > kMaxSectionCount || result.authority.size() > kMaxSectionCount || additional_count > kMaxSectionCount) {
                return std::nullopt;
            }
            Writer writer;
            writer.u16(query.id);
            writer.u16(response_flags(query.recursion_desired, result.rcode));
            writer.u16(1);
            writer.u16(static_cast<uint16_t>(result.answer.size()));
            writer.u16(static_cast<uint16_t>(result.authority.size()));
            writer.u16(static_cast<uint16_t>(additional_count));

            if (!write_name(writer, query.name)) {
                return std::nullopt;
            }
            writer.u16(static_cast<uint16_t>(query.type));
            writer.u16(kClassIn);

            for (const auto& record : result.answer) {
                if (!write_record(writer, record)) {
                    return std::nullopt;
                }
            }
            for (const auto& record : result.authority) {
                if (!write_record(writer, record)) {
                    return std::nullopt;
                }
            }
            // the OPT record has to come last: padding is sized from everything before it
            for (const auto& record : result.additional) {
                if (!write_record(writer, record)) {
                    return std::nullopt;
                }
            }
            if (query.has_edns) {
                write_opt_record(writer, query.wants_padding ? kPaddingBlockSize : 0);
            }
            if (writer.size() > kMaxMessageSize) {
                return std::nullopt;
            }
            return writer.take();
        }

        uint16_t u16_at(const std::vector<uint8_t>& msg, std::size_t pos) {
            return static_cast<uint16_t>(msg[pos] << 8 | msg[pos + 1]);
        }

        // where the name at pos ends in the stream. a compression pointer ends it after two bytes
        std::optional<std::size_t> skip_name(const std::vector<uint8_t>& msg, std::size_t pos) {
            while (true) {
                if (pos >= msg.size()) {
                    return std::nullopt;
                }
                const uint8_t length = msg[pos];
                if (length == 0) {
                    return pos + 1;
                }
                if ((length & 0xC0) == 0xC0) {
                    if (pos + 2 > msg.size()) {
                        return std::nullopt;
                    }
                    return pos + 2;
                }
                if ((length & 0xC0) != 0) {
                    return std::nullopt;
                }
                pos += 1 + length;
            }
        }

        // the decompressed name at pos, and where it ends in the stream
        std::optional<std::pair<DomainName, std::size_t>> read_wire_name(const std::vector<uint8_t>& msg, std::size_t pos) {
            const auto end = skip_name(msg, pos);
            if (!end) {
                return std::nullopt;
            }
            try {
                return std::pair{ DomainName(msg, pos), *end };
            } catch (const std::runtime_error&) {
                return std::nullopt;
            }
        }

        // rdata made of fixed bytes, then names, then fixed bytes again
        struct RdataLayout {
            std::size_t prefix = 0;
            int names          = 1;
            std::size_t suffix = 0;
        };

        // the types whose rdata may hold compressed names (RFC 3597 section 4, plus SRV and DNAME seen in the wild)
        std::optional<RdataLayout> rdata_layout(RecordType type) {
            switch (type) {
            case RecordType::NS:
            case RecordType::MD:
            case RecordType::MF:
            case RecordType::CNAME:
            case RecordType::MB:
            case RecordType::MG:
            case RecordType::MR:
            case RecordType::PTR:
            case RecordType::DNAME:
                return RdataLayout{ 0, 1, 0 };
            case RecordType::SOA:
                return RdataLayout{ 0, 2, 20 }; // mname, rname, serial refresh retry expire minimum
            case RecordType::MINFO:
            case RecordType::RP:
                return RdataLayout{ 0, 2, 0 };
            case RecordType::MX:
            case RecordType::AFSDB:
            case RecordType::RT:
            case RecordType::KX:
                return RdataLayout{ 2, 1, 0 }; // preference, name
            case RecordType::PX:
                return RdataLayout{ 2, 2, 0 };
            case RecordType::SRV:
                return RdataLayout{ 6, 1, 0 }; // priority, weight, port, target
            default:
                return std::nullopt;
            }
        }

        std::optional<std::vector<uint8_t>> read_rdata(const std::vector<uint8_t>& msg, std::size_t pos, std::size_t length, RecordType type) {
            const std::size_t end = pos + length;
            const auto layout     = rdata_layout(type);
            if (!layout) {
                return std::vector<uint8_t>(msg.begin() + pos, msg.begin() + end);
            }
            if (layout->prefix > length) {
                return std::nullopt;
            }
            std::vector<uint8_t> out(msg.begin() + pos, msg.begin() + pos + layout->prefix);
            pos += layout->prefix;
            for (int i = 0; i < layout->names; ++i) {
                const auto name = read_wire_name(msg, pos);
                if (!name || name->second > end) {
                    return std::nullopt;
                }
                const std::vector<uint8_t> bytes = name->first;
                out.insert(out.end(), bytes.begin(), bytes.end());
                pos = name->second;
            }
            if (end - pos != layout->suffix) {
                return std::nullopt;
            }
            out.insert(out.end(), msg.begin() + pos, msg.begin() + end);
            return out;
        }

    } // namespace

    std::expected<DnsQuery, ParseError> parse_query(std::span<const std::byte> wire) {
        if (wire.size() < kHeaderSize) {
            return std::unexpected(ParseError{ Rcode::FormErr, std::nullopt });
        }
        Reader reader(wire);
        const uint16_t id               = *reader.u16();
        const uint16_t flags            = *reader.u16();
        const uint16_t question_count   = *reader.u16();
        const uint16_t answer_count     = *reader.u16();
        const uint16_t authority_count  = *reader.u16();
        const uint16_t additional_count = *reader.u16();

        const auto fail = [id](Rcode rcode) { return std::unexpected(ParseError{ rcode, id }); };

        const bool is_response       = (flags >> 15) & 1;
        const auto opcode            = (flags >> 11) & 0xF;
        const bool recursion_desired = (flags >> 8) & 1;

        if (is_response) {
            return std::unexpected(ParseError{ Rcode::FormErr, std::nullopt });
        }
        if (opcode != 0) {
            return fail(Rcode::NotImp);
        }
        if (question_count != 1 || answer_count != 0 || authority_count != 0 || additional_count > 1) {
            return fail(Rcode::FormErr);
        }

        const auto raw_name = read_name(reader);
        if (!raw_name) {
            return fail(Rcode::FormErr);
        }
        // read_name already enforces label and name lengths. the case is kept so the reply echoes it
        std::string name = raw_name->empty() ? "." : *raw_name;

        const auto qtype  = reader.u16();
        const auto qclass = reader.u16();
        if (!qtype || !qclass) {
            return fail(Rcode::FormErr);
        }
        if (*qclass != kClassIn) {
            return fail(Rcode::NotImp);
        }
        const auto type = to_record_type(*qtype);
        if (!type) {
            return fail(Rcode::NotImp);
        }

        const bool has_edns  = additional_count == 1;
        bool wants_padding   = false;
        uint8_t edns_version = 0;
        if (has_edns) {
            const auto edns = read_opt_record(reader);
            if (!edns) {
                return fail(Rcode::FormErr);
            }
            wants_padding = edns->wants_padding;
            edns_version  = edns->version;
        }

        if (reader.remaining() != 0) {
            return fail(Rcode::FormErr);
        }
        // only a well-formed query earns BADVERS; a broken one is FORMERR whatever its version
        if (edns_version != 0) {
            return std::unexpected(ParseError{ Rcode::NoError, id, true });
        }

        return DnsQuery{ id, recursion_desired, std::move(name), *type, has_edns, wants_padding };
    }

    std::vector<std::byte> encode_response(const DnsQuery& query, const ResolveResult& result) {
        if (auto encoded = try_encode(query, result)) {
            return std::move(*encoded);
        }
        ResolveResult servfail;
        servfail.rcode = Rcode::ServFail;
        if (auto encoded = try_encode(query, servfail)) {
            return std::move(*encoded);
        }
        return encode_error(query.id, Rcode::ServFail);
    }

    std::vector<std::byte> encode_error(uint16_t id, Rcode rcode) {
        Writer writer;
        writer.u16(id);
        writer.u16(response_flags(false, rcode));
        for (int i = 0; i < 4; ++i) {
            writer.u16(0);
        }
        return writer.take();
    }

    std::vector<std::byte> encode_bad_version(uint16_t id) {
        Writer writer;
        writer.u16(id);
        // BADVERS is 16: its low four bits (0) go in the header, the high eight bits (1) in the OPT record
        writer.u16(response_flags(false, Rcode::NoError));
        writer.u16(0);
        writer.u16(0);
        writer.u16(0);
        writer.u16(1);
        writer.u8(0);
        writer.u16(kTypeOpt);
        writer.u16(kEdnsUdpSize);
        writer.u8(kBadVersExtendedRcode);
        writer.u8(0); // the highest version we support
        writer.u16(0);
        writer.u16(0);
        return writer.take();
    }

    std::optional<std::vector<std::byte>> encode_parse_error(const ParseError& error) {
        if (!error.id) {
            return std::nullopt;
        }
        if (error.bad_edns_version) {
            return encode_bad_version(*error.id);
        }
        return encode_error(*error.id, error.rcode);
    }

    std::vector<std::byte> encode_query(uint16_t id, const DomainName& name, RecordType type, RecordClass rclass, bool recursion_desired,
                                        std::size_t pad_block) {
        Writer writer;
        writer.u16(id);
        writer.u16(recursion_desired ? kFlagRecursionDesired : 0);
        writer.u16(1);
        writer.u16(0);
        writer.u16(0);
        writer.u16(1);
        if (!write_domain_name(writer, name)) {
            throw std::invalid_argument("encode_query: name does not fit in a DNS message");
        }
        writer.u16(static_cast<uint16_t>(type));
        writer.u16(static_cast<uint16_t>(rclass));
        write_opt_record(writer, pad_block);
        return writer.take();
    }

    std::optional<DnsResponse> parse_response(std::span<const std::byte> wire) {
        if (wire.size() < kHeaderSize || wire.size() > kMaxMessageSize) {
            return std::nullopt;
        }
        // DomainName reads compressed names out of a byte vector
        std::vector<uint8_t> msg(wire.size());
        std::ranges::transform(wire, msg.begin(), [](std::byte b) { return std::to_integer<uint8_t>(b); });

        const uint16_t flags = u16_at(msg, 2);
        if (!(flags & kFlagResponse)) {
            return std::nullopt;
        }
        DnsResponse response;
        response.id                     = u16_at(msg, 0);
        response.truncated              = flags & kFlagTruncated;
        response.authoritative          = flags & kFlagAuthoritative;
        const uint16_t question_count   = u16_at(msg, 4);
        const uint16_t answer_count     = u16_at(msg, 6);
        const uint16_t authority_count  = u16_at(msg, 8);
        const uint16_t additional_count = u16_at(msg, 10);
        if (question_count > 1) {
            return std::nullopt;
        }

        std::size_t pos = kHeaderSize;
        if (question_count == 1) {
            auto name = read_wire_name(msg, pos);
            if (!name || name->second + 4 > msg.size()) {
                return std::nullopt;
            }
            pos                   = name->second;
            response.question     = std::move(name->first);
            response.qtype        = static_cast<RecordType>(u16_at(msg, pos));
            response.qclass       = static_cast<RecordClass>(u16_at(msg, pos + 2));
            response.has_question = true;
            pos += 4;
        }
        // a truncated reply may stop mid record, and the caller asks again over TCP anyway
        if (response.truncated) {
            return response;
        }

        uint8_t extended_rcode = 0;
        auto read_section      = [&](uint16_t count, std::vector<ResourceRecord>& out, bool is_additional) {
            for (uint16_t i = 0; i < count; ++i) {
                auto name = read_wire_name(msg, pos);
                if (!name || name->second + 10 > msg.size()) {
                    return false;
                }
                pos                   = name->second;
                const uint16_t type   = u16_at(msg, pos);
                const uint16_t rclass = u16_at(msg, pos + 2);
                const uint32_t ttl    = static_cast<uint32_t>(u16_at(msg, pos + 4)) << 16 | u16_at(msg, pos + 6);
                const uint16_t length = u16_at(msg, pos + 8);
                pos += 10;
                if (pos + length > msg.size()) {
                    return false;
                }
                if (type == kTypeOpt) {
                    if (!is_additional) {
                        return false;
                    }
                    extended_rcode = static_cast<uint8_t>(ttl >> 24);
                    pos += length;
                    continue;
                }
                auto rdata = read_rdata(msg, pos, length, static_cast<RecordType>(type));
                if (!rdata) {
                    return false;
                }
                pos += length;
                // RFC 2181 section 8: a TTL with the top bit set is treated as zero
                out.push_back(ResourceRecord{ std::move(name->first), static_cast<RecordType>(type), static_cast<RecordClass>(rclass),
                                              ttl > 0x7FFFFFFF ? 0 : ttl, std::move(*rdata) });
            }
            return true;
        };
        if (!read_section(answer_count, response.result.answer, false) || !read_section(authority_count, response.result.authority, false) ||
            !read_section(additional_count, response.result.additional, true)) {
            return std::nullopt;
        }

        const unsigned rcode   = static_cast<unsigned>(extended_rcode) << 4 | (flags & 0xF);
        response.result.rcode  = rcode <= static_cast<unsigned>(Rcode::DSOTypeNI) ? static_cast<Rcode>(rcode) : Rcode::ServFail;
        return response;
    }

} // namespace types
