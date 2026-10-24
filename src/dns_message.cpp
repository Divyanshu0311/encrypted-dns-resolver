#include "mw/dns_message.hpp"

#include <string_view>
#include <utility>

#include "mw/dns_name.hpp"

namespace mw {
namespace {

constexpr std::size_t kHeaderSize = 12;
constexpr std::size_t kMaxLabelLength = 63;
constexpr std::size_t kMaxWireNameLength = 255;
constexpr uint16_t kClassIn = 1;
constexpr uint16_t kTypeOpt = 41;
constexpr uint16_t kOptionPadding = 12;
constexpr std::size_t kMaxMessageSize = 65535;
constexpr std::size_t kMaxSectionCount = 65535;
constexpr uint16_t kEdnsUdpSize = 1232;
constexpr std::size_t kPaddingBlockSize = 468;

constexpr uint16_t kFlagResponse = 0x8000;
constexpr uint16_t kFlagRecursionDesired = 0x0100;
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
    const auto low = std::to_integer<uint16_t>(data_[pos_ + 1]);
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

std::optional<std::string> read_name(Reader &reader) {
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
      if (c == '.') {
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
  }
  return std::nullopt;
}

struct EdnsInfo {
  bool wants_padding = false;
};

std::optional<EdnsInfo> read_opt_record(Reader &reader) {
  const auto root = reader.u8();
  const auto type = reader.u16();
  const auto udp_size = reader.u16();
  const auto extended_rcode = reader.u8();
  const auto version = reader.u8();
  const auto flags = reader.u16();
  const auto data_length = reader.u16();
  if (!root || !type || !udp_size || !extended_rcode || !version || !flags || !data_length) {
    return std::nullopt;
  }
  if (*root != 0 || *type != kTypeOpt || *version != 0) {
    return std::nullopt;
  }
  const auto data = reader.bytes(*data_length);
  if (!data) {
    return std::nullopt;
  }

  EdnsInfo info;
  Reader options(*data);
  while (options.remaining() > 0) {
    const auto code = options.u16();
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
  void u8(uint8_t value) { out_.push_back(std::byte{value}); }

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

bool write_name(Writer &writer, std::string_view text) {
  if (text.empty() || text == ".") {
    writer.u8(0);
    return true;
  }
  if (text.back() == '.') {
    text.remove_suffix(1);
  }
  std::size_t wire_length = 1;
  std::size_t start = 0;
  while (true) {
    const auto dot = text.find('.', start);
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

bool write_record(Writer &writer, const ResourceRecord &record) {
  if (record.rdata.size() > kMaxMessageSize || !write_name(writer, record.name)) {
    return false;
  }
  writer.u16(static_cast<uint16_t>(record.type));
  writer.u16(record.dns_class);
  writer.u32(record.ttl);
  writer.u16(static_cast<uint16_t>(record.rdata.size()));
  writer.bytes(record.rdata);
  return true;
}

void write_opt_record(Writer &writer, bool pad) {
  writer.u8(0);
  writer.u16(kTypeOpt);
  writer.u16(kEdnsUdpSize);
  writer.u8(0);
  writer.u8(0);
  writer.u16(0);

  const std::size_t unpadded = writer.size() + 2 + 4;
  const std::size_t padding =
      (kPaddingBlockSize - unpadded % kPaddingBlockSize) % kPaddingBlockSize;
  if (!pad || unpadded + padding > kMaxMessageSize) {
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

std::optional<std::vector<std::byte>> try_encode(const DnsQuery &query,
                                                 const ResolveResult &result) {
  if (result.records.size() > kMaxSectionCount || result.authority.size() > kMaxSectionCount) {
    return std::nullopt;
  }
  Writer writer;
  writer.u16(query.id);
  writer.u16(response_flags(query.recursion_desired, result.rcode));
  writer.u16(1);
  writer.u16(static_cast<uint16_t>(result.records.size()));
  writer.u16(static_cast<uint16_t>(result.authority.size()));
  writer.u16(query.has_edns ? 1 : 0);

  if (!write_name(writer, query.name)) {
    return std::nullopt;
  }
  writer.u16(static_cast<uint16_t>(query.type));
  writer.u16(kClassIn);

  for (const auto &record : result.records) {
    if (!write_record(writer, record)) {
      return std::nullopt;
    }
  }
  for (const auto &record : result.authority) {
    if (!write_record(writer, record)) {
      return std::nullopt;
    }
  }
  if (query.has_edns) {
    write_opt_record(writer, query.wants_padding);
  }
  if (writer.size() > kMaxMessageSize) {
    return std::nullopt;
  }
  return writer.take();
}

} // namespace

std::expected<DnsQuery, ParseError> parse_query(std::span<const std::byte> wire) {
  if (wire.size() < kHeaderSize) {
    return std::unexpected(ParseError{Rcode::FormErr, std::nullopt});
  }
  Reader reader(wire);
  const uint16_t id = *reader.u16();
  const uint16_t flags = *reader.u16();
  const uint16_t question_count = *reader.u16();
  const uint16_t answer_count = *reader.u16();
  const uint16_t authority_count = *reader.u16();
  const uint16_t additional_count = *reader.u16();

  const auto fail = [id](Rcode rcode) { return std::unexpected(ParseError{rcode, id}); };

  const bool is_response = (flags >> 15) & 1;
  const auto opcode = (flags >> 11) & 0xF;
  const bool recursion_desired = (flags >> 8) & 1;

  if (is_response) {
    return std::unexpected(ParseError{Rcode::FormErr, std::nullopt});
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
  std::string name = normalize(*raw_name);
  if (!is_valid(name)) {
    return fail(Rcode::FormErr);
  }

  const auto qtype = reader.u16();
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

  const bool has_edns = additional_count == 1;
  bool wants_padding = false;
  if (has_edns) {
    const auto edns = read_opt_record(reader);
    if (!edns) {
      return fail(Rcode::FormErr);
    }
    wants_padding = edns->wants_padding;
  }

  if (reader.remaining() != 0) {
    return fail(Rcode::FormErr);
  }

  return DnsQuery{id, recursion_desired, std::move(name), *type, has_edns, wants_padding};
}

std::vector<std::byte> encode_response(const DnsQuery &query, const ResolveResult &result) {
  if (auto encoded = try_encode(query, result)) {
    return std::move(*encoded);
  }
  if (auto encoded = try_encode(query, ResolveResult::error(Rcode::ServFail))) {
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

} // namespace mw
