#include "mw/dot_framer.hpp"

namespace mw {
namespace {

constexpr std::size_t kLengthPrefixSize = 2;
constexpr std::size_t kMaxMessageSize = 65535;

} // namespace

void DotFramer::feed(std::span<const std::byte> data) {
  if (invalid_) {
    return;
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

FrameStatus DotFramer::next(std::vector<std::byte> &message) {
  if (invalid_) {
    return FrameStatus::Invalid;
  }
  if (buffer_.size() < kLengthPrefixSize) {
    return FrameStatus::NeedMoreData;
  }
  const std::size_t length =
      std::to_integer<std::size_t>(buffer_[0]) << 8 | std::to_integer<std::size_t>(buffer_[1]);
  if (length == 0) {
    invalid_ = true;
    buffer_.clear();
    return FrameStatus::Invalid;
  }
  if (buffer_.size() < kLengthPrefixSize + length) {
    return FrameStatus::NeedMoreData;
  }
  const auto begin = buffer_.begin() + kLengthPrefixSize;
  const auto end = begin + length;
  message.assign(begin, end);
  buffer_.erase(buffer_.begin(), end);
  return FrameStatus::Complete;
}

std::optional<std::vector<std::byte>> frame(std::span<const std::byte> message) {
  if (message.size() > kMaxMessageSize) {
    return std::nullopt;
  }
  std::vector<std::byte> out;
  out.reserve(kLengthPrefixSize + message.size());
  out.push_back(static_cast<std::byte>(message.size() >> 8));
  out.push_back(static_cast<std::byte>(message.size() & 0xFF));
  out.insert(out.end(), message.begin(), message.end());
  return out;
}

} // namespace mw
