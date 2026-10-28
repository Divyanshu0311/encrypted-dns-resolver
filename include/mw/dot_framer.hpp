#pragma once
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace mw {

    enum class FrameStatus {
        Complete,
        NeedMoreData,
        Invalid
    };

    class DotFramer {
    public:
        void feed(std::span<const std::byte> data);
        FrameStatus next(std::vector<std::byte>& message);

    private:
        std::vector<std::byte> buffer_;
        bool invalid_ = false;
    };

    std::optional<std::vector<std::byte>> frame(std::span<const std::byte> message);

} // namespace mw
