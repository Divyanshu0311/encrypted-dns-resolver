#pragma once
#include<cstddef>
#include<cstdint>
#include<optional>
#include<shared_mutex>
#include<string>
#include<string_view>
#include<unordered_map>

#include "mw/types.hpp"

// Will hold: mw::BlockList

namespace mw {

enum class Offence : uint8_t {
  RateLimited, // middleware: the rate limiter refused a query
  Protocol     // front end: bad frame, failed TLS handshake, malformed query
};

struct BlockPolicy {
  uint32_t rate_limit_strikes = 0; // 0 disables blocking for this offence
  uint32_t protocol_strikes = 0;   // set higher than rate_limit_strikes: honest clients do hit these sometimes
  Ms window{10000};                // strikes older than this are forgotten
  Ms duration{300000};             // how long a block lasts
  std::size_t max_entries = 100000;
};

// sources that broke the rules too often recently. IPv4 is tracked per address, IPv6 per /64,
// since one IPv6 host usually owns a whole /64. many readers, few writers
class BlockList {
  private:
    struct Entry {
      uint32_t rate_limit_strikes = 0;
      uint32_t protocol_strikes = 0;
      TimePoint window_start;
      TimePoint blocked_until; // in the past means not blocked
    };

    const BlockPolicy policy_;
    Clock clock_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    uint64_t strikes_since_sweep_ = 0;

    static constexpr uint64_t kSweepEvery = 1024;

    void sweep(TimePoint now);

  public:
    BlockList(BlockPolicy policy, Clock clock);

    bool is_blocked(std::string_view ip) const;

    // true only for the strike that started a new block
    bool strike(std::string_view ip, Offence offence);

    std::size_t tracked_sources() const;

    // sources blocked right now
    std::size_t blocked_count() const;

    // lifts a block (and forgets the strikes) early. true if ip was blocked
    bool unblock(std::string_view ip);

    // the address bytes (IPv4, or IPv4-mapped IPv6) or the /64 prefix. nullopt if ip is not an address
    static std::optional<std::string> key_for(std::string_view ip);
};

} // namespace mw
