#pragma once
#include<cstddef>
#include<memory>
#include<mutex>
#include<unordered_map>
#include<vector>

#include "mw/responder.hpp"
#include "mw/types.hpp"

// Will hold: mw::InFlightTable

namespace mw {

// request coalescing: every waiter for the same (name, type) hangs off one entry, so the
// resolver runs once. callers complete or fail what they take after the call returns, never
// under the lock. every entry must be removed exactly once (take or take_all), else later
// requests for that key wait forever
class InFlightTable {
  private:
    mutable std::mutex mutex_;
    std::unordered_map<QueryKey, std::vector<std::shared_ptr<Responder>>, QueryKeyHash> map_;

  public:
    // true: first for this key, the caller must submit a job (leader).
    // false: joined an existing lookup (follower)
    bool attach(const QueryKey& key, std::shared_ptr<Responder> r);

    // removes the entry and returns its waiters, empty if absent
    std::vector<std::shared_ptr<Responder>> take(const QueryKey& key);

    // removes everything, used at shutdown
    std::vector<std::shared_ptr<Responder>> take_all();

    // keys currently in flight
    std::size_t size() const;
};

} // namespace mw
