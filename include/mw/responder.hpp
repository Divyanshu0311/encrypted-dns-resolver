#pragma once
#include<atomic>

#include "mw/metrics.hpp"
#include "mw/types.hpp"

// Will hold: mw::Responder

namespace mw {

// one client request waiting for its answer. always made with make_shared and shared by the
// in-flight table and the deadline timer. its one job: the callback runs exactly once
class Responder {
  private:
    QueryKey key_;
    ClientInfo client_;
    ResultCallback callback_;
    TimePoint start_; // when submit() got it, for latency
    Metrics& metrics_;
    Clock clock_;
    std::atomic<bool> done_{false}; // the exactly once guard

  public:
    Responder(QueryKey key, ClientInfo client, ResultCallback callback, TimePoint start, Metrics& metrics, Clock clock);

    Responder(const Responder&) = delete;
    Responder& operator=(const Responder&) = delete;
    Responder(Responder&&) = delete;
    Responder& operator=(Responder&&) = delete;

    // true only for the call that actually delivered the result
    bool complete(ResolveResult result);
    bool fail(Rcode rc);

    bool is_done() const noexcept { return done_.load(std::memory_order_acquire); }
    const QueryKey& key() const noexcept { return key_; }
    const ClientInfo& client() const noexcept { return client_; }
};

} // namespace mw
