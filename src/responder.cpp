#include "mw/responder.hpp"
#include<chrono>
#include<utility>

#include "mw/logger.hpp"

namespace mw {

Responder::Responder(QueryKey key, ClientInfo client, ResultCallback callback, TimePoint start, Metrics& metrics, Clock clock)
    : key_(std::move(key)), client_(std::move(client)), callback_(std::move(callback)), start_(start), metrics_(metrics), clock_(std::move(clock)) {}

bool Responder::complete(ResolveResult result) {
  if (done_.exchange(true, std::memory_order_acq_rel))
    return false; // someone else already answered

  auto latency = std::chrono::duration_cast<Ms>(clock_() - start_);
  metrics_.record_reply(result.rcode, latency);
  if (!callback_)
    return true;
  try {
    callback_(std::move(result));
  }
  catch (const std::exception& e) {
    warn("result callback for {} threw: {}", std::string(key_.name), e.what());
  }
  catch (...) {
    warn("result callback for {} threw", std::string(key_.name));
  }
  return true;
}

bool Responder::fail(Rcode rc, std::string why) {
  return complete(error_result(rc, std::move(why)));
}

} // namespace mw
