#include "mw/resolver_factory.hpp"
#include<atomic>
#include<memory>
#include<stdexcept>
#include<thread>

#include "mw/logger.hpp"

namespace mw {

StubResolver::StubResolver(StubOptions opts) : opts_(opts), rng_(opts.seed) {
  if (opts_.failure_rate < 0 || opts_.failure_rate > 1)
    throw std::invalid_argument("StubOptions failure_rate must be in [0, 1]");
  if (opts_.throw_rate < 0 || opts_.throw_rate > 1)
    throw std::invalid_argument("StubOptions throw_rate must be in [0, 1]");
}

types::ResolveResult StubResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                           const bool recurse) {
  (void)recurse;
  if (opts_.delay.count() > 0)
    std::this_thread::sleep_for(opts_.delay);

  if (dist_(rng_) < opts_.throw_rate)
    throw std::runtime_error("stub: injected failure");
  if (dist_(rng_) < opts_.failure_rate)
    return error_result(Rcode::ServFail);

  static const types::DomainName nx("nx.test.");
  if (name == nx)
    return error_result(Rcode::NXDomain);

  ResolveResult result;
  if (type == RecordType::A) {
    result.answer.push_back(ResourceRecord{name, RecordType::A, rclass, 60, {127, 0, 0, 1}});
  }
  else if (type == RecordType::AAAA) {
    std::vector<uint8_t> loopback(16, 0); // ::1
    loopback.back() = 1;
    result.answer.push_back(ResourceRecord{name, RecordType::AAAA, rclass, 60, std::move(loopback)});
  }
  return result;
}

ResolverFactory make_factory(const Config& cfg, std::optional<StubOptions> stub) {
  // later: branch on cfg.mode to build backend::ForwardingResolver(cfg.upstreams) or
  // backend::RecursiveResolver, with the local records resolver in front when cfg.records_file is set
  (void)cfg;
  if (!stub) {
    warn("real resolvers are not wired in yet, using the stub resolver");
    stub = StubOptions{};
  }

  // shared so every copy of the factory keeps counting, each worker gets seed + n
  auto calls = std::make_shared<std::atomic<uint32_t>>(0);
  return [opts = *stub, calls]() -> std::unique_ptr<backend::Resolver> {
    StubOptions mine = opts;
    mine.seed = opts.seed + calls->fetch_add(1);
    return std::make_unique<StubResolver>(mine);
  };
}

} // namespace mw
