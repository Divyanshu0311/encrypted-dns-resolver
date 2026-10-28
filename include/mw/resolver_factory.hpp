#pragma once
#include<atomic>
#include<cstdint>
#include<memory>
#include<optional>
#include<random>

#include "backend/Cache.hpp"
#include "backend/Resolver.hpp"
#include "mw/config.hpp"
#include "mw/types.hpp"

// Will hold: mw::StubResolver, mw::make_factory

namespace mw {

struct StubOptions {
  Ms delay{0};
  double failure_rate = 0.0; // chance of a ServFail answer
  double throw_rate = 0.0;   // chance of throwing
  uint32_t seed = 42;
};

// fake answers so the middleware can run before the real resolvers are wired in.
// one instance per worker, so the rng needs no lock
class StubResolver final : public backend::Resolver {
  private:
    const StubOptions opts_;
    std::mt19937 rng_;
    std::uniform_real_distribution<double> dist_{0.0, 1.0};

  public:
    explicit StubResolver(StubOptions opts);

    // nx.test. -> NXDomain, A -> 127.0.0.1, AAAA -> ::1, anything else -> NoError with no answers
    types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                 const bool recurse = true) override;
};

// a switch the admin page flips at run time, so the demo can show the circuit breakers working
struct FaultInjection {
  std::atomic<double> fail_rate{0.0}; // chance a lookup is answered SERVFAIL without being tried
};

// what every worker's chain shares. the caller keeps copies to read cache stats or flip the faults
struct ResolverShared {
  std::shared_ptr<backend::Cache> cache = std::make_shared<backend::Cache>();
  std::shared_ptr<FaultInjection> faults = std::make_shared<FaultInjection>();
};

// the one place resolver chains get built: the records_file resolver (if set) in front of a forwarding or
// recursive resolver, all chains sharing one cache. with stub set, every chain is a StubResolver instead.
// throws std::invalid_argument for an upstream that is not an IP address
ResolverFactory make_factory(const Config& cfg, std::optional<StubOptions> stub = std::nullopt, ResolverShared shared = {});

} // namespace mw
