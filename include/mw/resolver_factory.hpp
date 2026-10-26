#pragma once
#include<cstdint>
#include<optional>
#include<random>

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

// the one place resolver chains get built. today a stub, later Arnav's backend classes
ResolverFactory make_factory(const Config& cfg, std::optional<StubOptions> stub = std::nullopt);

} // namespace mw
