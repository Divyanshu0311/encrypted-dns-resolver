#pragma once
#include<atomic>
#include<cstdint>
#include<memory>
#include<optional>
#include<random>
#include<string>
#include<string_view>
#include<vector>

#include "backend/Cache.hpp"
#include "backend/Resolver.hpp"
#include "backend/Upstream.hpp"
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

// a resolver the server can be switched to at run time
struct ResolverChoice {
  std::string id;    // "configured", "upstream:8.8.8.8:53", "dot:8.8.8.8:853" or "recursive"
  std::string label; // for the admin page
};

// which resolver every worker's chain asks after the records file. make_factory fills choices (once, before
// any chain exists) and sets active from cfg.mode; the admin page moves active
struct ResolverSwitch {
  std::vector<ResolverChoice> choices;
  std::atomic<std::size_t> active{0};

  std::optional<std::size_t> find(std::string_view id) const;
};

// what every worker's chain shares. the caller keeps copies to read cache stats, flip the faults or switch resolver
struct ResolverShared {
  std::shared_ptr<backend::Cache> cache = std::make_shared<backend::Cache>();
  std::shared_ptr<FaultInjection> faults = std::make_shared<FaultInjection>();
  std::shared_ptr<ResolverSwitch> resolvers = std::make_shared<ResolverSwitch>();
  // every DNS-over-TLS upstream connects through this one, so the admin page sees all their certificate checks.
  // make_factory configures it (cfg.upstream_ca_file) unless the caller already did
  std::shared_ptr<backend::TlsClient> upstream_tls = std::make_shared<backend::TlsClient>();
};

// the configured upstreams, the tls:// ones going through tls. throws std::invalid_argument for a host that
// is not an IP address
std::vector<backend::Endpoint> configured_upstreams(const Config& cfg, const std::shared_ptr<backend::TlsClient>& tls);

// the public resolvers offered next to the configured ones: Google, Cloudflare and Quad9, plain and over TLS
std::vector<backend::Endpoint> public_upstreams(const std::shared_ptr<backend::TlsClient>& tls);

// "upstream:1.1.1.1:53" or, over TLS, "dot:1.1.1.1:853": one upstream's id in ResolverSwitch and on the admin page
std::string upstream_id(const backend::Endpoint& e);

// "1.1.1.1", "[2606:4700::1111]:5353", "1.1.1.1 over TLS (cloudflare-dns.com)"
std::string upstream_label(const backend::Endpoint& e);

// the one place resolver chains get built: the records_file resolver (if set) in front of the switched resolver
// (forwarding or recursive, see ResolverSwitch), all chains sharing one cache. with stub set, every chain is a StubResolver instead.
// throws std::invalid_argument for an upstream that is not an IP address, forwarding mode without upstreams,
// or an upstream_ca_file that can't be loaded
ResolverFactory make_factory(const Config& cfg, std::optional<StubOptions> stub = std::nullopt, ResolverShared shared = {});

} // namespace mw
