#include "mw/resolver_factory.hpp"
#include<algorithm>
#include<atomic>
#include<format>
#include<memory>
#include<stdexcept>
#include<thread>
#include<vector>

#include "IP.hpp"
#include "backend/Cache.hpp"
#include "backend/ForwardingResolver.hpp"
#include "backend/HostsFileResolver.hpp"
#include "backend/RecursiveResolver.hpp"
#include "backend/ZoneFilesResolver.hpp"
#include "mw/logger.hpp"

namespace mw {
namespace {

// one resolver the server can be switched to, and how to build it
struct ResolverSpec {
  enum class Kind { Forwarding, Recursive } kind;
  ResolverChoice choice;
  std::vector<backend::Endpoint> endpoints; // forwarding only
};

// the same list, in the same order, for every chain: the configured upstreams together, each upstream on its
// own (the configured ones and the public resolvers, plain and over TLS), then recursion
std::vector<ResolverSpec> resolver_specs(const Config& cfg, const std::shared_ptr<backend::TlsClient>& tls) {
  auto configured = configured_upstreams(cfg, tls);
  if (cfg.mode == Mode::Forwarding && configured.empty())
    throw std::invalid_argument("forwarding mode needs at least one upstream");

  std::vector<ResolverSpec> specs;
  if (!configured.empty()) {
    std::string names;
    for (const auto& e : configured)
      names += (names.empty() ? "" : ", ") + upstream_label(e);
    specs.push_back({ResolverSpec::Kind::Forwarding, {"configured", "Forward to " + names}, configured});
  }
  auto singles = configured;
  singles.append_range(public_upstreams(tls));
  for (const auto& e : singles) {
    std::string id = upstream_id(e);
    if (std::ranges::any_of(specs, [&](const auto& s) { return s.choice.id == id; }))
      continue;
    specs.push_back({ResolverSpec::Kind::Forwarding, {id, "Only " + upstream_label(e)}, {e}});
  }
  specs.push_back({ResolverSpec::Kind::Recursive, {"recursive", "Recursive from the root servers"}, {}});
  return specs;
}

// asks whichever resolver the switch points at
class SwitchedResolver final : public backend::Resolver {
  private:
    std::vector<std::unique_ptr<backend::Resolver>> options_;
    std::shared_ptr<ResolverSwitch> switch_;

  public:
    SwitchedResolver(std::vector<std::unique_ptr<backend::Resolver>> options, std::shared_ptr<ResolverSwitch> sw)
        : options_(std::move(options)), switch_(std::move(sw)) {}

    types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                 const bool recurse) override {
      auto i = std::min(switch_->active.load(std::memory_order_relaxed), options_.size() - 1);
      return options_[i]->resolve(name, type, rclass, recurse);
    }
};

// one worker's resolvers. owns the parts and keeps the shared cache alive as long as any chain uses it
class ResolverChain final : public backend::Resolver {
  private:
    // declared in dependency order, so each part is destroyed before what it points to
    std::shared_ptr<backend::Cache> cache_;
    std::shared_ptr<FaultInjection> faults_;
    std::mt19937 rng_{std::random_device{}()};
    std::uniform_real_distribution<double> dist_{0.0, 1.0};
    std::unique_ptr<backend::Resolver> upstream_;
    std::unique_ptr<backend::Resolver> local_; // records_file, asked first. null when unset

  public:
    ResolverChain(const Config& cfg, const ResolverShared& shared, const std::vector<ResolverSpec>& specs,
                  std::shared_ptr<std::atomic<std::size_t>> preferred)
        : cache_(shared.cache), faults_(shared.faults) {
      std::vector<std::unique_ptr<backend::Resolver>> options;
      for (const auto& spec : specs) {
        if (spec.kind == ResolverSpec::Kind::Recursive) {
          backend::RecursiveOptions opts;
          opts.total_timeout = cfg.request_timeout;
          if (!cfg.root_hints.empty())
            cache_->add_root_hints(cfg.root_hints);
          options.push_back(std::make_unique<backend::RecursiveResolver>(*cache_, opts));
          continue;
        }
        // every upstream gets a fair share of the request timeout, within reason
        auto per_upstream = std::clamp(cfg.request_timeout / static_cast<Ms::rep>(spec.endpoints.size()), Ms(100), Ms(1000));
        // the configured group shares which upstream answered last across workers, so a dead one costs one timeout
        auto shared_preferred = spec.choice.id == "configured" ? preferred : std::make_shared<std::atomic<std::size_t>>(0);
        options.push_back(std::make_unique<backend::ForwardingResolver>(spec.endpoints, *cache_, per_upstream, shared_preferred));
      }
      upstream_ = std::make_unique<SwitchedResolver>(std::move(options), shared.resolvers);

      if (!cfg.records_file.empty()) {
        // a .zone file is a master file, anything else a hosts file
        if (cfg.records_file.extension() == ".zone")
          local_ = std::make_unique<backend::ZoneFilesResolver>(std::vector<backend::ZoneFile>{{types::DomainName("."), cfg.records_file.string()}},
                                                               upstream_.get());
        else
          local_ = std::make_unique<backend::HostsFileResolver>(cfg.records_file.string(), upstream_.get());
      }
    }

    types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                 const bool recurse) override {
      if (double rate = faults_->fail_rate.load(std::memory_order_relaxed); rate > 0 && dist_(rng_) < rate)
        return error_result(Rcode::ServFail, "injected fault");
      auto result = (local_ ? *local_ : *upstream_).resolve(name, type, rclass, recurse);
      // the records file resolvers don't label their own answers
      if (result.served_by.empty())
        result.served_by = local_ ? "records file" : "resolver";
      return result;
    }
};

} // namespace

std::vector<backend::Endpoint> configured_upstreams(const Config& cfg, const std::shared_ptr<backend::TlsClient>& tls) {
  std::vector<backend::Endpoint> out;
  for (const auto& u : cfg.upstreams) {
    try {
      out.push_back(backend::Endpoint{types::IP(u.host), u.port, u.tls ? tls : nullptr, u.tls_name});
    }
    catch (const std::runtime_error&) {
      throw std::invalid_argument(std::format("upstream '{}' is not an IP address", u.host));
    }
  }
  return out;
}

std::vector<backend::Endpoint> public_upstreams(const std::shared_ptr<backend::TlsClient>& tls) {
  std::vector<backend::Endpoint> out;
  for (const char* ip : {"8.8.8.8", "1.1.1.1", "9.9.9.9"})
    out.push_back(backend::Endpoint{types::IP(std::string(ip)), 53, nullptr, ""});
  for (const auto& [ip, name] : {std::pair{"8.8.8.8", "dns.google"}, {"1.1.1.1", "cloudflare-dns.com"}, {"9.9.9.9", "dns.quad9.net"}})
    out.push_back(backend::Endpoint{types::IP(std::string(ip)), 853, tls, name});
  return out;
}

std::string upstream_id(const backend::Endpoint& e) {
  return std::format("{}:{}:{}", e.tls ? "dot" : "upstream", std::string(e.address), e.port);
}

std::string upstream_label(const backend::Endpoint& e) {
  std::string ip(e.address);
  std::string out = e.port == (e.tls ? 853 : 53) ? ip : e.address.is_ipv6() ? std::format("[{}]:{}", ip, e.port) : std::format("{}:{}", ip, e.port);
  if (e.tls)
    out += e.tls_name.empty() ? " over TLS" : " over TLS (" + e.tls_name + ")";
  return out;
}

std::optional<std::size_t> ResolverSwitch::find(std::string_view id) const {
  for (std::size_t i = 0; i < choices.size(); i++)
    if (choices[i].id == id)
      return i;
  return std::nullopt;
}

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
    return error_result(Rcode::ServFail, "stub: injected failure");

  static const types::DomainName nx("nx.test.");
  if (name == nx)
    return error_result(Rcode::NXDomain, "stub");

  ResolveResult result;
  result.served_by = "stub";
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

ResolverFactory make_factory(const Config& cfg, std::optional<StubOptions> stub, ResolverShared shared) {
  if (!stub) {
    if (!shared.upstream_tls->configured()) {
      if (auto ok = shared.upstream_tls->configure(cfg.upstream_ca_file); !ok)
        throw std::invalid_argument(ok.error());
    }
    auto specs = resolver_specs(cfg, shared.upstream_tls);
    shared.resolvers->choices.clear();
    for (const auto& spec : specs)
      shared.resolvers->choices.push_back(spec.choice);
    shared.resolvers->active = cfg.mode == Mode::Recursive ? specs.size() - 1 : 0;

    // which upstream answered last, shared so every worker skips a dead one after the first timeout
    auto preferred = std::make_shared<std::atomic<std::size_t>>(0);
    // built once here so a bad upstream or records file fails at startup, not in a worker
    ResolverChain check(cfg, shared, specs, preferred);
    return [cfg, shared, specs, preferred]() -> std::unique_ptr<backend::Resolver> {
      return std::make_unique<ResolverChain>(cfg, shared, specs, preferred);
    };
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
