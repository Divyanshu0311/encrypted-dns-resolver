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
    ResolverChain(const Config& cfg, ResolverShared shared, std::shared_ptr<std::atomic<std::size_t>> preferred)
        : cache_(std::move(shared.cache)), faults_(std::move(shared.faults)) {
      if (cfg.mode == Mode::Forwarding) {
        std::vector<backend::Endpoint> upstreams;
        for (const auto& u : cfg.upstreams) {
          try {
            upstreams.push_back(backend::Endpoint{types::IP(u.host), u.port});
          }
          catch (const std::runtime_error&) {
            throw std::invalid_argument(std::format("upstream '{}' is not an IP address", u.host));
          }
        }
        // every upstream gets a fair share of the request timeout, within reason
        auto per_upstream = std::clamp(cfg.request_timeout / std::max<Ms::rep>(static_cast<Ms::rep>(upstreams.size()), 1), Ms(100), Ms(1000));
        upstream_ = std::make_unique<backend::ForwardingResolver>(std::move(upstreams), *cache_, per_upstream, std::move(preferred));
      }
      else {
        backend::RecursiveOptions opts;
        opts.total_timeout = cfg.request_timeout;
        upstream_ = std::make_unique<backend::RecursiveResolver>(*cache_, opts);
      }

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
    // built once here so a bad upstream or records file fails at startup, not in a worker
    // which upstream answered last, shared so every worker skips a dead one after the first timeout
    auto preferred = std::make_shared<std::atomic<std::size_t>>(0);
    ResolverChain check(cfg, shared, preferred);
    return [cfg, shared, preferred]() -> std::unique_ptr<backend::Resolver> { return std::make_unique<ResolverChain>(cfg, shared, preferred); };
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
