#pragma once
#include<atomic>
#include<cstddef>
#include<vector>

#include "mw/types.hpp"
#include "mw/worker.hpp"

// Will hold: mw::LoadBalancer

namespace mw {

// picks which worker gets each job. the pointers are non-owning, Middleware owns the workers
class LoadBalancer {
  private:
    std::vector<Worker*> workers_; // never empty
    const LbPolicy policy_;
    Clock clock_;
    std::atomic<std::size_t> rr_{0}; // round robin cursor

    // at most two accepting workers, in preference order
    std::vector<Worker*> ranked(TimePoint now);

  public:
    LoadBalancer(std::vector<Worker*> workers, LbPolicy policy, Clock clock);

    // the policy's first choice, or nullptr if nobody is accepting
    Worker* pick();

    // tries the first choice, then the fallback. false means overload
    bool submit(const Job& job);

    LbPolicy policy() const noexcept { return policy_; }
};

} // namespace mw
