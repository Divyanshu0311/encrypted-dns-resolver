#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// Will hold: mw::ResolverInterface

namespace mw {
  enum class RecordType: uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    ANY = 255
  };
  enum class Rcode : uint8_t {
    NoError=0,
    FormErr=1,
    ServFail=2,
    NXDomain=3,
    NotImp=4,
    Refused=5
  };
struct ResourceRecord {
  std::string name;
  RecordType type;
  uint16_t rclass = 1;
  uint32_t ttl = 0;
  std::vector<std::byte> rdata;

  bool operator==(const ResourceRecord&) const = default;
};
// need to write Resolve result
struct ResolveResult {
  Rcode rcode = Rcode::NoError;
  std::vector<ResourceRecord> answers;
  std::vector<ResourceRecord> authority;
  static ResolveResult error(Rcode rc = Rcode::NoError) {
    return ResolveResult{rc, {}, {}};
  }
  bool operator==(const ResolveResult&) const = default;

};
class IResolver {
public:
  IResolver() = default;
  virtual ~IResolver() = default;
  IResolver(const IResolver&) = delete;
  IResolver& operator=(const IResolver&) = delete;
  virtual ResolveResult resolve(std::string_view name, RecordType type) = 0;
};

using ResolverFactory = std::function<std::unique_ptr<IResolver>()>;

} // namespace mw
