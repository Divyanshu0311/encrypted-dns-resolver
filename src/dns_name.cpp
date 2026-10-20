#include "mw/dns_name.hpp"
namespace mw {
std::string normalize(std::string_view name) {
  std::string normalised_name;
  for (char c : name) {
    if (c >= 'A' && c <= 'Z') {
      normalised_name.push_back(static_cast<char>(c - 'A' + 'a'));
    }
    else {
      normalised_name.push_back(c);
    }
  }
  if (normalised_name.empty() || normalised_name.back() != '.')
    normalised_name.push_back('.');
  return normalised_name;
}
bool is_valid(std::string_view normalized) noexcept {
  if (normalized == ".")
    return true;
  if (normalized.empty() || normalized.back() != '.' || normalized.size()>254 || normalized.find("..") != std::string_view::npos)
    return false;

  int len = 0;
  for (char c : normalized) {
    if (c!='.')
      len++;
    else {
      if (len <1 || len > 63)
        return false;
      len= 0;
    }
  }
  return true;
}
} // namespace mw
