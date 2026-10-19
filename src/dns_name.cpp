#include "mw/dns_name.hpp"
#include<bits/stdc++.h>
#include <cctype>
namespace mw {
std::string normalize(std::string_view name) {
  string normalised_name;
  for (char c : name) {
    if (isalpha(c)) {
      normalised_name.push_back(std::tolower(c));
    }
    else {
      normalised_name.push_back(c);
    }
  }
  normalised_name.push_back('.');
  return normalised_name;
}
bool is_valid(std::string_view normalized) noexcept {

}
} // namespace mw
