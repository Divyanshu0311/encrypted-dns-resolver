#pragma once
#include<string>
#include<string_view>

// Will hold: mw::DnsName
namespace mw {

std::string normalize(std::string_view name);
bool is_valid(std::string_view normalized) noexcept;

} // namespace mw
