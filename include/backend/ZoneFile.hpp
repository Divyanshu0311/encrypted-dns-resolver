#ifndef BACKEND_ZONEFILE_HPP
#define BACKEND_ZONEFILE_HPP

#include <string>
#include <vector>

#include "Records.hpp"

namespace backend {
    std::vector<types::ResourceRecord> records_from_zone_file(types::DomainName origin, const std::string& zone_file);
}

#endif
