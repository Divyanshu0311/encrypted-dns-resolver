#include <fstream>
#include <sstream>
#include <stdexcept>

#include "IP.hpp"
#include "backend/HostsFileResolver.hpp"

namespace backend {
    HostsFileResolver::HostsFileResolver(const std::string& hosts_file, Resolver* fallback) : fallback(fallback) {
        std::ifstream file(hosts_file);
        if (!file) throw std::runtime_error("HostsFileResolver: file does not exist");
        std::string line;
        while (std::getline(file, line)) {
            std::stringstream line_stream(line);
            std::string ip_str;
            line_stream >> ip_str;
            if (ip_str.empty()) continue;
            if (ip_str[0] == '#') continue;
            types::IP ip;
            try {
                ip = types::IP(ip_str);
            } catch (const std::exception& e) {
                throw std::runtime_error("HostsFileResolver: invalid IP address: " + ip_str + ": " + e.what());
            }
            while (!line_stream.eof()) {
                std::string name;
                line_stream >> name;
                if (name.empty()) continue;
                types::DomainName domain_name;
                try {
                    domain_name = types::DomainName(name);
                } catch (...) {
                    throw std::runtime_error("HostsFileResolver: invalid domain name: " + name);
                }
                domain_name.absolute = true;
                if (ip.is_ipv6())
                    records.push_back(types::ResourceRecord{ .name = domain_name, .type = types::RecordType::AAAA, .ttl = 0, .rdata = ip });
                else
                    records.push_back(types::ResourceRecord{ .name = domain_name, .type = types::RecordType::A, .ttl = 0, .rdata = ip });
                records.push_back(types::ResourceRecord{ .name = ip, .type = types::RecordType::PTR, .ttl = 0, .rdata = domain_name });
            }
        }
        file.close();
    }

    types::ResolveResult HostsFileResolver::resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass,
                                                    const bool recurse) {
                                                        types::ResolveResult result;
        if (rclass == types::RecordClass::IN) {
            std::vector<types::ResourceRecord> answers = types::find_records(records, name, type, rclass);
            if (!answers.empty()) {
                result.answer = answers;
                return result;
            }
        }
        if (fallback) return fallback->resolve(name, type, rclass, recurse);
        result.rcode = types::Rcode::Refused;
        return result;
    }
} // namespace backend
