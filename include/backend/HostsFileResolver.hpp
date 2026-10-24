#ifndef BACKEND_HOSTSFILERESOLVER_HPP
#define BACKEND_HOSTSFILERESOLVER_HPP

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "IP.hpp"
#include "Resolver.hpp"

namespace backend {
    class HostsFileResolver : public Resolver {
    private:
        std::vector<types::ResourceRecord> records;
        Resolver* fallback;

    public:
        HostsFileResolver(const std::string& hosts_file, Resolver* fallback) : fallback(fallback) {
            std::ifstream file(hosts_file);
            while (!file.eof()) {
                std::string line;
                std::getline(file, line);
                std::stringstream line_stream(line);
                std::string ip_str;
                line_stream >> ip_str;
                if (ip_str.size() == 0) continue;
                if (ip_str[0] == '#') continue;
                types::IP ip;
                try {
                    ip = types::IP(ip_str);
                } catch (...) {
                    throw std::runtime_error("Invalid IP address: " + ip_str);
                }
                while (!line_stream.eof()) {
                    std::string name;
                    line_stream >> name;
                    if (name.size() == 0) continue;
                    types::DomainName domain_name;
                    try {
                        domain_name = types::DomainName(name);
                    } catch (...) {
                        throw std::runtime_error("Invalid domain name: " + name);
                    }
                    if (ip.is_ipv6())
                        records.push_back(types::ResourceRecord{ .name = domain_name, .type = types::RecordType::AAAA, .ttl = 0, .rdata = ip.to_bytes() });
                    else
                        records.push_back(types::ResourceRecord{ .name = domain_name, .type = types::RecordType::A, .ttl = 0, .rdata = ip.to_bytes() });
                    records.push_back(
                        types::ResourceRecord{ .name = ip.to_domain(), .type = types::RecordType::PTR, .ttl = 0, .rdata = domain_name.to_bytes() });
                }
            }
            file.close();
        }

        HostsFileResolver(const char* hosts_file, Resolver* fallback) : HostsFileResolver(std::string(hosts_file), fallback) {}

        types::ResolveResult resolve(const types::DomainName& name, const types::RecordType type, const types::RecordClass rclass) {
            std::vector<types::ResourceRecord> answers;
            if (rclass == types::RecordClass::IN) {
                if ((type == types::RecordType::A) || (type == types::RecordType::ANY)) {
                    for (const types::ResourceRecord& record : records)
                        if (record.name == name && record.type == types::RecordType::A) answers.push_back(record);
                }
                if ((type == types::RecordType::AAAA) || (type == types::RecordType::ANY)) {
                    for (const types::ResourceRecord& record : records)
                        if (record.name == name && record.type == types::RecordType::AAAA) answers.push_back(record);
                }
                if (type == types::RecordType::PTR) {
                    for (const types::ResourceRecord& record : records)
                        if (record.name == name && record.type == types::RecordType::PTR) answers.push_back(record);
                }
            }
            if (answers.size()) return types::ResolveResult{ .answer = answers };
            if (fallback) return fallback->resolve(name, type, rclass);
            return types::ResolveResult{ .rcode = types::Rcode::NXDomain };
        }
    };
} // namespace backend

#endif
