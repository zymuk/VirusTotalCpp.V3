#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "vtapi/model/file_report.hpp" // AnalysisStats, AnalysisResult

namespace vtapi {

// One reverse-DNS record inside IPReport::last_dns_records (v3 shape: each
// entry is a resolution object whose attributes carry these three fields).
struct DNSResolution {
    std::string ip_address;
    std::string hostname;
    int64_t last_resolved = 0;
};

// Parsed GET /ip_addresses/{id} report (v3 JSON). Keeps v3 field names and
// types. data.id = the IP address itself. No v2-shape fields
// (resolutions/detected_urls/response_code/verbose_msg). The v3 field key is
// "last_dns_records" (the roadmap summary calls it "last_dns_results", but the
// real payload, and hence this model, follows the API).
struct IPReport {
    std::string type;        // data.type ("ip_address")
    std::string id;          // data.id (the IP address)
    std::string self_link;   // data.links.self

    // --- data.attributes.* ---
    std::string as_owner;
    int64_t asn = 0;
    std::string continent;
    std::string country;
    std::string network;
    std::string regional_internet_registry;

    int64_t first_seen_date = 0;
    int64_t last_analysis_date = 0;
    int64_t last_modification_date = 0;
    int64_t whois_date = 0;
    int reputation = 0;
    std::vector<std::string> tags;

    // attributes.total_votes: unweighted community votes, split harmless/malicious.
    struct Votes {
        int64_t harmless = 0;
        int64_t malicious = 0;
    };
    Votes total_votes;

    AnalysisStats last_analysis_stats;
    std::map<std::string, AnalysisResult> last_analysis_results;
    std::vector<DNSResolution> last_dns_records;
};

IPReport ip_report_from_json(const nlohmann::json& root);

} // namespace vtapi