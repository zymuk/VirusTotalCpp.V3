#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "vtapi/model/file_report.hpp" // AnalysisStats, AnalysisResult

namespace vtapi {

// One entry of DomainReport::last_dns_records. These are the domain's DNS
// records from the last scan (v3 field names: type, value, ttl, ...), not the
// resolution objects returned by the `resolutions` relationship.
struct DNSRecord {
    std::string type;    // "A", "AAAA", "MX", "SOA", "CAA", ...
    std::string value;   // record payload (an IP, a host, a text blob, ...)
    int ttl = 0;
    int priority = 0;
    std::string rname;   // SOA responsible party
    int serial = 0;
    int refresh = 0;
    int retry = 0;
    int expire = 0;
    int minimum = 0;
    int flag = 0;
    std::string tag;
};

// One entry of DomainReport::popularity_ranks, keyed by rank provider
// ("Alexa", "Cisco Umbrella", ...).
struct PopularityRank {
    int64_t rank = 0;
    int64_t timestamp = 0;
};

// Parsed GET /domains/{id} report (v3 JSON). Keeps v3 field names and types.
// data.id = the domain name. No v2-shape fields (detected_urls/
// undetected_urls/response_code/verbose_msg).
struct DomainReport {
    std::string type;        // data.type ("domain")
    std::string id;          // data.id (the domain name)
    std::string self_link;   // data.links.self

    // --- data.attributes.* ---
    std::map<std::string, std::string> categories;
    std::string registrar;
    int64_t creation_date = 0;
    int64_t first_seen_date = 0;
    int64_t last_analysis_date = 0;
    int64_t last_modification_date = 0;
    int64_t last_update_date = 0;
    int64_t whois_date = 0;
    int64_t last_dns_records_date = 0;
    int reputation = 0;
    std::vector<std::string> tags;
    std::string whois;

    // attributes.total_votes: unweighted community votes, split harmless/malicious.
    struct Votes {
        int64_t harmless = 0;
        int64_t malicious = 0;
    };
    Votes total_votes;

    AnalysisStats last_analysis_stats;
    std::map<std::string, AnalysisResult> last_analysis_results;
    std::vector<DNSRecord> last_dns_records;
    std::map<std::string, PopularityRank> popularity_ranks;
};

DomainReport domain_report_from_json(const nlohmann::json& root);

} // namespace vtapi