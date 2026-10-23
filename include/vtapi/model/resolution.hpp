#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

#include "vtapi/model/file_report.hpp" // AnalysisStats

namespace vtapi {

// Parsed GET /resolutions/{id} report (v3 JSON). One domain<->IP resolution as
// returned by the `resolutions` relationship too. Field names/types follow the
// v3 payload (date/host_name/resolver), not the v2-style hostname/last_resolved.
struct Resolution {
    std::string type;       // data.type ("resolution")
    std::string id;         // data.id ("<ip><host_name>")
    std::string self_link;  // data.links.self

    // --- data.attributes.* ---
    int64_t date = 0;             // when the resolution was observed (unix)
    std::string host_name;        // domain/subdomain that was resolved
    std::string ip_address;       // address the host_name resolved to
    std::string resolver;         // source of the resolution
    AnalysisStats host_name_last_analysis_stats;
    AnalysisStats ip_address_last_analysis_stats;
};

Resolution resolution_from_json(const nlohmann::json& root);

} // namespace vtapi