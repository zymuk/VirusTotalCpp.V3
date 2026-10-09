#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "vtapi/model/file_report.hpp" // AnalysisStats, AnalysisResult

namespace vtapi {

// Parsed GET /urls/{id} report (v3 JSON). Keeps v3 field names and types.
// data.id = base64url(url) (the resource id). No v2-shape fields
// (positives/scans/scan_id/permalink/response_code/verbose_msg).
struct UrlReport {
    std::string type;        // data.type ("url")
    std::string id;          // data.id (base64url url)
    std::string self_link;   // data.links.self

    std::string url;         // data.attributes.url
    int64_t last_analysis_date = 0;
    int64_t last_modification_date = 0;
    int times_submitted = 0;
    int reputation = 0;

    AnalysisStats last_analysis_stats;
    std::map<std::string, AnalysisResult> last_analysis_results;
};

UrlReport url_report_from_json(const nlohmann::json& root);

} // namespace vtapi
