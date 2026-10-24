#pragma once

#include <cstdint>
#include <map>
#include <string>

#include <nlohmann/json.hpp>

#include "vtapi/model/file_report.hpp"

namespace vtapi {

// Parsed GET /analyses/{id} report (v3 JSON). The analysis object returned by
// submissions/rescans; used to poll for completion.
struct AnalysisReport {
    std::string type;      // data.type, e.g. "analysis"
    std::string id;        // data.id
    std::string self_link; // data.links.self

    std::string status;    // "queued", "in-progress", "completed"
    int64_t date = 0;

    AnalysisStats stats;
    std::map<std::string, AnalysisResult> results;
};

AnalysisReport analysis_report_from_json(const nlohmann::json& root);

} // namespace vtapi
