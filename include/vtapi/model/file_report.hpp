#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// One engine's verdict inside last_analysis_results.
struct EngineResult {
    std::string category;
    std::string engine_name;
    std::string engine_version;
    std::string result;
};

// last_analysis_stats: per-category counts from the latest scan round.
struct AnalysisStats {
    uint64_t harmless = 0;
    uint64_t malicious = 0;
    uint64_t suspicious = 0;
    uint64_t timeout = 0;
    uint64_t undetected = 0;
    uint64_t type_unsupported = 0;

    uint64_t total_detections() const { return malicious; }
};

// Parsed /files/{id} report. Missing optional fields fall back to defaults.
struct FileReport {
    std::string id;                  // data.id — the file's sha256
    std::string sha256;
    std::string sha1;
    std::string md5;
    uint64_t size = 0;
    std::string type_description;
    std::vector<std::string> names;
    int64_t last_analysis_date = 0;
    AnalysisStats stats;
    std::map<std::string, EngineResult> last_analysis_results;
};

FileReport file_report_from_json(const nlohmann::json& root);

} // namespace vtapi