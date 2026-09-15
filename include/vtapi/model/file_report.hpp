#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// Aggregated verdicts across all engines, mirroring attributes.
// last_analysis_stats in the v3 response.
struct AnalysisStats {
    int64_t harmless = 0;
    int64_t malicious = 0;
    int64_t suspicious = 0;
    int64_t timeout = 0;
    int64_t undetected = 0;
    int64_t type_unsupported = 0;
};

// One engine's verdict inside FileReport::last_analysis_results. Field names
// and types match the v3 JSON per-engine objects exactly.
struct AnalysisResult {
    // Ranking bucket: "malicious", "suspicious", "harmless", "undetected", ...
    std::string category;
    // The malware name reported by the engine, if it flagged the file.
    std::string result;
    // Engine name; redundant with the map key but present in the JSON.
    std::string engine_name;
    // Date of the engine's latest signatures ("YYYYMMDD").
    std::string engine_update;
    // Version of the engine that produced the verdict.
    std::string engine_version;
};

// Parsed GET /files/{id} report. A flat mirror of the v3 JSON response:
// top-level fields come from data.* (type/id/links) and everything else from
// data.attributes.*. Field names and types follow the real v3 payload rather
// than any other client library.
struct FileReport {
    // data.type, e.g. "file".
    std::string type;
    // data.id, the file's sha256.
    std::string id;
    // data.links.self, the API URL that produced this report.
    std::string self_link;

    // --- data.attributes.* ---
    std::string sha256;
    std::string sha1;
    std::string md5;
    std::vector<std::string> names;
    // File type tags assigned by VirusTotal, e.g. {"peexe", "text"}.
    std::vector<std::string> type_tags;
    int64_t size = 0;
    std::string type_description;
    // PE header/format magic, e.g. "PE32 executable ... for MS Windows".
    std::string magic;
    // Locality-sensitive hash (TLSH) if computed.
    std::string tlsh;
    // Most common file name under which the file was submitted.
    std::string meaningful_name;

    // Unix timestamps (seconds since epoch). v3 returns raw integers, so the
    // model keeps them raw; convert to ISO-8601 at the formatting layer if needed.
    int64_t creation_date = 0;
    int64_t first_submission_date = 0;
    int64_t last_submission_date = 0;
    int64_t last_analysis_date = 0;
    int64_t last_modification_date = 0;
    int times_submitted = 0;
    // Community reputation; can be negative.
    int reputation = 0;

    AnalysisStats last_analysis_stats;
    // Per-engine verdicts keyed by engine name.
    std::map<std::string, AnalysisResult> last_analysis_results;
};

// Parses a v3 /files/{id} response body. Missing optional fields fall back to
// defaults; a malformed root yields an empty report (does not throw).
FileReport file_report_from_json(const nlohmann::json& root);

} // namespace vtapi