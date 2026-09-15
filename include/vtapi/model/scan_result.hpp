#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace vtapi {

// meta.file_info from the v3 upload response (meta is a top-level sibling of
// data). Identifies the uploaded file so the caller can look it up again later
// via GET /files/{id} after scanning completes.
struct FileInfo {
    std::string sha256;
    std::string sha1;
    std::string md5;
    int64_t size = 0;
    std::string name;
};

// Parsed POST /files response. Exact v3 shape: data.* identifies the submitted
// analysis, meta.file_info identifies the file behind it. There is no
// scan_id/response_code/verbose_msg in v3.
struct ScanResult {
    // data.type, e.g. "analysis".
    std::string type;
    // data.id, the analysis id ("u-...") used for GET /analyses/{id} polling.
    std::string id;
    // data.links.self, the API URL that produced this result.
    std::string self_link;
    // meta.file_info, the identifier for later GET /files/{sha256} lookups.
    FileInfo file_info;
};

// Parses a v3 upload response body. Missing optional fields fall back to
// defaults; a malformed root yields an empty result (does not throw).
ScanResult scan_result_from_json(const nlohmann::json& root);

} // namespace vtapi