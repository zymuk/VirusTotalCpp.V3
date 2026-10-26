#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace vtapi {

// ZIP creation job from POST /intelligence/zip_files and
// GET /intelligence/zip_files/{id}. `status` moves through starting →
// creating → finished (or timeout/error-starting/error-creating); only a
// finished ZIP can be downloaded.
struct ZipFile {
    std::string type; // data.type ("zip_file")
    std::string id;
    std::string status;
    int progress = 0;    // 0-100
    int files_ok = 0;
    int files_error = 0;

    // Full attributes object, preserved for fields not surfaced above.
    nlohmann::json raw;
};

ZipFile zip_file_from_json(const nlohmann::json& root);

} // namespace vtapi
