#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// Prior analysis chained into a Code Insights request. The API expects the
// original code block plus the summary it produced and any analyst remarks;
// the client base64-encodes `request` on the wire.
struct CodeInsightHistory {
    std::string request;     // earlier code block (raw text)
    std::string summary;     // Code Insights summary for that block
    std::string description; // analyst corrections/remarks
};

// Response of POST /codeinsights/analyse-binary. v3 currently answers with
// data.summary + data.description; an older shape returned data as a single
// base64-encoded description, which the client also accepts (summary stays
// empty in that case).
struct CodeInsightReport {
    std::string summary;
    std::string description;
    nlohmann::json raw; // full data value, verbatim
};

} // namespace vtapi
