#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// A parsed Sigma rule from GET /sigma_rules/{id}. The v3 attributes are title/
// description/level/status/source plus decay-* and tags; only the stable core
// is surfaced as typed fields, the full attributes object stays in `raw`.
struct SigmaRule {
    std::string id;
    std::string title;
    std::string description;
    // Detection confidence: "low", "medium", "high", "critical".
    std::string level;
    // Rule lifecycle status, e.g. "experimental" or "stable".
    std::string status;
    // Where the rule comes from, e.g. "Sigma Integrated Rule Set (GitHub)".
    std::string source;
    std::vector<std::string> tags;
    std::vector<std::string> false_positives;
    std::vector<std::string> fields;
    std::vector<std::string> references;
    nlohmann::json raw; // full attributes verbatim
};

SigmaRule sigma_rule_from_json(const nlohmann::json& root);

} // namespace vtapi