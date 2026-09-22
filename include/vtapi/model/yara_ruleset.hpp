#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace vtapi {

// A parsed YARA ruleset from GET /yara_rulesets/{id}. v3 exposes the ruleset as
// a plain string of YARA source and origin metadata; the full attributes object
// is kept verbatim in `raw`.
struct YaraRuleset {
    std::string id;
    std::string name;
    // The YARA ruleset source text, as returned by v3.
    std::string rules;
    // Origin of the ruleset, e.g. a GitHub repository URL.
    std::string source;
    nlohmann::json raw; // full attributes verbatim
};

YaraRuleset yara_ruleset_from_json(const nlohmann::json& root);

} // namespace vtapi