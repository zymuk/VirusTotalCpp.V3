#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// A crowdsourced YARA rule from GET /yara_rules/{id}. This is the community
// rule corpus; Livehunt rulesets behind GET /yara_rulesets/{id} use the
// separate YaraRuleset model.
struct YaraRule {
    std::string type;      // data.type ("yara_rule")
    std::string id;        // data.id ("<prefix>|<rule name>")
    std::string self_link; // data.links.self

    // --- data.attributes.* ---
    std::string name;
    std::string author;
    std::string rule; // YARA source, including imports/dependencies
    std::vector<std::string> tags;
    std::vector<std::string> threat_categories;
    int64_t matches = 0;
    bool enabled = false;
    int64_t creation_date = 0;
    int64_t included_date = 0;
    int64_t last_modification_date = 0;
    // attributes.meta verbatim: a list of {"key": ..., "value": ...} objects.
    nlohmann::json metadata = nlohmann::json::array();

    // Full attributes object, preserved for fields not surfaced above.
    nlohmann::json raw;
};

// Response of GET /yara_rules. `cursor` echoes meta.cursor for the next page;
// next_link is filled when v3 reports links.next.
struct YaraRuleList {
    std::string cursor;
    std::string self_link;
    std::string next_link;
    std::vector<YaraRule> rules;
    nlohmann::json raw;
};

YaraRule yara_rule_from_json(const nlohmann::json& root);
YaraRuleList yara_rule_list_from_json(const nlohmann::json& root);

} // namespace vtapi
