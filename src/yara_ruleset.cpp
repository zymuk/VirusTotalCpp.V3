#include "vtapi/model/yara_ruleset.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

YaraRuleset yara_ruleset_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_string;

    YaraRuleset ruleset;
    if (!root.is_object())
        return ruleset;

    // The ruleset lives under data.*; attributes hold the metadata.
    const nlohmann::json data = child_object(root, "data");
    if (!data.is_object())
        return ruleset;

    ruleset.id = json_string(data, "id");
    const nlohmann::json attrs = child_object(data, "attributes");
    ruleset.raw = attrs;
    ruleset.name = json_string(attrs, "name");
    ruleset.rules = json_string(attrs, "rules");
    ruleset.source = json_string(attrs, "source");
    return ruleset;
}

} // namespace vtapi