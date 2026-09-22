#include "vtapi/model/sigma_rule.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

SigmaRule sigma_rule_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_string;
    using detail::json_strings;

    SigmaRule rule;
    if (!root.is_object())
        return rule;

    // The rule lives under data.*; attributes hold the metadata.
    const nlohmann::json data = child_object(root, "data");
    if (!data.is_object())
        return rule;

    rule.id = json_string(data, "id");
    const nlohmann::json attrs = child_object(data, "attributes");
    rule.raw = attrs;
    rule.title = json_string(attrs, "title");
    rule.description = json_string(attrs, "description");
    rule.level = json_string(attrs, "level");
    rule.status = json_string(attrs, "status");
    rule.source = json_string(attrs, "source");
    rule.tags = json_strings(attrs, "tags");
    rule.false_positives = json_strings(attrs, "false_positives");
    rule.fields = json_strings(attrs, "fields");
    rule.references = json_strings(attrs, "references");
    return rule;
}

} // namespace vtapi