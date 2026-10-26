#include "vtapi/model/yara_rule.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {
namespace {

std::string link_value(const nlohmann::json& links, const char* key) {
    if (!links.is_object() || !links.contains(key))
        return {};
    const auto& value = links.at(key);
    if (value.is_string())
        return value.get<std::string>();
    if (value.is_object() && value.contains("href") && value.at("href").is_string())
        return value.at("href").get<std::string>();
    return {};
}

void parse_rule_object(const nlohmann::json& data, YaraRule& rule) {
    using detail::child_object;
    using detail::json_bool;
    using detail::json_int;
    using detail::json_string;
    using detail::json_strings;

    if (!data.is_object())
        return;

    rule.type = json_string(data, "type");
    rule.id = json_string(data, "id");
    if (data.contains("links") && data.at("links").is_object())
        rule.self_link = link_value(data.at("links"), "self");

    const nlohmann::json attrs = child_object(data, "attributes");
    rule.raw = attrs;

    rule.name = json_string(attrs, "name");
    rule.author = json_string(attrs, "author");
    rule.rule = json_string(attrs, "rule");
    rule.tags = json_strings(attrs, "tags");
    rule.threat_categories = json_strings(attrs, "threat_categories");
    rule.matches = json_int(attrs, "matches");
    rule.enabled = json_bool(attrs, "enabled");
    rule.creation_date = json_int(attrs, "creation_date");
    rule.included_date = json_int(attrs, "included_date");
    rule.last_modification_date = json_int(attrs, "last_modification_date");

    if (attrs.contains("meta") && attrs.at("meta").is_array())
        rule.metadata = attrs.at("meta");
}

} // namespace

YaraRule yara_rule_from_json(const nlohmann::json& root) {
    YaraRule rule;
    if (!root.is_object())
        return rule;

    if (root.contains("data") && root.at("data").is_object())
        parse_rule_object(root.at("data"), rule);
    else
        parse_rule_object(root, rule);
    return rule;
}

YaraRuleList yara_rule_list_from_json(const nlohmann::json& root) {
    YaraRuleList list;
    list.raw = root;
    if (!root.is_object())
        return list;

    if (root.contains("meta") && root.at("meta").is_object())
        list.cursor = detail::json_string(root.at("meta"), "cursor");
    if (root.contains("links") && root.at("links").is_object()) {
        list.self_link = link_value(root.at("links"), "self");
        list.next_link = link_value(root.at("links"), "next");
    }
    if (root.contains("data") && root.at("data").is_array()) {
        for (const auto& item : root.at("data")) {
            if (item.is_object())
                list.rules.push_back(yara_rule_from_json(item));
        }
    }
    return list;
}

} // namespace vtapi
