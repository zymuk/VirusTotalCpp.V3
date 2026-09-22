#include "vtapi/model/mitre.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

namespace {

MitreTechniqueNode technique_from_json(const nlohmann::json& node) {
    using detail::json_string;
    MitreTechniqueNode technique;
    technique.id = json_string(node, "id");
    technique.name = json_string(node, "name");
    technique.description = json_string(node, "description");
    technique.link = json_string(node, "link");
    if (const auto signatures = node.find("signatures");
        signatures != node.end() && signatures->is_array()) {
        for (const auto& element : *signatures) {
            if (!element.is_object())
                continue;
            MitreSignature signature;
            signature.severity = json_string(element, "severity");
            signature.description = json_string(element, "description");
            technique.signatures.push_back(std::move(signature));
        }
    }
    return technique;
}

MitreTactic tactic_from_json(const nlohmann::json& node) {
    using detail::json_string;
    MitreTactic tactic;
    tactic.id = json_string(node, "id");
    tactic.name = json_string(node, "name");
    tactic.description = json_string(node, "description");
    tactic.link = json_string(node, "link");
    if (const auto techniques = node.find("techniques");
        techniques != node.end() && techniques->is_array()) {
        for (const auto& element : *techniques) {
            if (!element.is_object())
                continue;
            tactic.techniques.push_back(technique_from_json(element));
        }
    }
    return tactic;
}

} // namespace

MitreSummary mitre_summary_from_json(const nlohmann::json& root) {
    MitreSummary summary;
    if (!root.is_object())
        return summary;

    const auto data = root.find("data");
    if (data == root.end() || !data->is_object())
        return summary;

    summary.raw = *data;
    for (auto it = data->begin(); it != data->end(); ++it) {
        if (!it->is_object())
            continue;
        std::vector<MitreTactic> tactics;
        if (const auto tactics_json = it->find("tactics");
            tactics_json != it->end() && tactics_json->is_array()) {
            for (const auto& element : *tactics_json) {
                if (!element.is_object())
                    continue;
                tactics.push_back(tactic_from_json(element));
            }
        }
        summary.sandboxes.emplace(it.key(), std::move(tactics));
    }
    return summary;
}

} // namespace vtapi