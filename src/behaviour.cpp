#pragma once

#include "vtapi/model/behaviour.hpp"
#include "vtapi/detail/json.hpp"

namespace vtapi {

FileBehaviour file_behaviour_from_json(const nlohmann::json& data) {
    using detail::child_object;
    using detail::json_bool;
    using detail::json_int;
    using detail::json_string;
    using detail::json_strings;

    FileBehaviour behaviour;
    if (!data.is_object())
        return behaviour;

    behaviour.type = json_string(data, "type");
    behaviour.id = json_string(data, "id");
    behaviour.self_link = json_string(child_object(data, "links"), "self");

    const nlohmann::json a = child_object(data, "attributes");
    behaviour.sandbox_name = json_string(a, "sandbox_name");
    behaviour.analysis_date = json_int(a, "analysis_date");
    behaviour.last_modification_date = json_int(a, "last_modification_date");
    behaviour.behash = json_string(a, "behash");
    behaviour.verdicts = json_strings(a, "verdicts");
    behaviour.tags = json_strings(a, "tags");
    behaviour.has_html_report = json_bool(a, "has_html_report");
    behaviour.has_pcap = json_bool(a, "has_pcap");

    if (const auto techniques = a.find("mitre_attack_techniques");
        techniques != a.end() && techniques->is_array()) {
        for (const auto& element : *techniques) {
            if (!element.is_object())
                continue;
            MitreTechnique technique;
            technique.id = json_string(element, "id");
            technique.signature_description =
                json_string(element, "signature_description");
            behaviour.mitre_attack_techniques.push_back(std::move(technique));
        }
    }

    if (const auto matches = a.find("signature_matches");
        matches != a.end() && matches->is_array()) {
        for (const auto& element : *matches) {
            if (!element.is_object())
                continue;
            SignatureMatch match;
            match.id = json_string(element, "id");
            match.name = json_string(element, "name");
            match.description = json_string(element, "description");
            match.format = json_string(element, "format");
            match.rule_src = json_string(element, "rule_src");
            match.authors = json_strings(element, "authors");
            match.match_data = json_strings(element, "match_data");
            behaviour.signature_matches.push_back(std::move(match));
        }
    }

    behaviour.attributes = a;
    return behaviour;
}

BehaviourList behaviour_list_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_int;

    BehaviourList list;
    if (!root.is_object())
        return list;

    const nlohmann::json meta = child_object(root, "meta");
    list.count = json_int(meta, "count");

    if (const auto data = root.find("data");
        data != root.end() && data->is_array())
        for (const auto& element : *data)
            list.behaviours.push_back(file_behaviour_from_json(element));
    return list;
}

namespace {

const char* behaviour_report_file_path(BehaviourReportFile format) {
    switch (format) {
        case BehaviourReportFile::kHtml: return "html";
        case BehaviourReportFile::kEvtx: return "evtx";
        case BehaviourReportFile::kPcap: return "pcap";
        case BehaviourReportFile::kMemdump: return "memdump";
    }
    return "html";
}

} // namespace

std::string behaviour_report_file_suffix(BehaviourReportFile format) {
    return behaviour_report_file_path(format);
}

BehaviourSummary behaviour_summary_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_string;
    using detail::json_strings;

    BehaviourSummary summary;
    if (!root.is_object())
        return summary;

    // The summary endpoint puts the merged attributes directly under `data`;
    // tolerate an attributes wrapper too, in case the shape ever changes.
    nlohmann::json data = child_object(root, "data");
    if (data.is_object()) {
        const auto attrs = data.find("attributes");
        if (attrs != data.end() && attrs->is_object())
            data = *attrs;
    }

    summary.behash = json_string(data, "behash");
    summary.tags = json_strings(data, "tags");
    summary.verdicts = json_strings(data, "verdicts");
    summary.attributes = data;
    return summary;
}

} // namespace vtapi