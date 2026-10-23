#include "vtapi/model/resolution.hpp"

namespace vtapi {

namespace {

AnalysisStats analysis_stats_from_json(const nlohmann::json& stats) {
    AnalysisStats s;
    if (!stats.is_object())
        return s;
    s.harmless = stats.value("harmless", 0);
    s.malicious = stats.value("malicious", 0);
    s.suspicious = stats.value("suspicious", 0);
    s.timeout = stats.value("timeout", 0);
    s.undetected = stats.value("undetected", 0);
    s.type_unsupported = stats.value("type-unsupported", 0);
    return s;
}

} // namespace

Resolution resolution_from_json(const nlohmann::json& root) {
    Resolution r;
    if (!root.contains("data") || !root.at("data").is_object())
        return r;

    const auto& data = root.at("data");
    r.type = data.value("type", "");
    r.id = data.value("id", "");

    if (data.contains("links") && data.at("links").contains("self"))
        r.self_link = data.at("links").at("self");

    if (data.contains("attributes") && data.at("attributes").is_object()) {
        const auto& attr = data.at("attributes");
        r.date = attr.value("date", 0);
        r.host_name = attr.value("host_name", "");
        r.ip_address = attr.value("ip_address", "");
        r.resolver = attr.value("resolver", "");
        if (attr.contains("host_name_last_analysis_stats"))
            r.host_name_last_analysis_stats =
                analysis_stats_from_json(attr.at("host_name_last_analysis_stats"));
        if (attr.contains("ip_address_last_analysis_stats"))
            r.ip_address_last_analysis_stats =
                analysis_stats_from_json(attr.at("ip_address_last_analysis_stats"));
    }
    return r;
}

} // namespace vtapi