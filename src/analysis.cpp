#include "vtapi/model/analysis.hpp"

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

AnalysisResult analysis_result_from_json(const nlohmann::json& j) {
    AnalysisResult r;
    if (!j.is_object())
        return r;
    if (j.contains("category") && !j["category"].is_null())
        r.category = j["category"].get<std::string>();
    if (j.contains("result") && !j["result"].is_null())
        r.result = j["result"].get<std::string>();
    if (j.contains("engine_name") && !j["engine_name"].is_null())
        r.engine_name = j["engine_name"].get<std::string>();
    if (j.contains("engine_update") && !j["engine_update"].is_null())
        r.engine_update = j["engine_update"].get<std::string>();
    if (j.contains("engine_version") && !j["engine_version"].is_null())
        r.engine_version = j["engine_version"].get<std::string>();
    return r;
}

} // namespace

AnalysisReport analysis_report_from_json(const nlohmann::json& root) {
    AnalysisReport a;
    if (!root.contains("data") || !root.at("data").is_object())
        return a;

    const auto& data = root.at("data");
    a.type = data.value("type", "");
    a.id = data.value("id", "");

    if (data.contains("links") && data.at("links").contains("self"))
        a.self_link = data.at("links").at("self");

    if (data.contains("attributes") && data.at("attributes").is_object()) {
        const auto& attr = data.at("attributes");
        a.status = attr.value("status", "");
        a.date = attr.value("date", 0);
        if (attr.contains("stats"))
            a.stats = analysis_stats_from_json(attr.at("stats"));
        if (attr.contains("results") && attr.at("results").is_object()) {
            const auto& results = attr.at("results");
            for (auto it = results.begin(); it != results.end(); ++it) {
                if (it.value().is_object())
                    a.results[it.key()] = analysis_result_from_json(it.value());
            }
        }
    }
    return a;
}

} // namespace vtapi
