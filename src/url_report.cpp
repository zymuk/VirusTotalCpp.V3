#include "vtapi/model/url_report.hpp"

#include <cstddef>

namespace vtapi {

UrlReport url_report_from_json(const nlohmann::json& root) {
    UrlReport r;
    if (!root.contains("data") || !root.at("data").is_object())
        return r;

    const auto& data = root.at("data");

    r.type = data.value("type", "");
    r.id = data.value("id", "");

    if (data.contains("links") && data.at("links").contains("self"))
        r.self_link = data.at("links").at("self");

    if (data.contains("attributes") && data.at("attributes").is_object()) {
        const auto& attr = data.at("attributes");
        r.url = attr.value("url", "");
        r.last_analysis_date = attr.value("last_analysis_date", 0);
        r.last_modification_date = attr.value("last_modification_date", 0);
        r.times_submitted = attr.value("times_submitted", 0);
        r.reputation = attr.value("reputation", 0);

        if (attr.contains("last_analysis_stats") &&
            attr.at("last_analysis_stats").is_object()) {
            const auto& stats = attr.at("last_analysis_stats");
            r.last_analysis_stats.harmless = stats.value("harmless", 0);
            r.last_analysis_stats.malicious = stats.value("malicious", 0);
            r.last_analysis_stats.suspicious = stats.value("suspicious", 0);
            r.last_analysis_stats.timeout = stats.value("timeout", 0);
            r.last_analysis_stats.undetected = stats.value("undetected", 0);
            r.last_analysis_stats.type_unsupported =
                stats.value("type-unsupported", 0);
        }

        if (attr.contains("last_analysis_results") &&
            attr.at("last_analysis_results").is_object()) {
            for (auto it = attr.at("last_analysis_results").begin();
                 it != attr.at("last_analysis_results").end(); ++it) {
                const std::string engine = it.key();
                AnalysisResult ar;
                ar.category = it.value().value("category", "");
                ar.result = it.value().value("result", "");
                ar.engine_name = it.value().value("engine_name", engine);
                ar.engine_update = it.value().value("engine_update", "");
                ar.engine_version = it.value().value("engine_version", "");
                r.last_analysis_results[engine] = ar;
            }
        }
    }
    return r;
}

} // namespace vtapi
