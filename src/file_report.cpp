#include "vtapi/model/file_report.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

FileReport file_report_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_int;
    using detail::json_string;
    using detail::json_strings;

    FileReport report;
    if (!root.is_object())
        return report;

    const auto data = root.find("data");
    if (data == root.end() || !data->is_object())
        return report;

    report.type = json_string(*data, "type");
    report.id = json_string(*data, "id");

    if (const auto links = data->find("links");
        links != data->end() && links->is_object())
        report.self_link = json_string(*links, "self");

    const auto attrs = data->find("attributes");
    if (attrs == data->end() || !attrs->is_object())
        return report;
    const nlohmann::json& a = *attrs;

    report.sha256 = json_string(a, "sha256");
    report.sha1 = json_string(a, "sha1");
    report.md5 = json_string(a, "md5");
    report.size = json_int(a, "size");
    report.type_description = json_string(a, "type_description");
    report.magic = json_string(a, "magic");
    report.tlsh = json_string(a, "tlsh");
    report.meaningful_name = json_string(a, "meaningful_name");
    report.names = json_strings(a, "names");
    report.type_tags = json_strings(a, "type_tags");

    report.creation_date = json_int(a, "creation_date");
    report.first_submission_date = json_int(a, "first_submission_date");
    report.last_submission_date = json_int(a, "last_submission_date");
    report.last_analysis_date = json_int(a, "last_analysis_date");
    report.last_modification_date = json_int(a, "last_modification_date");
    report.times_submitted = static_cast<int>(json_int(a, "times_submitted"));
    report.reputation = static_cast<int>(json_int(a, "reputation"));

    if (const auto stats = a.find("last_analysis_stats");
        stats != a.end() && stats->is_object()) {
        report.last_analysis_stats.harmless = json_int(*stats, "harmless");
        report.last_analysis_stats.malicious = json_int(*stats, "malicious");
        report.last_analysis_stats.suspicious = json_int(*stats, "suspicious");
        report.last_analysis_stats.timeout = json_int(*stats, "timeout");
        report.last_analysis_stats.undetected = json_int(*stats, "undetected");
        report.last_analysis_stats.type_unsupported = json_int(*stats, "type-unsupported");
    }

    // Verdicts are keyed by engine name, mirroring the JSON object structure.
    if (const auto results = a.find("last_analysis_results");
        results != a.end() && results->is_object()) {
        for (auto it = results->begin(); it != results->end(); ++it) {
            if (!it.value().is_object())
                continue;
            const nlohmann::json& e = it.value();
            AnalysisResult verdict;
            verdict.category = json_string(e, "category");
            verdict.result = json_string(e, "result");
            verdict.engine_name = json_string(e, "engine_name");
            verdict.engine_update = json_string(e, "engine_update");
            verdict.engine_version = json_string(e, "engine_version");
            report.last_analysis_results[it.key()] = std::move(verdict);
        }
    }

    return report;
}

} // namespace vtapi