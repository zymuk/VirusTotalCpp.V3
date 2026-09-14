#include "vtapi/model/file_report.hpp"

namespace {

uint64_t json_uint64(const nlohmann::json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_unsigned())
        return 0;
    return it->get<uint64_t>();
}

std::string json_string(const nlohmann::json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string())
        return {};
    return it->get<std::string>();
}

} // namespace

namespace vtapi {

FileReport file_report_from_json(const nlohmann::json& root) {
    FileReport report;
    if (!root.is_object())
        return report;

    const auto data = root.find("data");
    if (data == root.end() || !data->is_object())
        return report;

    report.id = json_string(*data, "id");

    const auto attrs = data->find("attributes");
    if (attrs == data->end() || !attrs->is_object())
        return report;
    const nlohmann::json& a = *attrs;

    report.sha256 = json_string(a, "sha256");
    report.sha1 = json_string(a, "sha1");
    report.md5 = json_string(a, "md5");

    const auto size = a.find("size");
    if (size != a.end() && size->is_number_unsigned())
        report.size = size->get<uint64_t>();

    report.type_description = json_string(a, "type_description");

    if (const auto names = a.find("names"); names != a.end() && names->is_array()) {
        for (const auto& name : *names)
            if (name.is_string())
                report.names.push_back(name.get<std::string>());
    }

    const auto last_date = a.find("last_analysis_date");
    if (last_date != a.end() && last_date->is_number_integer())
        report.last_analysis_date = last_date->get<int64_t>();

    if (const auto stats = a.find("last_analysis_stats");
        stats != a.end() && stats->is_object()) {
        report.stats.harmless = json_uint64(*stats, "harmless");
        report.stats.malicious = json_uint64(*stats, "malicious");
        report.stats.suspicious = json_uint64(*stats, "suspicious");
        report.stats.timeout = json_uint64(*stats, "timeout");
        report.stats.undetected = json_uint64(*stats, "undetected");
        report.stats.type_unsupported = json_uint64(*stats, "type-unsupported");
    }

    if (const auto results = a.find("last_analysis_results");
        results != a.end() && results->is_object()) {
        for (auto it = results->begin(); it != results->end(); ++it) {
            if (!it.value().is_object())
                continue;
            const nlohmann::json& e = it.value();
            EngineResult engine;
            engine.category = json_string(e, "category");
            engine.engine_name = json_string(e, "engine_name");
            engine.engine_version = json_string(e, "engine_version");
            engine.result = json_string(e, "result");
            report.last_analysis_results[it.key()] = std::move(engine);
        }
    }

    return report;
}

} // namespace vtapi