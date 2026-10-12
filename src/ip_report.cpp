#include "vtapi/model/ip_report.hpp"

#include <cstddef>

namespace vtapi {

IPReport ip_report_from_json(const nlohmann::json& root) {
    IPReport r;
    if (!root.contains("data") || !root.at("data").is_object())
        return r;

    const auto& data = root.at("data");

    r.type = data.value("type", "");
    r.id = data.value("id", "");

    if (data.contains("links") && data.at("links").contains("self"))
        r.self_link = data.at("links").at("self");

    if (data.contains("attributes") && data.at("attributes").is_object()) {
        const auto& attr = data.at("attributes");

        r.as_owner = attr.value("as_owner", "");
        r.asn = attr.value("asn", 0);
        r.continent = attr.value("continent", "");
        r.country = attr.value("country", "");
        r.network = attr.value("network", "");
        r.regional_internet_registry = attr.value("regional_internet_registry", "");

        r.first_seen_date = attr.value("first_seen_date", 0);
        r.last_analysis_date = attr.value("last_analysis_date", 0);
        r.last_modification_date = attr.value("last_modification_date", 0);
        r.whois_date = attr.value("whois_date", 0);
        r.reputation = attr.value("reputation", 0);

        if (attr.contains("tags") && attr.at("tags").is_array()) {
            for (const auto& tag : attr.at("tags"))
                if (tag.is_string())
                    r.tags.push_back(tag.get<std::string>());
        }

        if (attr.contains("total_votes") && attr.at("total_votes").is_object()) {
            const auto& votes = attr.at("total_votes");
            r.total_votes.harmless = votes.value("harmless", 0);
            r.total_votes.malicious = votes.value("malicious", 0);
        }

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

        if (attr.contains("last_dns_records") &&
            attr.at("last_dns_records").is_array()) {
            for (const auto& record : attr.at("last_dns_records")) {
                if (!record.is_object() || !record.contains("attributes") ||
                    !record.at("attributes").is_object())
                    continue;
                const auto& rec_attr = record.at("attributes");
                DNSResolution dns;
                dns.ip_address = rec_attr.value("ip_address", "");
                dns.hostname = rec_attr.value("hostname", "");
                dns.last_resolved = rec_attr.value("last_resolved", 0);
                r.last_dns_records.push_back(std::move(dns));
            }
        }
    }
    return r;
}

} // namespace vtapi