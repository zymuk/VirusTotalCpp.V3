#include "vtapi/model/domain_report.hpp"

#include <cstddef>

namespace vtapi {

DomainReport domain_report_from_json(const nlohmann::json& root) {
    DomainReport r;
    if (!root.contains("data") || !root.at("data").is_object())
        return r;

    const auto& data = root.at("data");

    r.type = data.value("type", "");
    r.id = data.value("id", "");

    if (data.contains("links") && data.at("links").contains("self"))
        r.self_link = data.at("links").at("self");

    if (data.contains("attributes") && data.at("attributes").is_object()) {
        const auto& attr = data.at("attributes");

        r.registrar = attr.value("registrar", "");
        r.creation_date = attr.value("creation_date", 0);
        r.first_seen_date = attr.value("first_seen_date", 0);
        r.last_analysis_date = attr.value("last_analysis_date", 0);
        r.last_modification_date = attr.value("last_modification_date", 0);
        r.last_update_date = attr.value("last_update_date", 0);
        r.whois_date = attr.value("whois_date", 0);
        r.last_dns_records_date = attr.value("last_dns_records_date", 0);
        r.reputation = attr.value("reputation", 0);
        r.whois = attr.value("whois", "");

        if (attr.contains("categories") && attr.at("categories").is_object()) {
            for (auto it = attr.at("categories").begin();
                 it != attr.at("categories").end(); ++it)
                if (it.value().is_string())
                    r.categories[it.key()] = it.value().get<std::string>();
        }

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
            for (const auto& rec : attr.at("last_dns_records")) {
                if (!rec.is_object())
                    continue;
                DNSRecord dns;
                dns.type = rec.value("type", "");
                dns.value = rec.value("value", "");
                dns.ttl = rec.value("ttl", 0);
                dns.priority = rec.value("priority", 0);
                dns.rname = rec.value("rname", "");
                dns.serial = rec.value("serial", 0);
                dns.refresh = rec.value("refresh", 0);
                dns.retry = rec.value("retry", 0);
                dns.expire = rec.value("expire", 0);
                dns.minimum = rec.value("minimum", 0);
                dns.flag = rec.value("flag", 0);
                dns.tag = rec.value("tag", "");
                r.last_dns_records.push_back(std::move(dns));
            }
        }

        if (attr.contains("popularity_ranks") &&
            attr.at("popularity_ranks").is_object()) {
            for (auto it = attr.at("popularity_ranks").begin();
                 it != attr.at("popularity_ranks").end(); ++it) {
                if (!it.value().is_object())
                    continue;
                PopularityRank rank;
                rank.rank = it.value().value("rank", 0);
                rank.timestamp = it.value().value("timestamp", 0);
                r.popularity_ranks[it.key()] = rank;
            }
        }
    }
    return r;
}

} // namespace vtapi