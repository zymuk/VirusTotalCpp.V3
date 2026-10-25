#include "vtapi/model/search_result.hpp"

namespace vtapi {

SearchResult search_result_from_json(const nlohmann::json& root) {
    SearchResult r;
    if (!root.is_object())
        return r;
    if (root.contains("links") && root["links"].is_object()) {
        if (root["links"].contains("self"))
            r.self_link = root["links"]["self"].get<std::string>();
        if (root["links"].contains("next")) {
            if (root["links"]["next"].is_string())
                r.next_cursor = root["links"]["next"].get<std::string>();
            else if (root["links"]["next"].is_object() && root["links"]["next"].contains("href"))
                r.next_cursor = root["links"]["next"]["href"].get<std::string>();
        }
    }
    if (root.contains("meta") && root["meta"].is_object()) {
        if (root["meta"].contains("count"))
            r.count = root["meta"]["count"].get<int64_t>();
    }
    if (root.contains("data") && root["data"].is_array()) {
        for (const auto& item : root["data"]) {
            if (!item.is_object())
                continue;
            SearchResultItem it;
            it.raw = item;
            it.type = item.value("type", "");
            it.id = item.value("id", "");
            r.data.push_back(std::move(it));
        }
    }
    return r;
}

} // namespace vtapi
