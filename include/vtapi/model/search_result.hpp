#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

struct SearchResultItem {
    std::string type;
    std::string id;
    nlohmann::json raw;
};

struct SearchResult {
    std::vector<SearchResultItem> data;
    std::string next_cursor;
    std::string self_link;
    int64_t count = 0;
};

SearchResult search_result_from_json(const nlohmann::json& root);

} // namespace vtapi
