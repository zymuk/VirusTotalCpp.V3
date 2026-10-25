#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

struct SavedSearch {
    std::string type;
    std::string id;
    nlohmann::json raw;
};

struct SavedSearchList {
    std::vector<SavedSearch> data;
    nlohmann::json raw;
};

SavedSearch saved_search_from_json(const nlohmann::json& root);
SavedSearchList saved_search_list_from_json(const nlohmann::json& root);

} // namespace vtapi
