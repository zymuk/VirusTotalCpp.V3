#include "vtapi/model/saved_search.hpp"

namespace vtapi {

SavedSearch saved_search_from_json(const nlohmann::json& root) {
    SavedSearch s;
    if (root.is_object()) {
        s.raw = root;
        s.type = root.value("type", "");
        s.id = root.value("id", "");
    }
    return s;
}

SavedSearchList saved_search_list_from_json(const nlohmann::json& root) {
    SavedSearchList l;
    l.raw = root;
    if (root.is_object() && root.contains("data") && root["data"].is_array()) {
        for (const auto& item : root["data"]) {
            if (item.is_object())
                l.data.push_back(saved_search_from_json(item));
        }
    }
    return l;
}

} // namespace vtapi
