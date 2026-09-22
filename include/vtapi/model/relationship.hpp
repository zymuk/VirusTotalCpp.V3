#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// One element of a relationship collection: the related object. The full object
// (type + id + attributes + links) is preserved verbatim in `raw`.
struct RelatedObject {
    std::string type;
    std::string id;
    nlohmann::json raw;
};

// Parsed relationship response (data array + meta.count + links). Used by both
// file relationships (GET /files/{id}/{relationship}, full objects) and
// behaviour relationships (GET /file_behaviours/{id}/{relationship}).
struct RelationshipList {
    // meta.count, when the response reports it.
    int64_t count = 0;
    // links.self / links.next (next carries the pagination URL, if any).
    std::string self_link;
    std::string next_link;
    std::vector<RelatedObject> objects;
};

// Parses a v3 relationship response body. Missing optional fields fall back to
// defaults; a malformed root yields an empty list (does not throw).
RelationshipList relationship_list_from_json(const nlohmann::json& root);

} // namespace vtapi