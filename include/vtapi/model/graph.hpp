#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// One commonality attached to a relationship node (v3 graph node
// entity_attributes.commonalities[]).
struct GraphCommonality {
    std::string commonality;
    std::string value;
};

// Node entity attributes. Field names follow the v3 payload; only a subset is
// typed because the available fields depend on the node type.
struct GraphEntityAttributes {
    bool has_detections = false;
    std::string type_tag;
    std::string country;
    std::string relationship_type;
    std::string intelligence_query;
    std::string ruleset_id;
    std::string retrohunt_job_id;
    std::vector<GraphCommonality> commonalities;

    // Full raw attributes preserved for node types with extra fields.
    nlohmann::json raw;
};

// One graph node (attributes.nodes[]).
struct GraphNode {
    std::string type;
    std::string entity_id;
    std::string text;
    int64_t index = 0;
    double x = 0.0;
    double y = 0.0;
    bool has_fx = false;  // fx/fy are optional pinned positions
    bool has_fy = false;
    double fx = 0.0;
    double fy = 0.0;
    GraphEntityAttributes entity_attributes;
};

// One edge between two node entity ids (attributes.links[]).
struct GraphLink {
    std::string connection_type;
    std::string source;
    std::string target;
};

// High-level graph metadata (attributes.graph_data).
struct GraphData {
    std::string description;
    std::string version;
};

// Parsed graph object (GET /graphs/{id}, POST/PATCH /graphs).
struct Graph {
    std::string type;       // data.type ("graph")
    std::string id;         // data.id
    std::string self_link;  // data.links.self

    // --- data.attributes.* ---
    int64_t comments_count = 0;
    int64_t creation_date = 0;
    int64_t last_modified_date = 0;
    bool is_private = false;  // attributes.private ("private" is a C++ keyword)
    int64_t views_count = 0;
    GraphData graph_data;
    std::vector<GraphNode> nodes;
    std::vector<GraphLink> links;

    // Full raw object preserved for callers that need extra fields.
    nlohmann::json raw;
};

// Response of GET /graphs (graph search). Pagination links are preserved as
// returned by v3; next_link is empty when there are no more pages.
struct GraphList {
    int64_t count = 0;
    std::string self_link;
    std::string next_link;
    std::vector<Graph> data;
    nlohmann::json raw;
};

// Descriptor accepted when granting viewers/editors to a graph
// (POST /graphs/{id}/relationships/{viewers|editors}).
struct GraphPrincipal {
    std::string type;  // "user" or "group"
    std::string id;
};

Graph graph_from_json(const nlohmann::json& root);
GraphList graph_list_from_json(const nlohmann::json& root);

} // namespace vtapi
