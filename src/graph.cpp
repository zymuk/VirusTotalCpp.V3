#include "vtapi/model/graph.hpp"

namespace vtapi {
namespace {

void parse_entity_attributes(const nlohmann::json& attr, GraphEntityAttributes& out) {
    out.raw = attr;
    if (!attr.is_object())
        return;

    out.has_detections = attr.value("has_detections", false);
    out.type_tag = attr.value("type_tag", "");
    out.country = attr.value("country", "");
    out.relationship_type = attr.value("relationship_type", "");
    out.intelligence_query = attr.value("intelligence_query", "");
    out.ruleset_id = attr.value("ruleset_id", "");
    out.retrohunt_job_id = attr.value("retrohunt_job_id", "");

    if (attr.contains("commonalities") && attr.at("commonalities").is_array()) {
        for (const auto& item : attr.at("commonalities")) {
            if (!item.is_object())
                continue;
            GraphCommonality commonality;
            commonality.commonality = item.value("commonality", "");
            commonality.value = item.value("value", "");
            out.commonalities.push_back(std::move(commonality));
        }
    }
}

void parse_node(const nlohmann::json& root, GraphNode& node) {
    if (!root.is_object())
        return;

    node.type = root.value("type", "");
    node.entity_id = root.value("entity_id", "");
    node.text = root.value("text", "");
    node.index = root.value("index", 0);
    node.x = root.value("x", 0.0);
    node.y = root.value("y", 0.0);
    if (root.contains("fx") && root.at("fx").is_number()) {
        node.has_fx = true;
        node.fx = root.at("fx").get<double>();
    }
    if (root.contains("fy") && root.at("fy").is_number()) {
        node.has_fy = true;
        node.fy = root.at("fy").get<double>();
    }
    if (root.contains("entity_attributes"))
        parse_entity_attributes(root.at("entity_attributes"), node.entity_attributes);
}

void parse_link(const nlohmann::json& root, GraphLink& link) {
    if (!root.is_object())
        return;
    link.connection_type = root.value("connection_type", "");
    link.source = root.value("source", "");
    link.target = root.value("target", "");
}

void parse_attributes(const nlohmann::json& attr, Graph& g) {
    if (!attr.is_object())
        return;

    g.comments_count = attr.value("comments_count", 0);
    g.creation_date = attr.value("creation_date", 0);
    g.last_modified_date = attr.value("last_modified_date", 0);
    g.is_private = attr.value("private", false);
    g.views_count = attr.value("views_count", 0);

    if (attr.contains("graph_data") && attr.at("graph_data").is_object()) {
        const auto& data = attr.at("graph_data");
        g.graph_data.description = data.value("description", "");
        g.graph_data.version = data.value("version", "");
    }

    if (attr.contains("nodes") && attr.at("nodes").is_array()) {
        for (const auto& item : attr.at("nodes")) {
            GraphNode node;
            parse_node(item, node);
            if (item.is_object())
                g.nodes.push_back(std::move(node));
        }
    }

    if (attr.contains("links") && attr.at("links").is_array()) {
        for (const auto& item : attr.at("links")) {
            GraphLink link;
            parse_link(item, link);
            if (item.is_object())
                g.links.push_back(std::move(link));
        }
    }
}

void parse_graph_object(const nlohmann::json& data, Graph& g) {
    if (!data.is_object())
        return;
    g.type = data.value("type", "");
    g.id = data.value("id", "");
    if (data.contains("links") && data.at("links").is_object() &&
        data.at("links").contains("self") && data.at("links").at("self").is_string())
        g.self_link = data.at("links").at("self").get<std::string>();
    if (data.contains("attributes"))
        parse_attributes(data.at("attributes"), g);
}

std::string link_value(const nlohmann::json& links, const char* key) {
    if (!links.is_object() || !links.contains(key))
        return {};
    const auto& value = links.at(key);
    if (value.is_string())
        return value.get<std::string>();
    if (value.is_object() && value.contains("href") && value.at("href").is_string())
        return value.at("href").get<std::string>();
    return {};
}

} // namespace

Graph graph_from_json(const nlohmann::json& root) {
    Graph g;
    g.raw = root;
    if (!root.is_object())
        return g;
    if (root.contains("data"))
        parse_graph_object(root.at("data"), g);
    else
        parse_graph_object(root, g);
    return g;
}

GraphList graph_list_from_json(const nlohmann::json& root) {
    GraphList list;
    list.raw = root;
    if (!root.is_object())
        return list;

    if (root.contains("meta") && root.at("meta").is_object())
        list.count = root.at("meta").value("count", 0);
    if (root.contains("links") && root.at("links").is_object()) {
        list.self_link = link_value(root.at("links"), "self");
        list.next_link = link_value(root.at("links"), "next");
    }
    if (root.contains("data") && root.at("data").is_array()) {
        for (const auto& item : root.at("data")) {
            if (item.is_object())
                list.data.push_back(graph_from_json(item));
        }
    }
    return list;
}

} // namespace vtapi
