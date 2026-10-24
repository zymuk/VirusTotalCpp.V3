#include "vtapi/model/comment.hpp"

namespace vtapi {

Comment comment_from_json(const nlohmann::json& root) {
    Comment c;
    if (root.is_object()) {
        c.raw = root;
        c.type = root.value("type", "");
        c.id = root.value("id", "");
        if (root.contains("links") && root["links"].is_object() &&
            root["links"].contains("self"))
            c.self_link = root["links"]["self"].get<std::string>();
        if (root.contains("attributes") && root["attributes"].is_object()) {
            const auto& attr = root["attributes"];
            if (attr.contains("text") && !attr["text"].is_null())
                c.text = attr["text"].get<std::string>();
            c.date = attr.value("date", 0);
            if (attr.contains("votes") && attr["votes"].is_object()) {
                const auto& v = attr["votes"];
                c.votes_positive = v.value("positive", 0);
                c.votes_negative = v.value("negative", 0);
            }
            if (attr.contains("html") && !attr["html"].is_null())
                c.html = attr["html"].get<std::string>();
        }
    } else if (root.contains("data") && root["data"].is_object()) {
        // pass through data object
        const auto& data = root["data"];
        return comment_from_json(data);
    }
    return c;
}

CommentListResult comment_list_from_json(const nlohmann::json& root) {
    CommentListResult r;
    if (!root.is_object())
        return r;
    if (root.contains("links") && root["links"].is_object()) {
        if (root["links"].contains("self"))
            r.self_link = root["links"]["self"].get<std::string>();
        if (root["links"].contains("next")) {
            // v3 often gives next as full URL; keep as-is string if present
            if (root["links"]["next"].is_string())
                r.next_cursor = root["links"]["next"].get<std::string>();
            else if (root["links"]["next"].is_object() && root["links"]["next"].contains("href"))
                r.next_cursor = root["links"]["next"]["href"].get<std::string>();
        }
    }
    if (root.contains("data") && root["data"].is_array()) {
        for (const auto& item : root["data"]) {
            if (item.is_object())
                r.data.push_back(comment_from_json(item));
        }
    } else if (root.is_array()) {
        for (const auto& item : root) {
            if (item.is_object())
                r.data.push_back(comment_from_json(item));
        }
    }
    return r;
}

} // namespace vtapi
