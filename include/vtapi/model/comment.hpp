#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// A single comment object as returned by v3 (/comments, /{type}/{id}/comments).
struct Comment {
    std::string type; // "comment"
    std::string id;
    std::string self_link;

    std::string text;
    int64_t date = 0;
    int64_t votes_positive = 0;
    int64_t votes_negative = 0;
    std::string html;

    // Full raw object preserved for callers that need extra fields.
    nlohmann::json raw;
};

// List result for comment collections. Links carry pagination cursors when present.
struct CommentListResult {
    std::vector<Comment> data;
    std::string next_cursor;
    std::string self_link;
};

// Max length enforced by VirusTotal for comment text.
constexpr std::size_t kCommentSizeLimit = 4096;

Comment comment_from_json(const nlohmann::json& root);
CommentListResult comment_list_from_json(const nlohmann::json& root);

} // namespace vtapi
