#include "vtapi/detail/response.hpp"

#include "vtapi/types.hpp"

namespace {

nlohmann::json try_parse(const std::string& body) {
    try {
        return nlohmann::json::parse(body);
    } catch (...) {
        return nlohmann::json::object();
    }
}

std::string fallback_message(const vtapi::detail::HttpResponse& resp) {
    if (!resp.error.empty())
        return resp.error;
    constexpr std::size_t kMaxMessageLength = 512;
    if (resp.body.size() > kMaxMessageLength)
        return resp.body.substr(0, kMaxMessageLength);
    return resp.body;
}

} // namespace

namespace vtapi {
namespace detail {

nlohmann::json json_or_throw(const HttpResponse& resp) {
    nlohmann::json json = try_parse(resp.body);

    std::string code;
    std::string message;
    if (json.is_object() && json.contains("error") && json["error"].is_object()) {
        const nlohmann::json& err = json["error"];
        if (err.contains("code") && err["code"].is_string())
            code = err["code"].get<std::string>();
        if (err.contains("message") && err["message"].is_string())
            message = err["message"].get<std::string>();
    }
    if (message.empty())
        message = fallback_message(resp);

    switch (resp.status) {
        case 200:
        case 201:
        case 204:
            return json;
        case 403:
            throw AuthError(message);
        case 404:
            throw NotFound(message);
        case 429:
            throw RateLimit(message);
        case 0:
            throw NetworkError(message);
        default:
            throw ApiError(static_cast<int>(resp.status), code, message);
    }
}

} // namespace detail
} // namespace vtapi