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

void extract_error(const nlohmann::json& json, std::string& code,
                   std::string& message) {
    if (json.is_object() && json.contains("error") && json["error"].is_object()) {
        const nlohmann::json& err = json["error"];
        if (err.contains("code") && err["code"].is_string())
            code = err["code"].get<std::string>();
        if (err.contains("message") && err["message"].is_string())
            message = err["message"].get<std::string>();
    }
}

// Maps an HTTP status to the matching typed exception; only reaches here for
// non-2xx statuses and transport failures (status 0).
[[noreturn]] void throw_for_status(long status, const std::string& code,
                                   const std::string& message) {
    switch (status) {
        case 403:
            throw vtapi::AuthError(message);
        case 404:
            throw vtapi::NotFound(message);
        case 429:
            throw vtapi::RateLimit(message);
        case 0:
            throw vtapi::NetworkError(message);
        default:
            throw vtapi::ApiError(static_cast<int>(status), code, message);
    }
}

} // namespace

namespace vtapi {
namespace detail {

nlohmann::json json_or_throw(const HttpResponse& resp) {
    nlohmann::json json = try_parse(resp.body);

    std::string code;
    std::string message;
    extract_error(json, code, message);
    if (message.empty())
        message = fallback_message(resp);

    switch (resp.status) {
        case 200:
        case 201:
        case 204:
            return json;
        default:
            throw_for_status(resp.status, code, message);
    }
}

std::string body_or_throw(const HttpResponse& resp) {
    if (resp.status == 200 || resp.status == 201 || resp.status == 204)
        return resp.body; // raw bytes, binary-safe (used by download endpoints)

    nlohmann::json json = try_parse(resp.body);
    std::string code;
    std::string message;
    extract_error(json, code, message);
    if (message.empty())
        message = fallback_message(resp);
    throw_for_status(resp.status, code, message);
}

} // namespace detail
} // namespace vtapi