#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace vtapi {

// Base class for every error surfaced by the library.
class VtError : public std::runtime_error {
public:
    explicit VtError(const std::string& message) : std::runtime_error(message) {}
};

// 403 Forbidden / invalid API key.
class AuthError : public VtError {
public:
    explicit AuthError(const std::string& message) : VtError(message) {}
};

// 429 Too Many Requests — the public rate limit was exceeded.
class RateLimit : public VtError {
public:
    explicit RateLimit(const std::string& message) : VtError(message) {}
};

// 404 Not Found — the requested object was never scanned.
class NotFound : public VtError {
public:
    explicit NotFound(const std::string& message) : VtError(message) {}
};

// Any other non-2xx HTTP status, carrying the status code and API error code.
class ApiError : public VtError {
public:
    ApiError(int http_status, std::string api_code, const std::string& message)
        : VtError(message), http_status_(http_status), api_code_(std::move(api_code)) {}

    int http_status() const { return http_status_; }
    const std::string& api_code() const { return api_code_; }

private:
    int http_status_;
    std::string api_code_;
};

// Transport-level failure (DNS, connect, timeout, write) or HTTP status 0.
class NetworkError : public VtError {
public:
    explicit NetworkError(const std::string& message) : VtError(message) {}
};

} // namespace vtapi