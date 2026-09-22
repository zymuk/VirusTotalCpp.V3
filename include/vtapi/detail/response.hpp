#pragma once

#include <nlohmann/json.hpp>

#include "vtapi/detail/http.hpp"

namespace vtapi {
namespace detail {

// Translates an HTTP response into a JSON value or a typed vtapi exception.
// Raw body is parsed leniently: invalid JSON becomes an empty object.
nlohmann::json json_or_throw(const HttpResponse& resp);

// Like json_or_throw but keeps the raw body for 2xx responses. Used by
// endpoints that return bytes (e.g. /files/{id}/download) where the body is
// not JSON; non-2xx statuses map to the same exceptions as json_or_throw.
std::string body_or_throw(const HttpResponse& resp);

} // namespace detail
} // namespace vtapi