#pragma once

#include <nlohmann/json.hpp>

#include "vtapi/detail/http.hpp"

namespace vtapi {
namespace detail {

// Translates an HTTP response into a JSON value or a typed vtapi exception.
// Raw body is parsed leniently: invalid JSON becomes an empty object.
nlohmann::json json_or_throw(const HttpResponse& resp);

} // namespace detail
} // namespace vtapi