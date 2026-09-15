#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {
namespace detail {

// Defensive JSON accessors shared by all model parsers: missing keys or wrong
// types yield the type's default value instead of throwing. Callers rely on
// this so a malformed-but-parseable response still produces a usable model.

inline std::string json_string(const nlohmann::json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string())
        return {};
    return it->get<std::string>();
}

inline int64_t json_int(const nlohmann::json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_integer())
        return 0;
    return it->get<int64_t>();
}

inline std::vector<std::string> json_strings(const nlohmann::json& object,
                                             const char* key) {
    std::vector<std::string> out;
    const auto it = object.find(key);
    if (it == object.end() || !it->is_array())
        return out;
    for (const auto& element : *it)
        if (element.is_string())
            out.push_back(element.get<std::string>());
    return out;
}

// Returns the keyed child object, or an empty object when absent/mistyped.
inline nlohmann::json child_object(const nlohmann::json& root, const char* key) {
    const auto it = root.find(key);
    if (it == root.end() || !it->is_object())
        return nlohmann::json::object();
    return *it;
}

} // namespace detail
} // namespace vtapi