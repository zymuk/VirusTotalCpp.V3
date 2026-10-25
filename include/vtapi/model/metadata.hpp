#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

struct Metadata {
    nlohmann::json raw;
};

Metadata metadata_from_json(const nlohmann::json& root);

} // namespace vtapi
