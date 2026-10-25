#include "vtapi/model/metadata.hpp"

namespace vtapi {

Metadata metadata_from_json(const nlohmann::json& root) {
    Metadata m;
    if (root.is_object()) {
        m.raw = root;
    } else if (root.contains("data")) {
        m.raw = root["data"];
    }
    return m;
}

} // namespace vtapi
