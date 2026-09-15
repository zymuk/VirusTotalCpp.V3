#include "vtapi/model/scan_result.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

ScanResult scan_result_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_int;
    using detail::json_string;

    ScanResult result;
    if (!root.is_object())
        return result;

    const nlohmann::json data = child_object(root, "data");
    result.type = json_string(data, "type");
    result.id = json_string(data, "id");

    const nlohmann::json links = child_object(data, "links");
    result.self_link = json_string(links, "self");

    // meta.file_info is a top-level sibling of data in the real v3 payload.
    const nlohmann::json meta = child_object(root, "meta");
    const nlohmann::json file_info = child_object(meta, "file_info");
    result.file_info.sha256 = json_string(file_info, "sha256");
    result.file_info.sha1 = json_string(file_info, "sha1");
    result.file_info.md5 = json_string(file_info, "md5");
    result.file_info.size = json_int(file_info, "size");
    result.file_info.name = json_string(file_info, "name");

    return result;
}

} // namespace vtapi