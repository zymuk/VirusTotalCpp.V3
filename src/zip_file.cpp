#include "vtapi/model/zip_file.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

ZipFile zip_file_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_int;
    using detail::json_string;

    ZipFile zip;
    if (!root.is_object())
        return zip;

    // The job lives under data.*; attributes hold the progress fields.
    const nlohmann::json data = child_object(root, "data");
    if (!data.is_object())
        return zip;

    zip.type = json_string(data, "type");
    zip.id = json_string(data, "id");

    const nlohmann::json attrs = child_object(data, "attributes");
    zip.raw = attrs;
    zip.status = json_string(attrs, "status");
    zip.progress = static_cast<int>(json_int(attrs, "progress"));
    zip.files_ok = static_cast<int>(json_int(attrs, "files_ok"));
    zip.files_error = static_cast<int>(json_int(attrs, "files_error"));
    return zip;
}

} // namespace vtapi
