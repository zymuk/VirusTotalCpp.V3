#include "vtapi/model/relationship.hpp"

#include "vtapi/detail/json.hpp"

namespace vtapi {

RelationshipList relationship_list_from_json(const nlohmann::json& root) {
    using detail::child_object;
    using detail::json_int;
    using detail::json_string;

    RelationshipList list;
    if (!root.is_object())
        return list;

    if (const auto data = root.find("data");
        data != root.end() && data->is_array()) {
        for (const auto& element : *data) {
            if (!element.is_object())
                continue;
            RelatedObject object;
            object.type = json_string(element, "type");
            object.id = json_string(element, "id");
            object.raw = element;
            list.objects.push_back(std::move(object));
        }
    }

    const nlohmann::json meta = child_object(root, "meta");
    list.count = json_int(meta, "count");

    const nlohmann::json links = child_object(root, "links");
    list.self_link = json_string(links, "self");
    list.next_link = json_string(links, "next");
    return list;
}

} // namespace vtapi