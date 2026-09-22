#pragma once

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// One signature a sandbox engine matched for a MITRE technique. Severity is one
// of "HIGH"/"MEDIUM"/"LOW"/"INFO"/"UNKNOWN" as returned by the v3 API.
struct MitreSignature {
    std::string severity;
    std::string description;
};

// A technique node of the per-sandbox ATT&CK tree. Unlike the flat
// MitreTechnique refs inside a file_behaviour report, this one carries the full
// technique metadata plus the signatures matched by the sandbox.
struct MitreTechniqueNode {
    std::string id;
    std::string name;
    std::string description;
    std::string link;
    std::vector<MitreSignature> signatures;
};

// A tactic of the tree, holding the techniques observed under it. Ids map to
// attack.mitre.org identifiers ("TA####" for tactics, "T####" for techniques).
struct MitreTactic {
    std::string id;
    std::string name;
    std::string description;
    std::string link;
    std::vector<MitreTechniqueNode> techniques;
};

// Parsed GET /files/{id}/behaviour_mitre_trees. The response's data object is
// keyed by sandbox name, each holding a tactics tree. A missing or malformed
// tree yields empty sandboxes rather than throwing.
struct MitreSummary {
    std::map<std::string, std::vector<MitreTactic>> sandboxes;
    // The complete data.* object verbatim, when present.
    nlohmann::json raw;
};

MitreSummary mitre_summary_from_json(const nlohmann::json& root);

} // namespace vtapi