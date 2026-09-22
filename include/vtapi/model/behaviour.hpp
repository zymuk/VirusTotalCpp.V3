#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vtapi {

// One MITRE ATT&CK technique observed inside a sandbox report. Only the id and
// the sandbox's observed behaviour are modelled here; the full technique tree
// lives in MitreSummary (behaviour_mitre_trees endpoint).
struct MitreTechnique {
    // Attack.mitre.org id, e.g. "T1082".
    std::string id;
    // What the sandbox saw that matched this technique.
    std::string signature_description;
};

// One signature a sandbox engine (e.g. CAPA/MalConf) matched in the sample.
struct SignatureMatch {
    std::string id;
    std::string name;
    std::string description;
    // "SIG_FORMAT_CAPA", "SIG_FORMAT_MALCONF", ...
    std::string format;
    std::string rule_src;
    std::vector<std::string> authors;
    std::vector<std::string> match_data;
};

// Parsed GET /file_behaviours/{id} (and one element of /files/{id}/behaviours).
// A curated subset of the sandbox's attributes is surfaced as typed fields;
// the complete attributes object is kept verbatim in `attributes` so no data
// is lost.
struct FileBehaviour {
    // data.type, e.g. "file_behaviour".
    std::string type;
    // data.id, "<sha256>_<sandbox name>", e.g. "275a..0f_VirusTotal Jujubox".
    std::string id;
    // data.links.self.
    std::string self_link;

    // --- data.attributes.* ---
    std::string sandbox_name;
    // Unix timestamps (seconds since epoch), kept raw like v3 returns them.
    int64_t analysis_date = 0;
    int64_t last_modification_date = 0;
    std::string behash;
    std::vector<std::string> verdicts;
    std::vector<std::string> tags;
    bool has_html_report = false;
    bool has_pcap = false;
    std::vector<MitreTechnique> mitre_attack_techniques;
    std::vector<SignatureMatch> signature_matches;
    // The complete data.attributes object, verbatim.
    nlohmann::json attributes;
};

// Parses a behaviour `data` object (single report or one element of a list).
// Missing optional fields fall back to defaults; a malformed root yields an
// empty report (does not throw).
FileBehaviour file_behaviour_from_json(const nlohmann::json& data);

// Parsed GET /files/{id}/behaviours: the list of sandbox reports for a file.
struct BehaviourList {
    // meta.count, when the response reports it.
    int64_t count = 0;
    std::vector<FileBehaviour> behaviours;
};

BehaviourList behaviour_list_from_json(const nlohmann::json& root);

// Parsed GET /files/{id}/behaviour_summary. The summary merges the attributes
// of every sandbox report and drops the per-sandbox fields, so `attributes`
// is the merged object; a few common keys are surfaced as typed fields.
struct BehaviourSummary {
    std::string behash;
    std::vector<std::string> tags;
    std::vector<std::string> verdicts;
    nlohmann::json attributes;
};

BehaviourSummary behaviour_summary_from_json(const nlohmann::json& root);

// Which raw artefact to fetch for a sandbox report. Maps to the path suffix of
// /file_behaviours/{id}/{html|evtx|pcap|memdump}.
enum class BehaviourReportFile { kHtml, kEvtx, kPcap, kMemdump };

// Returns the URL path suffix ("html", "evtx", "pcap", "memdump") for a format.
std::string behaviour_report_file_suffix(BehaviourReportFile format);

} // namespace vtapi