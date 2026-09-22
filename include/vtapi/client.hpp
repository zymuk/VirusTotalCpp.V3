#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vtapi/detail/http.hpp"
#include "vtapi/detail/ratelimit.hpp"
#include "vtapi/model/behaviour.hpp"
#include "vtapi/model/file_report.hpp"
#include "vtapi/model/mitre.hpp"
#include "vtapi/model/relationship.hpp"
#include "vtapi/model/scan_result.hpp"
#include "vtapi/model/sigma_rule.hpp"
#include "vtapi/model/yara_ruleset.hpp"

namespace vtapi {

struct ClientOptions {
    std::string api_key;              // required, at least 64 chars
    std::string base_url = "https://www.virustotal.com/api/v3";
    bool verify_ssl = true;
    std::chrono::seconds timeout{30};
    double requests_per_minute = 4.0;
    std::string proxy;                // "" = none
};

// One HTTP-backed VT client. Owns the shared curl handle and the rate limiter,
// so a single instance must not be used from multiple threads at once.
class VirusTotal {
public:
    explicit VirusTotal(ClientOptions options);

    VirusTotal(const VirusTotal&) = delete;
    VirusTotal& operator=(const VirusTotal&) = delete;

    // Reports whether a file was already scanned. hash must be a 32/40/64-char
    // hex id (md5/sha1/sha256). If VT has never seen the file → NotFound.
    FileReport get_file_report(const std::string& hash);

    // Public virustotal.com analysis-page link for a file hash (no HTTP call).
    std::string get_public_file_scan_link(const std::string& hash);

    // Submits a file for scanning and returns the queued analysis. filename is
    // sent to VT; password (optional) protects the scan with a password. Files
    // larger than kFileSizeLimit throw VtError — use scan_large_file for
    // anything bigger.
    ScanResult scan_file(std::vector<uint8_t> data, std::string filename,
                         std::optional<std::string> password = {});

    // Reads the file at path into memory and delegates to the data overload;
    // the filename sent to VT is the path's basename. Missing or oversized
    // files throw VtError before any request is made.
    ScanResult scan_file(const std::string& path,
                         std::optional<std::string> password = {});

    // v3's scan_file accepts at most 32 MB - 1063 bytes; larger files go
    // through the two-step scan_large_file flow instead (no privileged key
    // required by the /files/upload_url endpoint).
    static constexpr int64_t kFileSizeLimit = 33553369;

    // Submits a file larger than kFileSizeLimit (up to kLargeFileSizeLimit)
    // using the two-step flow: GET /files/upload_url, then POST the file to the
    // returned upload URL. Same effective shape as scan_file (password optional).
    ScanResult scan_large_file(std::vector<uint8_t> data, std::string filename,
                               std::optional<std::string> password = {});

    // Reads the file at path into memory, gates the size up front, then
    // delegates to the data overload. Missing or oversized files throw VtError
    // before any request is made.
    ScanResult scan_large_file(const std::string& path,
                               std::optional<std::string> password = {});

    // VirusTotal's two-step upload accepts files up to 650 MB.
    static constexpr int64_t kLargeFileSizeLimit = 650LL * 1024 * 1024;

    // Returns the one-time signed download URL for a file. Premium-only
    // endpoint; the URL expires after 1 hour and can be reused freely until then.
    std::string get_file_download_url(const std::string& hash);

    // Downloads a file and writes its raw bytes to dest_path. The endpoint
    // redirects to a signed URL that curl follows transparently. Writes to a
    // temporary file first and renames it into place, so a failed transfer
    // never leaves a partial file. Premium-only endpoint.
    void download_file(const std::string& hash, const std::string& dest_path);

    // Requests a fresh analysis of a file already known to VirusTotal. The
    // returned ScanResult carries the new analysis id; polling it tells when
    // the re-analysis finished. 404 → NotFound (file never scanned).
    ScanResult rescan_file(const std::string& hash);

    // Loop wrapper around rescan_file (v3 has no batch endpoint, so each hash
    // costs one request). All hashes are validated before any request is made.
    std::vector<ScanResult> rescan_files(const std::vector<std::string>& hashes);

    // Loop wrapper around get_file_report (mimics the old v2 batch call for
    // callers used to it). A hash VirusTotal has never seen throws NotFound.
    std::vector<FileReport> get_file_reports(const std::vector<std::string>& hashes);

    // Lists every sandbox behaviour report available for a file.
    // 404 → NotFound (the file is untracked or has no sandbox reports).
    BehaviourList get_file_behaviours(const std::string& hash);

    // Merged summary of all sandbox reports for a file (/behaviour_summary).
    BehaviourSummary get_file_behaviour_summary(const std::string& hash);

    // One sandbox report. sandbox_id is "<sha256>_<sandbox name>", which may
    // contain spaces; it is percent-encoded before it hits the path.
    FileBehaviour get_file_behaviour(const std::string& sandbox_id);

    // Objects related to a sandbox report (GET /file_behaviours/{id}/{rel}).
    RelationshipList get_file_behaviour_relationships(
        const std::string& sandbox_id, const std::string& relationship);

    // Raw HTML/EVTX/PCAP/memory-dump artefact of a sandbox report; the bytes
    // are returned as-is (HTML is text, the rest is binary).
    std::string get_file_behaviour_file(const std::string& sandbox_id,
                                        BehaviourReportFile format);

    // File relationships (GET /files/{id}/relationships/{relationship}).
    // The relationship argument is e.g. "communicating_files",
    // "contacted_urls", "contacted_domains", "contacted_ips",
    // "bundled_files", "dropped_files", "collections", "graphs".
    RelationshipList get_file_relationships(const std::string& hash,
                                             const std::string& relationship);

    // A single Sigma rule (GET /sigma_rules/{id}).
    SigmaRule get_sigma_rule(const std::string& id);

    // A single YARA ruleset (GET /yara_rulesets/{id}).
    YaraRuleset get_yara_ruleset(const std::string& id);

    // MITRE ATT&CK tree for a file (GET /files/{id}/behaviour_mitre_trees).
    // The response groups tactics per sandbox name; the trees are kept nested
    // like v3 returns them rather than flattened into one collection.
    MitreSummary get_mitre_summary(const std::string& hash);

private:
    detail::HttpClient http_;
    std::string api_key_;
    std::string base_url_;
    detail::RateLimiter limiter_;
};

} // namespace vtapi