#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vtapi/detail/http.hpp"
#include "vtapi/detail/ratelimit.hpp"
#include "vtapi/model/analysis.hpp"
#include "vtapi/model/collection.hpp"
#include "vtapi/model/comment.hpp"
#include "vtapi/model/search_result.hpp"
#include "vtapi/model/metadata.hpp"
#include "vtapi/model/saved_search.hpp"
#include "vtapi/model/behaviour.hpp"
#include "vtapi/model/domain_report.hpp"
#include "vtapi/model/file_report.hpp"
#include "vtapi/model/ip_report.hpp"
#include "vtapi/model/url_report.hpp"
#include "vtapi/model/mitre.hpp"
#include "vtapi/model/relationship.hpp"
#include "vtapi/model/resolution.hpp"
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

    // URL scan (POST /urls). Returns a ScanResult carrying the analysis id
    // (poll with M1's get_file_report or await with M8's await_analysis).
    ScanResult scan_url(const std::string& url);

    // Public virustotal.com analysis-page link for a URL (no HTTP call).
    std::string get_public_url_scan_link(const std::string& url);

    // Loop wrapper around scan_url (v3 has no batch endpoint, so each URL costs
    // one request). All URLs are validated before any request is made.
    std::vector<ScanResult> scan_urls(const std::vector<std::string>& urls);
    UrlReport get_url_report(const std::string& url_or_id,
                             bool scan_if_no_report = false);

    // Loop wrapper around get_url_report (mimics the old v2 batch call for
    // callers used to it). A URL VirusTotal has never seen throws NotFound.
    std::vector<UrlReport> get_url_reports(const std::vector<std::string>& urls);

    ScanResult rescan_url(const std::string& url_or_id);
    // URL comments / votes / relationships (reuse M8 generic template).
    std::string get_url_comments(const std::string& url_or_id);
    void post_url_comment(const std::string& url_or_id, const std::string& text);
    void post_url_vote(const std::string& url_or_id, bool positive);
    std::string get_url_votes(const std::string& url_or_id);
    std::string get_url_relationships(const std::string& url_or_id,
                                      const std::string& relationship);

    // IP address report (GET /ip_addresses/{id}). id is the IP itself; v3 has
    // no batch endpoint, so callers repeat this per address.
    IPReport get_ip_report(const std::string& ip);

    // Re-runs the IP analysis (POST /ip_addresses/{id}/analyse). Returns the
    // new analysis unit; poll with get_ip_report.
    ScanResult rescan_ip(const std::string& ip);

    // IP comments / votes / relationships (reuse M8 generic template).
    std::string get_ip_comments(const std::string& ip);
    void post_ip_comment(const std::string& ip, const std::string& text);
    void post_ip_vote(const std::string& ip, bool positive);
    std::string get_ip_votes(const std::string& ip);
    std::string get_ip_relationships(const std::string& ip,
                                     const std::string& relationship);

    // Domain report (GET /domains/{id}). id is the domain itself; v3 has no
    // batch endpoint, so callers repeat this per domain.
    DomainReport get_domain_report(const std::string& domain);

    // Re-runs the domain analysis (POST /domains/{id}/analyse). Returns the new
    // analysis unit; poll with get_domain_report.
    ScanResult rescan_domain(const std::string& domain);

    // Domain comments / votes / relationships (reuse M8 generic template).
    std::string get_domain_comments(const std::string& domain);
    void post_domain_comment(const std::string& domain, const std::string& text);
    void post_domain_vote(const std::string& domain, bool positive);
    std::string get_domain_votes(const std::string& domain);
    std::string get_domain_relationships(const std::string& domain,
                                         const std::string& relationship);

    // One domain<->IP resolution (GET /resolutions/{id}). id is the opaque
    // resolution id ("<ip><host_name>"); also surfaced via the `resolutions`
    // relationship of domains and IPs.
    Resolution get_resolution(const std::string& id);

    // One analysis unit (GET /analyses/{id}). id is the analysis id returned by
    // scan_file/scan_url/rescan_*. Use status ("queued"/"in-progress"/
    // "completed") to know when the results are final.
    AnalysisReport get_analysis(const std::string& id);

    // Polls GET /analyses/{id} until status becomes "completed" or the timeout
    // elapses. interval is clamped to >= 2s. Throws VtError on timeout.
    AnalysisReport await_analysis(const std::string& id,
                                  std::chrono::seconds timeout = std::chrono::seconds(120),
                                  std::chrono::seconds interval = std::chrono::seconds(2));

    // Comments (GET /comments or /{type}/{id}/comments). text limited to
    // kCommentSizeLimit; exceeding throws VtError.
    CommentListResult get_comments(const std::string& object_type,
                                   const std::string& object_id);
    CommentListResult get_comments_latest();
    Comment get_comment(const std::string& comment_id);
    void delete_comment(const std::string& comment_id);
    void post_comment(const std::string& object_type, const std::string& object_id,
                      const std::string& text);
    void vote_comment(const std::string& comment_id, bool positive);

    // Votes generic (POST/GET on /{type}/{id}/votes). Uses M5–M7 style
    // endpoints; also works for comments via vote_comment above.
    void put_vote(const std::string& object_type, const std::string& object_id,
                  bool positive);
    std::string get_votes(const std::string& object_type, const std::string& object_id);

    // Relationships / Descriptors (generic). GET /{type}/{id}/relationships/{r}
    // returns full objects (raw JSON). GET /{type}/{id}/relationships/{r}/{related_id}
    // returns descriptor JSON.
    std::string get_relationships(const std::string& object_type,
                                  const std::string& object_id,
                                  const std::string& relationship);
    std::string get_relationship_descriptor(const std::string& object_type,
                                            const std::string& object_id,
                                            const std::string& relationship,
                                            const std::string& related_id);

    // Search (GET /search)
    SearchResult search(const std::string& query);
    std::string intelligence_search(const std::string& query);
    std::string get_search_snippets(const std::string& query);

    // Metadata (GET /metadata)
    Metadata get_metadata();

    // Saved searches (GET|POST /user_saved_searches, etc.)
    SavedSearchList get_saved_searches();
    SavedSearch get_saved_search(const std::string& id);
    SavedSearch create_saved_search(const std::string& name, const std::string& query);
    SavedSearch update_saved_search(const std::string& id, const std::string& name,
                                    const std::string& query);
    void delete_saved_search(const std::string& id);

    // Collections (POST/GET/PATCH/DELETE /collections[/{id}]). raw_items lets
    // VirusTotal extract additional IoCs from free text when non-empty.
    Collection create_collection(const std::string& name,
                                 const std::string& description = {},
                                 const std::string& raw_items = {});
    Collection get_collection(const std::string& id);
    Collection update_collection(const std::string& id,
                                 const std::string& name = {},
                                 const std::string& description = {},
                                 const std::string& raw_items = {});
    void delete_collection(const std::string& id);

    // Premium collection listing (GET /collections).
    CollectionList list_collections(int limit = 10, const std::string& cursor = {},
                                    const std::string& filter = {},
                                    const std::string& order = {});

    // Collection comments (reuse the M8 Comment model).
    CommentListResult get_collection_comments(const std::string& id, int limit = 10,
                                              const std::string& cursor = {});
    Comment post_collection_comment(const std::string& id, const std::string& text);

    // Add/remove IoCs. relationship is e.g. "files", "urls", "domains",
    // "ip_addresses" or "references". V3 accepts a batch of descriptors in the
    // request body for both POST and DELETE.
    void add_collection_items(const std::string& id, const std::string& relationship,
                              const std::vector<CollectionElement>& elements);
    void remove_collection_items(const std::string& id, const std::string& relationship,
                                 const std::vector<CollectionElement>& elements);

    // Collection relationships: full objects (/collections/{id}/{relationship})
    // and descriptors (/collections/{id}/relationships/{relationship}).
    RelationshipList get_collection_relationships(
        const std::string& id, const std::string& relationship, int limit = 10,
        const std::string& cursor = {});
    RelationshipList get_collection_relationship_descriptors(
        const std::string& id, const std::string& relationship, int limit = 10,
        const std::string& cursor = {});

    // Premium collection exports and in-collection IoC search.
    std::string export_collection_iocs(const std::string& id,
                                       const std::string& format = "json");
    std::string export_collection_relationship_iocs(
        const std::string& id, const std::string& relationship,
        const std::string& format = "json");
    std::string export_collection_aggregations(const std::string& id,
                                               const std::string& format = "json");
    SearchResult search_collection_iocs(const std::string& id, const std::string& query,
                                        int limit = 10, const std::string& cursor = {},
                                        const std::string& order = {},
                                        const std::string& attributes = {},
                                        const std::string& relationships = {});

private:
    detail::HttpClient http_;
    std::string api_key_;
    std::string base_url_;
    detail::RateLimiter limiter_;
};

} // namespace vtapi