#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vtapi/detail/http.hpp"
#include "vtapi/detail/ratelimit.hpp"
#include "vtapi/model/file_report.hpp"
#include "vtapi/model/scan_result.hpp"

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
    // larger than kFileSizeLimit throw VtError — use scan_large_file (premium)
    // for anything bigger.
    ScanResult scan_file(std::vector<uint8_t> data, std::string filename,
                         std::optional<std::string> password = {});

    // Reads the file at path into memory and delegates to the data overload;
    // the filename sent to VT is the path's basename. Missing or oversized
    // files throw VtError before any request is made.
    ScanResult scan_file(const std::string& path,
                         std::optional<std::string> password = {});

    // v3's scan_file accepts at most 32 MB - 1063 bytes (premium keys can go
    // beyond via the two-step scan_large_file flow).
    static constexpr int64_t kFileSizeLimit = 33553369;

private:
    detail::HttpClient http_;
    std::string api_key_;
    std::string base_url_;
    detail::RateLimiter limiter_;
};

} // namespace vtapi