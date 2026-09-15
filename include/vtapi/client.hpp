#pragma once

#include <chrono>
#include <string>

#include "vtapi/detail/http.hpp"
#include "vtapi/detail/ratelimit.hpp"
#include "vtapi/model/file_report.hpp"

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

private:
    detail::HttpClient http_;
    std::string api_key_;
    std::string base_url_;
    detail::RateLimiter limiter_;
};

} // namespace vtapi