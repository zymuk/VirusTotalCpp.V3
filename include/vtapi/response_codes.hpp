#pragma once

// Response-code enums, kept for method-level parity with Genbox/VirusTotalNet
// (snake_case, C++ idiom). v3 encodes success as HTTP 200 and "never seen" as
// HTTP 404, so models carry no response_code field; these enums exist for the
// action layer (scan/comment results) when a status is needed.

namespace vtapi {

// Status of a file report. present = report data was returned (HTTP 200).
enum class FileReportResponseCode : int {
    // The resource is still being scanned (analysis not finished).
    queued = -2,
    // The resource was not present in VirusTotal's dataset (HTTP 404).
    not_present = 0,
    // The resource was present and its report was retrieved.
    present = 1
};

// Status of a URL report.
enum class UrlReportResponseCode : int {
    not_present = 0,
    present = 1
};

// Result of POST /files (scan a file).
enum class ScanFileResponseCode : int {
    // An error happened in the request.
    error = 0,
    // The submitted item is queued for analysis.
    queued = 1
};

// Result of POST /urls (scan a URL).
enum class UrlScanResponseCode : int {
    queued = 1
};

// Result of a file rescan (POST /files/{id}/analyse).
enum class RescanResponseCode : int {
    // The resource was not found.
    resource_not_found = 0,
    // The requested item is queued for analysis.
    queued = 1
};

// Status of a domain report.
enum class DomainResponseCode : int {
    not_present = 0,
    present = 1
};

// Status of an IP address report.
enum class IPReportResponseCode : int {
    not_present = 0,
    present = 1
};

// Result of creating a comment.
enum class CommentResponseCode : int {
    error = 0,
    success = 1
};

} // namespace vtapi