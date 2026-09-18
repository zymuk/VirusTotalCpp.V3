#include "vtapi/client.hpp"

#include <fstream>
#include <utility>

#include "vtapi/detail/hashing.hpp"
#include "vtapi/detail/response.hpp"
#include "vtapi/types.hpp"
#include "vtapi/version.hpp"

using vtapi::detail::is_hex_hash;

namespace vtapi {

VirusTotal::VirusTotal(ClientOptions options)
    : api_key_(options.api_key),
      base_url_(options.base_url),
      limiter_(options.requests_per_minute) {
    if (api_key_.size() < 64)
        throw VtError("api_key must be at least 64 characters");
    http_.set_timeout(options.timeout);
    http_.set_ssl_verify(options.verify_ssl);
    if (!options.proxy.empty())
        http_.set_proxy(options.proxy);
    http_.set_header("x-apikey", api_key_);
}

FileReport VirusTotal::get_file_report(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/files/" + hash);
    return file_report_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_public_file_scan_link(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    return "https://www.virustotal.com/gui/file/" + hash + "/detection";
}

ScanResult VirusTotal::scan_file(std::vector<uint8_t> data, std::string filename,
                                 std::optional<std::string> password) {
    if (data.size() > static_cast<std::size_t>(kFileSizeLimit))
        throw VtError("file too large: use scan_large_file()");

    std::map<std::string, std::string> fields;
    if (password && !password->empty())
        fields["password"] = *password;

    limiter_.wait();
    const detail::HttpResponse resp = http_.post_multipart(
        base_url_ + "/files", fields, {{"file", std::move(filename), std::move(data)}});
    return scan_result_from_json(detail::json_or_throw(resp));
}

namespace {

// Last path component of a native path. Treats both separators (POSIX and
// Windows) as directory delimiters so an upload name stays a plain filename.
std::string base_name(const std::string& path) {
    const std::string::size_type sep = path.find_last_of("/\\");
    return sep == std::string::npos ? path : path.substr(sep + 1);
}

} // namespace

ScanResult VirusTotal::scan_file(const std::string& path,
                                 std::optional<std::string> password) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw VtError("cannot open file: " + path);
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        throw VtError("cannot read file: " + path);
    }
    return scan_file(std::move(data), base_name(path), std::move(password));
}

namespace {

// JSON helper for the two-step flow: GET /files/upload_url returns a plain
// string payload. We wrap that in json_or_throw and expect a {"data":"url"}.
std::string upload_url_from_json(const nlohmann::json& root) {
    if (!root.is_object() || !root.contains("data") || !root["data"].is_string())
        throw VtError("upload_url response: missing data string");
    return root["data"].get<std::string>();
}

} // namespace

ScanResult VirusTotal::scan_large_file(std::vector<uint8_t> data,
                                       std::string filename,
                                       std::optional<std::string> password) {
    if (data.size() > static_cast<std::size_t>(kLargeFileSizeLimit))
        throw VtError("file too large: VirusTotal accepts at most 650 MB per upload");

    limiter_.wait();
    const detail::HttpResponse url_resp =
        http_.get(base_url_ + "/files/upload_url");
    std::string upload_url =
        upload_url_from_json(detail::json_or_throw(url_resp));
    if (upload_url.find("://") == std::string::npos) {
        upload_url = (upload_url.empty() || upload_url[0] != '/')
                         ? base_url_ + "/" + upload_url
                         : base_url_ + upload_url;
    }

    std::map<std::string, std::string> fields;
    if (password && !password->empty())
        fields["password"] = *password;

    limiter_.wait();
    const detail::HttpResponse resp = http_.post_multipart(
        upload_url, fields, {{"file", std::move(filename), std::move(data)}});
    return scan_result_from_json(detail::json_or_throw(resp));
}

ScanResult VirusTotal::scan_large_file(const std::string& path,
                                       std::optional<std::string> password) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw VtError("cannot open file: " + path);
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        throw VtError("cannot read file: " + path);
    }
    return scan_large_file(std::move(data), base_name(path), std::move(password));
}

} // namespace vtapi