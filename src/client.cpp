#include "vtapi/client.hpp"

#include <filesystem>
#include <fstream>
#include <system_error>
#include <utility>

#include "vtapi/detail/hashing.hpp"
#include "vtapi/detail/response.hpp"
#include "vtapi/detail/url.hpp"
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

// Plain string payloads ({"data":"<url>"}) for download_url/upload_url. The
// "what" label names the endpoint in the error when the shape is off.
std::string data_string_from_json(const nlohmann::json& root, const char* what) {
    if (!root.is_object() || !root.contains("data") || !root["data"].is_string())
        throw VtError(std::string(what) + ": missing data string");
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
        data_string_from_json(detail::json_or_throw(url_resp), "upload_url response");
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

std::string VirusTotal::get_file_download_url(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/files/" + hash + "/download_url");
    return data_string_from_json(detail::json_or_throw(resp), "download_url response");
}

void VirusTotal::download_file(const std::string& hash, const std::string& dest_path) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/files/" + hash + "/download");
    const std::string body = detail::body_or_throw(resp);

    // A failed transfer must not leave a partial file at the destination, so
    // write into a temporary sibling and rename it into place on success.
    const std::filesystem::path dest(dest_path);
    const std::filesystem::path tmp =
        dest.parent_path() / (dest.filename().string() + ".part");
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out)
            throw VtError("cannot write file: " + dest_path);
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        if (!out) {
            out.close();
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            throw VtError("cannot write file: " + dest_path);
        }
    }
    std::error_code ec;
    std::filesystem::rename(tmp, dest, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        throw VtError("cannot write file: " + dest_path);
    }
}

ScanResult VirusTotal::rescan_file(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        base_url_ + "/files/" + hash + "/analyse", "", "application/json");
    return scan_result_from_json(detail::json_or_throw(resp));
}

namespace {

void require_valid_hashes(const std::vector<std::string>& hashes) {
    for (const auto& hash : hashes)
        if (!is_hex_hash(hash))
            throw VtError("invalid hash in list: expected 32/40/64 hex characters");
}

} // namespace

std::vector<ScanResult> VirusTotal::rescan_files(const std::vector<std::string>& hashes) {
    require_valid_hashes(hashes);
    std::vector<ScanResult> out;
    out.reserve(hashes.size());
    for (const auto& hash : hashes)
        out.push_back(rescan_file(hash));
    return out;
}

std::vector<FileReport> VirusTotal::get_file_reports(const std::vector<std::string>& hashes) {
    require_valid_hashes(hashes);
    std::vector<FileReport> out;
    out.reserve(hashes.size());
    for (const auto& hash : hashes)
        out.push_back(get_file_report(hash));
    return out;
}

BehaviourList VirusTotal::get_file_behaviours(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/files/" + hash + "/behaviours");
    return behaviour_list_from_json(detail::json_or_throw(resp));
}

BehaviourSummary VirusTotal::get_file_behaviour_summary(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/files/" + hash + "/behaviour_summary");
    return behaviour_summary_from_json(detail::json_or_throw(resp));
}

FileBehaviour VirusTotal::get_file_behaviour(const std::string& sandbox_id) {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        base_url_ + "/file_behaviours/" + detail::percent_encode(sandbox_id));
    const nlohmann::json root = detail::json_or_throw(resp);
    const auto data = root.find("data");
    if (data == root.end() || !data->is_object())
        return file_behaviour_from_json(nlohmann::json::object());
    return file_behaviour_from_json(*data);
}

RelationshipList VirusTotal::get_file_behaviour_relationships(
    const std::string& sandbox_id, const std::string& relationship) {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        base_url_ + "/file_behaviours/" + detail::percent_encode(sandbox_id) +
        "/" + detail::percent_encode(relationship));
    return relationship_list_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_file_behaviour_file(const std::string& sandbox_id,
                                                BehaviourReportFile format) {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        base_url_ + "/file_behaviours/" + detail::percent_encode(sandbox_id) +
        "/" + behaviour_report_file_suffix(format));
    return detail::body_or_throw(resp);
}

RelationshipList VirusTotal::get_file_relationships(const std::string& hash,
                                                      const std::string& relationship) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        base_url_ + "/files/" + hash + "/relationships/" +
        detail::percent_encode(relationship));
    return relationship_list_from_json(detail::json_or_throw(resp));
}

SigmaRule VirusTotal::get_sigma_rule(const std::string& id) {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/sigma_rules/" + id);
    return sigma_rule_from_json(detail::json_or_throw(resp));
}

YaraRuleset VirusTotal::get_yara_ruleset(const std::string& id) {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/yara_rulesets/" + id);
    return yara_ruleset_from_json(detail::json_or_throw(resp));
}

MitreSummary VirusTotal::get_mitre_summary(const std::string& hash) {
    if (!is_hex_hash(hash))
        throw VtError("invalid hash: expected 32/40/64 hex characters");

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/files/" + hash + "/behaviour_mitre_trees");
    return mitre_summary_from_json(detail::json_or_throw(resp));
}

} // namespace vtapi