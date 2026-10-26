#include <thread>

#include "vtapi/client.hpp"

#include <filesystem>
#include <fstream>
#include <system_error>
#include <utility>

#include "vtapi/detail/base64.hpp"
#include "vtapi/detail/hashing.hpp"
#include "vtapi/detail/json.hpp"
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

// A failed transfer must not leave a partial file at the destination, so write
// into a temporary sibling and rename it into place on success.
void write_file_atomic(const std::string& dest_path, const std::string& body) {
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

    write_file_atomic(dest_path, body);
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

ScanResult VirusTotal::scan_url(const std::string& url) {
    if (url.empty() || url.find("://") == std::string::npos)
        throw VtError("invalid url: must contain ://");

    limiter_.wait();
    const detail::HttpResponse resp = http_.post_multipart(
        base_url_ + "/urls",
        {{"url", url}},
        {});
    return scan_result_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_public_url_scan_link(const std::string& url) {
    if (url.empty() || url.find("://") == std::string::npos)
        throw VtError("invalid url: must contain ://");
    return "https://www.virustotal.com/gui/url/" +
           detail::base64url_encode(url) + "/detection";
}

namespace {

void require_valid_urls(const std::vector<std::string>& urls) {
    for (const auto& url : urls)
        if (url.empty() || url.find("://") == std::string::npos)
            throw VtError("invalid url in list: must contain ://");
}

// IPv4 ("1.2.3.4") or IPv6 ("2001:db8::1") literal. Anything else (a hostname,
// an empty string) cannot address an IP object id, so reject it before the HTTP
// round-trip. Zone ids ("fe80::1%eth0") are not accepted by the API.
bool is_valid_ip(const std::string& ip) {
    if (ip.empty())
        return false;
    if (ip.find(':') != std::string::npos) {
        // IPv6. The ::: uppercase/lowercase scans one pass; a literal may start
        // with "::" (leading zero run), so allow up to eight hex groups.
        std::size_t groups = 0;
        bool in_group = false;
        for (const char c : ip) {
            const bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                (c >= 'A' && c <= 'F');
            if (is_hex) {
                in_group = true;
            } else if (c == ':') {
                if (in_group)
                    ++groups;
                in_group = false;
            } else {
                return false;
            }
        }
        if (in_group)
            ++groups;
        return groups >= 1 && groups <= 8;
    }
    // IPv4 dotted quad: exactly one dot in each gap, values 0..255.
    std::size_t octets = 0;
    int value = 0;
    int digits = 0;
    for (const char c : ip) {
        if (c >= '0' && c <= '9') {
            value = value * 10 + (c - '0');
            ++digits;
            if (digits > 3 || value > 255)
                return false;
        } else if (c == '.') {
            if (digits == 0)
                return false;
            ++octets;
            value = 0;
            digits = 0;
        } else {
            return false;
        }
    }
    return octets == 3 && digits > 0;
}

// Hostname/DNS name ("example.com", "sub.example.com"). The v3 domain object id
// is the domain itself (no base64url), so reject anything that cannot be a host
// name before the HTTP round-trip: empty, too long, spaces, leading/trailing or
// doubled dots, hyphens at label edges.
bool is_valid_domain(const std::string& domain) {
    if (domain.empty() || domain.size() > 253)
        return false;
    // An IPv4 literal ("1.2.3.4") passes the label checks below; it is not a
    // domain object id.
    if (is_valid_ip(domain))
        return false;
    std::size_t labels = 0;
    std::size_t label_len = 0;
    bool label_has_alpha = false;
    for (std::size_t i = 0; i < domain.size(); ++i) {
        const char c = domain[i];
        if (c == '.') {
            if (label_len == 0 || domain[i - 1] == '-')
                return false;
            ++labels;
            label_len = 0;
            label_has_alpha = false;
        } else {
            const bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            const bool alnum = alpha || (c >= '0' && c <= '9');
            if (!(alnum || c == '-'))
                return false;
            if (c == '-' && label_len == 0)
                return false;
            if (++label_len > 63)
                return false;
            label_has_alpha = label_has_alpha || alpha;
        }
    }
    // No trailing dot/empty label, no trailing hyphen, and a TLD with a letter
    // (a purely numeric last label is an IP, not a domain).
    if (label_len == 0 || domain.back() == '-' || !label_has_alpha)
        return false;
    ++labels;
    return labels >= 2; // require a dot: a bare TLD is not a domain object
}

// v3 requires the object `type` in the POST body; without it the API rejects the
// request with "Expecting object type ... but got None". The comment text is
// JSON-escaped here (a raw quote would otherwise break the payload).
std::string comment_body(const std::string& text) {
    nlohmann::json j;
    j["data"]["type"] = "comment";
    j["data"]["attributes"]["text"] = text;
    return j.dump();
}

// Vote bodies carry type="vote"; `verdict` is "harmless" or "malicious" in v3
// (v2's positive/negative naming no longer applies).
std::string vote_body(bool positive) {
    nlohmann::json j;
    j["data"]["type"] = "vote";
    j["data"]["attributes"]["verdict"] = positive ? "harmless" : "malicious";
    return j.dump();
}

} // namespace

std::vector<ScanResult> VirusTotal::scan_urls(const std::vector<std::string>& urls) {
    require_valid_urls(urls);
    std::vector<ScanResult> out;
    out.reserve(urls.size());
    for (const auto& url : urls)
        out.push_back(scan_url(url));
    return out;
}

UrlReport VirusTotal::get_url_report(const std::string& url_or_id,
                                     bool scan_if_no_report) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(url_or_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/urls/" + id);
    try {
        return url_report_from_json(detail::json_or_throw(resp));
    } catch (const NotFound&) {
        if (scan_if_no_report) {
            scan_url(url_or_id);
            // After scan, retry once; if still missing, throw.
            limiter_.wait();
            const detail::HttpResponse retry =
                http_.get(base_url_ + "/urls/" + id);
            return url_report_from_json(detail::json_or_throw(retry));
        }
        throw;
    }
}

std::vector<UrlReport> VirusTotal::get_url_reports(const std::vector<std::string>& urls) {
    require_valid_urls(urls);
    std::vector<UrlReport> out;
    out.reserve(urls.size());
    for (const auto& url : urls)
        out.push_back(get_url_report(url));
    return out;
}

ScanResult VirusTotal::rescan_url(const std::string& url_or_id) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(url_or_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/urls/" + id + "/analyse", "", "");
    return scan_result_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_url_comments(const std::string& url_or_id) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) id = detail::base64url_encode(url_or_id);
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/urls/" + id + "/comments");
    return detail::json_or_throw(resp).dump();
}

void VirusTotal::post_url_comment(const std::string& url_or_id, const std::string& text) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) id = detail::base64url_encode(url_or_id);
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/urls/" + id + "/comments",
        comment_body(text), "application/json");
    detail::json_or_throw(resp);
}

void VirusTotal::post_url_vote(const std::string& url_or_id, bool positive) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) id = detail::base64url_encode(url_or_id);
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/urls/" + id + "/votes",
        vote_body(positive), "application/json");
    detail::json_or_throw(resp);
}

std::string VirusTotal::get_url_votes(const std::string& url_or_id) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) id = detail::base64url_encode(url_or_id);
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/urls/" + id + "/votes");
    return detail::json_or_throw(resp).dump();
}

std::string VirusTotal::get_url_relationships(const std::string& url_or_id,
                                              const std::string& relationship) {
    std::string id = url_or_id;
    if (url_or_id.find("://") != std::string::npos) id = detail::base64url_encode(url_or_id);
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/urls/" + id + "/relationships/" + relationship);
    return detail::json_or_throw(resp).dump();
}

IPReport VirusTotal::get_ip_report(const std::string& ip) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/ip_addresses/" + ip);
    return ip_report_from_json(detail::json_or_throw(resp));
}

ScanResult VirusTotal::rescan_ip(const std::string& ip) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/ip_addresses/" + ip + "/analyse", "", "");
    return scan_result_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_ip_comments(const std::string& ip) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/ip_addresses/" + ip + "/comments");
    return detail::json_or_throw(resp).dump();
}

void VirusTotal::post_ip_comment(const std::string& ip, const std::string& text) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/ip_addresses/" + ip + "/comments",
        comment_body(text), "application/json");
    detail::json_or_throw(resp);
}

void VirusTotal::post_ip_vote(const std::string& ip, bool positive) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/ip_addresses/" + ip + "/votes",
        vote_body(positive), "application/json");
    detail::json_or_throw(resp);
}

std::string VirusTotal::get_ip_votes(const std::string& ip) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/ip_addresses/" + ip + "/votes");
    return detail::json_or_throw(resp).dump();
}

std::string VirusTotal::get_ip_relationships(const std::string& ip,
                                             const std::string& relationship) {
    if (!is_valid_ip(ip))
        throw VtError("invalid ip address");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/ip_addresses/" + ip + "/relationships/" + relationship);
    return detail::json_or_throw(resp).dump();
}

DomainReport VirusTotal::get_domain_report(const std::string& domain) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/domains/" + domain);
    return domain_report_from_json(detail::json_or_throw(resp));
}

ScanResult VirusTotal::rescan_domain(const std::string& domain) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/domains/" + domain + "/analyse", "", "");
    return scan_result_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_domain_comments(const std::string& domain) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/domains/" + domain + "/comments");
    return detail::json_or_throw(resp).dump();
}

void VirusTotal::post_domain_comment(const std::string& domain, const std::string& text) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/domains/" + domain + "/comments",
        comment_body(text), "application/json");
    detail::json_or_throw(resp);
}

void VirusTotal::post_domain_vote(const std::string& domain, bool positive) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/domains/" + domain + "/votes",
        vote_body(positive), "application/json");
    detail::json_or_throw(resp);
}

std::string VirusTotal::get_domain_votes(const std::string& domain) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/domains/" + domain + "/votes");
    return detail::json_or_throw(resp).dump();
}

std::string VirusTotal::get_domain_relationships(const std::string& domain,
                                                 const std::string& relationship) {
    if (!is_valid_domain(domain))
        throw VtError("invalid domain");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/domains/" + domain + "/relationships/" + relationship);
    return detail::json_or_throw(resp).dump();
}

Resolution VirusTotal::get_resolution(const std::string& id) {
    if (id.empty())
        throw VtError("invalid resolution id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/resolutions/" + id);
    return resolution_from_json(detail::json_or_throw(resp));
}

AnalysisReport VirusTotal::get_analysis(const std::string& id) {
    if (id.empty())
        throw VtError("invalid analysis id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/analyses/" + id);
    return analysis_report_from_json(detail::json_or_throw(resp));
}

AnalysisReport VirusTotal::await_analysis(const std::string& id,
                                         std::chrono::seconds timeout,
                                         std::chrono::seconds interval) {
    if (id.empty())
        throw VtError("invalid analysis id");
    if (interval < std::chrono::seconds(2))
        interval = std::chrono::seconds(2);
    if (timeout < interval)
        timeout = interval;

    const auto start = std::chrono::steady_clock::now();
    AnalysisReport last;
    while (true) {
        last = get_analysis(id);
        if (last.status == "completed")
            return last;
        const auto now = std::chrono::steady_clock::now();
        if (now - start >= timeout)
            throw VtError("await_analysis timed out");
        std::this_thread::sleep_for(interval);
    }
}

namespace {

bool is_valid_object_type(const std::string& t) {
    return t == "files" || t == "urls" || t == "domains" || t == "ip_addresses" ||
           t == "comments" || t == "analyses" || t == "collections";
}

} // namespace

CommentListResult VirusTotal::get_comments(const std::string& object_type,
                                          const std::string& object_id) {
    if (!is_valid_object_type(object_type))
        throw VtError("invalid object type");
    if (object_id.empty())
        throw VtError("invalid object id");
    if (object_type == "files" && !is_hex_hash(object_id))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    if (object_type == "ip_addresses" && !is_valid_ip(object_id))
        throw VtError("invalid ip address");
    if (object_type == "domains" && !is_valid_domain(object_id))
        throw VtError("invalid domain");
    if (object_type == "urls") {
        // allow raw url or base64url id; if it looks like url require ://
        if (object_id.find("://") != std::string::npos &&
            (object_id.empty() || object_id.find("://") == std::string::npos))
            throw VtError("invalid url");
        // if it's a raw url, convert later? but we need id for path; use as-is if not url form? handle in path
    }

    std::string id = object_id;
    if (object_type == "urls" && object_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(object_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/" + object_type + "/" + id + "/comments");
    return comment_list_from_json(detail::json_or_throw(resp));
}

CommentListResult VirusTotal::get_comments_latest() {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/comments");
    return comment_list_from_json(detail::json_or_throw(resp));
}

Comment VirusTotal::get_comment(const std::string& comment_id) {
    if (comment_id.empty())
        throw VtError("invalid comment id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/comments/" + comment_id);
    const nlohmann::json j = detail::json_or_throw(resp);
    if (j.contains("data"))
        return comment_from_json(j["data"]);
    return comment_from_json(j);
}

void VirusTotal::delete_comment(const std::string& comment_id) {
    if (comment_id.empty())
        throw VtError("invalid comment id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(base_url_ + "/comments/" + comment_id);
    detail::json_or_throw(resp);
}

void VirusTotal::post_comment(const std::string& object_type, const std::string& object_id,
                              const std::string& text) {
    if (!is_valid_object_type(object_type))
        throw VtError("invalid object type");
    if (object_id.empty())
        throw VtError("invalid object id");
    if (text.size() > kCommentSizeLimit)
        throw VtError("comment text exceeds kCommentSizeLimit");
    if (object_type == "files" && !is_hex_hash(object_id))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    if (object_type == "ip_addresses" && !is_valid_ip(object_id))
        throw VtError("invalid ip address");
    if (object_type == "domains" && !is_valid_domain(object_id))
        throw VtError("invalid domain");

    std::string id = object_id;
    if (object_type == "urls" && object_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(object_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/" + object_type + "/" + id + "/comments",
                                                  comment_body(text), "application/json");
    detail::json_or_throw(resp);
}

void VirusTotal::vote_comment(const std::string& comment_id, bool positive) {
    if (comment_id.empty())
        throw VtError("invalid comment id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/comments/" + comment_id + "/votes",
                                                  vote_body(positive), "application/json");
    detail::json_or_throw(resp);
}

void VirusTotal::put_vote(const std::string& object_type, const std::string& object_id,
                          bool positive) {
    if (!is_valid_object_type(object_type) || object_type == "comments")
        throw VtError("invalid object type");
    if (object_id.empty())
        throw VtError("invalid object id");
    if (object_type == "files" && !is_hex_hash(object_id))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    if (object_type == "ip_addresses" && !is_valid_ip(object_id))
        throw VtError("invalid ip address");
    if (object_type == "domains" && !is_valid_domain(object_id))
        throw VtError("invalid domain");

    std::string id = object_id;
    if (object_type == "urls" && object_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(object_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp = http_.post(base_url_ + "/" + object_type + "/" + id + "/votes",
                                                  vote_body(positive), "application/json");
    detail::json_or_throw(resp);
}

std::string VirusTotal::get_votes(const std::string& object_type, const std::string& object_id) {
    if (!is_valid_object_type(object_type) || object_type == "comments")
        throw VtError("invalid object type");
    if (object_id.empty())
        throw VtError("invalid object id");
    if (object_type == "files" && !is_hex_hash(object_id))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    if (object_type == "ip_addresses" && !is_valid_ip(object_id))
        throw VtError("invalid ip address");
    if (object_type == "domains" && !is_valid_domain(object_id))
        throw VtError("invalid domain");

    std::string id = object_id;
    if (object_type == "urls" && object_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(object_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/" + object_type + "/" + id + "/votes");
    return detail::json_or_throw(resp).dump();
}

std::string VirusTotal::get_relationships(const std::string& object_type,
                                         const std::string& object_id,
                                         const std::string& relationship) {
    if (!is_valid_object_type(object_type))
        throw VtError("invalid object type");
    if (object_id.empty() || relationship.empty())
        throw VtError("invalid relationship request");
    if (object_type == "files" && !is_hex_hash(object_id))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    if (object_type == "ip_addresses" && !is_valid_ip(object_id))
        throw VtError("invalid ip address");
    if (object_type == "domains" && !is_valid_domain(object_id))
        throw VtError("invalid domain");
    if (object_type == "analyses" && object_id.empty())
        throw VtError("invalid analysis id");

    std::string id = object_id;
    if (object_type == "urls" && object_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(object_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/" + object_type + "/" + id + "/relationships/" + relationship);
    return detail::json_or_throw(resp).dump();
}

std::string VirusTotal::get_relationship_descriptor(const std::string& object_type,
                                                   const std::string& object_id,
                                                   const std::string& relationship,
                                                   const std::string& related_id) {
    if (!is_valid_object_type(object_type))
        throw VtError("invalid object type");
    if (object_id.empty() || relationship.empty() || related_id.empty())
        throw VtError("invalid relationship request");
    if (object_type == "files" && !is_hex_hash(object_id))
        throw VtError("invalid hash: expected 32/40/64 hex characters");
    if (object_type == "ip_addresses" && !is_valid_ip(object_id))
        throw VtError("invalid ip address");
    if (object_type == "domains" && !is_valid_domain(object_id))
        throw VtError("invalid domain");
    if (object_type == "analyses" && object_id.empty())
        throw VtError("invalid analysis id");

    std::string id = object_id;
    if (object_type == "urls" && object_id.find("://") != std::string::npos) {
        id = detail::base64url_encode(object_id);
    }

    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        base_url_ + "/" + object_type + "/" + id + "/relationships/" + relationship + "/" + related_id);
    return detail::json_or_throw(resp).dump();
}

SearchResult VirusTotal::search(const std::string& query) {
    if (query.empty())
        throw VtError("invalid search query");
    limiter_.wait();
    // v3 search uses query parameter; base_url may have trailing slash not typical
    std::string url = base_url_ + "/search?query=" + detail::percent_encode(query);
    const detail::HttpResponse resp = http_.get(url);
    return search_result_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::intelligence_search(const std::string& query) {
    if (query.empty())
        throw VtError("invalid search query");
    nlohmann::json body;
    body["query"] = query;
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/intelligence/search", body.dump(), "application/json");
    return detail::json_or_throw(resp).dump();
}

std::string VirusTotal::get_search_snippets(const std::string& query) {
    if (query.empty())
        throw VtError("invalid search query");
    limiter_.wait();
    std::string url = base_url_ + "/intelligence/search/snippets?query=" + detail::percent_encode(query);
    const detail::HttpResponse resp = http_.get(url);
    return detail::json_or_throw(resp).dump();
}

Metadata VirusTotal::get_metadata() {
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/metadata");
    return metadata_from_json(detail::json_or_throw(resp));
}

SavedSearchList VirusTotal::get_saved_searches() {
    limiter_.wait();
    try {
        const detail::HttpResponse resp = http_.get(base_url_ + "/user_saved_searches");
        return saved_search_list_from_json(detail::json_or_throw(resp));
    } catch (const NotFound&) {
        SavedSearchList empty;
        return empty;
    }
}

SavedSearch VirusTotal::get_saved_search(const std::string& id) {
    if (id.empty())
        throw VtError("invalid saved search id");
    limiter_.wait();
    try {
        const detail::HttpResponse resp = http_.get(base_url_ + "/user_saved_searches/" + id);
        const nlohmann::json j = detail::json_or_throw(resp);
        if (j.contains("data"))
            return saved_search_from_json(j["data"]);
        return saved_search_from_json(j);
    } catch (const NotFound&) {
        SavedSearch s;
        return s;
    }
}

SavedSearch VirusTotal::create_saved_search(const std::string& name, const std::string& query) {
    if (name.empty() || query.empty())
        throw VtError("invalid saved search");
    nlohmann::json body;
    body["data"]["type"] = "user_saved_search";
    body["data"]["attributes"]["name"] = name;
    body["data"]["attributes"]["query"] = query;
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/user_saved_searches", body.dump(), "application/json");
    const nlohmann::json j = detail::json_or_throw(resp);
    if (j.contains("data"))
        return saved_search_from_json(j["data"]);
    return saved_search_from_json(j);
}

SavedSearch VirusTotal::update_saved_search(const std::string& id, const std::string& name,
                                            const std::string& query) {
    if (id.empty())
        throw VtError("invalid saved search id");
    nlohmann::json body;
    body["data"]["type"] = "user_saved_search";
    body["data"]["id"] = id;
    if (!name.empty())
        body["data"]["attributes"]["name"] = name;
    if (!query.empty())
        body["data"]["attributes"]["query"] = query;
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.patch(base_url_ + "/user_saved_searches/" + id, body.dump(), "application/json");
    const nlohmann::json j = detail::json_or_throw(resp);
    if (j.contains("data"))
        return saved_search_from_json(j["data"]);
    return saved_search_from_json(j);
}

void VirusTotal::delete_saved_search(const std::string& id) {
    if (id.empty())
        throw VtError("invalid saved search id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(base_url_ + "/user_saved_searches/" + id);
    detail::json_or_throw(resp);
}

namespace {

std::string collection_url(const std::string& base_url, const std::string& id) {
    return base_url + "/collections/" + id;
}

std::string append_query(
    std::string url,
    const std::vector<std::pair<std::string, std::string>>& params) {
    bool first = url.find('?') == std::string::npos;
    for (const auto& param : params) {
        if (param.second.empty())
            continue;
        url += first ? "?" : "&";
        first = false;
        url += detail::percent_encode(param.first);
        url += "=";
        url += detail::percent_encode(param.second);
    }
    return url;
}

std::string collection_attributes_body(const std::string& name,
                                       const std::string& description,
                                       const std::string& raw_items) {
    nlohmann::json body;
    body["data"]["type"] = "collection";
    if (!name.empty())
        body["data"]["attributes"]["name"] = name;
    if (!description.empty())
        body["data"]["attributes"]["description"] = description;
    if (!raw_items.empty())
        body["data"]["raw_items"] = raw_items;
    return body.dump();
}

std::string collection_items_body(const std::vector<CollectionElement>& elements) {
    nlohmann::json data = nlohmann::json::array();
    for (const auto& element : elements) {
        nlohmann::json descriptor;
        descriptor["type"] = element.type;
        if (element.type == "url" && !element.url.empty())
            descriptor["url"] = element.url;
        else
            descriptor["id"] = element.id;
        data.push_back(std::move(descriptor));
    }
    nlohmann::json body;
    body["data"] = std::move(data);
    return body.dump();
}

void validate_collection_items(const std::string& id, const std::string& relationship,
                               const std::vector<CollectionElement>& elements) {
    if (id.empty())
        throw VtError("invalid collection id");
    if (relationship.empty())
        throw VtError("invalid collection relationship");
    if (elements.empty())
        throw VtError("empty collection item list");
    for (const auto& element : elements) {
        if (element.type.empty())
            throw VtError("invalid collection item type");
        if (element.type == "url" && !element.url.empty())
            continue;
        if (element.id.empty())
            throw VtError("invalid collection item id");
    }
}

void validate_export_format(const std::string& format, bool aggregations) {
    if (format == "json" || format == "csv")
        return;
    if (!aggregations && format == "stix")
        return;
    throw VtError("invalid collection export format");
}

} // namespace

Collection VirusTotal::create_collection(const std::string& name,
                                          const std::string& description,
                                          const std::string& raw_items) {
    if (name.empty())
        throw VtError("invalid collection name");
    const std::string body = collection_attributes_body(name, description, raw_items);
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/collections", body, "application/json");
    return collection_from_json(detail::json_or_throw(resp));
}

Collection VirusTotal::get_collection(const std::string& id) {
    if (id.empty())
        throw VtError("invalid collection id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(collection_url(base_url_, id));
    return collection_from_json(detail::json_or_throw(resp));
}

Collection VirusTotal::update_collection(const std::string& id,
                                         const std::string& name,
                                         const std::string& description,
                                         const std::string& raw_items) {
    if (id.empty())
        throw VtError("invalid collection id");
    if (name.empty() && description.empty() && raw_items.empty())
        throw VtError("empty collection update");
    const std::string body = collection_attributes_body(name, description, raw_items);
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.patch(collection_url(base_url_, id), body, "application/json");
    return collection_from_json(detail::json_or_throw(resp));
}

void VirusTotal::delete_collection(const std::string& id) {
    if (id.empty())
        throw VtError("invalid collection id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(collection_url(base_url_, id));
    detail::json_or_throw(resp);
}

CollectionList VirusTotal::list_collections(int limit, const std::string& cursor,
                                            const std::string& filter,
                                            const std::string& order) {
    if (limit < 1 || limit > 40)
        throw VtError("collection list limit must be between 1 and 40");
    const std::string url = append_query(
        base_url_ + "/collections",
        {{"limit", std::to_string(limit)}, {"cursor", cursor}, {"filter", filter},
         {"order", order}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return collection_list_from_json(detail::json_or_throw(resp));
}

CommentListResult VirusTotal::get_collection_comments(const std::string& id, int limit,
                                                      const std::string& cursor) {
    if (id.empty())
        throw VtError("invalid collection id");
    if (limit < 1)
        throw VtError("invalid comment limit");
    const std::string url = append_query(
        collection_url(base_url_, id) + "/comments",
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return comment_list_from_json(detail::json_or_throw(resp));
}

Comment VirusTotal::post_collection_comment(const std::string& id,
                                            const std::string& text) {
    if (id.empty())
        throw VtError("invalid collection id");
    if (text.size() > kCommentSizeLimit)
        throw VtError("comment text exceeds kCommentSizeLimit");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        collection_url(base_url_, id) + "/comments", comment_body(text),
        "application/json");
    const nlohmann::json j = detail::json_or_throw(resp);
    if (j.contains("data"))
        return comment_from_json(j["data"]);
    return comment_from_json(j);
}

void VirusTotal::add_collection_items(const std::string& id,
                                      const std::string& relationship,
                                      const std::vector<CollectionElement>& elements) {
    validate_collection_items(id, relationship, elements);
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        collection_url(base_url_, id) + "/" + relationship,
        collection_items_body(elements), "application/json");
    detail::json_or_throw(resp);
}

void VirusTotal::remove_collection_items(const std::string& id,
                                         const std::string& relationship,
                                         const std::vector<CollectionElement>& elements) {
    validate_collection_items(id, relationship, elements);
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(
        collection_url(base_url_, id) + "/" + relationship,
        collection_items_body(elements), "application/json");
    detail::json_or_throw(resp);
}

RelationshipList VirusTotal::get_collection_relationships(
    const std::string& id, const std::string& relationship, int limit,
    const std::string& cursor) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid collection relationship request");
    if (limit < 1)
        throw VtError("invalid relationship limit");
    const std::string url = append_query(
        collection_url(base_url_, id) + "/" + relationship,
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return relationship_list_from_json(detail::json_or_throw(resp));
}

RelationshipList VirusTotal::get_collection_relationship_descriptors(
    const std::string& id, const std::string& relationship, int limit,
    const std::string& cursor) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid collection relationship request");
    if (limit < 1)
        throw VtError("invalid relationship limit");
    const std::string url = append_query(
        collection_url(base_url_, id) + "/relationships/" + relationship,
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return relationship_list_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::export_collection_iocs(const std::string& id,
                                               const std::string& format) {
    if (id.empty())
        throw VtError("invalid collection id");
    validate_export_format(format, false);
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        collection_url(base_url_, id) + "/download/" + format);
    return detail::body_or_throw(resp);
}

std::string VirusTotal::export_collection_relationship_iocs(
    const std::string& id, const std::string& relationship,
    const std::string& format) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid collection relationship request");
    validate_export_format(format, false);
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        collection_url(base_url_, id) + "/" + relationship + "/download/" + format);
    return detail::body_or_throw(resp);
}

std::string VirusTotal::export_collection_aggregations(const std::string& id,
                                                       const std::string& format) {
    if (id.empty())
        throw VtError("invalid collection id");
    validate_export_format(format, true);
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        collection_url(base_url_, id) + "/aggregations/download/" + format);
    return detail::body_or_throw(resp);
}

SearchResult VirusTotal::search_collection_iocs(
    const std::string& id, const std::string& query, int limit,
    const std::string& cursor, const std::string& order,
    const std::string& attributes, const std::string& relationships) {
    if (id.empty() || query.empty())
        throw VtError("invalid collection search request");
    if (limit < 1 || limit > 40)
        throw VtError("collection search limit must be between 1 and 40");
    const std::string url = append_query(
        collection_url(base_url_, id) + "/search",
        {{"query", query}, {"limit", std::to_string(limit)}, {"cursor", cursor},
         {"order", order}, {"attributes", attributes},
         {"relationships", relationships}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return search_result_from_json(detail::json_or_throw(resp));
}

namespace {

std::string graph_url(const std::string& base_url, const std::string& id) {
    return base_url + "/graphs/" + id;
}

void validate_graph_attributes(const nlohmann::json& attributes) {
    if (!attributes.is_object() || attributes.empty())
        throw VtError("invalid graph attributes");
}

std::string graph_attributes_body(const nlohmann::json& attributes) {
    nlohmann::json body;
    body["data"]["type"] = "graph";
    body["data"]["attributes"] = attributes;
    return body.dump();
}

std::string graph_principals_body(const std::vector<GraphPrincipal>& principals) {
    nlohmann::json data = nlohmann::json::array();
    for (const auto& principal : principals) {
        nlohmann::json descriptor;
        descriptor["type"] = principal.type;
        descriptor["id"] = principal.id;
        data.push_back(std::move(descriptor));
    }
    nlohmann::json body;
    body["data"] = std::move(data);
    return body.dump();
}

void validate_graph_principals(const std::vector<GraphPrincipal>& principals) {
    if (principals.empty())
        throw VtError("empty graph principal list");
    for (const auto& principal : principals) {
        if (principal.type != "user" && principal.type != "group")
            throw VtError("invalid graph principal type");
        if (principal.id.empty())
            throw VtError("invalid graph principal id");
    }
}

bool bool_or_throw(const detail::HttpResponse& resp) {
    const nlohmann::json j = detail::json_or_throw(resp);
    if (j.contains("data") && j.at("data").is_boolean())
        return j.at("data").get<bool>();
    return false;
}

} // namespace

Graph VirusTotal::create_graph(const nlohmann::json& attributes) {
    validate_graph_attributes(attributes);
    const std::string body = graph_attributes_body(attributes);
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.post(base_url_ + "/graphs", body, "application/json");
    return graph_from_json(detail::json_or_throw(resp));
}

Graph VirusTotal::get_graph(const std::string& id) {
    if (id.empty())
        throw VtError("invalid graph id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(graph_url(base_url_, id));
    return graph_from_json(detail::json_or_throw(resp));
}

Graph VirusTotal::update_graph(const std::string& id,
                               const nlohmann::json& attributes) {
    if (id.empty())
        throw VtError("invalid graph id");
    validate_graph_attributes(attributes);
    const std::string body = graph_attributes_body(attributes);
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.patch(graph_url(base_url_, id), body, "application/json");
    return graph_from_json(detail::json_or_throw(resp));
}

void VirusTotal::delete_graph(const std::string& id) {
    if (id.empty())
        throw VtError("invalid graph id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(graph_url(base_url_, id));
    detail::json_or_throw(resp);
}

GraphList VirusTotal::search_graphs(const std::string& filter, int limit,
                                    const std::string& cursor,
                                    const std::string& order,
                                    const std::string& attributes) {
    if (limit < 1 || limit > 40)
        throw VtError("graph search limit must be between 1 and 40");
    const std::string url = append_query(
        base_url_ + "/graphs",
        {{"filter", filter}, {"limit", std::to_string(limit)}, {"cursor", cursor},
         {"order", order}, {"attributes", attributes}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return graph_list_from_json(detail::json_or_throw(resp));
}

CommentListResult VirusTotal::get_graph_comments(const std::string& id, int limit,
                                                 const std::string& cursor) {
    if (id.empty())
        throw VtError("invalid graph id");
    if (limit < 1)
        throw VtError("invalid comment limit");
    const std::string url = append_query(
        graph_url(base_url_, id) + "/comments",
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return comment_list_from_json(detail::json_or_throw(resp));
}

Comment VirusTotal::post_graph_comment(const std::string& id,
                                       const std::string& text) {
    if (id.empty())
        throw VtError("invalid graph id");
    if (text.size() > kCommentSizeLimit)
        throw VtError("comment text exceeds kCommentSizeLimit");
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        graph_url(base_url_, id) + "/comments", comment_body(text),
        "application/json");
    const nlohmann::json j = detail::json_or_throw(resp);
    if (j.contains("data"))
        return comment_from_json(j["data"]);
    return comment_from_json(j);
}

RelationshipList VirusTotal::get_graph_relationships(
    const std::string& id, const std::string& relationship, int limit,
    const std::string& cursor) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid graph relationship request");
    if (limit < 1)
        throw VtError("invalid relationship limit");
    const std::string url = append_query(
        graph_url(base_url_, id) + "/" + relationship,
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return relationship_list_from_json(detail::json_or_throw(resp));
}

RelationshipList VirusTotal::get_graph_relationship_descriptors(
    const std::string& id, const std::string& relationship, int limit,
    const std::string& cursor) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid graph relationship request");
    if (limit < 1)
        throw VtError("invalid relationship limit");
    const std::string url = append_query(
        graph_url(base_url_, id) + "/relationships/" + relationship,
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return relationship_list_from_json(detail::json_or_throw(resp));
}

RelationshipList VirusTotal::get_graph_viewers(const std::string& id, int limit,
                                               const std::string& cursor) {
    return get_graph_relationships(id, "viewers", limit, cursor);
}

RelationshipList VirusTotal::get_graph_editors(const std::string& id, int limit,
                                               const std::string& cursor) {
    return get_graph_relationships(id, "editors", limit, cursor);
}

RelationshipList VirusTotal::add_graph_viewers(
    const std::string& id, const std::vector<GraphPrincipal>& principals) {
    if (id.empty())
        throw VtError("invalid graph id");
    validate_graph_principals(principals);
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        graph_url(base_url_, id) + "/relationships/viewers",
        graph_principals_body(principals), "application/json");
    return relationship_list_from_json(detail::json_or_throw(resp));
}

RelationshipList VirusTotal::add_graph_editors(
    const std::string& id, const std::vector<GraphPrincipal>& principals) {
    if (id.empty())
        throw VtError("invalid graph id");
    validate_graph_principals(principals);
    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        graph_url(base_url_, id) + "/relationships/editors",
        graph_principals_body(principals), "application/json");
    return relationship_list_from_json(detail::json_or_throw(resp));
}

bool VirusTotal::check_graph_viewer(const std::string& id,
                                    const std::string& user_or_group_id) {
    if (id.empty() || user_or_group_id.empty())
        throw VtError("invalid graph viewer check");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        graph_url(base_url_, id) + "/relationships/viewers/" + user_or_group_id);
    return bool_or_throw(resp);
}

bool VirusTotal::check_graph_editor(const std::string& id,
                                    const std::string& user_or_group_id) {
    if (id.empty() || user_or_group_id.empty())
        throw VtError("invalid graph editor check");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(
        graph_url(base_url_, id) + "/relationships/editors/" + user_or_group_id);
    return bool_or_throw(resp);
}

void VirusTotal::remove_graph_viewer(const std::string& id,
                                     const std::string& user_or_group_id) {
    if (id.empty() || user_or_group_id.empty())
        throw VtError("invalid graph viewer removal");
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(
        graph_url(base_url_, id) + "/relationships/viewers/" + user_or_group_id);
    detail::json_or_throw(resp);
}

void VirusTotal::remove_graph_editor(const std::string& id,
                                     const std::string& user_or_group_id) {
    if (id.empty() || user_or_group_id.empty())
        throw VtError("invalid graph editor removal");
    limiter_.wait();
    const detail::HttpResponse resp = http_.del(
        graph_url(base_url_, id) + "/relationships/editors/" + user_or_group_id);
    detail::json_or_throw(resp);
}

YaraRuleList VirusTotal::list_yara_rules(int limit, const std::string& cursor,
                                         const std::string& filter,
                                         const std::string& order) {
    if (limit < 1)
        throw VtError("invalid YARA rule list limit");
    const std::string url = append_query(
        base_url_ + "/yara_rules",
        {{"limit", std::to_string(limit)},
         {"cursor", cursor},
         {"filter", filter},
         {"order", order}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return yara_rule_list_from_json(detail::json_or_throw(resp));
}

YaraRule VirusTotal::get_yara_rule(const std::string& id) {
    if (id.empty())
        throw VtError("invalid YARA rule id");
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(base_url_ + "/yara_rules/" + id);
    return yara_rule_from_json(detail::json_or_throw(resp));
}

RelationshipList VirusTotal::get_yara_rule_relationships(
    const std::string& id, const std::string& relationship, int limit,
    const std::string& cursor) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid YARA rule relationship request");
    if (limit < 1)
        throw VtError("invalid relationship limit");
    const std::string url = append_query(
        base_url_ + "/yara_rules/" + id + "/" + relationship,
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return relationship_list_from_json(detail::json_or_throw(resp));
}

RelationshipList VirusTotal::get_yara_rule_relationship_descriptors(
    const std::string& id, const std::string& relationship, int limit,
    const std::string& cursor) {
    if (id.empty() || relationship.empty())
        throw VtError("invalid YARA rule relationship request");
    if (limit < 1)
        throw VtError("invalid relationship limit");
    const std::string url = append_query(
        base_url_ + "/yara_rules/" + id + "/relationships/" + relationship,
        {{"limit", std::to_string(limit)}, {"cursor", cursor}});
    limiter_.wait();
    const detail::HttpResponse resp = http_.get(url);
    return relationship_list_from_json(detail::json_or_throw(resp));
}

ZipFile VirusTotal::create_zip(const std::vector<std::string>& hashes,
                               const std::string& password) {
    if (hashes.empty())
        throw VtError("zip requires at least one file hash");
    for (const auto& hash : hashes) {
        if (!is_hex_hash(hash))
            throw VtError("invalid hash: expected 32/40/64 hex characters");
    }

    nlohmann::json body;
    body["data"]["hashes"] = hashes;
    if (!password.empty())
        body["data"]["password"] = password;

    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        base_url_ + "/intelligence/zip_files", body.dump(),
        "application/json");
    return zip_file_from_json(detail::json_or_throw(resp));
}

ZipFile VirusTotal::get_zip_status(const std::string& id) {
    if (id.empty())
        throw VtError("invalid zip id");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/intelligence/zip_files/" + id);
    return zip_file_from_json(detail::json_or_throw(resp));
}

std::string VirusTotal::get_zip_download_url(const std::string& id) {
    if (id.empty())
        throw VtError("invalid zip id");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/intelligence/zip_files/" + id + "/download_url");
    return data_string_from_json(detail::json_or_throw(resp),
                                 "zip download_url response");
}

void VirusTotal::download_zip(const std::string& id,
                              const std::string& dest_path) {
    if (id.empty())
        throw VtError("invalid zip id");
    if (dest_path.empty())
        throw VtError("invalid destination path");
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/intelligence/zip_files/" + id + "/download");
    write_file_atomic(dest_path, detail::body_or_throw(resp));
}

CodeInsightReport VirusTotal::analyse_code(
    const std::string& code, const std::string& code_type,
    const std::vector<CodeInsightHistory>& history) {
    if (code.empty())
        throw VtError("code insight requires a non-empty code block");
    if (code_type != "disassembled" && code_type != "decompiled")
        throw VtError("code_type must be 'disassembled' or 'decompiled'");
    for (const auto& entry : history) {
        if (entry.request.empty())
            throw VtError("code insight history entry requires a code block");
    }

    nlohmann::json body;
    body["data"]["code"] = detail::base64_encode(code);
    body["data"]["code_type"] = code_type;
    if (!history.empty()) {
        nlohmann::json entries = nlohmann::json::array();
        for (const auto& entry : history) {
            nlohmann::json item;
            item["request"] = detail::base64_encode(entry.request);
            item["response"]["summary"] = entry.summary;
            item["response"]["description"] = entry.description;
            entries.push_back(std::move(item));
        }
        body["data"]["history"] = std::move(entries);
    }

    limiter_.wait();
    const detail::HttpResponse resp = http_.post(
        base_url_ + "/codeinsights/analyse-binary", body.dump(),
        "application/json");
    const nlohmann::json root = detail::json_or_throw(resp);
    if (!root.is_object() || !root.contains("data"))
        throw VtError("code insights response: missing data");

    CodeInsightReport report;
    report.raw = root["data"];
    if (report.raw.is_object()) {
        report.summary = detail::json_string(report.raw, "summary");
        report.description = detail::json_string(report.raw, "description");
    } else if (report.raw.is_string()) {
        // Older payload shape: data is the base64-encoded description.
        if (!detail::base64_decode(report.raw.get<std::string>(),
                                   report.description))
            throw VtError("code insights response: invalid base64");
    } else {
        throw VtError("code insights response: unexpected data type");
    }
    return report;
}

std::vector<std::string> VirusTotal::get_popular_threat_categories() {
    limiter_.wait();
    const detail::HttpResponse resp =
        http_.get(base_url_ + "/popular_threat_categories");
    const nlohmann::json root = detail::json_or_throw(resp);
    if (!root.is_object() || !root.contains("data") || !root["data"].is_array())
        throw VtError("popular threat categories: missing data array");

    std::vector<std::string> categories;
    for (const auto& item : root["data"]) {
        if (item.is_string())
            categories.push_back(item.get<std::string>());
        else if (item.is_object() && item.contains("id") &&
                 item["id"].is_string())
            categories.push_back(item["id"].get<std::string>());
    }
    return categories;
}

} // namespace vtapi
