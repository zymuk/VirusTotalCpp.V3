// Micro test harness. No external framework: one binary grows test-by-test as
// endpoint steps land. Run via `ctest --test-dir build`.

#ifndef _WIN32
// The CLI tests spawn the built binary and capture its streams, which uses
// fork/exec/pipe; that part is POSIX only.
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <chrono>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "mock_server.hpp"
#include "vtapi/client.hpp"
#include "vtapi/detail/hashing.hpp"
#include "vtapi/detail/http.hpp"
#include "vtapi/detail/ratelimit.hpp"
#include "vtapi/detail/response.hpp"
#include "vtapi/detail/url.hpp"
#include "vtapi/model/analysis.hpp"
#include "vtapi/model/behaviour.hpp"
#include "vtapi/model/collection.hpp"
#include "vtapi/model/comment.hpp"
#include "vtapi/model/domain_report.hpp"
#include "vtapi/model/file_report.hpp"
#include "vtapi/model/graph.hpp"
#include "vtapi/model/ip_report.hpp"
#include "vtapi/model/mitre.hpp"
#include "vtapi/model/relationship.hpp"
#include "vtapi/model/resolution.hpp"
#include "vtapi/model/scan_result.hpp"
#include "vtapi/model/url_report.hpp"
#include "vtapi/model/sigma_rule.hpp"
#include "vtapi/model/yara_ruleset.hpp"
#include "vtapi/types.hpp"

namespace {

std::size_t g_checks = 0;
std::size_t g_failures = 0;

void check_failed(const char* file, int line, const std::string& expr) {
    ++g_failures;
    std::cerr << "FAIL " << file << ":" << line << ": " << expr << "\n";
}

#define CHECK(expr)                                                       \
    do {                                                                  \
        ++g_checks;                                                       \
        if (!(expr)) check_failed(__FILE__, __LINE__, #expr);             \
    } while (0)

#define CHECK_THROWS_AS(expr, expected_type)                              \
    do {                                                                  \
        ++g_checks;                                                       \
        bool caught_type = false, caught_base = false;                    \
        try {                                                             \
            (void)(expr);                                                 \
        } catch (const expected_type&) {                                  \
            caught_type = true;                                           \
        } catch (const vtapi::VtError&) {                                 \
            caught_base = true;                                           \
        } catch (...) {                                                   \
        }                                                                 \
        if (!caught_type || caught_base)                                  \
            check_failed(__FILE__, __LINE__, "THROWS_AS " #expr " -> " #expected_type); \
    } while (0)

void test_exception_hierarchy() {
    // Each leaf exception is catchable both as its own type and as VtError (base).
    CHECK_THROWS_AS(throw vtapi::AuthError("bad key"), vtapi::AuthError);
    CHECK_THROWS_AS(throw vtapi::RateLimit("too many"), vtapi::RateLimit);
    CHECK_THROWS_AS(throw vtapi::NotFound("never seen"), vtapi::NotFound);
    CHECK_THROWS_AS(throw vtapi::NetworkError("connect failed"), vtapi::NetworkError);

    // dynamic_cast through a VtError& must resolve back to the concrete type.
    try {
        throw vtapi::NotFound("never seen");
    } catch (const vtapi::VtError& e) {
        CHECK(dynamic_cast<const vtapi::NotFound*>(&e) != nullptr);
        CHECK(dynamic_cast<const vtapi::AuthError*>(&e) == nullptr);
        CHECK(std::string(e.what()) == "never seen");
    }

    // ApiError carries HTTP status + API error code and stays a VtError.
    try {
        throw vtapi::ApiError(503, "Unavailable", "backend busy");
    } catch (const vtapi::VtError& e) {
        CHECK(dynamic_cast<const vtapi::ApiError*>(&e) != nullptr);
        const auto& api = dynamic_cast<const vtapi::ApiError&>(e);
        CHECK(api.http_status() == 503);
        CHECK(api.api_code() == "Unavailable");
    }

    // VtError is a std::exception: message propagates.
    try {
        throw vtapi::VtError("generic");
    } catch (const std::exception& e) {
        CHECK(std::string(e.what()) == "generic");
    }
}

void test_hashing() {
    // EICAR bytes — canonical digest vectors must match exactly.
    const std::string eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    CHECK(vtapi::detail::sha256_hex(eicar) ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(vtapi::detail::md5_hex(eicar) == "44d88612fea8a8f36de82e1278abb02f");
    CHECK(vtapi::detail::sha1_hex(eicar) == "3395856ce81f2b7382dee72602f798b642f14140");

    // Buffer overload must agree with the string overload.
    const unsigned char* raw =
        reinterpret_cast<const unsigned char*>(eicar.data());
    CHECK(vtapi::detail::sha256_hex(raw, eicar.size()) ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

    // Empty-input vectors (independent sanity check).
    CHECK(vtapi::detail::sha256_hex("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(vtapi::detail::md5_hex("") == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(vtapi::detail::sha1_hex("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

void test_rate_limiter() {
    // Disabled limiter (0) must return immediately.
    vtapi::detail::RateLimiter disabled(0.0);
    const auto d0 = std::chrono::steady_clock::now();
    disabled.wait();
    disabled.wait();
    const auto d1 = std::chrono::steady_clock::now();
    CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(d1 - d0).count() < 50);

    // 600/min = one token every 100ms: 3 calls must take at least ~150ms.
    vtapi::detail::RateLimiter limiter(600.0);
    const auto r0 = std::chrono::steady_clock::now();
    limiter.wait();
    limiter.wait();
    limiter.wait();
    const auto r1 = std::chrono::steady_clock::now();
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(r1 - r0).count();
    CHECK(elapsed >= 150);

    CHECK(limiter.requests_per_minute() == 600.0);
    CHECK(disabled.requests_per_minute() == 0.0);
}

void test_http_client() {
    vtapi::detail::HttpClient client;
    client.set_timeout(std::chrono::seconds(5));
    client.set_connect_timeout(std::chrono::seconds(2));

    // GET: correct status + body round-trips through the handler.
    MockServer get_server([](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" && req.path == "/hello")
            return {200, "hello body", "text/plain"};
        return {404, "not found"};
    });
    vtapi::detail::HttpResponse ok = client.get(get_server.url("/hello"));
    CHECK(ok.status == 200);
    CHECK(ok.body == "hello body");
    CHECK(ok.error.empty());

    // Non-200 statuses are reported, not thrown.
    vtapi::detail::HttpResponse nf = client.get(get_server.url("/missing"));
    CHECK(nf.status == 404);
    CHECK(nf.body == "not found");

    // POST: method, body bytes and Content-Type reach the handler.
    MockServer post_server([](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.body != "{\"a\":1}")
            return {400, "bad post"};
        const auto ct = req.headers.find("Content-Type");
        if (ct == req.headers.end() || ct->second != "application/json")
            return {400, "bad content type"};
        return {201, "posted"};
    });
    vtapi::detail::HttpResponse posted =
        client.post(post_server.url("/submit"), "{\"a\":1}", "application/json");
    CHECK(posted.status == 201);
    CHECK(posted.body == "posted");

    // Persistent default headers are sent on every request.
    MockServer header_server([](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != "secret")
            return {400, "missing api key"};
        return {200, "ok"};
    });
    vtapi::detail::HttpClient header_client;
    header_client.set_header("x-apikey", "secret");
    CHECK(header_client.get(header_server.url("/")).status == 200);

    // Per-call headers coexist with default headers.
    MockServer extra_server([](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        const auto extra = req.headers.find("X-Test");
        if (key == req.headers.end() || key->second != "secret" ||
            extra == req.headers.end() || extra->second != "extra")
            return {400, "bad headers"};
        return {200, "ok"};
    });
    vtapi::detail::HttpClient combo_client;
    combo_client.set_header("x-apikey", "secret");
    CHECK(combo_client.get(extra_server.url("/"), {"X-Test: extra"}).status == 200);

    // Multipart upload: text field + binary file part with the right name.
    MockServer mime_server([](const MockRequest& req) -> MockResponse {
        if (req.method != "POST")
            return {400, "not a post"};
        const auto pw = req.form_fields.find("password");
        if (pw == req.form_fields.end() || pw->second != "p@ss")
            return {400, "bad field"};
        if (req.files.size() != 1 || req.files[0].field != "file" ||
            req.files[0].filename != "eicar.com")
            return {400, "bad file part"};
        const std::vector<uint8_t> expected = {0x58, 0x59, 0x5a};
        if (req.files[0].data != expected)
            return {400, "bad file bytes"};
        return {200, "uploaded"};
    });
    vtapi::detail::HttpResponse uploaded = client.post_multipart(
        mime_server.url("/files"), {{"password", "p@ss"}},
        {{"file", "eicar.com", std::vector<uint8_t>{0x58, 0x59, 0x5a}}});
    CHECK(uploaded.status == 200);
    CHECK(uploaded.body == "uploaded");

    // Connecting to a port with no listener must raise NetworkError.
    const int dead_port = mock::unused_local_port();
    vtapi::detail::HttpClient dead_client;
    dead_client.set_connect_timeout(std::chrono::seconds(1));
    CHECK_THROWS_AS(
        dead_client.get("http://127.0.0.1:" + std::to_string(dead_port) + "/"),
        vtapi::NetworkError);
}

void test_response_mapping() {
    using vtapi::detail::HttpResponse;
    using vtapi::detail::json_or_throw;

    // 2xx: parsed JSON comes back (invalid JSON becomes {}).
    nlohmann::json parsed = json_or_throw(
        HttpResponse{200, "{\"a\": 1}"});
    CHECK(parsed["a"] == 1);

    nlohmann::json blank = json_or_throw(HttpResponse{204, "{not json"});
    CHECK(blank.is_object());
    CHECK(blank.empty());

    // 404: NotFound carrying the API error message.
    bool not_found = false;
    try {
        json_or_throw(HttpResponse{404,
                                   R"({"error":{"code":"NotFoundError","message":"File not found","detail":null}})"});
    } catch (const vtapi::NotFound& e) {
        not_found = std::string(e.what()) == "File not found";
    }
    CHECK(not_found);

    // 403 → AuthError, 429 → RateLimit, 0 → NetworkError (transport text).
    CHECK_THROWS_AS(json_or_throw(HttpResponse{403, R"({"error":{"message":"bad key"}})"}),
                    vtapi::AuthError);
    CHECK_THROWS_AS(
        json_or_throw(HttpResponse{429, R"({"error":{"code":"QuotaExceededError","message":"limit"}})"}),
        vtapi::RateLimit);
    CHECK_THROWS_AS(json_or_throw(HttpResponse{0, "", "connection refused"}),
                    vtapi::NetworkError);

    // Any other status → ApiError(status, code, message).
    bool api_error = false;
    try {
        json_or_throw(HttpResponse{503,
                                   R"({"error":{"code":"BackendUnavailable","message":"busy"}})"});
    } catch (const vtapi::ApiError& e) {
        api_error = e.http_status() == 503 && e.api_code() == "BackendUnavailable" &&
                    std::string(e.what()) == "busy";
    }
    CHECK(api_error);

    // Non-JSON body on an unexpected status → message falls back to raw body.
    bool fallback = false;
    try {
        json_or_throw(HttpResponse{503, "service is down"});
    } catch (const vtapi::ApiError& e) {
        fallback = e.http_status() == 503 && std::string(e.what()) == "service is down";
    }
    CHECK(fallback);

    // Oversized raw body is truncated to 512 chars in the fallback message.
    bool truncated = false;
    try {
        json_or_throw(HttpResponse{503, std::string(600, 'x')});
    } catch (const vtapi::ApiError& e) {
        truncated = std::string(e.what()).size() == 512;
    }
    CHECK(truncated);

    // End-to-end: mock server 200 + real HttpClient flows through json_or_throw.
    MockServer server([](const MockRequest& req) -> MockResponse {
        return {200, "{\"ok\": true}", "application/json"};
    });
    const vtapi::detail::HttpResponse resp =
        vtapi::detail::HttpClient().get(server.url("/"));
    const nlohmann::json end_to_end = json_or_throw(resp);
    CHECK(end_to_end["ok"] == true);
}

std::string load_fixture(const std::string& name) {
    const std::filesystem::path path =
        std::filesystem::path(__FILE__).parent_path() / "fixtures" / name;
    std::ifstream in(path);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

void test_file_report() {
    // Canonical EICAR report parses into a fully-populated FileReport.
    const nlohmann::json root = nlohmann::json::parse(load_fixture("file_report.json"));
    const vtapi::FileReport report = vtapi::file_report_from_json(root);
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    // data.* and data.attributes.* fields surface with their v3 names and types.
    CHECK(report.type == "file");
    CHECK(report.id == kSha256);
    CHECK(report.self_link == "https://www.virustotal.com/api/v3/files/" + kSha256);

    CHECK(report.sha256 == kSha256);
    CHECK(report.sha1 == "3395856ce81f2b7382dee72602f798b642f14140");
    CHECK(report.md5 == "44d88612fea8a8f36de82e1278abb02f");
    CHECK(report.size == 68);
    CHECK(report.type_description == "Text");
    CHECK(report.magic == "ASCII text, with CRLF line terminators");
    CHECK(report.meaningful_name == "eicar.com");
    CHECK(report.names.size() == 1 && report.names[0] == "eicar.com");
    CHECK(report.type_tags.size() == 1 && report.type_tags[0] == "text");

    // Timestamps stay raw unix integers, exactly as v3 returns them.
    CHECK(report.creation_date == 1653654377);
    CHECK(report.first_submission_date == 1653654377);
    CHECK(report.last_submission_date == 1653654377);
    CHECK(report.last_analysis_date == 1653654377);
    CHECK(report.last_modification_date == 1653654377);
    CHECK(report.times_submitted == 1);
    CHECK(report.reputation == 0);

    const vtapi::AnalysisStats& stats = report.last_analysis_stats;
    CHECK(stats.harmless == 0);
    CHECK(stats.malicious == 64);
    CHECK(stats.suspicious == 0);
    CHECK(stats.timeout == 0);
    CHECK(stats.undetected == 0);
    CHECK(stats.type_unsupported == 0);

    // Per-engine verdicts, keyed by engine name like the JSON object.
    CHECK(report.last_analysis_results.size() == 2);
    const auto flagged = report.last_analysis_results.find("Acronis");
    CHECK(flagged != report.last_analysis_results.end());
    if (flagged != report.last_analysis_results.end()) {
        CHECK(flagged->second.category == "malicious");
        CHECK(flagged->second.result == "EICAR-Test-File");
        CHECK(flagged->second.engine_name == "Acronis");
        CHECK(flagged->second.engine_version == "1.0");
        CHECK(flagged->second.engine_update.empty());
    }
    const auto clean = report.last_analysis_results.find("Bkav");
    CHECK(clean != report.last_analysis_results.end());
    if (clean != report.last_analysis_results.end())
        CHECK(clean->second.category == "undetected");

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::FileReport sparse =
        vtapi::file_report_from_json(nlohmann::json::parse(R"({"data":{"id":"x"}})"));
    CHECK(sparse.id == "x");
    CHECK(sparse.type.empty());
    CHECK(sparse.self_link.empty());
    CHECK(sparse.sha256.empty());
    CHECK(sparse.names.empty());
    CHECK(sparse.type_tags.empty());
    CHECK(sparse.last_analysis_date == 0);
    CHECK(sparse.last_analysis_stats.malicious == 0);
    CHECK(sparse.last_analysis_results.empty());

    // Non-object roots are tolerated (defensive, empty report).
    const vtapi::FileReport weird = vtapi::file_report_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
    CHECK(weird.sha256.empty());
}

void test_url_report() {
    // Canonical URL report parses into a fully-populated UrlReport.
    const nlohmann::json root = nlohmann::json::parse(load_fixture("url_report.json"));
    const vtapi::UrlReport report = vtapi::url_report_from_json(root);

    // data.* carries the base64url id (no "positives"/"response_code" v2 shape).
    CHECK(report.type == "url");
    CHECK(report.id == "aHR0cHM6Ly9leGFtcGxlLmNvbQ");
    CHECK(report.self_link == "https://www.virustotal.com/api/v3/urls/aHR0cHM6Ly9leGFtcGxlLmNvbQ");

    // data.attributes.* surfaces with v3 names.
    CHECK(report.url == "https://example.com");
    CHECK(report.last_analysis_date == 1653654377);
    CHECK(report.last_modification_date == 1653654377);
    CHECK(report.times_submitted == 1);
    CHECK(report.reputation == 0);

    const vtapi::AnalysisStats& stats = report.last_analysis_stats;
    CHECK(stats.harmless == 10);
    CHECK(stats.malicious == 50);
    CHECK(stats.suspicious == 0);
    CHECK(stats.timeout == 0);
    CHECK(stats.undetected == 5);
    CHECK(stats.type_unsupported == 0);

    CHECK(report.last_analysis_results.size() == 1);
    const auto flagged = report.last_analysis_results.find("EngineA");
    CHECK(flagged != report.last_analysis_results.end());
    if (flagged != report.last_analysis_results.end()) {
        CHECK(flagged->second.category == "malicious");
        CHECK(flagged->second.result == "Phishing");
        CHECK(flagged->second.engine_name == "EngineA");
        CHECK(flagged->second.engine_version == "2.0");
        CHECK(flagged->second.engine_update == "20230101");
    }

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::UrlReport sparse =
        vtapi::url_report_from_json(nlohmann::json::parse(R"({"data":{"id":"x"}})"));
    CHECK(sparse.id == "x");
    CHECK(sparse.type.empty());
    CHECK(sparse.self_link.empty());
    CHECK(sparse.url.empty());
    CHECK(sparse.last_analysis_date == 0);
    CHECK(sparse.times_submitted == 0);
    CHECK(sparse.reputation == 0);
    CHECK(sparse.last_analysis_stats.malicious == 0);
    CHECK(sparse.last_analysis_results.empty());

    // Non-object root tolerated (empty report).
    const vtapi::UrlReport weird = vtapi::url_report_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
}

void test_ip_report() {
    // Canonical IP report parses into a fully-populated IPReport.
    const nlohmann::json root =
        nlohmann::json::parse(load_fixture("ip_address_report.json"));
    const vtapi::IPReport report = vtapi::ip_report_from_json(root);

    // data.* carries the IP as id (no "resolutions"/"response_code" v2 shape).
    CHECK(report.type == "ip_address");
    CHECK(report.id == "8.8.8.8");
    CHECK(report.self_link == "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8");

    // data.attributes.* surfaces with v3 names.
    CHECK(report.as_owner == "Google LLC");
    CHECK(report.asn == 15169);
    CHECK(report.continent == "NA");
    CHECK(report.country == "US");
    CHECK(report.network == "8.8.8.0/24");
    CHECK(report.regional_internet_registry == "ARIN");
    CHECK(report.first_seen_date == 1528408800);
    CHECK(report.last_analysis_date == 1653654377);
    CHECK(report.last_modification_date == 1653654377);
    CHECK(report.whois_date == 1653654377);
    CHECK(report.reputation == 289);

    CHECK(report.tags.size() == 2);
    CHECK(report.tags[0] == "ipv4");
    CHECK(report.tags[1] == "dns-server");

    CHECK(report.total_votes.harmless == 31);
    CHECK(report.total_votes.malicious == 1);

    const vtapi::AnalysisStats& stats = report.last_analysis_stats;
    CHECK(stats.harmless == 10);
    CHECK(stats.malicious == 50);
    CHECK(stats.suspicious == 0);
    CHECK(stats.timeout == 0);
    CHECK(stats.undetected == 5);
    CHECK(stats.type_unsupported == 0);

    CHECK(report.last_analysis_results.size() == 1);
    const auto flagged = report.last_analysis_results.find("EngineA");
    CHECK(flagged != report.last_analysis_results.end());
    if (flagged != report.last_analysis_results.end()) {
        CHECK(flagged->second.category == "malicious");
        CHECK(flagged->second.result == "Malicious site");
        CHECK(flagged->second.engine_name == "EngineA");
        CHECK(flagged->second.engine_version == "2.0");
        CHECK(flagged->second.engine_update == "20230101");
    }

    // last_dns_records entries land as DNSResolution objects.
    CHECK(report.last_dns_records.size() == 2);
    CHECK(report.last_dns_records[0].ip_address == "8.8.8.8");
    CHECK(report.last_dns_records[0].hostname == "dns.google");
    CHECK(report.last_dns_records[0].last_resolved == 1653654377);
    CHECK(report.last_dns_records[1].hostname == "www.google.com");

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::IPReport sparse =
        vtapi::ip_report_from_json(nlohmann::json::parse(R"({"data":{"id":"1.2.3.4"}})"));
    CHECK(sparse.id == "1.2.3.4");
    CHECK(sparse.type.empty());
    CHECK(sparse.self_link.empty());
    CHECK(sparse.as_owner.empty());
    CHECK(sparse.asn == 0);
    CHECK(sparse.country.empty());
    CHECK(sparse.reputation == 0);
    CHECK(sparse.tags.empty());
    CHECK(sparse.total_votes.malicious == 0);
    CHECK(sparse.last_analysis_stats.malicious == 0);
    CHECK(sparse.last_analysis_results.empty());
    CHECK(sparse.last_dns_records.empty());

    // Non-object root tolerated (empty report).
    const vtapi::IPReport weird = vtapi::ip_report_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
}

void test_domain_report() {
    // Canonical domain report parses into a fully-populated DomainReport.
    const nlohmann::json root =
        nlohmann::json::parse(load_fixture("domain_report.json"));
    const vtapi::DomainReport report = vtapi::domain_report_from_json(root);

    // data.* carries the domain as id (no "detected_urls"/"response_code" v2 shape).
    CHECK(report.type == "domain");
    CHECK(report.id == "example.com");
    CHECK(report.self_link == "https://www.virustotal.com/api/v3/domains/example.com");

    // data.attributes.* surfaces with v3 names.
    CHECK(report.registrar == "MarkMonitor Inc.");
    CHECK(report.creation_date == 1106675546);
    CHECK(report.first_seen_date == 1528408800);
    CHECK(report.last_analysis_date == 1653654377);
    CHECK(report.last_modification_date == 1653654377);
    CHECK(report.last_update_date == 1577183919);
    CHECK(report.whois_date == 1653654377);
    CHECK(report.last_dns_records_date == 1653654377);
    CHECK(report.reputation == 42);
    CHECK(report.tags.size() == 1 && report.tags[0] == "dga");
    CHECK(!report.whois.empty());

    CHECK(report.categories.size() == 2);
    CHECK(report.categories.at("Dr.Web") == "known infection source");

    CHECK(report.total_votes.harmless == 12);
    CHECK(report.total_votes.malicious == 3);

    const vtapi::AnalysisStats& stats = report.last_analysis_stats;
    CHECK(stats.harmless == 60);
    CHECK(stats.malicious == 4);
    CHECK(stats.suspicious == 1);
    CHECK(stats.undetected == 4);

    CHECK(report.last_analysis_results.size() == 1);
    const auto flagged = report.last_analysis_results.find("EngineA");
    CHECK(flagged != report.last_analysis_results.end());
    if (flagged != report.last_analysis_results.end()) {
        CHECK(flagged->second.category == "malicious");
        CHECK(flagged->second.result == "Malware");
    }

    // last_dns_records are DNS records (type/value/ttl), not resolutions.
    CHECK(report.last_dns_records.size() == 5);
    CHECK(report.last_dns_records[0].type == "A");
    CHECK(report.last_dns_records[0].value == "93.184.216.34");
    CHECK(report.last_dns_records[0].ttl == 1799);
    // SOA extras surface on the record.
    const vtapi::DNSRecord& soa = report.last_dns_records[2];
    CHECK(soa.type == "SOA");
    CHECK(soa.rname == "hostmaster.example.com");
    CHECK(soa.serial == 2020061203);
    CHECK(soa.refresh == 3600);
    CHECK(soa.retry == 300);
    CHECK(soa.expire == 1814400);
    CHECK(soa.minimum == 600);
    // MX priority.
    CHECK(report.last_dns_records[3].priority == 10);
    // CAA flag/tag.
    CHECK(report.last_dns_records[4].flag == 0);
    CHECK(report.last_dns_records[4].tag == "issue");

    CHECK(report.popularity_ranks.size() == 2);
    const auto alexa = report.popularity_ranks.find("Alexa");
    CHECK(alexa != report.popularity_ranks.end());
    if (alexa != report.popularity_ranks.end()) {
        CHECK(alexa->second.rank == 47288);
        CHECK(alexa->second.timestamp == 1591630561);
    }

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::DomainReport sparse =
        vtapi::domain_report_from_json(nlohmann::json::parse(R"({"data":{"id":"x.com"}})"));
    CHECK(sparse.id == "x.com");
    CHECK(sparse.type.empty());
    CHECK(sparse.self_link.empty());
    CHECK(sparse.registrar.empty());
    CHECK(sparse.creation_date == 0);
    CHECK(sparse.reputation == 0);
    CHECK(sparse.tags.empty());
    CHECK(sparse.categories.empty());
    CHECK(sparse.total_votes.malicious == 0);
    CHECK(sparse.last_analysis_stats.malicious == 0);
    CHECK(sparse.last_analysis_results.empty());
    CHECK(sparse.last_dns_records.empty());
    CHECK(sparse.popularity_ranks.empty());

    // Non-object root tolerated (empty report).
    const vtapi::DomainReport weird =
        vtapi::domain_report_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
}

void test_resolution() {
    const nlohmann::json root =
        nlohmann::json::parse(load_fixture("resolution.json"));
    const vtapi::Resolution r = vtapi::resolution_from_json(root);

    CHECK(r.type == "resolution");
    CHECK(r.id == "111.222.33.44example.com");
    CHECK(r.self_link ==
          "https://www.virustotal.com/api/v3/resolutions/111.222.33.44example.com");

    // v3 attribute names (date/host_name/resolver), not hostname/last_resolved.
    CHECK(r.date == 1599471348);
    CHECK(r.host_name == "example.com");
    CHECK(r.ip_address == "111.222.33.44");
    CHECK(r.resolver == "VirusTotal");

    CHECK(r.host_name_last_analysis_stats.harmless == 77);
    CHECK(r.host_name_last_analysis_stats.undetected == 8);
    CHECK(r.host_name_last_analysis_stats.malicious == 0);
    CHECK(r.ip_address_last_analysis_stats.harmless == 75);
    CHECK(r.ip_address_last_analysis_stats.undetected == 10);

    // Sparse and non-object roots fall back to defaults without throwing.
    const vtapi::Resolution sparse =
        vtapi::resolution_from_json(nlohmann::json::parse(R"({"data":{"id":"x"}})"));
    CHECK(sparse.id == "x");
    CHECK(sparse.date == 0);
    CHECK(sparse.host_name.empty());
    CHECK(sparse.resolver.empty());
    CHECK(sparse.host_name_last_analysis_stats.harmless == 0);
    CHECK(vtapi::resolution_from_json(nlohmann::json::array()).id.empty());
}

void test_get_ip_report() {
    const std::string kKey(64, 'a');
    const std::string kIp = "8.8.8.8";

    auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0; // disable pacing for tests
        return opt;
    };

    // 200 → full IPReport (and the api key header is sent).
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/ip_addresses/" + kIp)
            return {404, "wrong path"};
        return {200, load_fixture("ip_address_report.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(ok_server.url(""))};
    const vtapi::IPReport report = vt.get_ip_report(kIp);
    CHECK(report.id == kIp);
    CHECK(report.as_owner == "Google LLC");
    CHECK(report.asn == 15169);
    CHECK(report.last_dns_records.size() == 2);
    CHECK(report.last_analysis_stats.malicious == 50);

    // 404 → NotFound ("no data for this IP yet").
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"IP address not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal not_found{options(nf_server.url(""))};
    CHECK_THROWS_AS(not_found.get_ip_report(kIp), vtapi::NotFound);

    // Invalid IP (hostname, junk, empty) → VtError before any HTTP request.
    MockServer junk_server([](const MockRequest&) -> MockResponse {
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{options(junk_server.url(""))};
    bool rejected = false;
    try {
        junk.get_ip_report("example.com");
    } catch (const vtapi::VtError&) {
        rejected = true;
    }
    CHECK(rejected);
    CHECK_THROWS_AS(junk.get_ip_report("not-an-ip"), vtapi::VtError);
    CHECK_THROWS_AS(junk.get_ip_report(""), vtapi::VtError);
    // As long as it is still an IP, the request happens.
    CHECK_THROWS_AS(not_found.get_ip_report("1.2.3.4"), vtapi::NotFound);
}

void test_rescan_ip() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    MockServer server([](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/ip_addresses/8.8.8.8/analyse")
            return {400, "bad"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};
    const vtapi::ScanResult result = vt.rescan_ip("8.8.8.8");
    CHECK(!result.id.empty());

    // Invalid IP → VtError before any HTTP request.
    bool bad = false;
    try {
        vt.rescan_ip("bad");
    } catch (const vtapi::VtError&) {
        bad = true;
    }
    CHECK(bad);
}

void test_ip_comments_votes() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Mock: GET/POST /ip_addresses/8.8.8.8/comments|votes + GET relationships
    // all return 200. Matching by path substring keeps the mock short. POST
    // bodies must carry the v3 object type or the API rejects them.
    std::string last_vote_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.path.find("/comments") != std::string::npos) {
            if (req.method == "GET")
                return {200, R"({"data":[{"id":"c1","attributes":{"text":"hello"}}]})", "application/json"};
            if (req.method == "POST") {
                if (req.body.find("\"type\":\"comment\"") == std::string::npos)
                    return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
                return {200, "{}", "application/json"};
            }
        }
        if (req.path.find("/votes") != std::string::npos && req.method == "POST") {
            if (req.body.find("\"type\":\"vote\"") == std::string::npos)
                return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
            last_vote_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.path.find("/votes") != std::string::npos && req.method == "GET")
            return {200, R"({"data":[{"id":"v1","attributes":{"verdict":"harmless"}}]})", "application/json"};
        if (req.method == "GET" && req.path.find("/relationships") != std::string::npos)
            return {200, "{}", "application/json"};
        return {404, "{}"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    // Valid IP: get comments returns JSON string; post + vote + get votes pass.
    const std::string comments = vt.get_ip_comments("8.8.8.8");
    CHECK(!comments.empty());
    vt.post_ip_comment("8.8.8.8", "test note");
    vt.post_ip_vote("8.8.8.8", true);
    CHECK(last_vote_body.find("\"verdict\":\"harmless\"") != std::string::npos);
    const std::string votes = vt.get_ip_votes("8.8.8.8");
    CHECK(!votes.empty());
    const std::string rels = vt.get_ip_relationships("8.8.8.8", "downloaded_files");
    CHECK(rels == "{}");

    // Invalid IP → VtError before any HTTP request.
    bool bad = false;
    try {
        vt.post_ip_comment("bad", "nope");
    } catch (const vtapi::VtError&) {
        bad = true;
    }
    CHECK(bad);
}

void test_get_domain_report() {
    const std::string kKey(64, 'a');
    const std::string kDomain = "example.com";
    const auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // 200 → full DomainReport (id = the domain; api key header is sent).
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/domains/" + kDomain)
            return {404, "wrong path"};
        return {200, load_fixture("domain_report.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(ok_server.url(""))};
    const vtapi::DomainReport report = vt.get_domain_report(kDomain);
    CHECK(report.id == kDomain);
    CHECK(report.registrar == "MarkMonitor Inc.");
    CHECK(report.last_dns_records.size() == 5);
    CHECK(report.last_analysis_stats.malicious == 4);

    // 404 → NotFound ("no data for this domain yet").
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"Domain not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal not_found{options(nf_server.url(""))};
    CHECK_THROWS_AS(not_found.get_domain_report(kDomain), vtapi::NotFound);

    // Invalid domain (IP, junk, empty, leading hyphen) → VtError, no HTTP.
    MockServer junk_server([](const MockRequest&) -> MockResponse {
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{options(junk_server.url(""))};
    CHECK_THROWS_AS(junk.get_domain_report("1.2.3.4"), vtapi::VtError);
    CHECK_THROWS_AS(junk.get_domain_report("not a domain"), vtapi::VtError);
    CHECK_THROWS_AS(junk.get_domain_report("-bad.com"), vtapi::VtError);
    CHECK_THROWS_AS(junk.get_domain_report("example"), vtapi::VtError);
    CHECK_THROWS_AS(junk.get_domain_report(""), vtapi::VtError);
    // As long as it is still a domain, the request happens.
    CHECK_THROWS_AS(not_found.get_domain_report("sub.example.com"), vtapi::NotFound);
}

void test_rescan_domain() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    MockServer server([](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/domains/example.com/analyse")
            return {400, "bad"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};
    const vtapi::ScanResult result = vt.rescan_domain("example.com");
    CHECK(!result.id.empty());

    // Invalid domain → VtError before any HTTP request.
    CHECK_THROWS_AS(vt.rescan_domain("1.2.3.4"), vtapi::VtError);
    CHECK_THROWS_AS(vt.rescan_domain("bad domain"), vtapi::VtError);
}

void test_domain_comments_votes() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Mock: GET/POST /domains/example.com/comments|votes + GET relationships.
    // POST bodies must carry the v3 object type or the API rejects them.
    std::string last_vote_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.path.find("/comments") != std::string::npos) {
            if (req.method == "GET")
                return {200, R"({"data":[{"id":"c1","attributes":{"text":"hello"}}]})", "application/json"};
            if (req.method == "POST") {
                if (req.body.find("\"type\":\"comment\"") == std::string::npos)
                    return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
                return {200, "{}", "application/json"};
            }
        }
        if (req.path.find("/votes") != std::string::npos && req.method == "POST") {
            if (req.body.find("\"type\":\"vote\"") == std::string::npos)
                return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
            last_vote_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.path.find("/votes") != std::string::npos && req.method == "GET")
            return {200, R"({"data":[{"id":"v1","attributes":{"verdict":"harmless"}}]})", "application/json"};
        if (req.method == "GET" && req.path.find("/relationships") != std::string::npos)
            return {200, "{}", "application/json"};
        return {404, "{}"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const std::string comments = vt.get_domain_comments("example.com");
    CHECK(!comments.empty());
    vt.post_domain_comment("example.com", "test note");
    vt.post_domain_vote("example.com", true);
    CHECK(last_vote_body.find("\"verdict\":\"harmless\"") != std::string::npos);
    vt.post_domain_vote("example.com", false);
    CHECK(last_vote_body.find("\"verdict\":\"malicious\"") != std::string::npos);
    const std::string votes = vt.get_domain_votes("example.com");
    CHECK(!votes.empty());
    const std::string rels = vt.get_domain_relationships("example.com", "resolutions");
    CHECK(rels == "{}");

    // Invalid domain → VtError before any HTTP request.
    CHECK_THROWS_AS(vt.get_domain_comments("bad"), vtapi::VtError);
    CHECK_THROWS_AS(vt.post_domain_vote("bad", true), vtapi::VtError);
}

void test_get_resolution() {
    const std::string kKey(64, 'a');
    const std::string kId = "111.222.33.44example.com";
    const auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // 200 → full Resolution.
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        if (req.path != "/resolutions/" + kId)
            return {404, "wrong path"};
        return {200, load_fixture("resolution.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(ok_server.url(""))};
    const vtapi::Resolution r = vt.get_resolution(kId);
    CHECK(r.host_name == "example.com");
    CHECK(r.ip_address == "111.222.33.44");
    CHECK(r.host_name_last_analysis_stats.harmless == 77);

    // 404 → NotFound.
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"Resolution not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal not_found{options(nf_server.url(""))};
    CHECK_THROWS_AS(not_found.get_resolution(kId), vtapi::NotFound);

    // Empty id → VtError before any HTTP request.
    CHECK_THROWS_AS(not_found.get_resolution(""), vtapi::VtError);
}

void test_analysis() {
    const nlohmann::json root =
        nlohmann::json::parse(load_fixture("analysis.json"));
    const vtapi::AnalysisReport a = vtapi::analysis_report_from_json(root);

    CHECK(a.type == "analysis");
    CHECK(a.id == "u-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d-1600000000");
    CHECK(!a.self_link.empty());
    CHECK(a.status == "completed");
    CHECK(a.date == 1600000000);
    CHECK(a.stats.harmless == 60);
    CHECK(a.stats.malicious == 5);
    CHECK(a.stats.type_unsupported == 3);
    CHECK(a.results.size() == 2);
    CHECK(a.results.at("EngineOne").category == "malicious");
    CHECK(a.results.at("EngineOne").result == "EICAR-Test-File");
    CHECK(a.results.at("EngineTwo").engine_version == "2.1.0");

    // Sparse / malformed roots fall back to defaults without throwing.
    const vtapi::AnalysisReport sparse = vtapi::analysis_report_from_json(
        nlohmann::json::parse(R"({"data":{"id":"x","attributes":{"status":"queued"}}})"));
    CHECK(sparse.id == "x");
    CHECK(sparse.status == "queued");
    CHECK(sparse.stats.malicious == 0);
    CHECK(vtapi::analysis_report_from_json(nlohmann::json::array()).id.empty());
}

void test_get_analysis() {
    const std::string kKey(64, 'a');
    const std::string kId = "u-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d-1600000000";
    const auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // 200 → full AnalysisReport (api key header is sent).
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.method != "GET" || req.path != "/analyses/" + kId)
            return {404, "wrong path"};
        return {200, load_fixture("analysis.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(ok_server.url(""))};
    const vtapi::AnalysisReport a = vt.get_analysis(kId);
    CHECK(a.id == kId);
    CHECK(a.status == "completed");
    CHECK(a.stats.malicious == 5);

    // 404 → NotFound.
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"Analysis not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal not_found{options(nf_server.url(""))};
    CHECK_THROWS_AS(not_found.get_analysis(kId), vtapi::NotFound);

    // Empty id → VtError before any HTTP request.
    CHECK_THROWS_AS(not_found.get_analysis(""), vtapi::VtError);
}

void test_comments() {
    const std::string kKey(64, 'c');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Mock for comments: GET/POST on /files/{hash}/comments, /comments, /comments/{id}
    std::string last_vote_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" && req.path == "/comments") {
            return {200,
                    R"({"data":[{"type":"comment","id":"c1","links":{"self":"https://x/api/v3/comments/c1"},"attributes":{"text":"hello","date":1,"votes":{"positive":1,"negative":0},"html":"<p>hello</p>"}}],"links":{"self":"https://x/api/v3/comments"}})",
                    "application/json"};
        }
        if (req.method == "GET" && req.path.find("/files/") != std::string::npos &&
            req.path.find("/comments") != std::string::npos) {
            return {200,
                    R"({"data":[{"type":"comment","id":"c2","attributes":{"text":"file note","date":2,"votes":{"positive":0,"negative":0}}}]} )",
                    "application/json"};
        }
        if (req.method == "GET" && req.path.find("/comments/") != std::string::npos &&
            req.path.find("/votes") == std::string::npos) {
            // get single comment
            return {200,
                    R"({"data":{"type":"comment","id":"c9","attributes":{"text":"single","date":3,"votes":{"positive":2,"negative":1}}}})",
                    "application/json"};
        }
        if (req.method == "POST" && req.path.find("/comments/") != std::string::npos &&
            req.path.find("/votes") != std::string::npos) {
            if (req.body.find("\"type\":\"vote\"") == std::string::npos)
                return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
            last_vote_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.method == "POST" && req.path.find("/comments") != std::string::npos &&
            req.path.find("/votes") == std::string::npos &&
            req.path.find("/files/") == std::string::npos) {
            // not expected here
        }
        if (req.method == "POST" && req.path.find("/files/") != std::string::npos &&
            req.path.find("/comments") != std::string::npos) {
            if (req.body.find("\"type\":\"comment\"") == std::string::npos)
                return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
            return {200, "{}", "application/json"};
        }
        if (req.method == "DELETE" && req.path.find("/comments/c9") != std::string::npos) {
            return {204, "", "text/plain"};
        }
        return {404, "{}"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const auto latest = vt.get_comments_latest();
    CHECK(latest.data.size() == 1);
    CHECK(latest.data[0].id == "c1");
    CHECK(latest.data[0].text == "hello");
    CHECK(latest.data[0].votes_positive == 1);

    const auto fcomments = vt.get_comments("files", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(fcomments.data.size() == 1);
    CHECK(fcomments.data[0].text == "file note");

    const auto c = vt.get_comment("c9");
    CHECK(c.id == "c9");
    CHECK(c.votes_negative == 1);

    vt.post_comment("files", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "nice");
    vt.vote_comment("c9", true);
    CHECK(last_vote_body.find("\"verdict\":\"harmless\"") != std::string::npos);
    vt.delete_comment("c9");

    vt.delete_comment("c9");

    // kCommentSizeLimit enforced.
    std::string big(vtapi::kCommentSizeLimit + 1, 'x');
    CHECK_THROWS_AS(vt.post_comment("files", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", big), vtapi::VtError);
    CHECK_THROWS_AS(vt.post_comment("files", "bad", "hi"), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_comments("badtype", "x"), vtapi::VtError);
}

void test_votes_generic() {
    const std::string kKey(64, 'd');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    std::string last_vote_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "POST" && req.path.find("/votes") != std::string::npos) {
            if (req.body.find("\"type\":\"vote\"") == std::string::npos)
                return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
            last_vote_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.method == "GET" && req.path.find("/votes") != std::string::npos)
            return {200, R"({"data":[{"id":"v1"}]})", "application/json"};
        return {404, "{}"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    vt.put_vote("files", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", false);
    CHECK(last_vote_body.find("\"verdict\":\"malicious\"") != std::string::npos);
    vt.put_vote("urls", "http://example.com", true);
    vt.put_vote("domains", "example.com", true);
    vt.put_vote("ip_addresses", "8.8.8.8", false);

    const std::string votes = vt.get_votes("domains", "example.com");
    CHECK(!votes.empty());

    CHECK_THROWS_AS(vt.put_vote("comments", "c1", true), vtapi::VtError);
    CHECK_THROWS_AS(vt.put_vote("files", "bad", true), vtapi::VtError);
}

void test_relationships_generic() {
    const std::string kKey(64, 'e');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" && req.path.find("/files/") != std::string::npos &&
            req.path.find("/relationships/") != std::string::npos) {
            // "/relationships/<r>/<id>" is a descriptor
            if (req.path.find("/relationships/communicating_files/") != std::string::npos)
                return {200, R"({"data":{"type":"file","id":"abc"},"meta":{"count":1}})", "application/json"};
            // collection (ends with /relationships/<r>)
            if (req.path.rfind("/relationships/communicating_files") != std::string::npos &&
                req.path.back() != 's')
                return {200, R"({"data":[{"type":"file","id":"abc"}]})", "application/json"};
            return {200, R"({"data":[]})", "application/json"};
        }
        if (req.method == "GET" && req.path.find("/urls/") != std::string::npos &&
            req.path.find("/relationships/") != std::string::npos)
            return {200, R"({"data":[]})", "application/json"};
        if (req.method == "GET" && req.path.find("/domains/") != std::string::npos &&
            req.path.find("/relationships/") != std::string::npos)
            return {200, R"({"data":[]})", "application/json"};
        if (req.method == "GET" && req.path.find("/ip_addresses/") != std::string::npos &&
            req.path.find("/relationships/") != std::string::npos)
            return {200, R"({"data":[]})", "application/json"};
        return {404, "{}"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const std::string rels = vt.get_relationships("files", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "communicating_files");
    CHECK(!rels.empty());
    const std::string desc = vt.get_relationship_descriptor("files", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "communicating_files", "abc");
    CHECK(desc.find("\"data\"") != std::string::npos);

    vt.get_relationships("urls", "http://example.com", "last_serving_ip_address");
    vt.get_relationships("domains", "example.com", "resolutions");
    vt.get_relationships("ip_addresses", "8.8.8.8", "resolutions");

    CHECK_THROWS_AS(vt.get_relationships("files", "bad", "x"), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_relationships("comments", "c1", "x"), vtapi::VtError);
}

void test_await_analysis() {
    const std::string kKey(64, 'b');
    const std::string kId = "u-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d-1600000000";
    const auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // queued -> in-progress -> completed.
    int count = 0;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method != "GET" || req.path != "/analyses/" + kId)
            return {404, "wrong path"};
        ++count;
        if (count == 1)
            return {200,
                    R"({"data":{"type":"analysis","id":"u-1","attributes":{"status":"queued","date":1,"stats":{"harmless":0,"malicious":0,"suspicious":0,"timeout":0,"undetected":0,"type-unsupported":0},"results":{}}}})",
                    "application/json"};
        if (count == 2)
            return {200,
                    R"({"data":{"type":"analysis","id":"u-1","attributes":{"status":"in-progress","date":2,"stats":{"harmless":1,"malicious":0,"suspicious":0,"timeout":0,"undetected":0,"type-unsupported":0},"results":{}}}})",
                    "application/json"};
        return {200, load_fixture("analysis.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(server.url(""))};
    const vtapi::AnalysisReport a = vt.await_analysis(kId, std::chrono::seconds(10), std::chrono::seconds(2));
    CHECK(a.status == "completed");
    CHECK(a.stats.malicious == 5);
    CHECK(count >= 3);

    // timeout -> VtError.
    int count2 = 0;
    MockServer never([&](const MockRequest&) -> MockResponse {
        ++count2;
        return {200,
                R"({"data":{"type":"analysis","id":"u-1","attributes":{"status":"queued","date":1,"stats":{"harmless":0,"malicious":0,"suspicious":0,"timeout":0,"undetected":0,"type-unsupported":0},"results":{}}}})",
                "application/json"};
    });
    vtapi::VirusTotal vt2{options(never.url(""))};
    CHECK_THROWS_AS(vt2.await_analysis(kId, std::chrono::seconds(4), std::chrono::seconds(2)), vtapi::VtError);
    CHECK(count2 >= 1);

    // Empty id -> VtError before any HTTP request.
    CHECK_THROWS_AS(vt2.await_analysis(""), vtapi::VtError);
}

void test_scan_url() {
    const std::string kKey(64, 'a');
    const std::string kAnalysisId =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1680798089";
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    MockServer server([](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/urls")
            return {400, "bad"};
        const auto url_field = req.form_fields.find("url");
        if (url_field == req.form_fields.end() || url_field->second != "https://example.com")
            return {400, "bad url field"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};
    const vtapi::ScanResult result = vt.scan_url("https://example.com");
    CHECK(result.id == kAnalysisId);
    CHECK(result.file_info.sha256 ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

    // Invalid URL → VtError before HTTP.
    bool bad_url = false;
    try {
        vt.scan_url("");
    } catch (const vtapi::VtError&) {
        bad_url = true;
    }
    CHECK(bad_url);
    bool bad_url2 = false;
    try {
        vt.scan_url("not-a-url");
    } catch (const vtapi::VtError&) {
        bad_url2 = true;
    }
    CHECK(bad_url2);
}

void test_rescan_url() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    MockServer server([](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/urls/aHR0cHM6Ly9leGFtcGxlLmNvbQ/analyse")
            return {400, "bad"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};
    const vtapi::ScanResult result = vt.rescan_url("https://example.com");
    CHECK(!result.id.empty());

    bool bad = false;
    try {
        vt.rescan_url("bad");
    } catch (const vtapi::VtError&) {
        bad = true;
    }
    CHECK(bad);
}

void test_url_comments_votes() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Mock: GET/POST /urls/{id}/comments|votes + GET relationships all return
    // 200. Matching by path substring because the base64url id varies. POST
    // bodies must carry the v3 object type or the API rejects them.
    std::string last_vote_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.path.find("/comments") != std::string::npos) {
            if (req.method == "GET")
                return {200, R"({"data":[{"id":"c1","attributes":{"text":"hello"}}]})", "application/json"};
            if (req.method == "POST") {
                if (req.body.find("\"type\":\"comment\"") == std::string::npos)
                    return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
                return {200, "{}", "application/json"};
            }
        }
        if (req.path.find("/votes") != std::string::npos && req.method == "POST") {
            if (req.body.find("\"type\":\"vote\"") == std::string::npos)
                return {400, R"({"error":{"code":"BadRequestError","message":"no type"}})"};
            last_vote_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.path.find("/votes") != std::string::npos && req.method == "GET")
            return {200, R"({"data":[{"id":"v1","attributes":{"verdict":"harmless"}}]})", "application/json"};
        if (req.method == "GET" && req.path.find("/relationships") != std::string::npos)
            return {200, "{}", "application/json"};
        return {404, "{}"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    // get_url_comments returns JSON string
    const std::string comments = vt.get_url_comments("https://example.com");
    CHECK(!comments.empty());

    // post_url_comment + vote + get_url_votes (no exception = pass through mock)
    vt.post_url_comment("https://example.com", "test note");
    vt.post_url_vote("https://example.com", true);
    CHECK(last_vote_body.find("\"verdict\":\"harmless\"") != std::string::npos);
    const std::string votes = vt.get_url_votes("https://example.com");
    CHECK(!votes.empty());

    // get_url_relationships
    const std::string rels = vt.get_url_relationships("https://example.com", "contacted_urls");
    CHECK(rels == "{}");
}

void test_scan_urls() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Mock counts POST /urls; returns a queued analysis for any valid scan.
    int posted = 0;
    MockServer server([&posted](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/urls")
            return {400, "bad"};
        ++posted;
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const std::vector<vtapi::ScanResult> results =
        vt.scan_urls({"https://example.com", "https://example.org", "https://example.net"});
    CHECK(results.size() == 3);
    CHECK(posted == 3);
    CHECK(!results[0].id.empty() && !results[2].id.empty());

    // Invalid URL anywhere in the list → VtError before any HTTP request.
    int hits = 0;
    MockServer junk_server([&hits](const MockRequest&) -> MockResponse {
        ++hits;
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    opt.base_url = junk_server.url("");
    vtapi::VirusTotal junk{opt};
    bool bad = false;
    try {
        junk.scan_urls({"https://example.com", "not-a-url"});
    } catch (const vtapi::VtError&) {
        bad = true;
    }
    CHECK(bad);
    CHECK(hits == 0);
}

void test_url_reports() {
    const std::string kKey(64, 'a');
    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Mock serves the canonical url_report for any GET /urls/{id}.
    MockServer server([](const MockRequest& req) -> MockResponse {
        if (req.method != "GET" || req.path.rfind("/urls/", 0) != 0)
            return {400, "bad"};
        return {200, load_fixture("url_report.json"), "application/json"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const std::vector<vtapi::UrlReport> reports =
        vt.get_url_reports({"https://example.com", "https://example.org"});
    CHECK(reports.size() == 2);
    CHECK(reports[0].id == "aHR0cHM6Ly9leGFtcGxlLmNvbQ");
    CHECK(reports[0].url == "https://example.com");

    // Invalid URL anywhere in the list → VtError before any HTTP request.
    int hits = 0;
    MockServer junk_server([&hits](const MockRequest&) -> MockResponse {
        ++hits;
        return {200, load_fixture("url_report.json"), "application/json"};
    });
    opt.base_url = junk_server.url("");
    vtapi::VirusTotal junk{opt};
    bool bad = false;
    try {
        junk.get_url_reports({"https://example.com", "not-a-url"});
    } catch (const vtapi::VtError&) {
        bad = true;
    }
    CHECK(bad);
    CHECK(hits == 0);

    // Public URL scan link: built locally, id is the base64url encoding.
    CHECK(vt.get_public_url_scan_link("https://example.com") ==
          "https://www.virustotal.com/gui/url/aHR0cHM6Ly9leGFtcGxlLmNvbQ/detection");
    bool bad_url = false;
    try {
        vt.get_public_url_scan_link("not-a-url");
    } catch (const vtapi::VtError&) {
        bad_url = true;
    }
    CHECK(bad_url);
}

void test_get_file_report() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0; // disable pacing for tests
        return opt;
    };

    // 200 → full FileReport (and the api key header is sent).
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/files/" + kSha256)
            return {404, "wrong path"};
        return {200, load_fixture("file_report.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(ok_server.url(""))};
    const vtapi::FileReport report = vt.get_file_report(kSha256);
    CHECK(report.id == kSha256);
    CHECK(report.sha256 == kSha256);
    CHECK(report.last_analysis_stats.malicious == 64);

    // 404 → NotFound ("never scanned").
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal not_found{options(nf_server.url(""))};
    CHECK_THROWS_AS(not_found.get_file_report(kSha256), vtapi::NotFound);

    // Junk hash → VtError before any HTTP request reaches the server.
    bool server_hit = false;
    MockServer junk_server([&server_hit](const MockRequest&) -> MockResponse {
        server_hit = true;
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{options(junk_server.url(""))};
    bool junk_rejected = false;
    try {
        junk.get_file_report("not-a-hash");
    } catch (const vtapi::VtError&) {
        junk_rejected = true;
    }
    CHECK(junk_rejected);
    CHECK(!server_hit);

    // Valid md5-length (32 chars) and uppercase hex pass validation and reach
    // the 404 mock → NotFound (proves the HTTP request actually happened).
    CHECK_THROWS_AS(not_found.get_file_report("44d88612fea8a8f36de82e1278abb02f"),
                    vtapi::NotFound);
    const std::string upper_sha =
        "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
    CHECK_THROWS_AS(not_found.get_file_report(upper_sha), vtapi::NotFound);

    // Short/empty api keys are rejected at construction time.
    bool short_key = false;
    try {
        vtapi::ClientOptions bad = options("http://127.0.0.1:1");
        bad.api_key = "short";
        vtapi::VirusTotal{std::move(bad)};
    } catch (const vtapi::VtError&) {
        short_key = true;
    }
    CHECK(short_key);
}

void test_public_scan_link() {
    vtapi::ClientOptions opt;
    opt.api_key = std::string(64, 'a');
    opt.requests_per_minute = 0.0;
    opt.base_url = "http://127.0.0.1:1"; // never contacted: pure string helper
    vtapi::VirusTotal vt{opt};

    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    CHECK(vt.get_public_file_scan_link(kSha256) ==
          "https://www.virustotal.com/gui/file/" + kSha256 + "/detection");

    // Junk hash is rejected by the same validation as get_file_report.
    bool junk_rejected = false;
    try {
        vt.get_public_file_scan_link("not-a-hash");
    } catch (const vtapi::VtError&) {
        junk_rejected = true;
    }
    CHECK(junk_rejected);
}

void test_scan_result() {
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kAnalysisId =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1680798089";

    // Canonical upload response parses into a fully-populated ScanResult.
    const nlohmann::json root = nlohmann::json::parse(load_fixture("scan_result.json"));
    const vtapi::ScanResult result = vtapi::scan_result_from_json(root);

    // data.* carries the analysis identifier (used for later polling).
    CHECK(result.type == "analysis");
    CHECK(result.id == kAnalysisId);
    CHECK(result.self_link ==
          "https://www.virustotal.com/api/v3/analyses/" + kAnalysisId);

    // meta.file_info identifies the file for later GET /files/{sha256}.
    CHECK(result.file_info.sha256 == kSha256);
    CHECK(result.file_info.sha1 == "3395856ce81f2b7382dee72602f798b642f14140");
    CHECK(result.file_info.md5 == "44d88612fea8a8f36de82e1278abb02f");
    CHECK(result.file_info.size == 68);
    CHECK(result.file_info.name == "eicar.com");

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::ScanResult sparse =
        vtapi::scan_result_from_json(nlohmann::json::parse(R"({"data":{"type":"analysis"}})"));
    CHECK(sparse.type == "analysis");
    CHECK(sparse.id.empty());
    CHECK(sparse.self_link.empty());
    CHECK(sparse.file_info.sha256.empty());
    CHECK(sparse.file_info.size == 0);
    CHECK(sparse.file_info.name.empty());

    // Non-object roots are tolerated (defensive, empty result).
    const vtapi::ScanResult weird =
        vtapi::scan_result_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
    CHECK(weird.file_info.sha256.empty());
}

void test_scan_file() {
    const std::string kKey(64, 'a');
    const std::string kAnalysisId =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1680798089";
    const std::vector<uint8_t> eicar = [] {
        const std::string bytes =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        return std::vector<uint8_t>(bytes.begin(), bytes.end());
    }();

    auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // POST /files: file part named "file" with the right filename + bytes, api
    // key header present, and the optional password carried as a text field.
    MockServer upload_server([&](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/files")
            return {400, "bad request"};
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        const auto pw = req.form_fields.find("password");
        if (pw == req.form_fields.end() || pw->second != "p@ss")
            return {400, "bad password"};
        if (req.files.size() != 1 || req.files[0].field != "file" ||
            req.files[0].filename != "eicar.com")
            return {400, "bad file part"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(upload_server.url(""))};
    const vtapi::ScanResult result = vt.scan_file(eicar, "eicar.com", "p@ss");
    CHECK(result.id == kAnalysisId);
    CHECK(result.file_info.sha256 ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(result.file_info.name == "eicar.com");

    // Without a password the multipart body carries no password field.
    MockServer no_pw_server([](const MockRequest& req) -> MockResponse {
        if (req.form_fields.find("password") != req.form_fields.end())
            return {400, "unexpected password"};
        if (req.files.size() != 1 || req.files[0].filename != "plain.bin")
            return {400, "bad file part"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    vtapi::VirusTotal no_pw{options(no_pw_server.url(""))};
    CHECK(no_pw.scan_file(eicar, "plain.bin").id == kAnalysisId);

    // Oversized input throws VtError BEFORE any request reaches the server.
    bool server_hit = false;
    MockServer gate_server([&server_hit](const MockRequest&) -> MockResponse {
        server_hit = true;
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    vtapi::VirusTotal gated{options(gate_server.url(""))};
    const std::vector<uint8_t> huge(vtapi::VirusTotal::kFileSizeLimit + 1, 0);
    bool too_large = false;
    try {
        gated.scan_file(huge, "huge.bin");
    } catch (const vtapi::VtError&) {
        too_large = true;
    }
    CHECK(too_large);
    CHECK(!server_hit);
}

void test_scan_large_file() {
    const std::string kKey(64, 'a');
    const std::vector<uint8_t> eicar = [] {
        const std::string bytes =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        return std::vector<uint8_t>(bytes.begin(), bytes.end());
    }();

    auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // Two-step flow: GET /files/upload_url returns a one-time upload URL, then
    // the file is POSTed to that exact URL (different path than /files) using
    // the normal multipart shape — no privileged key is involved anywhere.
    const std::string kUploadUrlGhost = "/upload_target";
    const std::string kAnalysisId617 =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1680798089";

    MockServer flow_server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" && req.path == "/files/upload_url") {
            return {200,
                    R"({"data":")" + std::string(kUploadUrlGhost) + R"("})",
                    "application/json"};
        }
        if (req.method == "POST" && req.path == "/upload_target") {
            const auto key = req.headers.find("x-apikey");
            if (key == req.headers.end() || key->second != kKey)
                return {403, "bad key"};
            const auto pw = req.form_fields.find("password");
            if (pw == req.form_fields.end() || pw->second != "p@ss")
                return {400, "bad password"};
            if (req.files.size() != 1 || req.files[0].field != "file" ||
                req.files[0].filename != "eicar.bin" ||
                std::string(req.files[0].data.begin(), req.files[0].data.end()) !=
                    std::string(eicar.begin(), eicar.end()))
                return {400, "bad file part"};
            return {200, load_fixture("scan_result.json"), "application/json"};
        }
        return {404, "unexpected request"};
    });
    vtapi::VirusTotal vt{options(flow_server.url(""))};
    const vtapi::ScanResult result =
        vt.scan_large_file(eicar, "eicar.bin", "p@ss");
    CHECK(result.id == kAnalysisId617);

    // Missing file → VtError before any request (server never sees it).
    bool miss_hit = false;
    MockServer miss_server([&miss_hit](const MockRequest&) -> MockResponse {
        miss_hit = true;
        return {200, "{}"};
    });
    vtapi::VirusTotal miss{options(miss_server.url(""))};
    bool missing = false;
    try {
        miss.scan_large_file("/nonexistent/nope.bin");
    } catch (const vtapi::VtError&) {
        missing = true;
    }
    CHECK(missing);
    CHECK(!miss_hit);

    // Password-empty file with no password: no password field, still two-step.
    MockServer no_pw_server([](const MockRequest& req) -> MockResponse {
        if (req.method == "POST" && req.path == "/upload_target") {
            if (req.form_fields.find("password") != req.form_fields.end())
                return {400, "unexpected password"};
            return {200, load_fixture("scan_result.json"), "application/json"};
        }
        if (req.method == "GET")
            return {200, R"({"data":"/upload_target"})", "application/json"};
        return {404, "no"};
    });
    vtapi::VirusTotal no_pw{options(no_pw_server.url(""))};
    CHECK(no_pw.scan_large_file(eicar, "plain.bin").id == kAnalysisId617);
}

void test_scan_file_path() {
    const std::string kKey(64, 'a');

    auto options = [&](const std::string& base_url) {
        vtapi::ClientOptions opt;
        opt.api_key = kKey;
        opt.base_url = base_url;
        opt.verify_ssl = false;
        opt.timeout = std::chrono::seconds(5);
        opt.requests_per_minute = 0.0;
        return opt;
    };

    // Write a benign nonce file into a temp dir with a subpath, so the mock
    // verifies the upload name is the basename, not the full path. Real EICAR
    // bytes are avoided on disk here: antivirus (e.g. Windows Defender)
    // quarantines the file mid-test and makes the run flaky. The bytes are
    // irrelevant to what this test checks (path handling), only round-trip
    // equality matters. In-memory EICAR vectors still cover the data overload.
    const std::filesystem::path temp =
        std::filesystem::temp_directory_path() /
        ("vtapi_scan_file_test_" +
         std::to_string(std::chrono::steady_clock::now()
                            .time_since_epoch()
                            .count()));
    std::filesystem::create_directories(temp / "sub");
    const std::filesystem::path file_path = temp / "sub" / "sample.bin";
    const std::string payload = "vtapi-path-upload-test";
    {
        std::ofstream out(file_path, std::ios::binary);
        out << payload;
    }

    // Handler re-checks the uploaded bytes against what was written.
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/files")
            return {400, "bad request"};
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.files.size() != 1 || req.files[0].field != "file" ||
            req.files[0].filename != "sample.bin" ||
            std::string(req.files[0].data.begin(), req.files[0].data.end()) != payload)
            return {400, "bad file part"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(server.url(""))};
    const vtapi::ScanResult result = vt.scan_file(file_path.string());
    CHECK(result.file_info.sha256 ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(result.file_info.name == "eicar.com"); // fixture's meta, not the upload name

    // A nonexistent path throws VtError without reaching the server.
    bool server_hit2 = false;
    MockServer err_server([&server_hit2](const MockRequest&) -> MockResponse {
        server_hit2 = true;
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    vtapi::VirusTotal err_vt{options(err_server.url(""))};
    bool missing = false;
    try {
        err_vt.scan_file((temp / "does_not_exist.bin").string());
    } catch (const vtapi::VtError&) {
        missing = true;
    }
    CHECK(missing);
    CHECK(!server_hit2);

    std::filesystem::remove_all(temp);
}

void test_get_file_download_url() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kSignedUrl =
        "https://vtsamples.commondatastorage.googleapis.com/275a0..fd0f?"
        "GoogleAccessId=vt&Expires=1524733537&Signature=abc";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // 200 → the signed URL from data; api key header is sent.
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/files/" + kSha256 + "/download_url")
            return {404, "wrong path"};
        return {200, R"({"data":")" + kSignedUrl + R"("})", "application/json"};
    });
    vtapi::VirusTotal vt{with_url(ok_server.url(""))};
    CHECK(vt.get_file_download_url(kSha256) == kSignedUrl);

    // Junk hash → VtError before any HTTP call.
    bool server_hit = false;
    MockServer junk_server([&server_hit](const MockRequest&) -> MockResponse {
        server_hit = true;
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{with_url(junk_server.url(""))};
    CHECK_THROWS_AS(junk.get_file_download_url("not-a-hash"), vtapi::VtError);
    CHECK(!server_hit);

    // 404 → NotFound (file never scanned).
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal nf{with_url(nf_server.url(""))};
    CHECK_THROWS_AS(nf.get_file_download_url(kSha256), vtapi::NotFound);
}

void test_download_file() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    const std::filesystem::path temp =
        std::filesystem::temp_directory_path() /
        ("vtapi_download_test_" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temp);
    const std::filesystem::path out = temp / "download.bin";

    // Real-world download flow: GET /files/{id}/download answers a 302 redirect
    // to a signed URL; curl follows it and the final body is the file bytes.
    std::string signed_target;
    MockServer dl_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path == "/files/" + kSha256 + "/download")
            return {302, "", "text/plain", signed_target};
        if (req.path == "/dl/eicar.bin")
            return {200, kEicar, "application/octet-stream"};
        return {404, "wrong path"};
    });
    signed_target = dl_server.url("/dl/eicar.bin");

    vtapi::VirusTotal vt{with_url(dl_server.url(""))};
    vt.download_file(kSha256, out.string());
    std::ifstream in(out, std::ios::binary);
    const std::string written{std::istreambuf_iterator<char>(in),
                              std::istreambuf_iterator<char>{}};
    CHECK(written == kEicar);
    // The temporary ".part" sibling must not survive a successful transfer.
    CHECK(!std::filesystem::exists(out.string() + ".part"));

    // Premium-required endpoint: 403 → AuthError. And 404 → NotFound.
    MockServer auth_server([](const MockRequest&) -> MockResponse {
        return {403, R"({"error":{"code":"ForbiddenError","message":"privileges required"}})",
                "application/json"};
    });
    vtapi::VirusTotal auth{with_url(auth_server.url(""))};
    CHECK_THROWS_AS(auth.download_file(kSha256, out.string()),
                    vtapi::AuthError);

    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal nf{with_url(nf_server.url(""))};
    CHECK_THROWS_AS(nf.download_file(kSha256, out.string()), vtapi::NotFound);

    // Unwritable destination → VtError and no partial file is left behind.
    MockServer ok_server([&](const MockRequest&) -> MockResponse {
        return {200, kEicar, "application/octet-stream"};
    });
    vtapi::VirusTotal writable{with_url(ok_server.url(""))};
    bool unwritable = false;
    try {
        writable.download_file(kSha256, (temp / "no_such_dir" / "x.bin").string());
    } catch (const vtapi::VtError&) {
        unwritable = true;
    }
    CHECK(unwritable);
    CHECK(!std::filesystem::exists(temp / "no_such_dir"));

    // Junk hash → VtError before any HTTP.
    bool hit = false;
    MockServer junk_server([&hit, &kEicar](const MockRequest&) -> MockResponse {
        hit = true;
        return {200, kEicar, "application/octet-stream"};
    });
    vtapi::VirusTotal junk{with_url(junk_server.url(""))};
    CHECK_THROWS_AS(junk.download_file("nope", out.string()), vtapi::VtError);
    CHECK(!hit);

    std::filesystem::remove_all(temp);
}

void test_rescan_file() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kAnalysisId =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-201701190253";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // POST /files/{id}/analyse answers a fresh analysis id (v3 analysis shape).
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/files/" + kSha256 + "/analyse")
            return {400, "bad request"};
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        return {200,
                R"({"data":{"type":"analysis","id":")" + kAnalysisId + R"("}})",
                "application/json"};
    });
    vtapi::VirusTotal vt{with_url(ok_server.url(""))};
    const vtapi::ScanResult result = vt.rescan_file(kSha256);
    CHECK(result.type == "analysis");
    CHECK(result.id == kAnalysisId);

    // 404 → NotFound: rescanning a file never scanned is meaningless.
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal nf{with_url(nf_server.url(""))};
    CHECK_THROWS_AS(nf.rescan_file(kSha256), vtapi::NotFound);

    // Junk hash → VtError before any HTTP.
    bool hit = false;
    MockServer junk_server([&hit](const MockRequest&) -> MockResponse {
        hit = true;
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{with_url(junk_server.url(""))};
    CHECK_THROWS_AS(junk.rescan_file("nope"), vtapi::VtError);
    CHECK(!hit);
}

void test_rescan_files_and_reports() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kSha256B =
        "3395856ce81f2b7382dee72602f798b642f14140";
    const std::string kAnalysisId =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1680798089";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // User flow: re-analyze several known files, one HTTP call per hash (v3
    // has no batch endpoint), then pull each report for the fresh verdicts.
    std::vector<std::string> rescanned;
    MockServer flow_server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "POST") {
            rescanned.push_back(req.path);
            return {200,
                    R"({"data":{"type":"analysis","id":")" + kAnalysisId + R"("}})",
                    "application/json"};
        }
        if (req.method == "GET") {
            if (req.path == "/files/" + kSha256)
                return {200, load_fixture("file_report.json"), "application/json"};
            if (req.path == "/files/" + kSha256B)
                return {200, load_fixture("file_report.json"), "application/json"};
            return {404, "no"};
        }
        return {400, "unexpected"};
    });
    vtapi::VirusTotal vt{with_url(flow_server.url(""))};

    const std::vector<std::string> hashes = {kSha256, kSha256B};
    const std::vector<vtapi::ScanResult> rescans = vt.rescan_files(hashes);
    CHECK(rescans.size() == 2);
    CHECK(rescans[0].id == kAnalysisId);
    CHECK(rescans[1].id == kAnalysisId);
    CHECK(rescanned.size() == 2);
    CHECK(rescanned[0] == "/files/" + kSha256 + "/analyse");
    CHECK(rescanned[1] == "/files/" + kSha256B + "/analyse");

    const std::vector<vtapi::FileReport> reports = vt.get_file_reports(hashes);
    CHECK(reports.size() == 2);
    CHECK(reports[0].sha256 == kSha256);
    CHECK(reports[1].sha256 == kSha256);

    // One junk hash in the list → VtError before any HTTP request is made.
    bool hit = false;
    MockServer junk_server([&hit](const MockRequest&) -> MockResponse {
        hit = true;
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{with_url(junk_server.url(""))};
    CHECK_THROWS_AS(junk.rescan_files({kSha256, "bad"}), vtapi::VtError);
    CHECK_THROWS_AS(junk.get_file_reports({kSha256, "bad"}), vtapi::VtError);
    CHECK(!hit);
}

void test_behaviour_model() {
    // Canonical behaviour list parses into typed fields + raw attributes.
    const nlohmann::json roots =
        nlohmann::json::parse(load_fixture("file_behaviours.json"));
    const vtapi::BehaviourList list = vtapi::behaviour_list_from_json(roots);
    CHECK(list.count == 2);
    CHECK(list.behaviours.size() == 2);

    const vtapi::FileBehaviour& first = list.behaviours[0];
    CHECK(first.type == "file_behaviour");
    CHECK(first.id ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_VirusTotal Jujubox");
    CHECK(first.sandbox_name == "VirusTotal Jujubox");
    CHECK(first.analysis_date == 1669409515);
    CHECK(first.last_modification_date == 1669409615);
    CHECK(first.behash == "62c2064909c818e0914b1df00b8b82dc79c47684");
    CHECK(first.verdicts.size() == 1 && first.verdicts[0] == "UNKNOWN_VERDICT");
    CHECK(first.tags.size() == 1 && first.tags[0] == "eicar");
    CHECK(first.has_pcap);
    CHECK(!first.has_html_report);
    CHECK(first.mitre_attack_techniques.size() == 1);
    CHECK(first.mitre_attack_techniques[0].id == "T1082");
    CHECK(first.mitre_attack_techniques[0].signature_description ==
          "Reads software policies");
    CHECK(first.signature_matches.size() == 1);
    const vtapi::SignatureMatch& match = first.signature_matches[0];
    CHECK(match.name == "detect-eicar");
    CHECK(match.format == "SIG_FORMAT_CAPA");
    CHECK(match.authors.size() == 1 && match.authors[0] == "VirusTotal");
    CHECK(match.match_data.size() == 1);
    // Raw attributes survive untouched.
    CHECK(first.attributes.contains("calls_highlighted") == false);
    CHECK(first.attributes["sandbox_name"] == "VirusTotal Jujubox");

    // The raw artefact suffix helper maps each enum value to its path segment.
    CHECK(vtapi::behaviour_report_file_suffix(vtapi::BehaviourReportFile::kHtml) ==
          "html");
    CHECK(vtapi::behaviour_report_file_suffix(vtapi::BehaviourReportFile::kEvtx) ==
          "evtx");
    CHECK(vtapi::behaviour_report_file_suffix(vtapi::BehaviourReportFile::kPcap) ==
          "pcap");
    CHECK(vtapi::behaviour_report_file_suffix(vtapi::BehaviourReportFile::kMemdump) ==
          "memdump");

    // Single report: same parser on a data object.
    const nlohmann::json single =
        nlohmann::json::parse(load_fixture("file_behaviour.json"));
    const vtapi::FileBehaviour report =
        vtapi::file_behaviour_from_json(single["data"]);
    CHECK(report.id == first.id);
    CHECK(report.sandbox_name == "VirusTotal Jujubox");

    // Summary keeps the merged attributes and a few typed fields.
    const nlohmann::json summary_root =
        nlohmann::json::parse(load_fixture("behaviour_summary.json"));
    const vtapi::BehaviourSummary summary =
        vtapi::behaviour_summary_from_json(summary_root);
    CHECK(summary.behash == "62c2064909c818e0914b1df00b8b82dc79c47684");
    CHECK(summary.tags.size() == 1 && summary.tags[0] == "eicar");
    CHECK(summary.attributes.contains("calls_highlighted"));
    CHECK(summary.attributes.contains("files_opened"));

    // Sparse input falls back to defaults without throwing.
    const vtapi::FileBehaviour sparse =
        vtapi::file_behaviour_from_json(nlohmann::json::object());
    CHECK(sparse.sandbox_name.empty());
    CHECK(sparse.analysis_date == 0);
    CHECK(sparse.mitre_attack_techniques.empty());
    const vtapi::BehaviourList empty_list =
        vtapi::behaviour_list_from_json(nlohmann::json::array());
    CHECK(empty_list.count == 0);
    CHECK(empty_list.behaviours.empty());
}

void test_behaviour_client() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // All behaviour endpoints for one file, served from real response shapes.
    MockServer server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path == "/files/" + kSha256 + "/behaviours")
            return {200, load_fixture("file_behaviours.json"), "application/json"};
        if (req.path == "/files/" + kSha256 + "/behaviour_summary")
            return {200, load_fixture("behaviour_summary.json"), "application/json"};
        return {404, "no such path"};
    });
    vtapi::VirusTotal vt{with_url(server.url(""))};

    const vtapi::BehaviourList list = vt.get_file_behaviours(kSha256);
    CHECK(list.count == 2);
    CHECK(list.behaviours.size() == 2);
    CHECK(list.behaviours[0].sandbox_name == "VirusTotal Jujubox");
    CHECK(list.behaviours[1].sandbox_name == "Zenbox");

    const vtapi::BehaviourSummary summary =
        vt.get_file_behaviour_summary(kSha256);
    CHECK(summary.behash == "62c2064909c818e0914b1df00b8b82dc79c47684");
    CHECK(summary.attributes.contains("calls_highlighted"));

    // 404 → NotFound (file never scanned / has no sandbox reports).
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal nf{with_url(nf_server.url(""))};
    CHECK_THROWS_AS(nf.get_file_behaviours(kSha256), vtapi::NotFound);

    // Junk hash → VtError before any HTTP.
    bool hit = false;
    MockServer junk_server([&hit](const MockRequest&) -> MockResponse {
        hit = true;
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{with_url(junk_server.url(""))};
    CHECK_THROWS_AS(junk.get_file_behaviours("nope"), vtapi::VtError);
    CHECK(!hit);

    // Sandbox ids contain spaces; the client percent-encodes them into the
    // request path, exactly as the real API expects.
    const std::string sandbox_id =
        kSha256 + "_VirusTotal Jujubox";
    const std::string encoded = vtapi::detail::percent_encode(sandbox_id);
    MockServer bh_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path == "/file_behaviours/" + encoded)
            return {200, load_fixture("file_behaviour.json"), "application/json"};
        return {404, "no such sandbox"};
    });
    vtapi::VirusTotal bh{with_url(bh_server.url(""))};
    const vtapi::FileBehaviour report = bh.get_file_behaviour(sandbox_id);
    CHECK(report.sandbox_name == "VirusTotal Jujubox");
    CHECK(report.behash == "62c2064909c818e0914b1df00b8b82dc79c47684");
}

void test_behaviour_relationships_and_files() {
    const std::string kKey(64, 'a');
    const std::string kSandbox =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f_VirusTotal Jujubox";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    const std::string encoded = vtapi::detail::percent_encode(kSandbox);

    // Behaviour relationships: GET /file_behaviours/{id}/processes.
    MockServer rel_server([&](const MockRequest& req) -> MockResponse {
        if (req.path == "/file_behaviours/" + encoded + "/processes") {
            return {200,
                    R"({"meta":{"count":1},"data":[{"type":"process","id":"2248"}],"links":{"self":"x"}})",
                    "application/json"};
        }
        return {404, "no"};
    });
    vtapi::VirusTotal rel{with_url(rel_server.url(""))};
    const vtapi::RelationshipList processes =
        rel.get_file_behaviour_relationships(kSandbox, "processes");
    CHECK(processes.count == 1);
    CHECK(processes.objects.size() == 1);
    CHECK(processes.objects[0].type == "process");
    CHECK(processes.objects[0].id == "2248");

    // Sandbox ids are free-form strings (including spaces) — still encoded.
    MockServer space_server([&](const MockRequest& req) -> MockResponse {
        if (req.path == "/file_behaviours/" + encoded)
            return {200, load_fixture("file_behaviour.json"), "application/json"};
        return {404, "no"};
    });
    vtapi::VirusTotal space{with_url(space_server.url(""))};
    CHECK(space.get_file_behaviour(kSandbox).sandbox_name ==
          "VirusTotal Jujubox");

    // Raw artefacts: html is text, evtx/pcap/memdump come back as bytes.
    MockServer art_server([&](const MockRequest& req) -> MockResponse {
        if (req.path == "/file_behaviours/" + encoded + "/html")
            return {200, "<!DOCTYPE html><html></html>", "text/plain"};
        if (req.path == "/file_behaviours/" + encoded + "/pcap")
            return {200, std::string("\x0a\x0b\x0c\x0d", 4), "application/octet-stream"};
        return {404, "no"};
    });
    vtapi::VirusTotal art{with_url(art_server.url(""))};
    CHECK(art.get_file_behaviour_file(kSandbox, vtapi::BehaviourReportFile::kHtml) ==
          "<!DOCTYPE html><html></html>");
    const std::string pcap = art.get_file_behaviour_file(
        kSandbox, vtapi::BehaviourReportFile::kPcap);
    CHECK(pcap.size() == 4 && pcap[0] == '\x0a' && pcap[3] == '\x0d');

    // Unknown sandbox report → NotFound.
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal nf{with_url(nf_server.url(""))};
    CHECK_THROWS_AS(nf.get_file_behaviour(kSandbox), vtapi::NotFound);
    CHECK_THROWS_AS(nf.get_file_behaviour_file(
                        kSandbox, vtapi::BehaviourReportFile::kEvtx),
                    vtapi::NotFound);
}

void test_sigma_rule() {
    const std::string kKey(64, 'a');
    const std::string kSigmaId =
        "5c3ea6806114163b8cdf5735aeb07e702ab63e0e486f721df84cf675e2b0a04b";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // 200 → full SigmaRule
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/sigma_rules/" + kSigmaId)
            return {404, "wrong path"};
        return {200, load_fixture("sigma_rule.json"), "application/json"};
    });
    vtapi::VirusTotal vt{with_url(ok_server.url(""))};
    const vtapi::SigmaRule rule = vt.get_sigma_rule(kSigmaId);
    CHECK(rule.id == kSigmaId);
    CHECK(rule.title == "Hiding Files with Attrib.exe");
    CHECK(rule.description == "Detects the use of attrib.exe to hide files");
    CHECK(rule.level == "low");
    CHECK(rule.status == "experimental");
    CHECK(rule.source == "Sigma Integrated Rule Set (GitHub)");
    CHECK(rule.tags.size() == 2);
    CHECK(rule.tags[0] == "attack.persistence");
    CHECK(rule.tags[1] == "attack.defense_evasion");
    CHECK(rule.false_positives.size() == 1);
    CHECK(rule.false_positives[0] == "Some legit apps can use attrib");
    CHECK(rule.fields.size() == 1);
    CHECK(rule.fields[0] == "CommandLine");
    CHECK(rule.references.size() == 1);
    CHECK(rule.references[0].find("SigmaHQ") != std::string::npos);
    // raw attributes should contain the full metadata
    CHECK(rule.raw.contains("title"));
    CHECK(rule.raw.contains("level"));

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::SigmaRule sparse =
        vtapi::sigma_rule_from_json(nlohmann::json::parse(R"json({"data":{"id":"x"}})json"));
    CHECK(sparse.id == "x");
    CHECK(sparse.title.empty());
    CHECK(sparse.description.empty());
    CHECK(sparse.level.empty());
    CHECK(sparse.status.empty());
    CHECK(sparse.tags.empty());

    // Non-object roots are tolerated (defensive, empty rule).
    const vtapi::SigmaRule weird =
        vtapi::sigma_rule_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
}

void test_yara_ruleset() {
    const std::string kKey(64, 'a');
    const std::string kYaraId = "000abc43";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // 200 → full YaraRuleset
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/yara_rulesets/" + kYaraId)
            return {404, "wrong path"};
        return {200, load_fixture("yara_ruleset.json"), "application/json"};
    });
    vtapi::VirusTotal vt{with_url(ok_server.url(""))};
    const vtapi::YaraRuleset ruleset = vt.get_yara_ruleset(kYaraId);
    CHECK(ruleset.id == kYaraId);
    CHECK(ruleset.name == "evilness");
    CHECK(ruleset.rules.find("rule evilness") != std::string::npos);
    CHECK(ruleset.rules.find("$s1 =") != std::string::npos);
    CHECK(ruleset.source ==
          "https://github.com/VirusTotal/yara/blob/master/evilness.yar");
    // raw attributes should contain the rules field
    CHECK(ruleset.raw.contains("rules"));
    CHECK(ruleset.raw.contains("source"));

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::YaraRuleset sparse =
        vtapi::yara_ruleset_from_json(nlohmann::json::parse(R"json({"data":{"id":"x"}})json"));
    CHECK(sparse.id == "x");
    CHECK(sparse.name.empty());
    CHECK(sparse.rules.empty());
    CHECK(sparse.source.empty());

    // Non-object roots are tolerated (defensive, empty ruleset).
    const vtapi::YaraRuleset weird =
        vtapi::yara_ruleset_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());
}

void test_file_relationships() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // 200 → full RelationshipList of communicating files.
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/files/" + kSha256 + "/relationships/communicating_files")
            return {404, "wrong path"};
        return {200, load_fixture("file_relationships.json"), "application/json"};
    });
    vtapi::VirusTotal vt{with_url(ok_server.url(""))};
    const vtapi::RelationshipList rels =
        vt.get_file_relationships(kSha256, "communicating_files");
    CHECK(rels.count == 2);
    CHECK(rels.objects.size() == 2);
    CHECK(rels.objects[0].type == "file");
    CHECK(rels.objects[0].id == "3395856ce81f2b7382dee72602f798b642f14140");
    CHECK(rels.objects[1].type == "file");
    CHECK(rels.objects[1].id == kSha256);
    CHECK(rels.self_link == "https://www.virustotal.com/api/v3/files/" + kSha256 +
                               "/relationships/communicating_files");
    CHECK(rels.next_link ==
          "https://www.virustotal.com/api/v3/files/" + kSha256 +
              "/relationships/communicating_files?cursor=next");

    // Sparse fixture: missing fields fall back to defaults without throwing.
    const vtapi::RelationshipList sparse =
        vtapi::relationship_list_from_json(nlohmann::json::parse(R"json({"data":[]})json"));
    CHECK(sparse.count == 0);
    CHECK(sparse.objects.empty());

    // Non-object roots are tolerated (defensive, empty relationships).
    const vtapi::RelationshipList weird =
        vtapi::relationship_list_from_json(nlohmann::json::array());
    CHECK(weird.objects.empty());
}

void test_mitre_summary() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    const auto with_url = [&](const std::string& url) {
        vtapi::ClientOptions o = opt;
        o.base_url = url;
        return o;
    };

    // 200 → MITRE trees grouped per sandbox name.
    MockServer ok_server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.path != "/files/" + kSha256 + "/behaviour_mitre_trees")
            return {404, "wrong path"};
        return {200, load_fixture("behaviour_mitre_trees.json"), "application/json"};
    });
    vtapi::VirusTotal vt{with_url(ok_server.url(""))};
    const vtapi::MitreSummary mitre = vt.get_mitre_summary(kSha256);
    CHECK(mitre.sandboxes.size() == 2);

    // Zenbox: two tactics, each with techniques and signatures.
    const auto zenbox = mitre.sandboxes.find("Zenbox");
    CHECK(zenbox != mitre.sandboxes.end());
    CHECK(zenbox->second.size() == 2);
    CHECK(zenbox->second[0].id == "TA0007");
    CHECK(zenbox->second[0].name == "Discovery");
    CHECK(zenbox->second[0].link == "https://attack.mitre.org/tactics/TA0007/");
    CHECK(zenbox->second[0].description.find("figure out your environment") !=
          std::string::npos);
    CHECK(zenbox->second[0].techniques.size() == 2);
    CHECK(zenbox->second[0].techniques[0].id == "T1082");
    CHECK(zenbox->second[0].techniques[0].name == "System Information Discovery");
    CHECK(zenbox->second[0].techniques[0].link ==
          "https://attack.mitre.org/techniques/T1082/");
    CHECK(zenbox->second[0].techniques[0].signatures.size() == 2);
    CHECK(zenbox->second[0].techniques[0].signatures[0].severity == "INFO");
    CHECK(zenbox->second[0].techniques[0].signatures[0].description ==
          "Reads software policies");
    CHECK(zenbox->second[0].techniques[0].signatures[1].severity == "MEDIUM");
    CHECK(zenbox->second[0].techniques[1].id == "T1057");
    CHECK(zenbox->second[1].id == "TA0002");
    CHECK(zenbox->second[1].techniques[0].signatures[0].severity == "HIGH");

    // VirusTotal Jujubox: no tactics observed.
    const auto jujubox = mitre.sandboxes.find("VirusTotal Jujubox");
    CHECK(jujubox != mitre.sandboxes.end());
    CHECK(jujubox->second.empty());

    // Sparse fixture: an empty data object yields no sandboxes.
    const vtapi::MitreSummary sparse =
        vtapi::mitre_summary_from_json(nlohmann::json::parse(R"json({"data":{}})json"));
    CHECK(sparse.sandboxes.empty());

    // Non-object roots are tolerated (defensive, empty summary).
    const vtapi::MitreSummary weird =
        vtapi::mitre_summary_from_json(nlohmann::json::array());
    CHECK(weird.sandboxes.empty());

    // 404 → VtError for file never scanned
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    vtapi::VirusTotal nf{with_url(nf_server.url(""))};
    CHECK_THROWS_AS(nf.get_mitre_summary(kSha256), vtapi::NotFound);

    // Junk hash → VtError before any HTTP
    bool hit = false;
    MockServer junk_server([&hit](const MockRequest&) -> MockResponse {
        hit = true;
        return {200, "{}", "application/json"};
    });
    vtapi::VirusTotal junk{with_url(junk_server.url(""))};
    CHECK_THROWS_AS(junk.get_mitre_summary("nope"), vtapi::VtError);
    CHECK(!hit);
}

void test_collection_model() {
    const nlohmann::json root = nlohmann::json::parse(load_fixture("collection.json"));
    const vtapi::Collection c = vtapi::collection_from_json(root);
    CHECK(c.type == "collection");
    CHECK(c.id == "malpedia_win_emotet");
    CHECK(c.self_link ==
          "https://virustotal.com/api/v3/collections/malpedia_win_emotet");
    CHECK(c.name == "Emotet");
    CHECK(c.description.find("banking malware") != std::string::npos);
    CHECK(c.creation_date == 1612569600);
    CHECK(c.last_modification_date == 1613148085);
    CHECK(c.files_count == 3688);
    CHECK(c.urls_count == 3);
    CHECK(c.domains_count == 0);
    CHECK(c.ip_addresses_count == 2);
    CHECK(c.references_count == 129);
    CHECK(c.recent_activity_relative_change == 0.39);
    CHECK(c.recent_activity_summary.size() == 3);
    CHECK(c.recent_activity_summary[1] == 26799);
    CHECK(c.alt_names.size() == 2);
    CHECK(c.alt_names[0] == "Geodo");
    CHECK(c.autogenerated_tags.size() == 3);
    CHECK(c.tags.size() == 1 && c.tags[0] == "upx");
    CHECK(c.targeted_industries.size() == 1);
    CHECK(c.targeted_regions.size() == 1);
    CHECK(c.top_icon_md5.size() == 2);
    CHECK(c.source_region == "US");
    CHECK(c.sponsor_region == "US");
    CHECK(c.status == "COMPUTED");
    CHECK(c.tlp == "WHITE");
    CHECK(c.summary_stats.first_submission_date.min == 1.0);
    CHECK(c.summary_stats.first_submission_date.max == 100.0);
    CHECK(c.summary_stats.first_submission_date.avg == 50.5);
    CHECK(c.summary_stats.urls_detections.avg == 5.0);
    CHECK(c.raw.contains("data"));

    const vtapi::Collection sparse =
        vtapi::collection_from_json(nlohmann::json::parse(R"json({"data":{"id":"x"}})json"));
    CHECK(sparse.id == "x");
    CHECK(sparse.name.empty());
    CHECK(sparse.files_count == 0);

    const vtapi::Collection weird =
        vtapi::collection_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());

    const vtapi::CollectionList list = vtapi::collection_list_from_json(
        nlohmann::json::parse(R"json({
            "data":[{"type":"collection","id":"a"},{"type":"collection","id":"b"}],
            "meta":{"count":2},
            "links":{"self":"https://x/api/v3/collections","next":"https://x/api/v3/collections?cursor=n"}
        })json"));
    CHECK(list.count == 2);
    CHECK(list.data.size() == 2);
    CHECK(list.data[1].id == "b");
    CHECK(list.self_link == "https://x/api/v3/collections");
    CHECK(list.next_link == "https://x/api/v3/collections?cursor=n");

    const vtapi::CollectionList empty =
        vtapi::collection_list_from_json(nlohmann::json::array());
    CHECK(empty.data.empty());
}

void test_collection_crud() {
    const std::string kKey(64, 'f');
    const std::string kId = "owner_abc123";
    const std::string kHash =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    std::string create_body;
    std::string update_body;
    bool deleted = false;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.method == "POST" && req.path == "/collections") {
            create_body = req.body;
            return {200, load_fixture("collection.json"), "application/json"};
        }
        if (req.method == "GET" && req.path == "/collections/" + kId)
            return {200, load_fixture("collection.json"), "application/json"};
        if (req.method == "PATCH" && req.path == "/collections/" + kId) {
            update_body = req.body;
            return {200, load_fixture("collection.json"), "application/json"};
        }
        if (req.method == "DELETE" && req.path == "/collections/" + kId) {
            deleted = true;
            return {200, "{}", "application/json"};
        }
        if (req.method == "GET" && req.path == "/collections/missing")
            return {404, R"({"error":{"code":"NotFoundError","message":"not found"}})",
                    "application/json"};
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const vtapi::Collection created =
        vt.create_collection("Test collection", "created via API");
    CHECK(created.id == "malpedia_win_emotet");
    CHECK(created.name == "Emotet");
    CHECK(create_body.find("\"type\":\"collection\"") != std::string::npos);
    CHECK(create_body.find("\"name\":\"Test collection\"") != std::string::npos);
    CHECK(create_body.find("\"description\":\"created via API\"") != std::string::npos);

    const vtapi::Collection fetched = vt.get_collection(kId);
    CHECK(fetched.id == "malpedia_win_emotet");

    const vtapi::Collection updated =
        vt.update_collection(kId, "Renamed", "", "a raw item www.virustotal.com");
    CHECK(updated.id == "malpedia_win_emotet");
    CHECK(update_body.find("\"name\":\"Renamed\"") != std::string::npos);
    CHECK(update_body.find("\"raw_items\":\"a raw item") != std::string::npos);
    CHECK(update_body.find("\"description\"") == std::string::npos);

    vt.delete_collection(kId);
    CHECK(deleted);

    CHECK_THROWS_AS(vt.get_collection("missing"), vtapi::NotFound);
    CHECK_THROWS_AS(vt.get_collection(""), vtapi::VtError);
    CHECK_THROWS_AS(vt.create_collection(""), vtapi::VtError);
    CHECK_THROWS_AS(vt.update_collection(kId), vtapi::VtError);
    CHECK_THROWS_AS(vt.delete_collection(""), vtapi::VtError);

    // Local validation must not spend a request.
    int hits = 0;
    MockServer counted([&hits](const MockRequest&) -> MockResponse {
        ++hits;
        return {200, "{}", "application/json"};
    });
    opt.base_url = counted.url("");
    vtapi::VirusTotal local{opt};
    CHECK_THROWS_AS(local.get_collection(""), vtapi::VtError);
    CHECK_THROWS_AS(local.create_collection(""), vtapi::VtError);
    CHECK_THROWS_AS(local.update_collection(kId), vtapi::VtError);
    CHECK_THROWS_AS(local.delete_collection(""), vtapi::VtError);
    CHECK(hits == 0);
}

void test_collection_comments_and_items() {
    const std::string kKey(64, 'g');
    const std::string kId = "owner_abc123";
    const std::string kHash =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    std::string comment_body;
    std::string add_body;
    std::string remove_body;
    std::string add_url_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" && req.path ==
                "/collections/" + kId + "/comments?limit=5&cursor=next") {
            return {200,
                    R"({"data":[{"type":"comment","id":"c1","attributes":{"text":"collection note","date":7,"votes":{"positive":3,"negative":1}}}],"links":{"self":"https://x/comments"}})",
                    "application/json"};
        }
        if (req.method == "POST" && req.path == "/collections/" + kId + "/comments") {
            comment_body = req.body;
            return {200,
                    R"({"data":{"type":"comment","id":"c2","attributes":{"text":"hello","date":8,"votes":{"positive":0,"negative":0}}}})",
                    "application/json"};
        }
        if (req.method == "POST" && req.path == "/collections/" + kId + "/files") {
            add_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.method == "POST" && req.path == "/collections/" + kId + "/urls") {
            add_url_body = req.body;
            return {200, "{}", "application/json"};
        }
        if (req.method == "DELETE" && req.path == "/collections/" + kId + "/files") {
            remove_body = req.body;
            return {200, "{}", "application/json"};
        }
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const vtapi::CommentListResult comments =
        vt.get_collection_comments(kId, 5, "next");
    CHECK(comments.data.size() == 1);
    CHECK(comments.data[0].id == "c1");
    CHECK(comments.data[0].text == "collection note");
    CHECK(comments.data[0].votes_positive == 3);

    const vtapi::Comment posted = vt.post_collection_comment(kId, "hello #tag");
    CHECK(posted.id == "c2");
    CHECK(comment_body.find("\"type\":\"comment\"") != std::string::npos);
    CHECK(comment_body.find("\"text\":\"hello #tag\"") != std::string::npos);

    vt.add_collection_items(kId, "files", {{"file", kHash}});
    CHECK(add_body.find("\"data\":[") != std::string::npos);
    CHECK(add_body.find("\"type\":\"file\"") != std::string::npos);
    CHECK(add_body.find(kHash) != std::string::npos);

    vt.add_collection_items(kId, "urls",
                            {{"url", "", "https://www.virustotal.com/"}});
    CHECK(add_url_body.find("\"type\":\"url\"") != std::string::npos);
    CHECK(add_url_body.find("\"url\":\"https://www.virustotal.com/\"") !=
          std::string::npos);
    CHECK(add_url_body.find("\"id\"") == std::string::npos);

    vt.remove_collection_items(kId, "files", {{"file", kHash}});
    CHECK(remove_body.find(kHash) != std::string::npos);

    const std::string too_long(vtapi::kCommentSizeLimit + 1, 'x');
    CHECK_THROWS_AS(vt.post_collection_comment(kId, too_long), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_collection_comments("", 5), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_collection_comments(kId, 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.add_collection_items(kId, "files", {}), vtapi::VtError);
    CHECK_THROWS_AS(vt.add_collection_items("", "files", {{"file", kHash}}),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.add_collection_items(kId, "", {{"file", kHash}}),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.add_collection_items(kId, "files", {{"", kHash}}),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.add_collection_items(kId, "files", {{"file", ""}}),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.remove_collection_items(kId, "files", {}), vtapi::VtError);
}

void test_collection_relationships() {
    const std::string kKey(64, 'h');
    const std::string kId = "owner_abc123";
    const std::string kHash =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" &&
            req.path == "/collections/" + kId + "/files?limit=2&cursor=next") {
            return {200,
                    R"({"data":[{"type":"file","id":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","attributes":{"sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}}],"meta":{"count":1},"links":{"self":"https://x/collections/o/files","next":"https://x/collections/o/files?cursor=n"}})",
                    "application/json"};
        }
        if (req.method == "GET" &&
            req.path == "/collections/" + kId + "/relationships/files?limit=2") {
            return {200,
                    R"({"data":[{"type":"file","id":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}],"meta":{"count":1}})",
                    "application/json"};
        }
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const vtapi::RelationshipList full =
        vt.get_collection_relationships(kId, "files", 2, "next");
    CHECK(full.count == 1);
    CHECK(full.objects.size() == 1);
    CHECK(full.objects[0].type == "file");
    CHECK(full.objects[0].id == kHash);
    CHECK(full.objects[0].raw.contains("attributes"));
    CHECK(full.next_link.find("cursor=n") != std::string::npos);

    const vtapi::RelationshipList descriptors =
        vt.get_collection_relationship_descriptors(kId, "files", 2);
    CHECK(descriptors.count == 1);
    CHECK(descriptors.objects.size() == 1);
    CHECK(descriptors.objects[0].id == kHash);
    CHECK(!descriptors.objects[0].raw.contains("attributes"));

    CHECK_THROWS_AS(vt.get_collection_relationships("", "files"), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_collection_relationships(kId, ""), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_collection_relationships(kId, "files", 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_collection_relationship_descriptors("", "files"),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.get_collection_relationship_descriptors(kId, ""),
                    vtapi::VtError);
}

void test_collection_premium() {
    const std::string kKey(64, 'i');
    const std::string kId = "owner_abc123";
    const std::string kHash =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    int hits = 0;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        ++hits;
        if (req.method == "GET" &&
            req.path == "/collections?limit=5&filter=source_region%3AUS&order=files-") {
            return {200,
                    R"({"data":[{"type":"collection","id":"owner_abc123","attributes":{"name":"Premium"}}],"meta":{"count":1},"links":{"self":"https://x/collections","next":"https://x/collections?cursor=n"}})",
                    "application/json"};
        }
        if (req.method == "GET" && req.path == "/collections/" + kId + "/download/json")
            return {200, R"({"files":["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]})",
                    "application/json"};
        if (req.method == "GET" &&
            req.path == "/collections/" + kId + "/files/download/csv")
            return {200, "sha256\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n",
                    "text/csv"};
        if (req.method == "GET" &&
            req.path == "/collections/" + kId + "/aggregations/download/json")
            return {200, R"({"files":{"contacted_domains":[{"count":2,"value":"example.com"}]}})",
                    "application/json"};
        if (req.method == "GET" &&
            req.path == "/collections/" + kId +
                            "/search?query=type%3Apeexe&limit=5&order=positives-") {
            return {200,
                    R"({"data":[{"type":"file","id":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}],"meta":{"count":1},"links":{"self":"https://x/collections/o/search","next":"https://x/collections/o/search?cursor=n"}})",
                    "application/json"};
        }
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const vtapi::CollectionList list =
        vt.list_collections(5, "", "source_region:US", "files-");
    CHECK(list.count == 1);
    CHECK(list.data.size() == 1);
    CHECK(list.data[0].name == "Premium");
    CHECK(list.next_link.find("cursor=n") != std::string::npos);

    const std::string iocs = vt.export_collection_iocs(kId);
    CHECK(iocs.find(kHash) != std::string::npos);

    const std::string relationship_iocs =
        vt.export_collection_relationship_iocs(kId, "files", "csv");
    CHECK(relationship_iocs.find("sha256") != std::string::npos);

    const std::string aggregations = vt.export_collection_aggregations(kId);
    CHECK(aggregations.find("contacted_domains") != std::string::npos);

    const vtapi::SearchResult search =
        vt.search_collection_iocs(kId, "type:peexe", 5, "", "positives-");
    CHECK(search.count == 1);
    CHECK(search.data.size() == 1);
    CHECK(search.data[0].id == kHash);
    CHECK(search.next_cursor.find("cursor=n") != std::string::npos);

    const int before = hits;
    CHECK_THROWS_AS(vt.export_collection_iocs(kId, "yaml"), vtapi::VtError);
    CHECK_THROWS_AS(vt.export_collection_iocs("", "json"), vtapi::VtError);
    CHECK_THROWS_AS(vt.export_collection_relationship_iocs(kId, "", "json"),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.export_collection_aggregations(kId, "stix"), vtapi::VtError);
    CHECK_THROWS_AS(vt.list_collections(0), vtapi::VtError);
    CHECK_THROWS_AS(vt.list_collections(41), vtapi::VtError);
    CHECK_THROWS_AS(vt.search_collection_iocs(kId, ""), vtapi::VtError);
    CHECK_THROWS_AS(vt.search_collection_iocs("", "x"), vtapi::VtError);
    CHECK_THROWS_AS(vt.search_collection_iocs(kId, "x", 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.search_collection_iocs(kId, "x", 41), vtapi::VtError);
    CHECK(hits == before);
}

void test_graph_model() {
    const nlohmann::json root = nlohmann::json::parse(load_fixture("graph.json"));
    const vtapi::Graph g = vtapi::graph_from_json(root);
    CHECK(g.type == "graph");
    CHECK(g.id == "g0538d03053194c338643183e315b134ec3463a392330430938033934f3be3f37");
    CHECK(g.self_link ==
          "https://www.virustotal.com/api/v3/graphs/"
          "g0538d03053194c338643183e315b134ec3463a392330430938033934f3be3f37");
    CHECK(g.comments_count == 2);
    CHECK(g.creation_date == 1599060646);
    CHECK(g.last_modified_date == 1599117623);
    CHECK(g.is_private);
    CHECK(g.views_count == 2);
    CHECK(g.graph_data.description == "test");
    CHECK(g.graph_data.version == "5.0.0");
    CHECK(g.nodes.size() == 3);
    CHECK(g.nodes[0].type == "url");
    CHECK(g.nodes[0].entity_attributes.has_detections);
    CHECK(!g.nodes[0].has_fx);
    CHECK(g.nodes[1].type == "ip_address");
    CHECK(g.nodes[1].entity_attributes.country == "OM");
    CHECK(g.nodes[1].has_fx && g.nodes[1].has_fy);
    CHECK(g.nodes[1].fx == -60.42155469411466);
    CHECK(g.nodes[2].type == "relationship");
    CHECK(g.nodes[2].text == "path: /");
    CHECK(g.nodes[2].entity_attributes.relationship_type == "commonality");
    CHECK(g.nodes[2].entity_attributes.commonalities.size() == 1);
    CHECK(g.nodes[2].entity_attributes.commonalities[0].commonality == "path");
    CHECK(g.nodes[2].entity_attributes.commonalities[0].value == "/");
    CHECK(g.nodes[2].entity_attributes.raw.contains("commonalities"));
    CHECK(g.links.size() == 2);
    CHECK(g.links[0].connection_type == "last_serving_ip_address");
    CHECK(g.links[1].target == "138.133.35.39");
    CHECK(g.raw.contains("data"));

    const vtapi::Graph sparse =
        vtapi::graph_from_json(nlohmann::json::parse(R"json({"data":{"id":"x"}})json"));
    CHECK(sparse.id == "x");
    CHECK(!sparse.is_private);
    CHECK(sparse.nodes.empty());
    CHECK(sparse.links.empty());

    const vtapi::Graph weird = vtapi::graph_from_json(nlohmann::json::array());
    CHECK(weird.id.empty());

    const vtapi::GraphList list = vtapi::graph_list_from_json(
        nlohmann::json::parse(R"json({
            "data":[{"type":"graph","id":"g1"},{"type":"graph","id":"g2"}],
            "meta":{"count":2},
            "links":{"self":"https://x/api/v3/graphs","next":"https://x/api/v3/graphs?cursor=n"}
        })json"));
    CHECK(list.count == 2);
    CHECK(list.data.size() == 2);
    CHECK(list.data[1].id == "g2");
    CHECK(list.self_link == "https://x/api/v3/graphs");
    CHECK(list.next_link == "https://x/api/v3/graphs?cursor=n");

    const vtapi::GraphList empty =
        vtapi::graph_list_from_json(nlohmann::json::array());
    CHECK(empty.data.empty());
}

void test_graph_crud_and_search() {
    const std::string kKey(64, 'j');
    const std::string kId = "g0538d03053194c338643183e315b134ec3463a392330430938033934f3be3f37";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    std::string create_body;
    std::string update_body;
    bool deleted = false;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "POST" && req.path == "/graphs") {
            create_body = req.body;
            return {200, R"({"data":{"type":"graph","id":"g1"}})",
                    "application/json"};
        }
        if (req.method == "GET" && req.path == "/graphs/" + kId)
            return {200, load_fixture("graph.json"), "application/json"};
        if (req.method == "PATCH" && req.path == "/graphs/" + kId) {
            update_body = req.body;
            return {200, load_fixture("graph.json"), "application/json"};
        }
        if (req.method == "DELETE" && req.path == "/graphs/" + kId) {
            deleted = true;
            return {200, "{}", "application/json"};
        }
        if (req.method == "GET" &&
            req.path == "/graphs?filter=name%3Atest%20graph&limit=5&order=creation_date-") {
            return {200,
                    R"({"data":[{"type":"graph","id":"g1","attributes":{"private":false}}],"meta":{"count":1},"links":{"self":"https://x/graphs","next":"https://x/graphs?cursor=n"}})",
                    "application/json"};
        }
        if (req.method == "GET" && req.path == "/graphs/missing")
            return {404, R"({"error":{"code":"NotFoundError","message":"not found"}})",
                    "application/json"};
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    nlohmann::json attributes = {
        {"private", true},
        {"graph_data", {{"description", "demo"}, {"version", "5.0.0"}}},
        {"nodes", nlohmann::json::array({{{"type", "domain"},
                                          {"entity_id", "example.com"},
                                          {"index", 0}}})},
        {"links", nlohmann::json::array()},
    };

    const vtapi::Graph created = vt.create_graph(attributes);
    CHECK(created.id == "g1");
    CHECK(create_body.find("\"type\":\"graph\"") != std::string::npos);
    CHECK(create_body.find("\"attributes\"") != std::string::npos);
    CHECK(create_body.find("\"description\":\"demo\"") != std::string::npos);

    const vtapi::Graph fetched = vt.get_graph(kId);
    CHECK(fetched.id == kId);
    CHECK(fetched.nodes.size() == 3);

    const vtapi::Graph updated =
        vt.update_graph(kId, {{"private", false}});
    CHECK(updated.id == kId);
    CHECK(update_body.find("\"private\":false") != std::string::npos);
    CHECK(update_body.find("\"type\":\"graph\"") != std::string::npos);

    vt.delete_graph(kId);
    CHECK(deleted);

    const vtapi::GraphList found =
        vt.search_graphs("name:test graph", 5, "", "creation_date-");
    CHECK(found.count == 1);
    CHECK(found.data.size() == 1);
    CHECK(found.data[0].id == "g1");
    CHECK(found.next_link.find("cursor=n") != std::string::npos);

    CHECK_THROWS_AS(vt.get_graph("missing"), vtapi::NotFound);
    CHECK_THROWS_AS(vt.get_graph(""), vtapi::VtError);
    CHECK_THROWS_AS(vt.create_graph(nlohmann::json::object()), vtapi::VtError);
    CHECK_THROWS_AS(vt.create_graph(nlohmann::json::array()), vtapi::VtError);
    CHECK_THROWS_AS(vt.update_graph("", {{"private", true}}), vtapi::VtError);
    CHECK_THROWS_AS(vt.update_graph(kId, nlohmann::json::object()), vtapi::VtError);
    CHECK_THROWS_AS(vt.delete_graph(""), vtapi::VtError);
    CHECK_THROWS_AS(vt.search_graphs("", 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.search_graphs("", 41), vtapi::VtError);

    // Local validation must not spend a request.
    int hits = 0;
    MockServer counted([&hits](const MockRequest&) -> MockResponse {
        ++hits;
        return {200, "{}", "application/json"};
    });
    opt.base_url = counted.url("");
    vtapi::VirusTotal local{opt};
    CHECK_THROWS_AS(local.get_graph(""), vtapi::VtError);
    CHECK_THROWS_AS(local.create_graph(nlohmann::json::object()), vtapi::VtError);
    CHECK_THROWS_AS(local.update_graph(kId, nlohmann::json::object()), vtapi::VtError);
    CHECK_THROWS_AS(local.delete_graph(""), vtapi::VtError);
    CHECK_THROWS_AS(local.search_graphs("", 0), vtapi::VtError);
    CHECK_THROWS_AS(local.search_graphs("", 41), vtapi::VtError);
    CHECK(hits == 0);
}

void test_graph_comments_and_relationships() {
    const std::string kKey(64, 'k');
    const std::string kId = "g0538d03053194c338643183e315b134ec3463a392330430938033934f3be3f37";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    std::string comment_body;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/comments?limit=5&cursor=next") {
            return {200,
                    R"({"data":[{"type":"comment","id":"c1","attributes":{"text":"graph note","date":7,"votes":{"positive":2,"negative":1}}}],"links":{"self":"https://x/comments"}})",
                    "application/json"};
        }
        if (req.method == "POST" && req.path == "/graphs/" + kId + "/comments") {
            comment_body = req.body;
            return {200,
                    R"({"data":{"type":"comment","id":"c2","attributes":{"text":"hello","date":8,"votes":{"positive":0,"negative":0}}}})",
                    "application/json"};
        }
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/items?limit=2&cursor=next") {
            return {200,
                    R"({"data":[{"type":"file","id":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","attributes":{"sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}}],"meta":{"count":1},"links":{"self":"https://x/graphs/g/items","next":"https://x/graphs/g/items?cursor=n"}})",
                    "application/json"};
        }
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/relationships/items?limit=2") {
            return {200,
                    R"({"data":[{"type":"file","id":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}],"meta":{"count":1}})",
                    "application/json"};
        }
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const vtapi::CommentListResult comments = vt.get_graph_comments(kId, 5, "next");
    CHECK(comments.data.size() == 1);
    CHECK(comments.data[0].text == "graph note");
    CHECK(comments.data[0].votes_positive == 2);

    const vtapi::Comment posted = vt.post_graph_comment(kId, "hello #graph");
    CHECK(posted.id == "c2");
    CHECK(comment_body.find("\"type\":\"comment\"") != std::string::npos);
    CHECK(comment_body.find("\"text\":\"hello #graph\"") != std::string::npos);

    const vtapi::RelationshipList full =
        vt.get_graph_relationships(kId, "items", 2, "next");
    CHECK(full.count == 1);
    CHECK(full.objects.size() == 1);
    CHECK(full.objects[0].type == "file");
    CHECK(full.objects[0].raw.contains("attributes"));
    CHECK(full.next_link.find("cursor=n") != std::string::npos);

    const vtapi::RelationshipList descriptors =
        vt.get_graph_relationship_descriptors(kId, "items", 2);
    CHECK(descriptors.count == 1);
    CHECK(descriptors.objects.size() == 1);
    CHECK(!descriptors.objects[0].raw.contains("attributes"));

    const std::string too_long(vtapi::kCommentSizeLimit + 1, 'x');
    CHECK_THROWS_AS(vt.post_graph_comment(kId, too_long), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_comments("", 5), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_comments(kId, 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_relationships("", "items"), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_relationships(kId, ""), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_relationships(kId, "items", 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_relationship_descriptors("", "items"),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_relationship_descriptors(kId, ""),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_relationship_descriptors(kId, "items", 0),
                    vtapi::VtError);
}

void test_graph_acl() {
    const std::string kKey(64, 'l');
    const std::string kId = "g0538d03053194c338643183e315b134ec3463a392330430938033934f3be3f37";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    std::string add_viewer_body;
    std::string add_editor_body;
    bool removed_viewer = false;
    bool removed_editor = false;
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/viewers?limit=2&cursor=next") {
            return {200,
                    R"({"data":[{"type":"user","id":"gilfoyle"}],"meta":{"count":1},"links":{"self":"https://x/graphs/g/viewers?limit=2"}})",
                    "application/json"};
        }
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/editors?limit=2") {
            return {200,
                    R"({"data":[{"type":"group","id":"piedpiper"}],"meta":{"count":1}})",
                    "application/json"};
        }
        if (req.method == "POST" &&
            req.path == "/graphs/" + kId + "/relationships/viewers") {
            add_viewer_body = req.body;
            return {200,
                    R"({"data":[{"type":"user","id":"gilfoyle"}]})",
                    "application/json"};
        }
        if (req.method == "POST" &&
            req.path == "/graphs/" + kId + "/relationships/editors") {
            add_editor_body = req.body;
            return {200,
                    R"({"data":[{"type":"group","id":"piedpiper"}]})",
                    "application/json"};
        }
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/relationships/viewers/gilfoyle")
            return {200, R"({"data":true})", "application/json"};
        if (req.method == "GET" &&
            req.path == "/graphs/" + kId + "/relationships/editors/piedpiper")
            return {200, R"({"data":false})", "application/json"};
        if (req.method == "DELETE" &&
            req.path == "/graphs/" + kId + "/relationships/viewers/gilfoyle") {
            removed_viewer = true;
            return {200, "{}", "application/json"};
        }
        if (req.method == "DELETE" &&
            req.path == "/graphs/" + kId + "/relationships/editors/piedpiper") {
            removed_editor = true;
            return {200, "{}", "application/json"};
        }
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    const vtapi::RelationshipList viewers = vt.get_graph_viewers(kId, 2, "next");
    CHECK(viewers.count == 1);
    CHECK(viewers.objects.size() == 1);
    CHECK(viewers.objects[0].type == "user");
    CHECK(viewers.objects[0].id == "gilfoyle");

    const vtapi::RelationshipList editors = vt.get_graph_editors(kId, 2);
    CHECK(editors.objects.size() == 1);
    CHECK(editors.objects[0].type == "group");

    const vtapi::RelationshipList granted =
        vt.add_graph_viewers(kId, {{"user", "gilfoyle"}});
    CHECK(granted.objects.size() == 1);
    CHECK(add_viewer_body.find("\"data\":[") != std::string::npos);
    CHECK(add_viewer_body.find("\"type\":\"user\"") != std::string::npos);
    CHECK(add_viewer_body.find("\"id\":\"gilfoyle\"") != std::string::npos);

    const vtapi::RelationshipList granted_editors =
        vt.add_graph_editors(kId, {{"group", "piedpiper"}});
    CHECK(granted_editors.objects.size() == 1);
    CHECK(add_editor_body.find("\"type\":\"group\"") != std::string::npos);

    CHECK(vt.check_graph_viewer(kId, "gilfoyle"));
    CHECK(!vt.check_graph_editor(kId, "piedpiper"));

    vt.remove_graph_viewer(kId, "gilfoyle");
    vt.remove_graph_editor(kId, "piedpiper");
    CHECK(removed_viewer);
    CHECK(removed_editor);

    CHECK_THROWS_AS(vt.get_graph_viewers("", 2), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_viewers(kId, 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_editors("", 2), vtapi::VtError);
    CHECK_THROWS_AS(vt.get_graph_editors(kId, 0), vtapi::VtError);
    CHECK_THROWS_AS(vt.add_graph_viewers("", {{"user", "gilfoyle"}}),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.add_graph_viewers(kId, {}), vtapi::VtError);
    CHECK_THROWS_AS(vt.add_graph_viewers(kId, {{"robot", "x"}}), vtapi::VtError);
    CHECK_THROWS_AS(vt.add_graph_viewers(kId, {{"user", ""}}), vtapi::VtError);
    CHECK_THROWS_AS(vt.add_graph_editors("", {{"user", "gilfoyle"}}),
                    vtapi::VtError);
    CHECK_THROWS_AS(vt.add_graph_editors(kId, {}), vtapi::VtError);
    CHECK_THROWS_AS(vt.check_graph_viewer("", "gilfoyle"), vtapi::VtError);
    CHECK_THROWS_AS(vt.check_graph_viewer(kId, ""), vtapi::VtError);
    CHECK_THROWS_AS(vt.check_graph_editor("", "piedpiper"), vtapi::VtError);
    CHECK_THROWS_AS(vt.check_graph_editor(kId, ""), vtapi::VtError);
    CHECK_THROWS_AS(vt.remove_graph_viewer("", "gilfoyle"), vtapi::VtError);
    CHECK_THROWS_AS(vt.remove_graph_viewer(kId, ""), vtapi::VtError);
    CHECK_THROWS_AS(vt.remove_graph_editor("", "piedpiper"), vtapi::VtError);
    CHECK_THROWS_AS(vt.remove_graph_editor(kId, ""), vtapi::VtError);
}

void test_check_then_scan_round_trip() {
    const std::string kKey(64, 'a');
    const std::string kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const std::vector<uint8_t> eicar(kEicar.begin(), kEicar.end());
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    vtapi::ClientOptions opt;
    opt.api_key = kKey;
    opt.verify_ssl = false;
    opt.timeout = std::chrono::seconds(5);
    opt.requests_per_minute = 0.0;

    // Stateful server mimicking the real flow: the file is unknown (404) until
    // it is uploaded (POST /files), after which lookups return a full report.
    std::atomic<bool> scanned{false};
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET") {
            if (req.path == "/files/" + kSha256) {
                if (!scanned.load()) {
                    return {404,
                            R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                            "application/json"};
                }
                return {200, load_fixture("file_report.json"), "application/json"};
            }
            return {404, "unknown path"};
        }
        if (req.method == "POST" && req.path == "/files") {
            // Repeat what the caller just taught the server.
            scanned.store(true);
            return {200, load_fixture("scan_result.json"), "application/json"};
        }
        return {400, "unexpected request"};
    });
    opt.base_url = server.url("");
    vtapi::VirusTotal vt{opt};

    // Step 1: file never scanned → NotFound (drives the app into step 2).
    CHECK_THROWS_AS(vt.get_file_report(kSha256), vtapi::NotFound);

    // Step 2: upload it; the scan result carries the analysis id + the sha256
    // to query again with (the value the local hash computed would match).
    const vtapi::ScanResult uploaded = vt.scan_file(eicar, "eicar.com");
    CHECK(!uploaded.id.empty());
    CHECK(uploaded.file_info.sha256 == kSha256);

    // Step 3: the same caller can now look the file up instead of throwing.
    const vtapi::FileReport report = vt.get_file_report(kSha256);
    CHECK(report.sha256 == kSha256);
    CHECK(report.last_analysis_stats.malicious == 64);
}

// stdout, stderr and exit status of a spawned vtapi_eicar invocation.
#ifndef _WIN32
struct CliOutcome {
    std::string out;
    std::string err;
    int code = -1;
};

// Runs the built vtapi_eicar binary (path injected by CMake) with the given
// arguments and captures its standard streams.
CliOutcome run_cli(const std::vector<std::string>& args) {
    std::vector<std::string> argv_str = {std::string{VTAPI_EICAR_BIN}};
    argv_str.insert(argv_str.end(), args.begin(), args.end());

    std::vector<char*> argv;
    argv.reserve(argv_str.size() + 1);
    for (auto& arg : argv_str)
        argv.push_back(arg.data());
    argv.push_back(nullptr);

    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0)
        return {};
    const pid_t pid = fork();
    if (pid == 0) {
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        execv(argv_str[0].c_str(), argv.data());
        _exit(127); // exec failed
    }
    close(out_pipe[1]);
    close(err_pipe[1]);

    auto drain = [](int fd) {
        std::string s;
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            s.append(buf, static_cast<std::size_t>(n));
        close(fd);
        return s;
    };
    const CliOutcome result{drain(out_pipe[0]), drain(err_pipe[0]), -1};

    int status = 0;
    if (pid > 0 && waitpid(pid, &status, 0) == pid)
        return {result.out, result.err, WIFEXITED(status) ? WEXITSTATUS(status) : -1};
    return result;
}

void test_cli_report() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    const auto run = [&](const std::string& base_url, const std::string& hash) {
        return run_cli({"--key", kKey, "--base-url", base_url, "--rpm", "0",
                        "report", "--hash", hash});
    };

    // 200 → full verdict summary on stdout, exit 0.
    MockServer ok_server([](const MockRequest&) -> MockResponse {
        return {200, load_fixture("file_report.json"), "application/json"};
    });
    {
        const CliOutcome r = run(ok_server.url(""), kSha256);
        CHECK(r.code == 0);
        CHECK(r.out.find("resource: " + kSha256) != std::string::npos);
        CHECK(r.out.find("Seen before: Yes") != std::string::npos);
        CHECK(r.out.find("Malicious: 64 / Total: 64") != std::string::npos);
        CHECK(r.out.find("Engines flagging: 1") != std::string::npos);
        CHECK(r.out.find("Top engine: Acronis → EICAR-Test-File") != std::string::npos);
    }

    // 404 → "not scanned yet" + hint, exit 0 (a normal answer, not an error).
    MockServer nf_server([](const MockRequest&) -> MockResponse {
        return {404, R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                "application/json"};
    });
    {
        const CliOutcome r = run(nf_server.url(""), kSha256);
        CHECK(r.code == 0);
        CHECK(r.out.find("Seen before: No") != std::string::npos);
        CHECK(r.out.find("scan-file --path") != std::string::npos);
        CHECK(r.out.find("Seen before: Yes") == std::string::npos);
    }

    // Junk hash → clear error on stderr + exit 1 (rejected before any HTTP).
    {
        const CliOutcome r = run(nf_server.url(""), "not-a-hash");
        CHECK(r.code == 1);
        CHECK(r.err.find("error: invalid hash") != std::string::npos);
    }

    // Missing --hash → usage error + exit 2.
    {
        const CliOutcome r = run_cli({"--key", kKey, "report"});
        CHECK(r.code == 2);
        CHECK(r.err.find("--hash") != std::string::npos);
    }
}

void test_cli_scan_file() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kAnalysisId =
        "u-275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1680798089";
    const std::string kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Write EICAR into a temp dir; the CLI uploads it by path.
    const std::filesystem::path temp =
        std::filesystem::temp_directory_path() /
        ("vtapi_cli_scan_file_test_" +
         std::to_string(std::chrono::steady_clock::now()
                            .time_since_epoch()
                            .count()));
    std::filesystem::create_directories(temp);
    const std::filesystem::path file_path = temp / "eicar.com";
    {
        std::ofstream out(file_path, std::ios::binary);
        out << kEicar;
    }

    // POST /files must carry the api key and exactly the file's bytes under the
    // basename; the CLI prints the analysis id and the locally computed sha256.
    MockServer upload_server([&](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/files")
            return {400, "bad request"};
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.files.size() != 1 || req.files[0].field != "file" ||
            req.files[0].filename != "eicar.com" ||
            std::string(req.files[0].data.begin(), req.files[0].data.end()) != kEicar)
            return {400, "bad file part"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    {
        const CliOutcome r =
            run_cli({"--key", kKey, "--base-url", upload_server.url(""), "--rpm", "0",
                     "scan-file", "--path", file_path.string()});
        CHECK(r.code == 0);
        CHECK(r.out.find("Uploaded. analysis id: " + kAnalysisId) != std::string::npos);
        CHECK(r.out.find("sha256: " + kSha256) != std::string::npos);
        CHECK(r.out.find("Run: vtapi_eicar report --hash " + kSha256) !=
              std::string::npos);
    }

    // Optional --password is forwarded as a multipart text field.
    MockServer pw_server([](const MockRequest& req) -> MockResponse {
        const auto pw = req.form_fields.find("password");
        if (pw == req.form_fields.end() || pw->second != "p@ss")
            return {400, "bad password"};
        if (req.files.size() != 1 || req.files[0].filename != "eicar.com")
            return {400, "bad file part"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    {
        const CliOutcome r = run_cli({"--key", kKey, "--base-url", pw_server.url(""),
                                      "--rpm", "0", "scan-file", "--path",
                                      file_path.string(), "--password", "p@ss"});
        CHECK(r.code == 0);
        CHECK(r.out.find("sha256: " + kSha256) != std::string::npos);
    }

    // Missing file → clear error, exit 1 (rejected before any HTTP).
    {
        const CliOutcome r =
            run_cli({"--key", kKey, "--base-url", upload_server.url(""), "--rpm", "0",
                     "scan-file", "--path", (temp / "does_not_exist.bin").string()});
        CHECK(r.code == 1);
        CHECK(r.err.find("error:") != std::string::npos);
    }

    // Missing --path → usage error + exit 2.
    {
        const CliOutcome r = run_cli({"--key", kKey, "scan-file"});
        CHECK(r.code == 2);
        CHECK(r.err.find("--path") != std::string::npos);
    }

    std::filesystem::remove_all(temp);
}

// Drives the whole flow the way a user would, through the CLI: unknown hash ->
// upload -> now found. The mock server keeps state across the three spawned
// invocations, just like the real API would.
void test_cli_check_then_scan() {
    const std::string kKey(64, 'a');
    const std::string kSha256 =
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    const std::string kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    // Stateful server: the hash is unknown (404) until POST /files teaches it.
    std::atomic<bool> scanned{false};
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method == "GET" && req.path == "/files/" + kSha256) {
            if (!scanned.load())
                return {404,
                        R"({"error":{"code":"NotFoundError","message":"File not found"}})",
                        "application/json"};
            return {200, load_fixture("file_report.json"), "application/json"};
        }
        if (req.method == "POST" && req.path == "/files") {
            scanned.store(true);
            return {200, load_fixture("scan_result.json"), "application/json"};
        }
        return {400, "unexpected request"};
    });

    const std::filesystem::path temp =
        std::filesystem::temp_directory_path() /
        ("vtapi_cli_round_trip_test_" +
         std::to_string(std::chrono::steady_clock::now()
                            .time_since_epoch()
                            .count()));
    std::filesystem::create_directories(temp);
    const std::filesystem::path file_path = temp / "eicar.com";
    {
        std::ofstream out(file_path, std::ios::binary);
        out << kEicar;
    }

    const std::vector<std::string> base = {"--key", kKey, "--base-url", server.url(""),
                                           "--rpm", "0"};
    const auto with = [&](std::initializer_list<std::string> extra) {
        std::vector<std::string> v = base;
        v.insert(v.end(), extra.begin(), extra.end());
        return run_cli(v);
    };

    // Step 1: never scanned → the app learns it must upload.
    {
        const CliOutcome r = with({"report", "--hash", kSha256});
        CHECK(r.code == 0);
        CHECK(r.out.find("Seen before: No") != std::string::npos);
    }

    // Step 2: submit the local file.
    {
        const CliOutcome r = with({"scan-file", "--path", file_path.string()});
        CHECK(r.code == 0);
        CHECK(r.out.find("Uploaded. analysis id:") != std::string::npos);
        CHECK(r.out.find("sha256: " + kSha256) != std::string::npos);
    }

    // Step 3: the same lookup now answers with a verdict.
    {
        const CliOutcome r = with({"report", "--hash", kSha256});
        CHECK(r.code == 0);
        CHECK(r.out.find("Seen before: Yes") != std::string::npos);
    }

    std::filesystem::remove_all(temp);
}
#endif // !_WIN32

} // namespace

int main() {
    test_exception_hierarchy();
    test_hashing();
    test_rate_limiter();
    test_http_client();
    test_response_mapping();
    test_scan_result();
    test_get_file_report();
    test_url_report();
    test_ip_report();
    test_domain_report();
    test_resolution();
    test_get_ip_report();
    test_rescan_ip();
    test_ip_comments_votes();
    test_get_domain_report();
    test_rescan_domain();
    test_domain_comments_votes();
    test_get_resolution();
    test_analysis();
    test_get_analysis();
    test_await_analysis();
    test_comments();
    test_votes_generic();
    test_scan_url();
    test_scan_urls();
    test_url_reports();
    test_rescan_url();
    test_url_comments_votes();
    test_scan_file();
    test_scan_file_path();
    test_scan_large_file();
    test_get_file_download_url();
    test_download_file();
    test_rescan_file();
    test_rescan_files_and_reports();
    test_check_then_scan_round_trip();
    test_public_scan_link();
    test_behaviour_model();
    test_behaviour_client();
    test_behaviour_relationships_and_files();
    test_sigma_rule();
    test_yara_ruleset();
    test_file_relationships();
    test_mitre_summary();
    test_relationships_generic();
    test_collection_model();
    test_collection_crud();
    test_collection_comments_and_items();
    test_collection_relationships();
    test_collection_premium();
    test_graph_model();
    test_graph_crud_and_search();
    test_graph_comments_and_relationships();
    test_graph_acl();
#ifndef _WIN32
    test_cli_report();
    test_cli_scan_file();
    test_cli_check_then_scan();
#endif

    if (g_failures) {
        std::cerr << g_failures << " of " << g_checks << " checks failed\n";
        return 1;
    }
    std::cout << "OK: " << g_checks << " checks passed\n";
    return 0;
}