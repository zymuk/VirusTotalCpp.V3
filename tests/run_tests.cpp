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
#include "vtapi/model/file_report.hpp"
#include "vtapi/model/scan_result.hpp"
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

    // Write an EICAR file into a temp dir with a subpath, so the mock verifies
    // the upload name is the basename, not the full path.
    const std::filesystem::path temp =
        std::filesystem::temp_directory_path() /
        ("vtapi_scan_file_test_" +
         std::to_string(std::chrono::steady_clock::now()
                            .time_since_epoch()
                            .count()));
    std::filesystem::create_directories(temp / "sub");
    const std::filesystem::path file_path = temp / "sub" / "eicar.com";
    const std::string eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    {
        std::ofstream out(file_path, std::ios::binary);
        out << eicar;
    }

    // Handler re-checks the uploaded bytes against the EICAR vector.
    MockServer server([&](const MockRequest& req) -> MockResponse {
        if (req.method != "POST" || req.path != "/files")
            return {400, "bad request"};
        const auto key = req.headers.find("x-apikey");
        if (key == req.headers.end() || key->second != kKey)
            return {403, "bad key"};
        if (req.files.size() != 1 || req.files[0].field != "file" ||
            req.files[0].filename != "eicar.com" ||
            std::string(req.files[0].data.begin(), req.files[0].data.end()) != eicar)
            return {400, "bad file part"};
        return {200, load_fixture("scan_result.json"), "application/json"};
    });
    vtapi::VirusTotal vt{options(server.url(""))};
    const vtapi::ScanResult result = vt.scan_file(file_path.string());
    CHECK(result.file_info.sha256 ==
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    CHECK(result.file_info.name == "eicar.com");

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
    test_file_report();
    test_scan_result();
    test_get_file_report();
    test_scan_file();
    test_scan_file_path();
    test_scan_large_file();
    test_check_then_scan_round_trip();
    test_public_scan_link();
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