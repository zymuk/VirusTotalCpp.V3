#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

// Opaque libcurl types: keep curl headers out of the public API surface.
struct curl_slist;
typedef void CURL;
struct curl_mime;

namespace vtapi {
namespace detail {

// Result of one HTTP exchange. status == 0 and a non-empty error indicate a
// transport-level failure surface (also surfaced as NetworkError below).
struct HttpResponse {
    long status = 0;
    std::string body;
    std::string error;
};

// One binary part of a multipart/form-data upload.
struct MultipartFile {
    std::string field;
    std::string filename;
    std::vector<uint8_t> data;
};

// Owns a single CURL* handle; each call re-applies a fresh option set so one
// instance can drive requests with different methods/headers sequentially.
class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    HttpResponse get(const std::string& url,
                     const std::vector<std::string>& headers = {});
    HttpResponse post(const std::string& url, const std::string& body,
                      const std::string& content_type);
    HttpResponse post_multipart(const std::string& url,
                                const std::map<std::string, std::string>& fields,
                                const std::vector<MultipartFile>& files);

    void set_timeout(std::chrono::seconds timeout);
    void set_connect_timeout(std::chrono::seconds timeout);
    void set_ssl_verify(bool verify);
    void set_user_agent(const std::string& user_agent);
    void set_proxy(const std::string& proxy);
    void set_header(const std::string& name, const std::string& value);
    void clear_headers();

private:
    curl_slist* build_headers(const std::vector<std::string>& extra) const;
    void apply_common_options(CURL* handle, const std::string& url);
    HttpResponse perform(CURL* handle, curl_slist* headers, curl_mime* mime);

    void* curl_ = nullptr;          // CURL*
    std::string post_buffer_;       // owned copy outliving curl_easy_perform
    std::vector<std::string> default_headers_;
    std::string user_agent_;
    std::string proxy_;
    std::chrono::seconds timeout_{30};
    std::chrono::seconds connect_timeout_{10};
    bool verify_ssl_ = true;
};

} // namespace detail
} // namespace vtapi