#include "vtapi/detail/http.hpp"

#include "vtapi/types.hpp"

#include <curl/curl.h>

#include <mutex>
#include <utility>

namespace {

std::once_flag g_curl_init_flag;

void ensure_curl_global_init() {
    // curl_global_init is not thread-safe; guard it once for the whole process.
    std::call_once(g_curl_init_flag, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

std::size_t write_callback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* body = static_cast<std::string*>(userdata);
    body->append(ptr, size * nmemb);
    return size * nmemb;
}

} // namespace

namespace vtapi {
namespace detail {

HttpClient::HttpClient() {
    ensure_curl_global_init();
    curl_ = curl_easy_init();
    if (curl_ == nullptr)
        throw VtError("failed to initialize curl easy handle");
}

HttpClient::~HttpClient() {
    if (curl_ != nullptr)
        curl_easy_cleanup(static_cast<CURL*>(curl_));
}

void HttpClient::set_timeout(std::chrono::seconds timeout) {
    timeout_ = timeout;
}

void HttpClient::set_connect_timeout(std::chrono::seconds timeout) {
    connect_timeout_ = timeout;
}

void HttpClient::set_ssl_verify(bool verify) {
    verify_ssl_ = verify;
}

void HttpClient::set_user_agent(const std::string& user_agent) {
    user_agent_ = user_agent;
}

void HttpClient::set_proxy(const std::string& proxy) {
    proxy_ = proxy;
}

void HttpClient::set_header(const std::string& name, const std::string& value) {
    default_headers_.push_back(name + ": " + value);
}

void HttpClient::clear_headers() {
    default_headers_.clear();
}

curl_slist* HttpClient::build_headers(const std::vector<std::string>& extra) const {
    curl_slist* list = nullptr;
    for (const auto& header : default_headers_)
        list = curl_slist_append(list, header.c_str());
    for (const auto& header : extra)
        list = curl_slist_append(list, header.c_str());
    return list;
}

void HttpClient::apply_common_options(CURL* handle, const std::string& url) {
    curl_easy_reset(handle);
    curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, static_cast<long>(timeout_.count()));
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT,
                     static_cast<long>(connect_timeout_.count()));
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, verify_ssl_ ? 1L : 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, verify_ssl_ ? 2L : 0L);
    curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    if (!user_agent_.empty())
        curl_easy_setopt(handle, CURLOPT_USERAGENT, user_agent_.c_str());
    if (!proxy_.empty()) {
        curl_easy_setopt(handle, CURLOPT_PROXY, proxy_.c_str());
        curl_easy_setopt(handle, CURLOPT_HTTPPROXYTUNNEL, 1L);
    }
}

HttpResponse HttpClient::perform(CURL* handle, curl_slist* headers, curl_mime* mime) {
    HttpResponse resp;

    if (headers != nullptr)
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    if (mime != nullptr)
        curl_easy_setopt(handle, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &resp.body);

    const CURLcode rc = curl_easy_perform(handle);
    if (headers != nullptr)
        curl_slist_free_all(headers);
    if (mime != nullptr)
        curl_mime_free(mime);

    if (rc != CURLE_OK) {
        resp.status = 0;
        resp.error = curl_easy_strerror(rc);
        throw NetworkError("network error: " + resp.error);
    }

    long status = 0;
    curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);
    resp.status = status;
    return resp;
}

HttpResponse HttpClient::get(const std::string& url,
                             const std::vector<std::string>& headers) {
    CURL* handle = static_cast<CURL*>(curl_);
    apply_common_options(handle, url);
    return perform(handle, build_headers(headers), nullptr);
}

HttpResponse HttpClient::post(const std::string& url, const std::string& body,
                              const std::string& content_type) {
    CURL* handle = static_cast<CURL*>(curl_);
    apply_common_options(handle, url);
    curl_easy_setopt(handle, CURLOPT_POST, 1L);
    if (body.empty()) {
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, 0L);
    } else {
        post_buffer_ = body; // buffer must outlive curl_easy_perform
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, post_buffer_.data());
        curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE,
                         static_cast<curl_off_t>(post_buffer_.size()));
    }
    curl_slist* headers = build_headers({});
    headers = curl_slist_append(headers, ("Content-Type: " + content_type).c_str());
    return perform(handle, headers, nullptr);
}

HttpResponse HttpClient::post_multipart(
    const std::string& url, const std::map<std::string, std::string>& fields,
    const std::vector<MultipartFile>& files) {
    CURL* handle = static_cast<CURL*>(curl_);
    apply_common_options(handle, url);

    curl_mime* mime = curl_mime_init(handle);
    for (const auto& field : fields) {
        curl_mimepart* part = curl_mime_addpart(mime);
        curl_mime_name(part, field.first.c_str());
        curl_mime_data(part, field.second.c_str(), CURL_ZERO_TERMINATED);
    }
    for (const auto& file : files) {
        curl_mimepart* part = curl_mime_addpart(mime);
        curl_mime_name(part, file.field.c_str());
        curl_mime_filename(part, file.filename.c_str());
        curl_mime_type(part, "application/octet-stream");
        curl_mime_data(part, reinterpret_cast<const char*>(file.data.data()),
                       file.data.size());
    }

    curl_slist* headers = build_headers({});
    return perform(handle, headers, mime);
}

} // namespace detail
} // namespace vtapi