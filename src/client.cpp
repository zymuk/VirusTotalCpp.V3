#include "vtapi/client.hpp"

#include "vtapi/detail/response.hpp"
#include "vtapi/types.hpp"
#include "vtapi/version.hpp"

namespace {

bool is_hex_hash(const std::string& value) {
    if (value.size() != 32 && value.size() != 40 && value.size() != 64)
        return false;
    for (const char c : value) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        const bool upper = c >= 'A' && c <= 'F';
        if (!digit && !lower && !upper)
            return false;
    }
    return true;
}

} // namespace

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

} // namespace vtapi