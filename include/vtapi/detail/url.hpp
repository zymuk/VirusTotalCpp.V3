#pragma once

#include <string>

namespace vtapi {
namespace detail {

// Percent-encodes a string for use as a URL path segment. Keeps the RFC 3986
// unreserved characters; everything else becomes %XX. Sandbox report ids such
// as "<sha256>_VirusTotal Jujubox" contain spaces, which are not valid in a
// request target, so any behaviour id is encoded before it hits the path.
inline std::string percent_encode(const std::string& value) {
    static const char* kHexDigits = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
            c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHexDigits[c >> 4]);
            out.push_back(kHexDigits[c & 0x0F]);
        }
    }
    return out;
}

} // namespace detail
} // namespace vtapi