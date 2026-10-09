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

// Base64url encoding (RFC 4648) without '=' padding: used by the v3 API to
// address URL objects (GET /urls/{id} where id = base64url(url)). The same
// convention applies to ip_addresses and domains — but those IDs are
// normally supplied already-encoded by the caller, so the URL case is the
// one the client must construct here. Alphabet index 62/63 map to '-'/'_'
// instead of '+'/'/'.
inline std::string base64url_encode(const std::string& value) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve((value.size() + 2) / 3 * 4);

    std::size_t i = 0;
    for (; i + 3 <= value.size(); i += 3) {
        const std::uint32_t n =
            (static_cast<unsigned char>(value[i]) << 16) |
            (static_cast<unsigned char>(value[i + 1]) << 8) |
            (static_cast<unsigned char>(value[i + 2]));
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kAlphabet[(n >> 6) & 0x3F]);
        out.push_back(kAlphabet[n & 0x3F]);
    }

    // Tail: emit only the groups fully determined by remaining bytes; no '='
    // padding is emitted because base64url is unpadded by definition.
    const std::size_t rest = value.size() - i;
    if (rest == 1) {
        const std::uint32_t n = static_cast<unsigned char>(value[i]);
        out.push_back(kAlphabet[(n >> 2) & 0x3F]);
        out.push_back(kAlphabet[(n << 4) & 0x3F]);
    } else if (rest == 2) {
        const std::uint32_t n =
            (static_cast<unsigned char>(value[i]) << 16) |
            (static_cast<unsigned char>(value[i + 1]) << 8);
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kAlphabet[(n >> 6) & 0x3F]);
    }
    return out;
}

} // namespace detail
} // namespace vtapi