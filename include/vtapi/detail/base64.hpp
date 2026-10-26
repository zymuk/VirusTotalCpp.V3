#pragma once

#include <cstdint>
#include <string>

namespace vtapi {
namespace detail {

// Standard Base64 (RFC 4648, '+' and '/', padded with '='). The Code Insights
// endpoint exchanges code blocks and descriptions in this alphabet, unlike the
// unpadded base64url used for URL object ids.
inline std::string base64_encode(const std::string& value) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

    const std::size_t rest = value.size() - i;
    if (rest == 1) {
        const std::uint32_t n = static_cast<unsigned char>(value[i]) << 16;
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rest == 2) {
        const std::uint32_t n =
            (static_cast<unsigned char>(value[i]) << 16) |
            (static_cast<unsigned char>(value[i + 1]) << 8);
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kAlphabet[(n >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

inline int base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

// Decodes Base64 into `out`. Whitespace is ignored and missing trailing
// padding is accepted, so both padded and unpadded responses work; returns
// false (with `out` cleared) for characters outside the alphabet or for a
// length that leaves an impossible number of bits.
inline bool base64_decode(const std::string& value, std::string& out) {
    out.clear();
    out.reserve(value.size() / 4 * 3);

    std::uint32_t buffer = 0;
    int bits = 0;
    for (const unsigned char c : value) {
        if (c == '=')
            break;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        const int v = base64_value(c);
        if (v < 0) {
            out.clear();
            return false;
        }
        buffer = (buffer << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }

    // A single trailing sextet can never encode a byte, and the unused bits of
    // a valid final group are always zero.
    if (bits >= 6 || (bits > 0 && (buffer & ((1u << bits) - 1)) != 0)) {
        out.clear();
        return false;
    }
    return true;
}

} // namespace detail
} // namespace vtapi
