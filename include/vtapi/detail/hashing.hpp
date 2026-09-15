#pragma once

#include <cstddef>
#include <string>

namespace vtapi {
namespace detail {

// Hex digests computed offline to derive the identifiers (hash) that address
// files in the v3 API. Buffer and string overloads share the same code path.

std::string sha256_hex(const unsigned char* data, std::size_t len);
std::string sha1_hex(const unsigned char* data, std::size_t len);
std::string md5_hex(const unsigned char* data, std::size_t len);

std::string sha256_hex(const std::string& data);
std::string sha1_hex(const std::string& data);
std::string md5_hex(const std::string& data);

// Reports whether value looks like a file id: 32/40/64 lowercase-or-uppercase
// hex chars (md5/sha1/sha256). Shared by every hash-validating entry point so
// the acceptance rule lives in exactly one place.
inline bool is_hex_hash(const std::string& value) {
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

} // namespace detail
} // namespace vtapi