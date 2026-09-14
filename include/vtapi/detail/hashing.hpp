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

} // namespace detail
} // namespace vtapi