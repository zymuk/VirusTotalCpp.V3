#include "vtapi/detail/hashing.hpp"

#include <openssl/evp.h>

#include <stdexcept>

namespace vtapi {
namespace detail {

namespace {

std::string hex_hash(const unsigned char* data, std::size_t len, const EVP_MD* algo) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr)
        throw std::runtime_error("hashing: EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx, algo, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("hashing: EVP digest failed");
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(digest_len) * 2);
    for (unsigned int i = 0; i < digest_len; ++i) {
        out.push_back(kHex[digest[i] >> 4]);
        out.push_back(kHex[digest[i] & 0x0F]);
    }
    return out;
}

} // namespace

std::string sha256_hex(const unsigned char* data, std::size_t len) {
    return hex_hash(data, len, EVP_sha256());
}

std::string sha1_hex(const unsigned char* data, std::size_t len) {
    return hex_hash(data, len, EVP_sha1());
}

std::string md5_hex(const unsigned char* data, std::size_t len) {
    return hex_hash(data, len, EVP_md5());
}

std::string sha256_hex(const std::string& data) {
    return hex_hash(reinterpret_cast<const unsigned char*>(data.data()), data.size(), EVP_sha256());
}

std::string sha1_hex(const std::string& data) {
    return hex_hash(reinterpret_cast<const unsigned char*>(data.data()), data.size(), EVP_sha1());
}

std::string md5_hex(const std::string& data) {
    return hex_hash(reinterpret_cast<const unsigned char*>(data.data()), data.size(), EVP_md5());
}

} // namespace detail
} // namespace vtapi