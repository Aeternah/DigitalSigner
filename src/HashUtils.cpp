#include "HashUtils.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

std::string HashUtils::lastError;

std::string HashUtils::sha256Bytes(const unsigned char* data, size_t len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { lastError = "EVP_MD_CTX_new failed"; return ""; }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) <= 0 ||
        EVP_DigestUpdate(ctx, data, len) <= 0 ||
        EVP_DigestFinal_ex(ctx, digest, &digestLen) <= 0) {
        unsigned long e = ERR_get_error();
        char buf[256]; ERR_error_string_n(e, buf, sizeof(buf));
        lastError = buf;
        EVP_MD_CTX_free(ctx);
        return "";
    }
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digestLen; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return oss.str();
}

std::string HashUtils::sha256File(const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open()) { lastError = "Cannot open: " + filePath; return ""; }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { lastError = "EVP_MD_CTX_new failed"; return ""; }

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[65536];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    EVP_DigestFinal_ex(ctx, digest, &digestLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digestLen; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return oss.str();
}

long HashUtils::fileSize(const std::string& filePath) {
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) return -1;
    return static_cast<long>(st.st_size);
}
