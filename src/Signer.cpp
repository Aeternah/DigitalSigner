#include "Signer.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>

Signer::Signer(KeyManager& keyManager) : keyManager_(keyManager) {}

bool Signer::readFile(const std::string& path, SecureBuffer& buffer) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        lastError_ = "Не удалось открыть файл: " + path;
        return false;
    }
    std::streamsize size = f.tellg();
    if (size < 0) {
        lastError_ = "Ошибка чтения размера файла: " + path;
        return false;
    }
    f.seekg(0, std::ios::beg);
    buffer.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buffer.data()), size)) {
        lastError_ = "Ошибка чтения файла: " + path;
        return false;
    }
    return true;
}

bool Signer::signFile(const std::string& filePath,
                      const std::string& privateKeyPath,
                      const std::string& sigPath,
                      const std::string& passphrase) {
    // 1. Загружаем приватный ключ
    EVP_PKEY* privKey = keyManager_.loadPrivateKey(privateKeyPath, passphrase);
    if (!privKey) {
        lastError_ = "Ошибка загрузки приватного ключа: " + keyManager_.lastError();
        return false;
    }

    // 2. Читаем файл в SecureBuffer
    SecureBuffer fileData(0);
    if (!readFile(filePath, fileData)) {
        keyManager_.wipeKey(privKey);
        return false;
    }

    // 3. Создаём контекст подписи (SHA-256 + RSA)
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        lastError_ = "EVP_MD_CTX_new: нехватка памяти";
        keyManager_.wipeKey(privKey);
        return false;
    }

    if (EVP_DigestSignInit(mdCtx, nullptr, EVP_sha256(), nullptr, privKey) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestSignInit: ") + buf;
        EVP_MD_CTX_free(mdCtx);
        keyManager_.wipeKey(privKey);
        return false;
    }

    if (EVP_DigestSignUpdate(mdCtx, fileData.data(), fileData.size()) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestSignUpdate: ") + buf;
        EVP_MD_CTX_free(mdCtx);
        keyManager_.wipeKey(privKey);
        return false;
    }

    // 4. Определяем размер подписи
    size_t sigLen = 0;
    if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestSignFinal (size): ") + buf;
        EVP_MD_CTX_free(mdCtx);
        keyManager_.wipeKey(privKey);
        return false;
    }

    SecureBuffer sig(sigLen);
    if (EVP_DigestSignFinal(mdCtx, sig.data(), &sigLen) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestSignFinal: ") + buf;
        EVP_MD_CTX_free(mdCtx);
        keyManager_.wipeKey(privKey);
        return false;
    }

    EVP_MD_CTX_free(mdCtx);
    keyManager_.wipeKey(privKey);

    // 5. Записываем подпись
    std::ofstream out(sigPath, std::ios::binary);
    if (!out.is_open()) {
        lastError_ = "Не удалось создать файл подписи: " + sigPath;
        return false;
    }
    out.write(reinterpret_cast<const char*>(sig.data()), static_cast<std::streamsize>(sigLen));
    if (!out) {
        lastError_ = "Ошибка записи файла подписи";
        return false;
    }

    return true;
}
