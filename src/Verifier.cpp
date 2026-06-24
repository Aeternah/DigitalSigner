#include "Verifier.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>

Verifier::Verifier(KeyManager& keyManager) : keyManager_(keyManager) {}

bool Verifier::readFile(const std::string& path, SecureBuffer& buffer) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        lastError_ = "Не удалось открыть файл: " + path;
        return false;
    }
    std::streamsize size = f.tellg();
    if (size < 0) {
        lastError_ = "Ошибка чтения размера файла";
        return false;
    }
    f.seekg(0, std::ios::beg);
    buffer.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buffer.data()), size)) {
        lastError_ = "Ошибка чтения содержимого файла";
        return false;
    }
    return true;
}

bool Verifier::verifyFile(const std::string& filePath,
                          const std::string& sigPath,
                          const std::string& publicKeyPath) {
    // 1. Загружаем публичный ключ
    EVP_PKEY* pubKey = keyManager_.loadPublicKey(publicKeyPath);
    if (!pubKey) {
        lastError_ = "Ошибка загрузки публичного ключа: " + keyManager_.lastError();
        return false;
    }

    // 2. Читаем исходный файл
    SecureBuffer fileData(0);
    if (!readFile(filePath, fileData)) {
        keyManager_.wipeKey(pubKey);
        return false;
    }

    // 3. Читаем файл подписи
    SecureBuffer sigData(0);
    if (!readFile(sigPath, sigData)) {
        keyManager_.wipeKey(pubKey);
        return false;
    }

    // 4. Проверяем подпись (SHA-256 + RSA)
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        lastError_ = "EVP_MD_CTX_new: нехватка памяти";
        keyManager_.wipeKey(pubKey);
        return false;
    }

    if (EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sha256(), nullptr, pubKey) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestVerifyInit: ") + buf;
        EVP_MD_CTX_free(mdCtx);
        keyManager_.wipeKey(pubKey);
        return false;
    }

    if (EVP_DigestVerifyUpdate(mdCtx, fileData.data(), fileData.size()) <= 0) {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestVerifyUpdate: ") + buf;
        EVP_MD_CTX_free(mdCtx);
        keyManager_.wipeKey(pubKey);
        return false;
    }

    int result = EVP_DigestVerifyFinal(mdCtx, sigData.data(), sigData.size());

    EVP_MD_CTX_free(mdCtx);
    keyManager_.wipeKey(pubKey);

    if (result == 1) {
        return true;
    } else if (result == 0) {
        lastError_ = "Подпись недействительна: файл был изменён или ключ не совпадает";
        return false;
    } else {
        unsigned long err = ERR_get_error();
        char buf[256]; ERR_error_string_n(err, buf, sizeof(buf));
        lastError_ = std::string("EVP_DigestVerifyFinal: ") + buf;
        return false;
    }
}
