#pragma once
#include "KeyManager.h"
#include "SecureMemory.h"
#include <string>

/**
 * Verifier — проверка цифровой подписи файла.
 * Использует EVP_DigestVerify API OpenSSL (SHA-256 + RSA).
 */
class Verifier {
public:
    explicit Verifier(KeyManager& keyManager);

    /**
     * Проверяет подпись файла filePath.
     * @param filePath   - исходный файл
     * @param sigPath    - файл подписи (.sig)
     * @param publicKeyPath - файл публичного ключа
     * @return true если подпись корректна
     */
    bool verifyFile(const std::string& filePath,
                    const std::string& sigPath,
                    const std::string& publicKeyPath);

    std::string lastError() const { return lastError_; }

private:
    KeyManager& keyManager_;
    std::string lastError_;

    bool readFile(const std::string& path, SecureBuffer& buffer);
};
