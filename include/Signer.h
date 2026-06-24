#pragma once
#include "KeyManager.h"
#include "SecureMemory.h"
#include <string>

/**
 * Signer — создание цифровой подписи файла.
 * Использует SHA-256 + RSA (через EVP_DigestSign API OpenSSL).
 * Подпись сохраняется в бинарный .sig файл.
 */
class Signer {
public:
    explicit Signer(KeyManager& keyManager);

    /**
     * Подписывает файл filePath приватным ключом из privateKeyPath.
     * Результат записывается в sigPath.
     * @return true при успехе
     */
    bool signFile(const std::string& filePath,
                  const std::string& privateKeyPath,
                  const std::string& sigPath,
                  const std::string& passphrase = "");

    std::string lastError() const { return lastError_; }

private:
    KeyManager& keyManager_;
    std::string lastError_;

    bool readFile(const std::string& path, SecureBuffer& buffer);
};
