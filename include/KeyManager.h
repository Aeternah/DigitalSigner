#pragma once
#include "SecureMemory.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <string>
#include <memory>

/**
 * KeyManager — управление RSA ключевыми парами.
 * Поддерживает генерацию ключей разной длины,
 * загрузку из PEM-файлов и безопасное удаление из памяти.
 */
class KeyManager {
public:
    enum class KeySize {
        RSA_2048 = 2048,
        RSA_3072 = 3072,
        RSA_4096 = 4096
    };

    KeyManager();
    ~KeyManager();

    /**
     * Генерирует пару RSA ключей заданного размера.
     * Сохраняет приватный ключ в privateKeyPath, публичный — в publicKeyPath.
     * @return true при успехе, false при ошибке
     */
    bool generateRSAKeyPair(const std::string& privateKeyPath,
                            const std::string& publicKeyPath,
                            KeySize size = KeySize::RSA_2048,
                            const std::string& passphrase = "");

    /**
     * Загружает приватный ключ из PEM-файла.
     * Пароль передаётся через SecureBuffer.
     */
    EVP_PKEY* loadPrivateKey(const std::string& path,
                             const std::string& passphrase = "");

    /**
     * Загружает публичный ключ из PEM-файла.
     */
    EVP_PKEY* loadPublicKey(const std::string& path);

    /**
     * Безопасно освобождает ключ из памяти (обнуляет и освобождает).
     */
    void wipeKey(EVP_PKEY*& key);

    /**
     * Возвращает последнее сообщение об ошибке.
     */
    std::string lastError() const { return lastError_; }

private:
    std::string lastError_;
    void setOpenSSLError(const std::string& context);
};
