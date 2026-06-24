#include "KeyManager.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <fstream>
#include <sstream>

KeyManager::KeyManager() {
    // Инициализация таблицы ошибок OpenSSL (для читаемых сообщений)
    ERR_load_crypto_strings();
}

KeyManager::~KeyManager() {
    ERR_free_strings();
}

void KeyManager::setOpenSSLError(const std::string& context) {
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    lastError_ = context + ": " + std::string(buf);
}

bool KeyManager::generateRSAKeyPair(const std::string& privateKeyPath,
                                     const std::string& publicKeyPath,
                                     KeySize size,
                                     const std::string& passphrase) {
    // Генерируем контекст EVP
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        setOpenSSLError("EVP_PKEY_CTX_new_id");
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        setOpenSSLError("EVP_PKEY_keygen_init");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(size)) <= 0) {
        setOpenSSLError("EVP_PKEY_CTX_set_rsa_keygen_bits");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        setOpenSSLError("EVP_PKEY_keygen");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // Записываем приватный ключ
    {
        FILE* f = fopen(privateKeyPath.c_str(), "wb");
        if (!f) {
            lastError_ = "Не удалось открыть файл для записи: " + privateKeyPath;
            EVP_PKEY_free(pkey);
            return false;
        }

        int ret;
        if (!passphrase.empty()) {
            ret = PEM_write_PrivateKey(f, pkey,
                                       EVP_aes_256_cbc(),
                                       reinterpret_cast<const unsigned char*>(passphrase.c_str()),
                                       static_cast<int>(passphrase.size()),
                                       nullptr, nullptr);
        } else {
            ret = PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        }
        fclose(f);

        if (!ret) {
            setOpenSSLError("PEM_write_PrivateKey");
            EVP_PKEY_free(pkey);
            return false;
        }
    }

    // Записываем публичный ключ
    {
        FILE* f = fopen(publicKeyPath.c_str(), "wb");
        if (!f) {
            lastError_ = "Не удалось открыть файл для записи: " + publicKeyPath;
            EVP_PKEY_free(pkey);
            return false;
        }
        int ret = PEM_write_PUBKEY(f, pkey);
        fclose(f);

        if (!ret) {
            setOpenSSLError("PEM_write_PUBKEY");
            EVP_PKEY_free(pkey);
            return false;
        }
    }

    EVP_PKEY_free(pkey);
    return true;
}

EVP_PKEY* KeyManager::loadPrivateKey(const std::string& path,
                                      const std::string& passphrase) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        lastError_ = "Файл не найден: " + path;
        return nullptr;
    }

    EVP_PKEY* key = nullptr;
    if (!passphrase.empty()) {
        // Передаём пароль напрямую
        key = PEM_read_PrivateKey(f, nullptr, nullptr,
                                   const_cast<char*>(passphrase.c_str()));
    } else {
        key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    }
    fclose(f);

    if (!key) {
        setOpenSSLError("PEM_read_PrivateKey");
    }
    return key;
}

EVP_PKEY* KeyManager::loadPublicKey(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        lastError_ = "Файл не найден: " + path;
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!key) {
        setOpenSSLError("PEM_read_PUBKEY");
    }
    return key;
}

void KeyManager::wipeKey(EVP_PKEY*& key) {
    if (key) {
        EVP_PKEY_free(key);
        key = nullptr;
    }
}
