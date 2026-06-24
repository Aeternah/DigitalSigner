#pragma once
#include <string>

/**
 * HashUtils — утилиты хеширования файлов через OpenSSL EVP.
 * Используется для отдельного вычисления и отображения SHA-256.
 */
class HashUtils {
public:
    /**
     * Вычисляет SHA-256 хеш файла.
     * @return hex-строка вида "a1b2c3..." или пустая строка при ошибке.
     */
    static std::string sha256File(const std::string& filePath);

    /**
     * Вычисляет SHA-256 хеш произвольного буфера байт.
     */
    static std::string sha256Bytes(const unsigned char* data, size_t len);

    /**
     * Возвращает размер файла в байтах, -1 при ошибке.
     */
    static long fileSize(const std::string& filePath);

    static std::string lastError;
};
