#pragma once
#include <openssl/crypto.h>
#include <vector>
#include <cstring>

/**
 * SecureBuffer — RAII-обёртка для чувствительных данных в памяти.
 * При уничтожении объекта память обнуляется через OPENSSL_cleanse(),
 * что предотвращает утечку ключевого материала через swap/core dump.
 */
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : data_(size, 0) {}

    SecureBuffer(const unsigned char* src, size_t size) : data_(src, src + size) {}

    ~SecureBuffer() {
        wipe();
    }

    // Запрещаем копирование
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Разрешаем перемещение
    SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {
        other.data_.clear();
    }

    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    void resize(size_t newSize) { data_.resize(newSize); }

    /**
     * Безопасное обнуление — OPENSSL_cleanse гарантирует,
     * что компилятор не оптимизирует memset.
     */
    void wipe() {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
    }

private:
    std::vector<unsigned char> data_;
};
