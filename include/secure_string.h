// Cross-platform secure-buffer wrapper for password / key material.
//
// Owns a heap allocation that is:
//   - Locked into RAM (best-effort) via VirtualLock on Windows or
//     sodium_mlock on Linux/macOS, so the OS can't page it to swap.
//   - Zeroed on destruction via sodium_memzero, which the optimiser
//     is forbidden from eliding (unlike memset).
//
// Move-only: copying defeats the point. If you need the bytes, ask
// for them explicitly via data() / size() and accept that you now
// own a second buffer that you must wipe.
//
// IMPORTANT: from_qstring() does NOT modify the source QString. An
// earlier attempt to const_cast-wipe the caller's QString broke
// encrypt-then-decrypt with the same password (see commit ba38107)
// because Qt's implicit sharing meant the caller saw zeros on the
// next call. Document the residual swap exposure in SECURITY.md
// instead — it's the lesser evil.
#ifndef OPENCRYPTUI_SECURE_STRING_H
#define OPENCRYPTUI_SECURE_STRING_H

#include <QByteArray>
#include <QString>
#include <cstddef>

class SecureString {
public:
    SecureString() noexcept = default;

    // Allocate a zero-filled buffer of `size` bytes and lock it.
    explicit SecureString(std::size_t size);

    // Copy `size` bytes from `src` into a freshly allocated locked buffer.
    SecureString(const char* src, std::size_t size);

    ~SecureString() noexcept;

    // Move-only.
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    // UTF-8 copy of the QString. Does NOT modify the source.
    static SecureString from_qstring(const QString& s);

    // Returns a *copy* of the contents as a QByteArray. The caller is
    // responsible for wiping that copy after use; this method exists
    // for legacy call sites that still take QByteArray.
    QByteArray as_byte_array_copy() const;

    char*       data() noexcept       { return m_data; }
    const char* data() const noexcept { return m_data; }
    std::size_t size() const noexcept { return m_size; }
    bool        empty() const noexcept { return m_size == 0; }

    // C-string view. Buffer is *not* null-terminated; only use this
    // with APIs that take an explicit length.
    const char* c_str() const noexcept { return m_data; }

private:
    void release() noexcept;        // zero + unlock + free, then null out
    char*       m_data = nullptr;
    std::size_t m_size = 0;
};

#endif // OPENCRYPTUI_SECURE_STRING_H
