#include "secure_string.h"
#include <sodium.h>
#include <cstdlib>
#include <cstring>
#include <utility>

#ifdef Q_OS_WIN
#  include <windows.h>
#endif

static void* secure_alloc(std::size_t n)
{
    if (n == 0) return nullptr;
    // calloc gives us zeroed memory; we'll usually overwrite immediately
    // but a zeroed initial state keeps SecureString(size_t) sensible.
    return std::calloc(1, n);
}

static void try_lock(void* p, std::size_t n) noexcept
{
    if (!p || n == 0) return;
#ifdef Q_OS_WIN
    // VirtualLock can only lock pages, not arbitrary byte ranges; the
    // kernel rounds up. Best-effort — if the per-process lock quota is
    // exhausted, we don't fail the call site.
    (void)VirtualLock(p, n);
#else
    (void)sodium_mlock(p, n);
#endif
}

static void try_unlock(void* p, std::size_t n) noexcept
{
    if (!p || n == 0) return;
#ifdef Q_OS_WIN
    (void)VirtualUnlock(p, n);
#else
    // sodium_munlock zeroizes before unlocking, which is what we want.
    (void)sodium_munlock(p, n);
#endif
}

SecureString::SecureString(std::size_t size)
    : m_data(static_cast<char*>(secure_alloc(size))), m_size(m_data ? size : 0)
{
    try_lock(m_data, m_size);
}

SecureString::SecureString(const char* src, std::size_t size)
    : SecureString(size)
{
    if (m_data && src && size > 0) {
        std::memcpy(m_data, src, size);
    }
}

SecureString::~SecureString() noexcept
{
    release();
}

SecureString::SecureString(SecureString&& other) noexcept
    : m_data(other.m_data), m_size(other.m_size)
{
    other.m_data = nullptr;
    other.m_size = 0;
}

SecureString& SecureString::operator=(SecureString&& other) noexcept
{
    if (this != &other) {
        release();
        m_data = other.m_data;
        m_size = other.m_size;
        other.m_data = nullptr;
        other.m_size = 0;
    }
    return *this;
}

void SecureString::release() noexcept
{
    if (!m_data) return;
    // sodium_memzero on Linux/macOS, manual zero on Windows (sodium handles it
    // via libsodium even on Windows; we use it everywhere for simplicity).
    sodium_memzero(m_data, m_size);
    try_unlock(m_data, m_size);
    std::free(m_data);
    m_data = nullptr;
    m_size = 0;
}

/*static*/ SecureString SecureString::from_qstring(const QString& s)
{
    // toUtf8() returns a fresh QByteArray; we copy out of it then wipe it.
    // We deliberately do NOT touch the source QString.
    QByteArray utf8 = s.toUtf8();
    SecureString out(utf8.constData(), static_cast<std::size_t>(utf8.size()));
    sodium_memzero(utf8.data(), static_cast<std::size_t>(utf8.size()));
    return out;
}

QByteArray SecureString::as_byte_array_copy() const
{
    if (m_size == 0) return QByteArray();
    return QByteArray(m_data, static_cast<int>(m_size));
}
