// pq_hybrid_stub.cpp — Always-compiled stub for PqHybrid when liboqs is absent.
//
// When OCUI_HAVE_LIBOQS is defined, pq_hybrid.cpp provides the real
// implementations and this file must NOT be compiled (otherwise the linker will
// complain about duplicate symbol definitions).  The CMake orchestrator is
// responsible for compiling exactly one of these two TUs per target.
//
// This stub allows the rest of the engine (and the full test suite) to build
// and link without liboqs installed, which is the default developer experience.

#ifndef OCUI_HAVE_LIBOQS

#include "pq_hybrid.h"
#include <QDebug>

namespace PqHybrid {

bool isAvailable()
{
    return false;
}

KeyPair generateKeyPair()
{
    qWarning() << "PqHybrid: PQ hybrid encryption is disabled in this build "
                  "(liboqs not found at configure time). "
                  "See docs/PQ_README.md for installation instructions.";
    return KeyPair{};
}

HybridWrappedKey wrap(const QByteArray& /*dek*/,
                      const QByteArray& /*classicalPublic*/,
                      const QByteArray& /*pqPublic*/)
{
    qWarning() << "PqHybrid::wrap: PQ disabled in this build — returning empty blob. "
                  "See docs/PQ_README.md.";
    return HybridWrappedKey{};
}

QByteArray unwrap(const HybridWrappedKey& /*blob*/,
                  const QByteArray& /*classicalSecret*/,
                  const QByteArray& /*pqSecret*/,
                  QString* errorOut)
{
    const char* msg = "PqHybrid::unwrap: PQ disabled in this build — cannot unwrap. "
                      "See docs/PQ_README.md.";
    qWarning() << msg;
    if (errorOut)
        *errorOut = QString::fromLatin1(msg);
    return QByteArray{};
}

} // namespace PqHybrid

#endif // !OCUI_HAVE_LIBOQS
