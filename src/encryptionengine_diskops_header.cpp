// On-disk encryption-header I/O for DiskOperations.
// Extracted from encryptionengine_diskops.cpp so the info/discovery path
// (getAvailableDisks, formatDiskSize, sector math, …) stays focused and
// doesn't carry the header-format churn. No behaviour change.
#include "encryptionengine_diskops.h"
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

// Magic strings used by the on-disk header. Kept identical to the pre-split
// values so already-encrypted volumes remain readable.
#define DISK_HEADER_MAGIC    "OPENCRYPT_DISK_V2"
#define DISK_HEADER_MAGIC_V1 "OPENCRYPT_DISK_V1"

namespace DiskOperations {

bool createEncryptionHeader(const QString& diskPath, const QString& algorithm, 
                           const QString& kdf, int iterations, bool useHMAC,
                           const QByteArray& salt, const QByteArray& iv,
                           bool hasHiddenVolume) {
    // Prepare the header data as JSON
    QJsonObject headerObj;
    headerObj["magic"] = DISK_HEADER_MAGIC;
    headerObj["algorithm"] = algorithm;
    headerObj["kdf"] = kdf;
    headerObj["iterations"] = iterations;
    headerObj["hmac"] = useHMAC;
    headerObj["salt"] = QString(salt.toBase64());
    headerObj["iv"] = QString(iv.toBase64());
    headerObj["version"] = DISK_HEADER_VERSION;
    headerObj["hasHiddenVolume"] = hasHiddenVolume;
    
    QJsonDocument headerDoc(headerObj);
    QByteArray headerData = headerDoc.toJson();
    
    // Pad the header to 4KB
    headerData.append(QByteArray(DISK_HEADER_SIZE - headerData.size(), 0));
    
    // Write the header to the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to open disk for writing header: %1").arg(diskPath));
        return false;
    }
    
    // Write the header at the beginning of the disk
    qint64 bytesWritten = diskFile.write(headerData);
    diskFile.flush(); // Ensure data is written to disk
    diskFile.close();
    
    if (bytesWritten != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to write complete header to disk: %1").arg(diskPath));
        return false;
    }
    
    return true;
}

bool readEncryptionHeader(const QString& diskPath, QString& algorithm, 
                         QString& kdf, int& iterations, bool& useHMAC,
                         QByteArray& salt, QByteArray& iv,
                         bool& hasHiddenVolume) {
    // Read the header from the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to open disk for reading header: %1").arg(diskPath));
        return false;
    }
    
    // Read the first 4KB for the header
    QByteArray headerData = diskFile.read(DISK_HEADER_SIZE);
    diskFile.close();
    
    if (headerData.size() != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to read complete header from disk: %1").arg(diskPath));
        return false;
    }
    
    // Parse the JSON header
    QJsonDocument headerDoc = QJsonDocument::fromJson(headerData);
    if (headerDoc.isNull() || !headerDoc.isObject()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid header format on disk: %1").arg(diskPath));
        return false;
    }
    
    QJsonObject headerObj = headerDoc.object();
    
    // Verify the magic string (support both formats for backward compatibility)
    QString magic = headerObj["magic"].toString();
    if (magic != DISK_HEADER_MAGIC && magic != DISK_HEADER_MAGIC_V1) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid magic number in header on disk: %1").arg(diskPath));
        return false;
    }
    
    // Extract the encryption parameters
    algorithm = headerObj["algorithm"].toString();
    kdf = headerObj["kdf"].toString();
    iterations = headerObj["iterations"].toInt();
    useHMAC = headerObj["hmac"].toBool();
    salt = QByteArray::fromBase64(headerObj["salt"].toString().toLatin1());
    iv = QByteArray::fromBase64(headerObj["iv"].toString().toLatin1());
    
    // Check for hidden volume (only in V2 format)
    hasHiddenVolume = false;
    if (magic == DISK_HEADER_MAGIC) {
        int version = headerObj["version"].toInt();
        if (version >= DISK_HEADER_VERSION) {
            hasHiddenVolume = headerObj["hasHiddenVolume"].toBool();
        }
    }
    
    return true;
}

bool createHiddenVolume(const QString& diskPath, qint64 hiddenVolumeSize,
                      const QString& algorithm, const QString& kdf,
                      int iterations, bool useHMAC,
                      const QByteArray& salt, const QByteArray& iv) {
    
    // First verify the disk is already encrypted with a main volume
    bool hasHiddenVol = false;
    QString mainAlgorithm, mainKdf;
    int mainIterations;
    bool mainUseHMAC;
    QByteArray mainSalt, mainIv;
    
    if (!readEncryptionHeader(diskPath, mainAlgorithm, mainKdf, mainIterations, 
                             mainUseHMAC, mainSalt, mainIv, hasHiddenVol)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to read main volume header: %1").arg(diskPath));
        return false;
    }
    
    // Make sure we don't already have a hidden volume
    if (hasHiddenVol) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Disk already has a hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Calculate the offset for the hidden volume (after the standard header)
    qint64 hiddenVolumeOffset = DISK_HIDDEN_HEADER_OFFSET;
    
    // Prepare the hidden volume header as JSON
    QJsonObject hiddenHeaderObj;
    hiddenHeaderObj["magic"] = DISK_HEADER_MAGIC;
    hiddenHeaderObj["type"] = "hidden";
    hiddenHeaderObj["algorithm"] = algorithm;
    hiddenHeaderObj["kdf"] = kdf;
    hiddenHeaderObj["iterations"] = iterations;
    hiddenHeaderObj["hmac"] = useHMAC;
    hiddenHeaderObj["salt"] = QString(salt.toBase64());
    hiddenHeaderObj["iv"] = QString(iv.toBase64());
    hiddenHeaderObj["offset"] = hiddenVolumeOffset + DISK_HEADER_SIZE;  // Start of actual hidden data
    hiddenHeaderObj["size"] = hiddenVolumeSize;
    hiddenHeaderObj["version"] = DISK_HEADER_VERSION;
    
    QJsonDocument hiddenHeaderDoc(hiddenHeaderObj);
    QByteArray hiddenHeaderData = hiddenHeaderDoc.toJson();
    
    // Pad the header to 4KB
    hiddenHeaderData.append(QByteArray(DISK_HEADER_SIZE - hiddenHeaderData.size(), 0));
    
    // Open the disk file for writing
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to open disk for writing hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Seek to the hidden volume header position
    if (!diskFile.seek(hiddenVolumeOffset)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to seek to hidden volume position: %1").arg(diskPath));
        diskFile.close();
        return false;
    }
    
    // Write the hidden volume header
    qint64 bytesWritten = diskFile.write(hiddenHeaderData);
    
    // Update main volume header to indicate it has a hidden volume
    diskFile.seek(0);
    
    // Read the main header
    QByteArray mainHeaderData = diskFile.read(DISK_HEADER_SIZE);
    QJsonDocument mainHeaderDoc = QJsonDocument::fromJson(mainHeaderData);
    QJsonObject mainHeaderObj = mainHeaderDoc.object();
    
    // Update the main header
    mainHeaderObj["hasHiddenVolume"] = true;
    mainHeaderObj["version"] = DISK_HEADER_VERSION;
    mainHeaderObj["magic"] = DISK_HEADER_MAGIC;
    
    // Write back the updated main header
    QJsonDocument updatedMainDoc(mainHeaderObj);
    QByteArray updatedMainData = updatedMainDoc.toJson();
    updatedMainData.append(QByteArray(DISK_HEADER_SIZE - updatedMainData.size(), 0));
    
    diskFile.seek(0);
    diskFile.write(updatedMainData);
    
    diskFile.close();
    
    if (bytesWritten != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to write complete hidden volume header: %1").arg(diskPath));
        return false;
    }
    
    return true;
}

bool readHiddenVolumeHeader(const QString& diskPath, HiddenVolumeInfo& hiddenInfo) {
    // Read the header from the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to open disk for reading hidden header: %1").arg(diskPath));
        return false;
    }
    
    // First check if the main volume has a hidden volume
    diskFile.seek(0);
    QByteArray mainHeaderData = diskFile.read(DISK_HEADER_SIZE);
    QJsonDocument mainHeaderDoc = QJsonDocument::fromJson(mainHeaderData);
    
    if (mainHeaderDoc.isNull() || !mainHeaderDoc.isObject()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid main header format on disk: %1").arg(diskPath));
        diskFile.close();
        return false;
    }
    
    QJsonObject mainHeaderObj = mainHeaderDoc.object();
    
    // Check if this volume has a hidden volume
    if (!mainHeaderObj.contains("hasHiddenVolume") || !mainHeaderObj["hasHiddenVolume"].toBool()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("No hidden volume on disk: %1").arg(diskPath));
        diskFile.close();
        return false;
    }
    
    // Seek to the hidden volume header
    diskFile.seek(DISK_HIDDEN_HEADER_OFFSET);
    
    // Read the hidden volume header
    QByteArray hiddenHeaderData = diskFile.read(DISK_HEADER_SIZE);
    diskFile.close();
    
    if (hiddenHeaderData.size() != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to read complete hidden header from disk: %1").arg(diskPath));
        return false;
    }
    
    // Parse the JSON header
    QJsonDocument hiddenHeaderDoc = QJsonDocument::fromJson(hiddenHeaderData);
    if (hiddenHeaderDoc.isNull() || !hiddenHeaderDoc.isObject()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid hidden header format on disk: %1").arg(diskPath));
        return false;
    }
    
    QJsonObject hiddenHeaderObj = hiddenHeaderDoc.object();
    
    // Verify the magic string and type
    if (hiddenHeaderObj["magic"].toString() != DISK_HEADER_MAGIC || 
        hiddenHeaderObj["type"].toString() != "hidden") {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid hidden volume header: %1").arg(diskPath));
        return false;
    }
    
    // Extract the hidden volume information
    hiddenInfo.offset = hiddenHeaderObj["offset"].toVariant().toLongLong();
    hiddenInfo.size = hiddenHeaderObj["size"].toVariant().toLongLong();
    hiddenInfo.algorithm = hiddenHeaderObj["algorithm"].toString();
    hiddenInfo.kdf = hiddenHeaderObj["kdf"].toString();
    hiddenInfo.iterations = hiddenHeaderObj["iterations"].toInt();
    hiddenInfo.useHMAC = hiddenHeaderObj["hmac"].toBool();
    hiddenInfo.salt = QByteArray::fromBase64(hiddenHeaderObj["salt"].toString().toLatin1());
    hiddenInfo.iv = QByteArray::fromBase64(hiddenHeaderObj["iv"].toString().toLatin1());
    
    return true;
}

bool hasHiddenVolume(const QString& diskPath) {
    // Read the header from the disk/volume
    QFile diskFile(diskPath);
    if (!diskFile.open(QIODevice::ReadOnly)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to open disk for checking hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Read the first 4KB for the header
    QByteArray headerData = diskFile.read(DISK_HEADER_SIZE);
    diskFile.close();
    
    if (headerData.size() != DISK_HEADER_SIZE) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Failed to read complete header for checking hidden volume: %1").arg(diskPath));
        return false;
    }
    
    // Parse the JSON header
    QJsonDocument headerDoc = QJsonDocument::fromJson(headerData);
    if (headerDoc.isNull() || !headerDoc.isObject()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid header format for checking hidden volume: %1").arg(diskPath));
        return false;
    }
    
    QJsonObject headerObj = headerDoc.object();
    
    // Check if this volume has a hidden volume
    if (headerObj.contains("hasHiddenVolume") && headerObj["hasHiddenVolume"].toBool()) {
        return true;
    }
    
    return false;
}

} // namespace DiskOperations
