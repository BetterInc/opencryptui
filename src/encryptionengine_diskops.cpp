#include "encryptionengine_diskops.h"
#include "encryptionengine.h"
#include "logging/secure_logger.h"
#include <QFile>
#include <QDir>
#include <QStorageInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRandomGenerator>
#include <QSettings>

// Header format for the encrypted disk
#define DISK_HEADER_MAGIC "OPENCRYPT_DISK_V2"  // Updated version for hidden volume support
#define DISK_HEADER_MAGIC_V1 "OPENCRYPT_DISK_V1"  // Original version for backward compatibility

namespace DiskOperations {

DiskInfoList getAvailableDisks() {
    DiskInfoList diskList;
    
    // Get list of mounted volumes
    QList<QStorageInfo> storages = QStorageInfo::mountedVolumes();
    
#ifdef Q_OS_LINUX
    // On Linux, use lsblk to get additional disk information
    QProcess process;
    process.start("lsblk", QStringList() << "-J" << "-o" << "NAME,SIZE,TYPE,MOUNTPOINT,REMOVABLE,FSTYPE");
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    
    // Parse JSON output
    QJsonDocument doc = QJsonDocument::fromJson(output);
    if (!doc.isNull() && doc.isObject()) {
        QJsonArray devices = doc.object()["blockdevices"].toArray();
        for (const QJsonValue &device : devices) {
            QJsonObject deviceObj = device.toObject();
            
            // Skip loop devices and CD-ROMs
            QString type = deviceObj["type"].toString();
            if (type == "loop" || type == "rom")
                continue;
                
            // Get device information
            DiskInfo diskInfo;
            diskInfo.name = deviceObj["name"].toString();
            diskInfo.path = "/dev/" + diskInfo.name;
            diskInfo.type = type;
            diskInfo.size = deviceObj["size"].toString().toLongLong();
            diskInfo.isRemovable = deviceObj["rm"].toString() == "1";
            
            // Check if it's a mounted partition
            QString mountpoint = deviceObj["mountpoint"].toString();
            if (!mountpoint.isEmpty() && mountpoint != "[SWAP]") {
                diskInfo.path = mountpoint;
            }
            
            // Check if device is already encrypted (LUKS)
            QString fstype = deviceObj["fstype"].toString();
            diskInfo.isEncrypted = fstype == "crypto_LUKS";
            
            diskList.append(diskInfo);
            
            // Check for partitions
            QJsonArray children = deviceObj["children"].toArray();
            for (const QJsonValue &child : children) {
                QJsonObject childObj = child.toObject();
                
                // Skip swap partitions
                QString childType = childObj["fstype"].toString();
                if (childType == "swap")
                    continue;
                    
                DiskInfo partInfo;
                partInfo.name = childObj["name"].toString();
                partInfo.path = "/dev/" + partInfo.name;
                partInfo.type = "partition";
                partInfo.size = childObj["size"].toString().toLongLong();
                partInfo.isRemovable = diskInfo.isRemovable;
                
                // Check if it's a mounted partition
                QString childMountpoint = childObj["mountpoint"].toString();
                if (!childMountpoint.isEmpty() && childMountpoint != "[SWAP]") {
                    partInfo.path = childMountpoint;
                }
                
                // Check if partition is already encrypted (LUKS)
                QString childFstype = childObj["fstype"].toString();
                partInfo.isEncrypted = childFstype == "crypto_LUKS";
                
                diskList.append(partInfo);
            }
        }
    }
#elif defined(Q_OS_WINDOWS)
    // Windows: Use WMI to get disk info (simplified version)
    QProcess process;
    process.start("wmic", QStringList() << "diskdrive" << "get" << "DeviceID,MediaType,Size,InterfaceType" << "/format:csv");
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    
    // Simple parsing of the CSV output
    QStringList lines = QString(output).split('\n');
    if (lines.size() > 1) {  // Skip the header line
        for (int i = 1; i < lines.size(); i++) {
            QStringList fields = lines[i].split(',');
            if (fields.size() >= 4) {
                DiskInfo diskInfo;
                diskInfo.path = fields[1]; // DeviceID
                diskInfo.name = diskInfo.path.mid(diskInfo.path.lastIndexOf('\\') + 1);
                diskInfo.type = fields[2]; // MediaType
                diskInfo.size = fields[3].toLongLong(); // Size
                diskInfo.isRemovable = (fields[4] == "USB");  // InterfaceType
                diskInfo.isEncrypted = false; // Cannot easily determine this in Windows
                
                diskList.append(diskInfo);
            }
        }
    }
    
    // Get volumes information
    process.start("wmic", QStringList() << "logicaldisk" << "get" << "DeviceID,DriveType,Size,VolumeName" << "/format:csv");
    process.waitForFinished();
    output = process.readAllStandardOutput();
    
    lines = QString(output).split('\n');
    if (lines.size() > 1) {  // Skip the header line
        for (int i = 1; i < lines.size(); i++) {
            QStringList fields = lines[i].split(',');
            if (fields.size() >= 4) {
                DiskInfo diskInfo;
                diskInfo.path = fields[1]; // DeviceID
                diskInfo.name = fields[4].isEmpty() ? diskInfo.path : fields[4]; // VolumeName
                diskInfo.type = "partition";
                diskInfo.size = fields[3].toLongLong(); // Size
                
                // DriveType: 2=Removable, 3=Fixed, 4=Network, 5=Optical, 6=RAM disk
                int driveType = fields[2].toInt(); 
                diskInfo.isRemovable = (driveType == 2 || driveType == 5 || driveType == 6);
                diskInfo.isEncrypted = false; // Cannot easily determine this in Windows
                
                diskList.append(diskInfo);
            }
        }
    }
#elif defined(Q_OS_MAC)
    // macOS: Use diskutil to get disk info
    QProcess process;
    process.start("diskutil", QStringList() << "list" << "-plist");
    process.waitForFinished();
    QByteArray output = process.readAllStandardOutput();
    
    // Parse plist output using QSettings
    QTemporaryFile tempFile;
    if (tempFile.open()) {
        tempFile.write(output);
        tempFile.close();
        
        QSettings plist(tempFile.fileName(), QSettings::NativeFormat);
        int diskCount = plist.beginReadArray("AllDisksAndPartitions");
        
        for (int i = 0; i < diskCount; i++) {
            plist.setArrayIndex(i);
            
            DiskInfo diskInfo;
            diskInfo.name = plist.value("DeviceIdentifier").toString();
            diskInfo.path = "/dev/" + diskInfo.name;
            diskInfo.size = plist.value("Size").toLongLong();
            
            // Get media type
            QProcess detailProcess;
            detailProcess.start("diskutil", QStringList() << "info" << "-plist" << diskInfo.path);
            detailProcess.waitForFinished();
            
            QTemporaryFile detailTempFile;
            if (detailTempFile.open()) {
                detailTempFile.write(detailProcess.readAllStandardOutput());
                detailTempFile.close();
                
                QSettings detailPlist(detailTempFile.fileName(), QSettings::NativeFormat);
                diskInfo.type = detailPlist.value("MediaType").toString();
                diskInfo.isRemovable = detailPlist.value("Removable").toBool();
                diskInfo.isEncrypted = detailPlist.value("Encrypted").toBool();
            }
            
            diskList.append(diskInfo);
            
            // Get partitions
            int partCount = plist.beginReadArray("Partitions");
            for (int j = 0; j < partCount; j++) {
                plist.setArrayIndex(j);
                
                DiskInfo partInfo;
                partInfo.name = plist.value("DeviceIdentifier").toString();
                partInfo.path = "/dev/" + partInfo.name;
                partInfo.type = "partition";
                partInfo.size = plist.value("Size").toLongLong();
                partInfo.isRemovable = diskInfo.isRemovable;
                
                // Get partition details
                QProcess partDetailProcess;
                partDetailProcess.start("diskutil", QStringList() << "info" << "-plist" << partInfo.path);
                partDetailProcess.waitForFinished();
                
                QTemporaryFile partDetailTempFile;
                if (partDetailTempFile.open()) {
                    partDetailTempFile.write(partDetailProcess.readAllStandardOutput());
                    partDetailTempFile.close();
                    
                    QSettings partDetailPlist(partDetailTempFile.fileName(), QSettings::NativeFormat);
                    partInfo.isEncrypted = partDetailPlist.value("Encrypted").toBool();
                    
                    // If mounted, use the mount point as path
                    if (partDetailPlist.value("Mounted").toBool()) {
                        partInfo.path = partDetailPlist.value("MountPoint").toString();
                    }
                }
                
                diskList.append(partInfo);
            }
            plist.endArray(); // Partitions
        }
        plist.endArray(); // AllDisksAndPartitions
    }
#endif

    // Also add all mounted volumes from QStorageInfo if not already in the list
    for (const QStorageInfo &storage : storages) {
        bool found = false;
        for (const DiskInfo &disk : diskList) {
            if (disk.path == storage.rootPath()) {
                found = true;
                break;
            }
        }
        
        if (!found && storage.isValid() && !storage.isReadOnly()) {
            DiskInfo diskInfo;
            diskInfo.path = storage.rootPath();
            diskInfo.name = storage.displayName();
            if (diskInfo.name.isEmpty()) {
                diskInfo.name = storage.rootPath();
            }
            diskInfo.type = "volume";
            diskInfo.size = storage.bytesTotal();
            diskInfo.isRemovable = false; // Cannot easily determine this
            diskInfo.isEncrypted = false; // Cannot easily determine this
            
            diskList.append(diskInfo);
        }
    }
    
    return diskList;
}

bool isValidDiskPath(const QString& path) {
    // First, check if the path exists
    QFileInfo fileInfo(path);
    if (!fileInfo.exists()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Path does not exist: %1").arg(path));
        return false;
    }
    
    // Make sure the path is writable
    if (!fileInfo.isWritable()) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Path is not writable: %1").arg(path));
        return false;
    }
    
#ifdef Q_OS_LINUX
    // On Linux, check if the path is a block device or a mounted directory
    if (path.startsWith("/dev/")) {
        // It's a block device, make sure we have permission to write to it
        QFile device(path);
        if (!device.open(QIODevice::ReadWrite)) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
            return false;
        }
        device.close();
        return true;
    } else {
        // It's a directory, make sure it's mounted and not the root directory
        QStorageInfo storage(path);
        if (!storage.isValid() || !storage.isReady() || storage.isRoot()) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid storage location or root directory: %1").arg(path));
            return false;
        }
        return true;
    }
#elif defined(Q_OS_WINDOWS)
    // On Windows, check if the path is a volume (like C:\)
    if (path.length() == 3 && path.at(1) == ':' && path.at(2) == '\\') {
        // It's a drive letter, make sure it's not the system drive
        QProcess process;
        process.start("wmic", QStringList() << "logicaldisk" << "where" << "DeviceID='" + path.left(2) + "'" << "get" << "DriveType");
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        
        // DriveType: 2=Removable, 3=Fixed, 4=Network, 5=Optical, 6=RAM disk
        // Only allow removable drives (2), network drives (4), or RAM disks (6)
        QStringList outputLines = output.trimmed().split('\n');
        int driveType = outputLines.last().trimmed().toInt();
        if (driveType == 3) {
            // It's a fixed drive, make sure it's not the system drive
            process.start("wmic", QStringList() << "OS" << "get" << "SystemDrive");
            process.waitForFinished();
            QString output = process.readAllStandardOutput().trimmed();
            QStringList lines = output.split('\n');
            QString systemDrive = lines.last().trimmed();
            
            if (systemDrive.compare(path.left(2), Qt::CaseInsensitive) == 0) {
                SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot encrypt system drive: %1").arg(path));
                return false;
            }
        }
        
        // For physical drives (\\.\PhysicalDriveX)
        if (path.startsWith("\\\\.\\")) {
            QFile device(path);
            if (!device.open(QIODevice::ReadWrite)) {
                SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
                return false;
            }
            device.close();
        }
        
        return true;
    } else {
        // It's a directory, make sure it exists and is writable
        QDir dir(path);
        if (!dir.exists()) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Directory does not exist: %1").arg(path));
            return false;
        }
        
        // Create a temp file to check if we can write to the directory
        QTemporaryFile tempFile(path + "/opencrypttest_XXXXXX");
        if (!tempFile.open()) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot write to directory: %1").arg(path));
            return false;
        }
        
        return true;
    }
#elif defined(Q_OS_MAC)
    // On macOS, check if the path is a disk device or a mounted directory
    if (path.startsWith("/dev/")) {
        // It's a disk device, check if we can open it for writing
        QFile device(path);
        if (!device.open(QIODevice::ReadWrite)) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
            return false;
        }
        device.close();
        
        // Make sure it's not the boot volume
        QProcess process;
        process.start("diskutil", QStringList() << "info" << "-plist" << path);
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        
        QTemporaryFile tempFile;
        if (tempFile.open()) {
            tempFile.write(output.toUtf8());
            tempFile.close();
            
            QSettings plist(tempFile.fileName(), QSettings::NativeFormat);
            bool isBootVolume = plist.value("SystemImage").toBool();
            
            if (isBootVolume) {
                SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot encrypt boot volume: %1").arg(path));
                return false;
            }
        }
        
        return true;
    } else {
        // It's a directory, make sure it's mounted and not the root directory
        QStorageInfo storage(path);
        if (!storage.isValid() || !storage.isReady() || storage.isRoot()) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Invalid storage location or root directory: %1").arg(path));
            return false;
        }
        
        // Create a temp file to check if we can write to the directory
        QTemporaryFile tempFile(path + "/opencrypttest_XXXXXX");
        if (!tempFile.open()) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot write to directory: %1").arg(path));
            return false;
        }
        
        return true;
    }
#else
    // Generic implementation for other platforms
    // Check if it's a directory and we can write to it
    QDir dir(path);
    if (dir.exists()) {
        QTemporaryFile tempFile(path + "/opencrypttest_XXXXXX");
        if (!tempFile.open()) {
            SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot write to directory: %1").arg(path));
            return false;
        }
        return true;
    }
    
    // Otherwise, it might be a device file - try to open it
    QFile device(path);
    if (!device.open(QIODevice::ReadWrite)) {
        SECURE_LOG(ERROR_LEVEL, "DiskOperations", QString("Cannot open device for writing: %1").arg(path));
        return false;
    }
    device.close();
    
    return true;
#endif
}

// -----------------------------------------------------------------------
// createEncryptionHeader / readEncryptionHeader / createHiddenVolume /
// readHiddenVolumeHeader / hasHiddenVolume moved to
//   src/encryptionengine_diskops_header.cpp
// -----------------------------------------------------------------------


int getDiskSectorSize(const QString& diskPath) {
    // Default sector size (512 bytes is common)
    int sectorSize = 512;
    
#ifdef Q_OS_LINUX
    // On Linux, use IOCTL to get the sector size
    if (diskPath.startsWith("/dev/")) {
        QFile device(diskPath);
        if (device.open(QIODevice::ReadOnly)) {
            // Use BLKSSZGET ioctl to get sector size
            int fd = device.handle();
            QProcess process;
            process.start("blockdev", QStringList() << "--getss" << diskPath);
            process.waitForFinished();
            QString output = process.readAllStandardOutput().trimmed();
            sectorSize = output.toInt();
            device.close();
        }
    }
#elif defined(Q_OS_WINDOWS)
    // On Windows, use DeviceIoControl for physical devices
    if (diskPath.startsWith("\\\\.\\")) {
        // For Windows, this is more complex and would require native API calls
        // Simplified for this example
        sectorSize = 512; // Assume 512 bytes for now
    }
#elif defined(Q_OS_MAC)
    // On macOS, use diskutil to get sector size
    if (diskPath.startsWith("/dev/")) {
        QProcess process;
        process.start("diskutil", QStringList() << "info" << "-plist" << diskPath);
        process.waitForFinished();
        QString output = process.readAllStandardOutput();
        
        QTemporaryFile tempFile;
        if (tempFile.open()) {
            tempFile.write(output.toUtf8());
            tempFile.close();
            
            QSettings plist(tempFile.fileName(), QSettings::NativeFormat);
            sectorSize = plist.value("DeviceBlockSize").toInt();
        }
    }
#endif
    
    // If we couldn't get the sector size, use a safe default
    if (sectorSize <= 0) {
        sectorSize = 512;
    }
    
    return sectorSize;
}

qint64 calculateEncryptableSectors(const QString& diskPath) {
    // Get disk size and sector size
    qint64 diskSize = 0;
    int sectorSize = getDiskSectorSize(diskPath);
    
    // Check if the path is a device or a directory
    if (diskPath.startsWith("/dev/") || diskPath.startsWith("\\\\.\\")) {
        // It's a device, get its size
        QFile device(diskPath);
        if (device.open(QIODevice::ReadOnly)) {
            diskSize = device.size();
            device.close();
        }
    } else {
        // It's a directory, get the free space
        QStorageInfo storage(diskPath);
        if (storage.isValid()) {
            diskSize = storage.bytesAvailable();
        }
    }
    
    // Reserve space for the standard header and potential hidden volume header
    qint64 reservedBytes = DISK_HIDDEN_HEADER_OFFSET + DISK_HEADER_SIZE;
    
    // Calculate the usable space
    qint64 usableBytes = diskSize - reservedBytes;
    
    // Convert to sectors
    qint64 sectors = usableBytes / sectorSize;
    
    return sectors;
}

qint64 calculateHiddenVolumeSize(const QString& diskPath, int percentage) {
    // Get disk size
    qint64 diskSize = 0;
    
    // Check if the path is a device or a directory
    if (diskPath.startsWith("/dev/") || diskPath.startsWith("\\\\.\\")) {
        // It's a device, get its size
        QFile device(diskPath);
        if (device.open(QIODevice::ReadOnly)) {
            diskSize = device.size();
            device.close();
        }
    } else {
        // It's a directory, get the free space
        QStorageInfo storage(diskPath);
        if (storage.isValid()) {
            diskSize = storage.bytesAvailable();
        }
    }
    
    // Make sure the percentage is within bounds
    if (percentage < 10) percentage = 10;
    if (percentage > 80) percentage = 80;
    
    // Reserve space for headers
    qint64 reservedBytes = DISK_HIDDEN_HEADER_OFFSET + DISK_HEADER_SIZE;
    qint64 usableBytes = diskSize - reservedBytes;
    
    // Calculate hidden volume size based on percentage
    qint64 hiddenVolumeSize = usableBytes * percentage / 100;
    
    return hiddenVolumeSize;
}

QString formatDiskSize(qint64 size) {
    constexpr qint64 KB = 1024;
    constexpr qint64 MB = KB * 1024;
    constexpr qint64 GB = MB * 1024;
    constexpr qint64 TB = GB * 1024;
    
    if (size >= TB) {
        return QString("%1 TB").arg(static_cast<double>(size) / TB, 0, 'f', 2);
    } else if (size >= GB) {
        return QString("%1 GB").arg(static_cast<double>(size) / GB, 0, 'f', 2);
    } else if (size >= MB) {
        return QString("%1 MB").arg(static_cast<double>(size) / MB, 0, 'f', 1);
    } else if (size >= KB) {
        return QString("%1 KB").arg(static_cast<double>(size) / KB, 0, 'f', 0);
    } else {
        return QString("%1 bytes").arg(size);
    }
}

QString getDiskDetails(const DiskInfo& diskInfo) {
    QString details;
    
    // Type and name
    details += QString("<b>%1: %2</b><br/>").arg(
        diskInfo.type.isEmpty() ? "Volume" : diskInfo.type.at(0).toUpper() + diskInfo.type.mid(1),
        diskInfo.name
    );
    
    // Path
    details += QString("Path: %1<br/>").arg(diskInfo.path);
    
    // Size
    details += QString("Size: %1<br/>").arg(formatDiskSize(diskInfo.size));
    
    // Removable status
    details += QString("Removable: %1<br/>").arg(diskInfo.isRemovable ? "Yes" : "No");
    
    // Encryption status
    details += QString("Encrypted: %1<br/>").arg(diskInfo.isEncrypted ? "Yes" : "No");
    
    // Hidden volume status
    if (diskInfo.isEncrypted) {
        details += QString("Hidden Volume: %1<br/>").arg(diskInfo.hasHiddenVolume ? "Yes" : "No");
    }
    
    return details;
}

} // namespace DiskOperations