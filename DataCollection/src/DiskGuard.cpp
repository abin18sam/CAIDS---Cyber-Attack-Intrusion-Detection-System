#include "DiskGuard.h"
#include <sys/statvfs.h>

namespace caids {

DiskStatus checkDiskFreePercent(const std::string& path) {
    DiskStatus status;
    struct statvfs vfs{};
    if (statvfs(path.c_str(), &vfs) != 0) {
        return status; // ok stays false
    }
    unsigned long total = vfs.f_blocks;
    unsigned long free_blocks = vfs.f_bavail;
    if (total == 0) return status;

    status.ok = true;
    status.percent_free = (static_cast<double>(free_blocks) / total) * 100.0;
    status.free_bytes = static_cast<long>(free_blocks) * vfs.f_frsize;
    return status;
}

} // namespace caids
