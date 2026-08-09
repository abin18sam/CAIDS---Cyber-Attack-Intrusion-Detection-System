#pragma once
#include <string>

// ============================================================================
// CAIDS Data Collection Service - DiskGuard
// Tiny helper to check free space on the output filesystem so a 24/7
// collector degrades gracefully (warns, then pauses raw pcap writes)
// instead of silently filling the disk or crashing.
// ============================================================================

namespace caids {

struct DiskStatus {
    bool ok = false;          // false if statvfs() failed
    double percent_free = 0;  // 0-100
    long free_bytes = 0;
};

DiskStatus checkDiskFreePercent(const std::string& path);

} // namespace caids
