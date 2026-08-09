#pragma once
#include "Common.h"
#include <unordered_map>
#include <vector>
#include <mutex>

// ============================================================================
// CAIDS - Network Detection / NIDS
// Module: FLOW ANALYSIS
//
// Maintains per-5-tuple flow state and per-source behavioral state across
// a sliding time window, to catch attacks that are invisible at the
// single-packet level: SYN floods, port scans, and abnormal flow rates.
//
// Thread-safe (guarded by a single mutex) so it can be fed from a capture
// thread while a separate maintenance thread prunes idle state.
// ============================================================================

namespace caids {

struct FlowStats {
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    uint32_t syn_count = 0;
    uint32_t fin_count = 0;
    uint32_t rst_count = 0;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

class FlowAnalyzer {
public:
    // syn_flood_threshold: SYNs from one source, to possibly many
    //   destinations, within `window` before raising SYN_FLOOD.
    // port_scan_threshold: distinct destination ports touched by one
    //   source within `window` before raising PORT_SCAN.
    explicit FlowAnalyzer(uint32_t syn_flood_threshold = 100,
                           uint32_t port_scan_threshold = 20,
                           std::chrono::seconds window = std::chrono::seconds(10));

    // Feed one analyzed packet into flow + behavioral state.
    // Returns any alerts triggered by this update.
    std::vector<Alert> update(const PacketInfo& info);

    // Evict flows/behavioral records idle longer than idle_timeout.
    // Call periodically (e.g. every few seconds) from a maintenance thread.
    void pruneIdle(std::chrono::seconds idle_timeout = std::chrono::seconds(300));

    size_t activeFlowCount() const;
    size_t trackedSourceCount() const;

private:
    mutable std::mutex mutex_;

    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;

    // Per-source-IP sliding window state for behavioral detection.
    struct SourceWindow {
        std::vector<std::chrono::steady_clock::time_point> syn_timestamps;
        std::unordered_map<uint16_t, std::chrono::steady_clock::time_point> ports_touched;
        std::chrono::steady_clock::time_point last_activity;
    };
    std::unordered_map<std::string, SourceWindow> sources_;

    uint32_t syn_flood_threshold_;
    uint32_t port_scan_threshold_;
    std::chrono::seconds window_;

    // Helpers assume mutex_ is already held.
    void evictOlderThan(std::vector<std::chrono::steady_clock::time_point>& ts,
                         std::chrono::steady_clock::time_point cutoff);
};

} // namespace caids
