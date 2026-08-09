#include "FlowAnalyzer.h"
#include <algorithm>

namespace caids {

FlowAnalyzer::FlowAnalyzer(uint32_t syn_flood_threshold,
                            uint32_t port_scan_threshold,
                            std::chrono::seconds window)
    : syn_flood_threshold_(syn_flood_threshold),
      port_scan_threshold_(port_scan_threshold),
      window_(window) {}

void FlowAnalyzer::evictOlderThan(std::vector<std::chrono::steady_clock::time_point>& ts,
                                   std::chrono::steady_clock::time_point cutoff) {
    ts.erase(std::remove_if(ts.begin(), ts.end(),
                             [cutoff](const auto& t) { return t < cutoff; }),
             ts.end());
}

std::vector<Alert> FlowAnalyzer::update(const PacketInfo& info) {
    std::vector<Alert> alerts;
    if (info.malformed || !info.isValidIPv4()) return alerts;

    const auto now = info.timestamp;
    std::lock_guard<std::mutex> lock(mutex_);

    // --- 1) Per-flow (5-tuple) statistics ---
    FlowKey key{info.src_ip, info.dst_ip, info.src_port, info.dst_port, info.protocol};
    FlowStats& stats = flows_[key];
    if (stats.packet_count == 0) {
        stats.first_seen = now;
    }
    stats.packet_count++;
    stats.byte_count += info.total_length;
    stats.last_seen = now;

    if (info.protocol == Protocol::TCP) {
        if (info.tcp_flags & tcp_flags::SYN) stats.syn_count++;
        if (info.tcp_flags & tcp_flags::FIN) stats.fin_count++;
        if (info.tcp_flags & tcp_flags::RST) stats.rst_count++;
    }

    // --- 2) Per-source behavioral tracking (window-based) ---
    SourceWindow& sw = sources_[info.src_ip];
    sw.last_activity = now;
    const auto cutoff = now - window_;

    // Port-scan detection: distinct destination ports touched within window
    sw.ports_touched[info.dst_port] = now;
    for (auto it = sw.ports_touched.begin(); it != sw.ports_touched.end(); ) {
        if (it->second < cutoff) it = sw.ports_touched.erase(it);
        else ++it;
    }
    if (sw.ports_touched.size() >= port_scan_threshold_) {
        alerts.push_back(Alert{
            "FlowAnalysis", "PORT_SCAN",
            "Source contacted " + std::to_string(sw.ports_touched.size()) +
                " distinct destination ports within the detection window",
            info.src_ip, info.dst_ip, 4});
    }

    // SYN-flood detection: rate of SYNs within window
    if (info.protocol == Protocol::TCP && (info.tcp_flags & tcp_flags::SYN) &&
        !(info.tcp_flags & tcp_flags::ACK)) {
        sw.syn_timestamps.push_back(now);
        evictOlderThan(sw.syn_timestamps, cutoff);
        if (sw.syn_timestamps.size() >= syn_flood_threshold_) {
            alerts.push_back(Alert{
                "FlowAnalysis", "SYN_FLOOD",
                std::to_string(sw.syn_timestamps.size()) +
                    " SYN packets from this source within the detection window",
                info.src_ip, info.dst_ip, 5});
        }
    }

    return alerts;
}

void FlowAnalyzer::pruneIdle(std::chrono::seconds idle_timeout) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = std::chrono::steady_clock::now();

    for (auto it = flows_.begin(); it != flows_.end(); ) {
        if (now - it->second.last_seen > idle_timeout) it = flows_.erase(it);
        else ++it;
    }
    for (auto it = sources_.begin(); it != sources_.end(); ) {
        if (now - it->second.last_activity > idle_timeout) it = sources_.erase(it);
        else ++it;
    }
}

size_t FlowAnalyzer::activeFlowCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}

size_t FlowAnalyzer::trackedSourceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sources_.size();
}

} // namespace caids
