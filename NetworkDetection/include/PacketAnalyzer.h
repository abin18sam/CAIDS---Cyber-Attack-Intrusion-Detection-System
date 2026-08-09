#pragma once
#include "Common.h"
#include <pcap.h>
#include <optional>
#include <vector>

// ============================================================================
// CAIDS - Network Detection / NIDS
// Module: PACKET ANALYSIS
//
// Parses raw Ethernet/IPv4/TCP/UDP/ICMP frames into a structured PacketInfo,
// and runs fast, stateless (single-packet) signature checks: malformed
// headers, NULL/XMAS/FIN scans, invalid TCP flag combinations, etc.
// Designed for O(1) work per packet - no allocations in the hot path
// beyond the two IP-address strings needed downstream.
// ============================================================================

namespace caids {

class PacketAnalyzer {
public:
    // Parse a captured frame. Returns std::nullopt if the frame is too
    // short to contain the headers it claims to, or uses an unsupported
    // link/ethertype (currently: Ethernet + IPv4 only).
    static std::optional<PacketInfo> parse(const struct pcap_pkthdr* header,
                                            const unsigned char* packet);

    // Stateless signature inspection of one already-parsed packet.
    // Cheap heuristics that don't require flow/history state.
    static std::vector<Alert> inspect(const PacketInfo& info);

private:
    static std::string ipv4ToString(uint32_t addr_network_order);
};

} // namespace caids
