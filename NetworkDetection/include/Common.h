#pragma once
#include <cstdint>
#include <string>
#include <chrono>
#include <functional>

// ============================================================================
// CAIDS - Cyber Attacks Intrusion Detection System
// Module: Network Detection / NIDS - Common Types
// ============================================================================

namespace caids {

enum class Protocol : uint8_t {
    UNKNOWN = 0,
    TCP,
    UDP,
    ICMP
};

inline const char* protocolToString(Protocol p) {
    switch (p) {
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
        case Protocol::ICMP: return "ICMP";
        default:             return "UNKNOWN";
    }
}

// Raw TCP flag bit masks (as they appear in the TCP header flags byte)
namespace tcp_flags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// Result of parsing a single captured frame - output of the
// "Packet Analysis" branch, consumed by "Flow Analysis".
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    Protocol protocol = Protocol::UNKNOWN;
    uint32_t total_length = 0;   // length reported by IP header
    uint32_t captured_length = 0; // length actually captured on the wire
    uint8_t  tcp_flags = 0;
    uint8_t  ttl = 0;
    bool malformed = false;      // header failed sanity checks
    std::chrono::steady_clock::time_point timestamp;

    bool isValidIPv4() const { return !src_ip.empty() && !dst_ip.empty(); }
};

// 5-tuple identifying a flow (uni-directional; src->dst)
struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    Protocol protocol;

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip &&
               src_port == other.src_port && dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept {
        std::size_t seed = std::hash<std::string>{}(k.src_ip);
        auto combine = [&seed](std::size_t h) {
            seed ^= h + 0x9e3779b9U + (seed << 6) + (seed >> 2);
        };
        combine(std::hash<std::string>{}(k.dst_ip));
        combine(std::hash<uint16_t>{}(k.src_port));
        combine(std::hash<uint16_t>{}(k.dst_port));
        combine(std::hash<uint8_t>{}(static_cast<uint8_t>(k.protocol)));
        return seed;
    }
};

// A single alert emitted by any detection stage.
struct Alert {
    std::string source;      // which module raised it: "PacketAnalysis" / "FlowAnalysis"
    std::string category;    // e.g. "PORT_SCAN", "SYN_FLOOD", "MALFORMED_PACKET"
    std::string description;
    std::string src_ip;
    std::string dst_ip;
    int severity = 1;        // 1 = low ... 5 = critical
    std::chrono::system_clock::time_point time = std::chrono::system_clock::now();
};

using AlertCallback = std::function<void(const Alert&)>;

} // namespace caids
