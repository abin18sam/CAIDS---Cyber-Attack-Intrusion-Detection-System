#pragma once
#include <string>
#include <fstream>
#include <chrono>
#include <cstdint>

// ============================================================================
// CAIDS Data Collection Service - RotatingMetadataWriter
// Writes one JSON-line per packet with just enough structure (timestamps,
// addresses, ports, protocol, length, TTL) for lightweight, human-greppable
// visibility into what's being collected, without needing to open the raw
// .pcap files. Full packet analysis still happens downstream from the
// .pcap files written by RotatingPcapWriter.
// ============================================================================

namespace caids {

struct QuickPacketSummary {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string protocol; // "TCP" / "UDP" / "ICMP" / "OTHER"
    uint32_t length = 0;
    uint8_t ttl = 0;
    bool valid = false; // false for non-IPv4 / truncated frames
};

// Best-effort, allocation-light parse of Ethernet+IPv4 headers, just far
// enough to populate QuickPacketSummary. Not a substitute for the full
// Packet Analysis module - deliberately minimal.
QuickPacketSummary quickParse(const unsigned char* packet, uint32_t caplen);

class RotatingMetadataWriter {
public:
    RotatingMetadataWriter(std::string output_dir, int rotate_seconds, long rotate_max_bytes);
    ~RotatingMetadataWriter();

    bool open();
    void write(const QuickPacketSummary& summary);
    void close();

private:
    bool rotate();
    std::string buildFilename() const;

    std::string output_dir_;
    int rotate_seconds_;
    long rotate_max_bytes_;

    std::ofstream file_;
    std::string current_path_;
    long bytes_written_ = 0;
    std::chrono::steady_clock::time_point file_opened_at_;
};

} // namespace caids
