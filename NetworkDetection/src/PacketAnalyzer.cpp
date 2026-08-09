#include "PacketAnalyzer.h"
#include <cstring>
#include <cstdio>
#ifdef _WIN32
#  include <winsock2.h>
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <arpa/inet.h>
#endif

// ----------------------------------------------------------------------------
// All header parsing below is done manually on the raw byte buffer (rather
// than casting into netinet/* structs) so that field access is explicit,
// bounds-checked, and portable across platforms. Multi-byte fields are
// read big-endian per the relevant RFCs and converted with ntohs/ntohl.
// ----------------------------------------------------------------------------

namespace caids {

namespace {
constexpr size_t ETH_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

constexpr uint8_t IPPROTO_ICMP_ = 1;
constexpr uint8_t IPPROTO_TCP_  = 6;
constexpr uint8_t IPPROTO_UDP_  = 17;
}

std::string PacketAnalyzer::ipv4ToString(uint32_t addr_network_order) {
    char buf[INET_ADDRSTRLEN] = {0};
    struct in_addr a{};
    a.s_addr = addr_network_order;
    if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) {
        return "0.0.0.0";
    }
    return std::string(buf);
}

std::optional<PacketInfo> PacketAnalyzer::parse(const struct pcap_pkthdr* header,
                                                  const unsigned char* packet) {
    if (!header || !packet) return std::nullopt;

    const uint32_t caplen = header->caplen;
    if (caplen < ETH_HEADER_LEN) return std::nullopt; // too short for Ethernet

    // --- Ethernet header ---
    uint16_t ethertype = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];
    if (ethertype != ETHERTYPE_IPV4) {
        return std::nullopt; // only IPv4 supported in this stage
    }

    const unsigned char* ip_start = packet + ETH_HEADER_LEN;
    const size_t remaining_after_eth = caplen - ETH_HEADER_LEN;
    if (remaining_after_eth < 20) return std::nullopt; // min IPv4 header size

    PacketInfo info;
    info.captured_length = caplen;
    info.timestamp = std::chrono::steady_clock::now();

    // --- IPv4 header ---
    uint8_t version_ihl = ip_start[0];
    uint8_t version = version_ihl >> 4;
    uint8_t ihl_words = version_ihl & 0x0F; // header length in 32-bit words
    size_t ip_header_len = static_cast<size_t>(ihl_words) * 4;

    if (version != 4 || ihl_words < 5 || remaining_after_eth < ip_header_len) {
        info.malformed = true;
        info.protocol = Protocol::UNKNOWN;
        return info; // still return it - "malformed" alert is meaningful
    }

    uint16_t total_length = (static_cast<uint16_t>(ip_start[2]) << 8) | ip_start[3];
    uint8_t ttl = ip_start[8];
    uint8_t ip_proto = ip_start[9];

    uint32_t src_addr, dst_addr;
    std::memcpy(&src_addr, ip_start + 12, 4);
    std::memcpy(&dst_addr, ip_start + 16, 4);

    info.src_ip = ipv4ToString(src_addr);
    info.dst_ip = ipv4ToString(dst_addr);
    info.total_length = total_length;
    info.ttl = ttl;

    const unsigned char* l4_start = ip_start + ip_header_len;
    const size_t remaining_after_ip = remaining_after_eth - ip_header_len;

    if (ip_proto == IPPROTO_TCP_) {
        if (remaining_after_ip < 20) { info.malformed = true; return info; }
        info.protocol = Protocol::TCP;
        info.src_port = (static_cast<uint16_t>(l4_start[0]) << 8) | l4_start[1];
        info.dst_port = (static_cast<uint16_t>(l4_start[2]) << 8) | l4_start[3];
        uint8_t data_offset_words = (l4_start[12] >> 4) & 0x0F;
        info.tcp_flags = l4_start[13]; // low 6 bits: URG ACK PSH RST SYN FIN order per RFC793 layout used here
        size_t tcp_header_len = static_cast<size_t>(data_offset_words) * 4;
        if (data_offset_words < 5 || remaining_after_ip < tcp_header_len) {
            info.malformed = true;
        }
    } else if (ip_proto == IPPROTO_UDP_) {
        if (remaining_after_ip < 8) { info.malformed = true; return info; }
        info.protocol = Protocol::UDP;
        info.src_port = (static_cast<uint16_t>(l4_start[0]) << 8) | l4_start[1];
        info.dst_port = (static_cast<uint16_t>(l4_start[2]) << 8) | l4_start[3];
    } else if (ip_proto == IPPROTO_ICMP_) {
        info.protocol = Protocol::ICMP;
        info.src_port = 0;
        info.dst_port = 0;
    } else {
        info.protocol = Protocol::UNKNOWN;
    }

    return info;
}

std::vector<Alert> PacketAnalyzer::inspect(const PacketInfo& info) {
    std::vector<Alert> alerts;

    if (info.malformed) {
        alerts.push_back(Alert{
            "PacketAnalysis", "MALFORMED_PACKET",
            "Packet with invalid/truncated header fields",
            info.src_ip, info.dst_ip, 2});
        return alerts; // don't trust flag fields on a malformed packet
    }

    if (info.protocol != Protocol::TCP) return alerts;

    const uint8_t f = info.tcp_flags;
    const bool syn = f & tcp_flags::SYN;
    const bool fin = f & tcp_flags::FIN;
    const bool ack = f & tcp_flags::ACK;
    const bool rst = f & tcp_flags::RST;
    const bool psh = f & tcp_flags::PSH;
    const bool urg = f & tcp_flags::URG;

    // NULL scan: no flags set at all
    if (f == 0) {
        alerts.push_back(Alert{"PacketAnalysis", "NULL_SCAN",
            "TCP packet with no flags set (NULL scan signature)",
            info.src_ip, info.dst_ip, 3});
    }
    // XMAS scan: FIN + PSH + URG set together
    if (fin && psh && urg) {
        alerts.push_back(Alert{"PacketAnalysis", "XMAS_SCAN",
            "TCP packet with FIN+PSH+URG set (XMAS scan signature)",
            info.src_ip, info.dst_ip, 3});
    }
    // SYN+FIN together is never legitimate
    if (syn && fin) {
        alerts.push_back(Alert{"PacketAnalysis", "INVALID_FLAG_COMBO",
            "TCP packet has SYN and FIN set simultaneously",
            info.src_ip, info.dst_ip, 3});
    }
    // SYN+RST together is never legitimate
    if (syn && rst) {
        alerts.push_back(Alert{"PacketAnalysis", "INVALID_FLAG_COMBO",
            "TCP packet has SYN and RST set simultaneously",
            info.src_ip, info.dst_ip, 3});
    }
    // Lone FIN scan (FIN set, ACK not set - used to probe closed ports stealthily)
    if (fin && !ack && !syn && !rst) {
        alerts.push_back(Alert{"PacketAnalysis", "FIN_SCAN",
            "Lone FIN packet outside an established connection (FIN scan signature)",
            info.src_ip, info.dst_ip, 2});
    }
    // Suspiciously low TTL can indicate spoofing/traceroute-style probing
    if (info.ttl != 0 && info.ttl < 5) {
        alerts.push_back(Alert{"PacketAnalysis", "SUSPICIOUS_TTL",
            "Unusually low TTL value observed",
            info.src_ip, info.dst_ip, 1});
    }

    return alerts;
}

} // namespace caids
