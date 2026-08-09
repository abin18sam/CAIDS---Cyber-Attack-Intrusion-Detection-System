#include "RotatingMetadataWriter.h"
#include "Logger.h"
#include <sys/stat.h>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace caids {

namespace {
constexpr size_t ETH_HEADER_LEN = 14;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint8_t IPPROTO_ICMP_ = 1;
constexpr uint8_t IPPROTO_TCP_ = 6;
constexpr uint8_t IPPROTO_UDP_ = 17;

std::string ipv4ToString(uint32_t addr_network_order) {
    char buf[INET_ADDRSTRLEN] = {0};
    struct in_addr a{};
    a.s_addr = addr_network_order;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

std::string timestampTag() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
    return buf;
}

std::string isoTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&t));
    std::ostringstream oss;
    oss << buf << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return oss.str();
}

// Minimal JSON string escaping (sufficient for IP-address-shaped strings,
// but safe even if that ever changes).
std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}
}

QuickPacketSummary quickParse(const unsigned char* packet, uint32_t caplen) {
    QuickPacketSummary s;
    if (!packet || caplen < ETH_HEADER_LEN) return s;

    uint16_t ethertype = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];
    if (ethertype != ETHERTYPE_IPV4) return s;

    const unsigned char* ip_start = packet + ETH_HEADER_LEN;
    size_t remaining = caplen - ETH_HEADER_LEN;
    if (remaining < 20) return s;

    uint8_t version_ihl = ip_start[0];
    uint8_t version = version_ihl >> 4;
    uint8_t ihl_words = version_ihl & 0x0F;
    size_t ip_header_len = static_cast<size_t>(ihl_words) * 4;
    if (version != 4 || ihl_words < 5 || remaining < ip_header_len) return s;

    uint16_t total_length = (static_cast<uint16_t>(ip_start[2]) << 8) | ip_start[3];
    uint8_t ttl = ip_start[8];
    uint8_t proto = ip_start[9];

    uint32_t src_addr, dst_addr;
    std::memcpy(&src_addr, ip_start + 12, 4);
    std::memcpy(&dst_addr, ip_start + 16, 4);

    s.src_ip = ipv4ToString(src_addr);
    s.dst_ip = ipv4ToString(dst_addr);
    s.length = total_length;
    s.ttl = ttl;
    s.valid = true;

    const unsigned char* l4 = ip_start + ip_header_len;
    size_t l4_remaining = remaining - ip_header_len;

    if (proto == IPPROTO_TCP_ && l4_remaining >= 4) {
        s.protocol = "TCP";
        s.src_port = (static_cast<uint16_t>(l4[0]) << 8) | l4[1];
        s.dst_port = (static_cast<uint16_t>(l4[2]) << 8) | l4[3];
    } else if (proto == IPPROTO_UDP_ && l4_remaining >= 4) {
        s.protocol = "UDP";
        s.src_port = (static_cast<uint16_t>(l4[0]) << 8) | l4[1];
        s.dst_port = (static_cast<uint16_t>(l4[2]) << 8) | l4[3];
    } else if (proto == IPPROTO_ICMP_) {
        s.protocol = "ICMP";
    } else {
        s.protocol = "OTHER";
    }

    return s;
}

RotatingMetadataWriter::RotatingMetadataWriter(std::string output_dir, int rotate_seconds,
                                                 long rotate_max_bytes)
    : output_dir_(std::move(output_dir)),
      rotate_seconds_(rotate_seconds),
      rotate_max_bytes_(rotate_max_bytes) {}

RotatingMetadataWriter::~RotatingMetadataWriter() { close(); }

std::string RotatingMetadataWriter::buildFilename() const {
    return output_dir_ + "/caids_meta_" + timestampTag() + ".jsonl";
}

bool RotatingMetadataWriter::open() {
    mkdir(output_dir_.c_str(), 0755);
    return rotate();
}

bool RotatingMetadataWriter::rotate() {
    if (file_.is_open()) file_.close();

    current_path_ = buildFilename();
    file_.open(current_path_, std::ios::app);
    if (!file_.is_open()) {
        Logger::instance().error("RotatingMetadataWriter", "Failed to open " + current_path_);
        return false;
    }
    bytes_written_ = 0;
    file_opened_at_ = std::chrono::steady_clock::now();
    return true;
}

void RotatingMetadataWriter::write(const QuickPacketSummary& s) {
    if (!s.valid) return;
    if (!file_.is_open()) return;

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - file_opened_at_).count();
    bool time_exceeded = rotate_seconds_ > 0 && elapsed >= rotate_seconds_;
    bool size_exceeded = rotate_max_bytes_ > 0 && bytes_written_ >= rotate_max_bytes_;
    if (time_exceeded || size_exceeded) rotate();

    std::ostringstream line;
    line << "{\"ts\":\"" << isoTimestamp() << "\","
         << "\"src_ip\":\"" << jsonEscape(s.src_ip) << "\","
         << "\"dst_ip\":\"" << jsonEscape(s.dst_ip) << "\","
         << "\"src_port\":" << s.src_port << ","
         << "\"dst_port\":" << s.dst_port << ","
         << "\"protocol\":\"" << s.protocol << "\","
         << "\"length\":" << s.length << ","
         << "\"ttl\":" << static_cast<int>(s.ttl) << "}\n";

    std::string out = line.str();
    file_ << out;
    file_.flush();
    bytes_written_ += static_cast<long>(out.size());
}

void RotatingMetadataWriter::close() {
    if (file_.is_open()) file_.close();
}

} // namespace caids
