#pragma once
#include <string>
#include <chrono>
#include <pcap.h>

// ============================================================================
// CAIDS Data Collection Service - RotatingPcapWriter
// Persists full-fidelity raw packets to disk as standard .pcap files,
// rotating to a new file by elapsed time or size so:
//   (a) disk usage stays bounded per-file and easy to archive/delete, and
//   (b) downstream modules (Packet/Flow Analysis) can consume completed
//       files without racing a writer that still has them open.
// ============================================================================

namespace caids {

class RotatingPcapWriter {
public:
    RotatingPcapWriter(std::string output_dir, int rotate_seconds, long rotate_max_bytes);
    ~RotatingPcapWriter();

    // Must be called once with the live pcap_t so files share its link-type/snaplen.
    bool open(pcap_t* source_handle);

    // Write one packet, rotating first if a threshold has been crossed.
    void write(const struct pcap_pkthdr* header, const unsigned char* packet);

    void close();
    std::string currentFilePath() const { return current_path_; }
    long currentFileBytes() const { return bytes_written_; }

private:
    bool rotate();
    std::string buildFilename() const;

    std::string output_dir_;
    int rotate_seconds_;
    long rotate_max_bytes_;

    pcap_t* source_handle_ = nullptr; // not owned
    pcap_dumper_t* dumper_ = nullptr;
    std::string current_path_;
    std::string tmp_path_;
    long bytes_written_ = 0;
    std::chrono::steady_clock::time_point file_opened_at_;
};

} // namespace caids
