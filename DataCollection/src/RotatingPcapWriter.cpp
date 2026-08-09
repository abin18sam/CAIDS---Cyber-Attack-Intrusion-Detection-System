#include "RotatingPcapWriter.h"
#include "Logger.h"
#include <sys/stat.h>
#include <cstdio>
#include <ctime>

namespace caids {

namespace {
constexpr long PCAP_RECORD_HEADER_BYTES = 16; // ts_sec, ts_usec, caplen, len

std::string timestampTag() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&t));
    return buf;
}
}

RotatingPcapWriter::RotatingPcapWriter(std::string output_dir, int rotate_seconds,
                                        long rotate_max_bytes)
    : output_dir_(std::move(output_dir)),
      rotate_seconds_(rotate_seconds),
      rotate_max_bytes_(rotate_max_bytes) {}

RotatingPcapWriter::~RotatingPcapWriter() { close(); }

std::string RotatingPcapWriter::buildFilename() const {
    return output_dir_ + "/caids_" + timestampTag() + ".pcap";
}

bool RotatingPcapWriter::open(pcap_t* source_handle) {
    source_handle_ = source_handle;
    mkdir(output_dir_.c_str(), 0755); // best-effort; ignore EEXIST
    return rotate();
}

bool RotatingPcapWriter::rotate() {
    if (dumper_) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
        // Atomically publish the completed file so a downstream reader never
        // sees a partially-written capture.
        if (!tmp_path_.empty()) {
            std::rename(tmp_path_.c_str(), current_path_.c_str());
        }
    }

    current_path_ = buildFilename();
    tmp_path_ = current_path_ + ".part";

    dumper_ = pcap_dump_open(source_handle_, tmp_path_.c_str());
    if (!dumper_) {
        Logger::instance().error("RotatingPcapWriter",
            std::string("Failed to open ") + tmp_path_ + ": " + pcap_geterr(source_handle_));
        return false;
    }

    bytes_written_ = 0;
    file_opened_at_ = std::chrono::steady_clock::now();
    Logger::instance().info("RotatingPcapWriter", "Rotated to new capture file: " + current_path_);
    return true;
}

void RotatingPcapWriter::write(const struct pcap_pkthdr* header, const unsigned char* packet) {
    if (!dumper_) return;

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - file_opened_at_).count();

    bool time_exceeded = rotate_seconds_ > 0 && elapsed >= rotate_seconds_;
    bool size_exceeded = rotate_max_bytes_ > 0 && bytes_written_ >= rotate_max_bytes_;

    if (time_exceeded || size_exceeded) {
        rotate();
    }

    pcap_dump(reinterpret_cast<unsigned char*>(dumper_), header, packet);
    bytes_written_ += header->caplen + PCAP_RECORD_HEADER_BYTES;
}

void RotatingPcapWriter::close() {
    if (dumper_) {
        pcap_dump_close(dumper_);
        dumper_ = nullptr;
        if (!tmp_path_.empty()) {
            std::rename(tmp_path_.c_str(), current_path_.c_str());
            tmp_path_.clear();
        }
    }
}

} // namespace caids
