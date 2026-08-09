#include "Config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace caids {

namespace {
std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

bool toBool(const std::string& v) {
    std::string lv = v;
    std::transform(lv.begin(), lv.end(), lv.begin(), ::tolower);
    return lv == "true" || lv == "1" || lv == "yes" || lv == "on";
}
}

CollectorConfig CollectorConfig::loadFromFile(const std::string& path, bool& ok) {
    CollectorConfig cfg;
    ok = false;

    std::ifstream file(path);
    if (!file.is_open()) {
        return cfg; // caller decides whether missing config is fatal
    }

    std::unordered_map<std::string, std::string> kv;
    std::string line;
    while (std::getline(file, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;
        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(trimmed.substr(0, eq));
        std::string value = trim(trimmed.substr(eq + 1));
        kv[key] = value;
    }

    auto getStr = [&](const std::string& key, const std::string& def) {
        auto it = kv.find(key);
        return it != kv.end() ? it->second : def;
    };
    auto getInt = [&](const std::string& key, int def) {
        auto it = kv.find(key);
        if (it == kv.end()) return def;
        try { return std::stoi(it->second); } catch (...) { return def; }
    };
    auto getLong = [&](const std::string& key, long def) {
        auto it = kv.find(key);
        if (it == kv.end()) return def;
        try { return std::stol(it->second); } catch (...) { return def; }
    };
    auto getBool = [&](const std::string& key, bool def) {
        auto it = kv.find(key);
        return it != kv.end() ? toBool(it->second) : def;
    };

    cfg.interface = getStr("interface", cfg.interface);
    cfg.bpf_filter = getStr("bpf_filter", cfg.bpf_filter);
    cfg.snaplen = getInt("snaplen", cfg.snaplen);
    cfg.promiscuous = getBool("promiscuous", cfg.promiscuous);
    cfg.read_timeout_ms = getInt("read_timeout_ms", cfg.read_timeout_ms);

    cfg.output_dir = getStr("output_dir", cfg.output_dir);
    cfg.log_dir = getStr("log_dir", cfg.log_dir);

    cfg.rotate_seconds = getInt("rotate_seconds", cfg.rotate_seconds);
    cfg.rotate_max_bytes = getLong("rotate_max_bytes", cfg.rotate_max_bytes);

    cfg.write_metadata_log = getBool("write_metadata_log", cfg.write_metadata_log);
    cfg.write_raw_pcap = getBool("write_raw_pcap", cfg.write_raw_pcap);

    cfg.stats_interval_seconds = getInt("stats_interval_seconds", cfg.stats_interval_seconds);
    cfg.min_free_disk_percent = getInt("min_free_disk_percent", cfg.min_free_disk_percent);
    cfg.reconnect_backoff_start_seconds = getInt("reconnect_backoff_start_seconds", cfg.reconnect_backoff_start_seconds);
    cfg.reconnect_backoff_max_seconds = getInt("reconnect_backoff_max_seconds", cfg.reconnect_backoff_max_seconds);

    ok = true;
    return cfg;
}

} // namespace caids
