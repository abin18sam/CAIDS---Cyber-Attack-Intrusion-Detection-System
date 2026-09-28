#pragma once

#include "EndpointEvent.h"
#include <string>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>

namespace caids {
namespace endpoint {

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t parent_pid = 0;
    std::string process_name;
    std::string exe_path;
    std::string command_line;
    std::string user;
    std::chrono::system_clock::time_point start_time;
};

using ProcessEventCallback = std::function<void(const ProcessInfo&, const std::string& /* event_type */)>;

class ProcessMonitor {
public:
    ProcessMonitor(int interval_ms = 1000);
    ~ProcessMonitor();

    void setEventCallback(ProcessEventCallback cb);
    bool start();
    void stop();
    bool isRunning() const { return running_; }

    // Take one snapshot manually (useful for testing)
    void scanOnce();

private:
    void monitorLoop();
    std::unordered_map<uint32_t, ProcessInfo> captureProcessSnapshot();

    int interval_ms_ = 1000;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    ProcessEventCallback callback_;
    std::unordered_map<uint32_t, ProcessInfo> active_processes_;
};

} // namespace endpoint
} // namespace caids
