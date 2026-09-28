#pragma once

#include "EndpointEvent.h"
#include "ProcessMonitor.h"
#include <string>
#include <vector>
#include <optional>
#include <atomic>
#include <thread>
#include <functional>

namespace caids {
namespace endpoint {

using KeyloggerAlertCallback = std::function<void(const EndpointEvent&)>;

class KeyloggerDetector {
public:
    KeyloggerDetector(int scan_interval_ms = 3000);
    ~KeyloggerDetector();

    void setAlertCallback(KeyloggerAlertCallback cb);
    bool start();
    void stop();

    // Inspect a specific process for keylogging indicators
    std::optional<EndpointEvent> inspectProcess(const ProcessInfo& proc);

    // Periodic sweep for input hooks and raw keyboard device access
    void scanSystemInputHooks();

private:
    void detectorLoop();

    int scan_interval_ms_ = 3000;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    KeyloggerAlertCallback callback_;

    std::vector<std::string> suspicious_hook_modules_;
};

} // namespace endpoint
} // namespace caids
