#include "KeyloggerDetector.h"
#include <iostream>
#include <algorithm>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#endif

namespace caids {
namespace endpoint {

KeyloggerDetector::KeyloggerDetector(int scan_interval_ms)
    : scan_interval_ms_(scan_interval_ms) {
    suspicious_hook_modules_ = {
        "hook.dll", "kbdlog.dll", "keylogger.dll",
        "spy.dll", "rawinput.dll", "kbdhook.dll"
    };
}

KeyloggerDetector::~KeyloggerDetector() {
    stop();
}

void KeyloggerDetector::setAlertCallback(KeyloggerAlertCallback cb) {
    callback_ = cb;
}

bool KeyloggerDetector::start() {
    if (running_) return false;
    running_ = true;
    worker_thread_ = std::thread(&KeyloggerDetector::detectorLoop, this);
    std::cout << "[KeyloggerDetector] Real-time input hook monitor active (interval: " 
              << scan_interval_ms_ << "ms).\n";
    return true;
}

void KeyloggerDetector::stop() {
    if (running_) {
        running_ = false;
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }
}

void KeyloggerDetector::detectorLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(scan_interval_ms_));
        if (!running_) break;
        scanSystemInputHooks();
    }
}

std::optional<EndpointEvent> KeyloggerDetector::inspectProcess(const ProcessInfo& proc) {
    std::string nameLower = proc.process_name;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    // Check if process name itself directly indicates keylogger activity
    if (nameLower.find("keylog") != std::string::npos || 
        nameLower.find("hookkey") != std::string::npos ||
        nameLower.find("kbdhook") != std::string::npos) {
        EndpointEvent alert;
        alert.event_type = "KEYLOGGER_INDICATOR";
        alert.process_name = proc.process_name;
        alert.pid = proc.pid;
        alert.parent_pid = proc.parent_pid;
        alert.exe_path = proc.exe_path;
        alert.user = proc.user;
        alert.severity = "CRITICAL";
        alert.reason = "Process attempted keyboard input monitoring (suspicious binary signature)";
        return alert;
    }

#if defined(_WIN32)
    // Scan modules loaded in the process for known keyboard hooking DLLs
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
    if (hProc) {
        HMODULE hMods[256];
        DWORD cbNeeded;
        if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            size_t modCount = cbNeeded / sizeof(HMODULE);
            for (size_t i = 0; i < modCount; ++i) {
                char modName[MAX_PATH];
                if (GetModuleBaseNameA(hProc, hMods[i], modName, sizeof(modName))) {
                    std::string modStr = modName;
                    std::transform(modStr.begin(), modStr.end(), modStr.begin(), [](unsigned char c) {
                        return std::tolower(c);
                    });

                    for (const auto& susMod : suspicious_hook_modules_) {
                        if (modStr.find(susMod) != std::string::npos) {
                            CloseHandle(hProc);
                            EndpointEvent alert;
                            alert.event_type = "KEYLOGGER_INDICATOR";
                            alert.process_name = proc.process_name;
                            alert.pid = proc.pid;
                            alert.parent_pid = proc.parent_pid;
                            alert.exe_path = proc.exe_path;
                            alert.user = proc.user;
                            alert.severity = "CRITICAL";
                            alert.reason = "Process attempted keyboard input monitoring via hook module: " + modStr;
                            return alert;
                        }
                    }
                }
            }
        }
        CloseHandle(hProc);
    }
#endif

    return std::nullopt;
}

void KeyloggerDetector::scanSystemInputHooks() {
#if defined(_WIN32)
    // Enumerate processes and check for input hooks or suspicious DLLs
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            // Ignore system idle / critical OS processes
            if (pe32.th32ProcessID <= 4) continue;

            ProcessInfo p;
            p.pid = pe32.th32ProcessID;
            p.parent_pid = pe32.th32ParentProcessID;

            int size_needed = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, NULL, 0, NULL, NULL);
            std::string procName(size_needed - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &procName[0], size_needed, NULL, NULL);
            p.process_name = procName;

            auto alert = inspectProcess(p);
            if (alert && callback_) {
                callback_(*alert);
            }

        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);

#else
    // Linux: Inspect /proc/*/fd for unauthorized access to /dev/input/*
    DIR* dir = opendir("/proc");
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr == '\0' && pid > 100) {
            std::string fdDir = std::string("/proc/") + entry->d_name + "/fd";
            DIR* fdd = opendir(fdDir.c_str());
            if (fdd) {
                struct dirent* fde;
                while ((fde = readdir(fdd)) != nullptr) {
                    std::string targetLink = fdDir + "/" + fde->d_name;
                    char buf[512] = {0};
                    ssize_t len = readlink(targetLink.c_str(), buf, sizeof(buf) - 1);
                    if (len > 0) {
                        std::string target(buf);
                        if (target.find("/dev/input/event") != std::string::npos) {
                            // Check process name
                            std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
                            std::ifstream cf(commPath);
                            std::string comm;
                            if (cf >> comm) {
                                // Exclude standard Xorg / display servers
                                if (comm != "Xorg" && comm != "gnome-shell" && comm != "wayland") {
                                    EndpointEvent alert;
                                    alert.event_type = "KEYLOGGER_INDICATOR";
                                    alert.process_name = comm;
                                    alert.pid = static_cast<uint32_t>(pid);
                                    alert.severity = "CRITICAL";
                                    alert.reason = "Process attempted keyboard input monitoring via direct /dev/input access";
                                    if (callback_) callback_(alert);
                                }
                            }
                        }
                    }
                }
                closedir(fdd);
            }
        }
    }
    closedir(dir);
#endif
}

} // namespace endpoint
} // namespace caids
