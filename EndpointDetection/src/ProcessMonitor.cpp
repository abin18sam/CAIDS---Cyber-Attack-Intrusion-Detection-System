#include "ProcessMonitor.h"
#include <iostream>
#include <algorithm>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>
#pragma comment(lib, "Advapi32.lib")
#else
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <pwd.h>
#endif

namespace caids {
namespace endpoint {

ProcessMonitor::ProcessMonitor(int interval_ms)
    : interval_ms_(interval_ms) {}

ProcessMonitor::~ProcessMonitor() {
    stop();
}

void ProcessMonitor::setEventCallback(ProcessEventCallback cb) {
    callback_ = cb;
}

bool ProcessMonitor::start() {
    if (running_) return false;
    running_ = true;

    // Populate initial baseline
    active_processes_ = captureProcessSnapshot();
    std::cout << "[ProcessMonitor] Baseline captured with " << active_processes_.size() << " running processes.\n";

    worker_thread_ = std::thread(&ProcessMonitor::monitorLoop, this);
    return true;
}

void ProcessMonitor::stop() {
    if (running_) {
        running_ = false;
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }
}

void ProcessMonitor::monitorLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
        if (!running_) break;
        scanOnce();
    }
}

void ProcessMonitor::scanOnce() {
    auto current_snapshot = captureProcessSnapshot();

    // 1. Detect new processes (PROCESS_START)
    for (const auto& [pid, info] : current_snapshot) {
        if (active_processes_.find(pid) == active_processes_.end()) {
            if (callback_) {
                callback_(info, "PROCESS_START");
            }
        }
    }

    // 2. Detect terminated processes (PROCESS_STOP)
    for (const auto& [pid, info] : active_processes_) {
        if (current_snapshot.find(pid) == current_snapshot.end()) {
            if (callback_) {
                callback_(info, "PROCESS_STOP");
            }
        }
    }

    active_processes_ = std::move(current_snapshot);
}

std::unordered_map<uint32_t, ProcessInfo> ProcessMonitor::captureProcessSnapshot() {
    std::unordered_map<uint32_t, ProcessInfo> snapshot;

#if defined(_WIN32)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return snapshot;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.parent_pid = pe32.th32ParentProcessID;

            // Convert wide char process name
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, NULL, 0, NULL, NULL);
            std::string procName(size_needed - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, &procName[0], size_needed, NULL, NULL);
            info.process_name = procName;
            info.start_time = std::chrono::system_clock::now();

            // Try to resolve full path and user if permissions allow
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProc) {
                wchar_t pathBuf[MAX_PATH];
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pathLen)) {
                    int pSize = WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, NULL, 0, NULL, NULL);
                    std::string fullPath(pSize - 1, 0);
                    WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, &fullPath[0], pSize, NULL, NULL);
                    info.exe_path = fullPath;
                }

                // Query process token user
                HANDLE hToken = NULL;
                if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                    DWORD tokenLen = 0;
                    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenLen);
                    if (tokenLen > 0) {
                        std::vector<BYTE> tokenBuf(tokenLen);
                        if (GetTokenInformation(hToken, TokenUser, tokenBuf.data(), tokenLen, &tokenLen)) {
                            TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(tokenBuf.data());
                            wchar_t nameBuf[256];
                            DWORD nameLen = 256;
                            wchar_t domBuf[256];
                            DWORD domLen = 256;
                            SID_NAME_USE sidUse;
                            if (LookupAccountSidW(NULL, pTokenUser->User.Sid, nameBuf, &nameLen, domBuf, &domLen, &sidUse)) {
                                int uSize = WideCharToMultiByte(CP_UTF8, 0, nameBuf, -1, NULL, 0, NULL, NULL);
                                std::string userName(uSize - 1, 0);
                                WideCharToMultiByte(CP_UTF8, 0, nameBuf, -1, &userName[0], uSize, NULL, NULL);
                                info.user = userName;
                            }
                        }
                    }
                    CloseHandle(hToken);
                }

                CloseHandle(hProc);
            }

            if (info.exe_path.empty()) {
                info.exe_path = info.process_name;
            }

            snapshot[info.pid] = info;

        } while (Process32NextW(hSnap, &pe32));
    }

    CloseHandle(hSnap);

#else
    // Linux /proc scanning fallback
    DIR* dir = opendir("/proc");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type == DT_DIR) {
                char* endptr;
                long pid = strtol(entry->d_name, &endptr, 10);
                if (*endptr == '\0' && pid > 0) {
                    ProcessInfo info;
                    info.pid = static_cast<uint32_t>(pid);

                    std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
                    std::ifstream commFile(commPath);
                    if (commFile.is_open()) {
                        std::getline(commFile, info.process_name);
                    }

                    std::string statPath = std::string("/proc/") + entry->d_name + "/stat";
                    std::ifstream statFile(statPath);
                    if (statFile.is_open()) {
                        std::string ppid_str;
                        // Skip pid and comm in stat
                        std::string token;
                        int idx = 0;
                        while (statFile >> token) {
                            if (idx == 3) {
                                info.parent_pid = std::stoul(token);
                                break;
                            }
                            idx++;
                        }
                    }

                    char exeBuf[1024];
                    std::string exeLink = std::string("/proc/") + entry->d_name + "/exe";
                    ssize_t len = readlink(exeLink.c_str(), exeBuf, sizeof(exeBuf) - 1);
                    if (len != -1) {
                        exeBuf[len] = '\0';
                        info.exe_path = exeBuf;
                    }

                    snapshot[info.pid] = info;
                }
            }
        }
        closedir(dir);
    }
#endif

    return snapshot;
}

} // namespace endpoint
} // namespace caids
