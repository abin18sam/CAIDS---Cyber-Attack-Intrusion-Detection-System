# CAIDS Endpoint Telemetry & Threat Detection Agent

> **Host-level endpoint telemetry, process lifecycle tracking, suspicious process detection, and keyboard input monitoring detector for the CAIDS pipeline.**

---

## 📁 Directory Structure

```text
EndpointDetection/
├── include/
│   ├── EndpointEvent.h              ← Standard event data structure & JSON serialization
│   ├── EventCollector.h             ← Thread-safe JSONL emitter & file writer
│   ├── ProcessMonitor.h             ← Process lifecycle tracker (PROCESS_START / PROCESS_STOP)
│   ├── SuspiciousProcessDetector.h  ← Masquerading, temp paths, suspicious parent detector
│   └── KeyloggerDetector.h          ← Input-hook & keyboard surveillance detector
│
├── src/
│   ├── EndpointEvent.cpp
│   ├── EventCollector.cpp
│   ├── ProcessMonitor.cpp
│   ├── SuspiciousProcessDetector.cpp
│   ├── KeyloggerDetector.cpp
│   └── main.cpp                     ← Standalone C++ agent daemon
│
├── config/
│   └── endpoint_config.json         ← Detection thresholds & rule configuration
│
├── logs/
│   └── endpoint_events.jsonl        ← Central JSONL stream for Threat Correlation
│
├── CMakeLists.txt                   ← CMake build configuration
├── endpoint_agent.py                ← Native Python agent (zero-dependency, ready-to-run)
└── README.md                        ← This file
```

---

## 🛡️ Detection Modules

### 1. Endpoint Event Collector
Emits standardized JSONL telemetry into `logs/endpoint_events.jsonl`:
```json
{
  "timestamp": "2026-09-28T05:10:00.481Z",
  "host_id": "HOST-001",
  "event_type": "PROCESS_START",
  "process_name": "powershell.exe",
  "pid": 4520,
  "parent_pid": 1024,
  "user": "abin",
  "exe_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "severity": "INFO"
}
```

### 2. Process Monitor
Continuously captures process creation and termination diffs:
- Tracks `pid`, `parent_pid`, `process_name`, and executable path.
- Generates `PROCESS_START` and `PROCESS_STOP` events.

### 3. Suspicious Process Detector
Inspects every newly spawned process against high-risk indicators:
- **Masquerading System Binaries**: Detects protected system processes (`svchost.exe`, `lsass.exe`, `csrss.exe`) executing outside `System32`.
- **Abnormal Parent-Child Spawns**: Flags Office applications (`winword.exe`, `excel.exe`) or browsers launching shells (`cmd.exe`, `powershell.exe`).
- **Untrusted Launch Paths**: Flags execution from `AppData\Local\Temp`, `Windows\Temp`, or public directories.
- **Obfuscated CLI Arguments**: Flags `-enc`, `bypass`, `downloadstring`, `iex`, `vssadmin delete shadows`.

### 4. Keylogger / Input Hook Detector
Detects attempts by software to monitor keyboard input (does **NOT** record keystrokes):
- Scans for low-level keyboard hooks (`WH_KEYBOARD` / `WH_KEYBOARD_LL`).
- Detects known keylogger DLLs (`hook.dll`, `kbdlog.dll`, `keylogger.dll`, `spy.dll`).
- Flags unauthorized `/dev/input/` access on Linux or raw input monitoring attempts.

---

## 🚀 How to Run

### Option A: Run the Native Python Agent (Zero Setup)
```bash
# Start live endpoint telemetry and threat monitoring:
python EndpointDetection/endpoint_agent.py

# Simulate test alerts:
python EndpointDetection/endpoint_agent.py --test-alert
```

### Option B: Build & Run the C++ Binary (CMake)
```bash
cd EndpointDetection
mkdir build && cd build
cmake ..
cmake --build . --config Release
./caids_endpoint_agent
```

---

## 🔗 Output Log Location
All telemetry and detected alerts are streamed live to:
`EndpointDetection/logs/endpoint_events.jsonl`
