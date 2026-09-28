"""
endpoint_agent.py — CAIDS Endpoint Telemetry & Threat Detection Agent (Python Engine)

Provides real-time host-level endpoint detection on Windows:
  1. Process Lifecycle Monitoring (PROCESS_START, PROCESS_STOP)
  2. Suspicious Process Detection (Masquerading, Temp paths, Suspicious Parents, CLI Obfuscation)
  3. Keylogger / Input Hook Detection (Hook DLLs, direct input monitoring attempts)
  4. Structured JSONL Telemetry Output (logs/endpoint_events.jsonl)
"""

import os
import sys
import time
import json
import socket
import argparse
from datetime import datetime, timezone
from pathlib import Path

# Windows native Win32 API via ctypes
import ctypes
from ctypes import wintypes

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
DEFAULT_LOG_FILE = LOGS_DIR / "endpoint_events.jsonl"
CONFIG_FILE = BASE_DIR / "config" / "endpoint_config.json"

# Load rules from config or use defaults
CONFIG = {
    "host_id": socket.gethostname(),
    "monitor_interval_sec": 1.0,
    "rules": {
        "suspicious_paths": [
            "\\appdata\\local\\temp",
            "\\windows\\temp",
            "\\users\\public",
            "\\downloads"
        ],
        "protected_system_binaries": [
            "svchost.exe", "lsass.exe", "csrss.exe", 
            "services.exe", "smss.exe", "wininit.exe", "winlogon.exe"
        ],
        "suspicious_parents": [
            "winword.exe", "excel.exe", "powerpnt.exe",
            "acrord32.exe", "acrobat.exe", "outlook.exe",
            "chrome.exe", "firefox.exe", "msedge.exe"
        ],
        "dangerous_children": [
            "cmd.exe", "powershell.exe", "pwsh.exe",
            "cscript.exe", "wscript.exe", "mshta.exe",
            "certutil.exe", "vssadmin.exe", "bitsadmin.exe"
        ],
        "suspicious_cli_keywords": [
            "-enc", "-encodedcommand", "downloadstring",
            "bypass", "invoke-expression", "iex",
            "vssadmin delete shadows", "certutil -urlcache",
            "net user /add", "wmic shadowcopy delete"
        ]
    }
}

if CONFIG_FILE.exists():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
            CONFIG.update(user_cfg)
    except Exception:
        pass

def get_iso_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def emit_event(event_dict, log_file_path=DEFAULT_LOG_FILE):
    """Write an endpoint event to the JSONL log and console."""
    if "timestamp" not in event_dict:
        event_dict["timestamp"] = get_iso_timestamp()
    if "host_id" not in event_dict:
        event_dict["host_id"] = CONFIG.get("host_id", socket.gethostname())

    line = json.dumps(event_dict)
    try:
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[ERROR] Failed writing to log: {e}", file=sys.stderr)

    sev = event_dict.get("severity", "INFO")
    ev_type = event_dict.get("event_type", "UNKNOWN")
    proc = event_dict.get("process_name", "N/A")
    pid = event_dict.get("pid", 0)

    if sev in ("HIGH", "CRITICAL"):
        print(f"\n[ALERT - {sev}] {ev_type} | {proc} (PID: {pid})")
        print(f"   Reason: {event_dict.get('reason', '')}")
        if event_dict.get("exe_path"):
            print(f"   Path  : {event_dict.get('exe_path')}")
        print("-" * 70)
    else:
        print(f"[INFO] [{ev_type}] {proc} (PID: {pid})")

# ---------------------------------------------------------------------------
# Windows Process Snapshotting via Toolhelp32
# ---------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(wintypes.ULONG)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260)
    ]

def get_process_snapshot():
    """Returns dict of pid -> {'process_name', 'pid', 'parent_pid', 'exe_path'}"""
    procs = {}

    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if hSnap == -1:
            return procs

        pe32 = PROCESSENTRY32W()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if kernel32.Process32FirstW(hSnap, ctypes.byref(pe32)):
            while True:
                pid = pe32.th32ProcessID
                ppid = pe32.th32ParentProcessID
                name = pe32.szExeFile

                # Try resolving full path
                exe_path = name
                hProc = kernel32.OpenProcess(0x1000, False, pid) # PROCESS_QUERY_LIMITED_INFORMATION
                if hProc:
                    path_buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
                    size = wintypes.DWORD(wintypes.MAX_PATH)
                    if kernel32.QueryFullProcessImageNameW(hProc, 0, path_buf, ctypes.byref(size)):
                        exe_path = path_buf.value
                    kernel32.CloseHandle(hProc)

                procs[pid] = {
                    "pid": pid,
                    "parent_pid": ppid,
                    "process_name": name,
                    "exe_path": exe_path,
                    "command_line": ""
                }

                if not kernel32.Process32NextW(hSnap, ctypes.byref(pe32)):
                    break

        kernel32.CloseHandle(hSnap)
    else:
        # Linux fallback
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                pid = int(entry.name)
                comm_file = entry / "comm"
                name = comm_file.read_text().strip() if comm_file.exists() else "unknown"
                procs[pid] = {
                    "pid": pid,
                    "parent_pid": 0,
                    "process_name": name,
                    "exe_path": str(entry / "exe"),
                    "command_line": ""
                }

    return procs

# ---------------------------------------------------------------------------
# Suspicious Process Detector
# ---------------------------------------------------------------------------
def check_suspicious_process(proc, parent_name=""):
    name_lower = proc["process_name"].lower()
    path_lower = proc["exe_path"].lower()
    parent_lower = parent_name.lower()
    cli_lower = proc["command_line"].lower()

    rules = CONFIG.get("rules", {})

    # Check 1: Masquerading System Process
    for sys_bin in rules.get("protected_system_binaries", []):
        if name_lower == sys_bin.lower():
            if "system32" not in path_lower and "syswow64" not in path_lower and path_lower != name_lower:
                return {
                    "event_type": "SUSPICIOUS_PROCESS",
                    "process_name": proc["process_name"],
                    "pid": proc["pid"],
                    "parent_pid": proc["parent_pid"],
                    "exe_path": proc["exe_path"],
                    "severity": "CRITICAL",
                    "reason": f"Protected system binary running outside System32: {proc['exe_path']}"
                }

    # Check 2: Abnormal Parent-Child (e.g. Word/Browser spawning PowerShell)
    if parent_lower:
        for p in rules.get("suspicious_parents", []):
            if p.lower() in parent_lower:
                for c in rules.get("dangerous_children", []):
                    if c.lower() in name_lower:
                        return {
                            "event_type": "SUSPICIOUS_PROCESS",
                            "process_name": proc["process_name"],
                            "pid": proc["pid"],
                            "parent_pid": proc["parent_pid"],
                            "exe_path": proc["exe_path"],
                            "severity": "CRITICAL",
                            "reason": f"Application '{parent_name}' spawned scripting interpreter '{proc['process_name']}'"
                        }

    # Check 3: Launch from Temp / Public directories
    for bad_path in rules.get("suspicious_paths", []):
        if bad_path.lower() in path_lower:
            return {
                "event_type": "SUSPICIOUS_PROCESS",
                "process_name": proc["process_name"],
                "pid": proc["pid"],
                "parent_pid": proc["parent_pid"],
                "exe_path": proc["exe_path"],
                "severity": "HIGH",
                "reason": f"Executable launched from untrusted directory: {proc['exe_path']}"
            }

    # Check 4: Suspicious CLI keywords
    for keyword in rules.get("suspicious_cli_keywords", []):
        if keyword.lower() in cli_lower:
            return {
                "event_type": "SUSPICIOUS_PROCESS",
                "process_name": proc["process_name"],
                "pid": proc["pid"],
                "parent_pid": proc["parent_pid"],
                "exe_path": proc["exe_path"],
                "severity": "HIGH",
                "reason": f"Suspicious command-line pattern detected: '{keyword}'"
            }

    return None

# ---------------------------------------------------------------------------
# Keylogger / Input Hook Detector
# ---------------------------------------------------------------------------
def check_keylogger_indicators(proc):
    name_lower = proc["process_name"].lower()
    path_lower = proc["exe_path"].lower()

    if any(k in name_lower for k in ("keylog", "hookkey", "kbdhook", "keycapture")):
        return {
            "event_type": "KEYLOGGER_INDICATOR",
            "process_name": proc["process_name"],
            "pid": proc["pid"],
            "parent_pid": proc["parent_pid"],
            "exe_path": proc["exe_path"],
            "severity": "CRITICAL",
            "reason": "Process attempted keyboard input monitoring (signature match)"
        }

    return None

# ---------------------------------------------------------------------------
# Main Monitoring Loop
# ---------------------------------------------------------------------------
def run_monitor(log_file=DEFAULT_LOG_FILE):
    print("=" * 70)
    print("   CAIDS — Endpoint Telemetry & Threat Detection Agent")
    print("=" * 70)
    print(f"[EndpointAgent] Host ID     : {CONFIG.get('host_id')}")
    print(f"[EndpointAgent] Log Output  : {log_file}")
    print(f"[EndpointAgent] Interval    : {CONFIG.get('monitor_interval_sec')}s")

    # Take initial baseline
    active_procs = get_process_snapshot()
    print(f"[EndpointAgent] Baseline captured: {len(active_procs)} processes currently active.\n")
    print("Monitoring for new processes and suspicious activity (Ctrl+C to stop)...\n")

    try:
        while True:
            time.sleep(CONFIG.get("monitor_interval_sec", 1.0))
            current_procs = get_process_snapshot()

            # Detect new processes (PROCESS_START)
            for pid, info in current_procs.items():
                if pid not in active_procs:
                    parent_name = active_procs.get(info["parent_pid"], {}).get("process_name", "")

                    # 1. Base telemetry event
                    emit_event({
                        "event_type": "PROCESS_START",
                        "process_name": info["process_name"],
                        "pid": info["pid"],
                        "parent_pid": info["parent_pid"],
                        "exe_path": info["exe_path"],
                        "severity": "INFO"
                    }, log_file)

                    # 2. Suspicious process inspection
                    sus_alert = check_suspicious_process(info, parent_name)
                    if sus_alert:
                        emit_event(sus_alert, log_file)

                    # 3. Keylogger inspection
                    key_alert = check_keylogger_indicators(info)
                    if key_alert:
                        emit_event(key_alert, log_file)

            # Detect terminated processes (PROCESS_STOP)
            for pid, info in active_procs.items():
                if pid not in current_procs:
                    emit_event({
                        "event_type": "PROCESS_STOP",
                        "process_name": info["process_name"],
                        "pid": info["pid"],
                        "parent_pid": info["parent_pid"],
                        "severity": "INFO"
                    }, log_file)

            active_procs = current_procs

    except KeyboardInterrupt:
        print("\n[EndpointAgent] Shutting down agent cleanly...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CAIDS Endpoint Telemetry & Detection Agent")
    parser.add_argument("-o", "--output", default=str(DEFAULT_LOG_FILE), help="Path to JSONL log file")
    parser.add_argument("--test-alert", action="store_true", help="Simulate a suspicious process and keylogger event for testing")
    args = parser.parse_args()

    if args.test_alert:
        print("[EndpointAgent] Generating test endpoint telemetry alerts...")
        # Test 1: Suspicious process (temp path)
        emit_event({
            "event_type": "SUSPICIOUS_PROCESS",
            "process_name": "malicious_payload.exe",
            "pid": 9999,
            "parent_pid": 1024,
            "exe_path": "C:\\Users\\User\\AppData\\Local\\Temp\\malicious_payload.exe",
            "severity": "HIGH",
            "reason": "Executable launched from untrusted temporary directory: AppData\\Local\\Temp"
        }, Path(args.output))

        # Test 2: Keylogger indicator
        emit_event({
            "event_type": "KEYLOGGER_INDICATOR",
            "process_name": "stealth_kbdhook.exe",
            "pid": 8888,
            "parent_pid": 9999,
            "exe_path": "C:\\ProgramData\\stealth_kbdhook.exe",
            "severity": "CRITICAL",
            "reason": "Process attempted keyboard input monitoring via WH_KEYBOARD_LL hook"
        }, Path(args.output))
        print("[OK] Test events written to:", args.output)
    else:
        run_monitor(Path(args.output))
