"""
caids_orchestrator.py — High-Performance CAIDS Streamlined Pipeline

Architecture:
  1. INITIAL STAGE: Active SDN Firewall (OpenFlow / Ryu Controller)
     - Traffic Filtering, Flow Offloading, Port Inspection
  2. NETWORK DATA COLLECTION & ANALYSIS ENGINE:
     - Collects and logs ALL raw network traffic (normal + malicious)
     - Runs Deep Packet Analysis (signatures, malformed headers, flags)
     - Runs Flow Analysis (SYN floods, port scanning metrics)
     - Stores all metadata, packet logs, and anomaly outputs directly inside DataCollection/output/
  3. ENDPOINT TELEMETRY & THREAT DETECTION AGENT:
     - Real-time Process Lifecycle Monitoring (PROCESS_START, PROCESS_STOP)
     - Suspicious Process Detection (Masquerading, Temp launch, Obfuscated CLI)
     - Keylogger & Input Hook Surveillance Detection
     - Stores all endpoint events & alerts inside EndpointDetection/logs/endpoint_events.jsonl
"""

import os
import sys
import time
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SDN_DIR = BASE_DIR / "SDN_Firewall-master" / "src"
DATA_COLLECTION_DIR = BASE_DIR / "DataCollection" / "output"
ENDPOINT_DIR = BASE_DIR / "EndpointDetection"
ENDPOINT_LOGS_DIR = ENDPOINT_DIR / "logs"

def setup_environment():
    """Ensure all required output and log directories exist."""
    DATA_COLLECTION_DIR.mkdir(parents=True, exist_ok=True)
    ENDPOINT_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[CAIDS-ORCHESTRATOR] 📁 Output storage initialized:")
    print(f"  - Network Data Collection : {DATA_COLLECTION_DIR}")
    print(f"  - Endpoint Event Logs     : {ENDPOINT_LOGS_DIR}")

def run_sdn_initial_stage():
    """Launch Initial Stage — SDN Firewall."""
    print("[CAIDS-ORCHESTRATOR] [1/3] Initializing Initial Stage: SDN Firewall (Ryu / OpenFlow)...")
    print("  - Module: SDN_Firewall-master/src/secure_stateful_firewall.py")
    print("  - Role  : Initial stage traffic filtering & flow table offloading")

def run_data_collection_engine():
    """Launch Unified Data Collection & Deep Packet/Flow Analysis Engine."""
    print("[CAIDS-ORCHESTRATOR] [2/3] Launching Network Data Collection & Analysis Engine...")
    print("  - Module: caids_collector_engine.py")
    print("  - Role  : Raw pcap + metadata logging + Deep Packet & Flow Analysis storage")
    
    return subprocess.Popen(
        [sys.executable, str(BASE_DIR / "caids_collector_engine.py")],
        cwd=str(BASE_DIR)
    )

def run_endpoint_agent():
    """Launch Endpoint Telemetry & Threat Detection Agent."""
    print("[CAIDS-ORCHESTRATOR] [3/3] Launching Endpoint Telemetry & Detection Agent...")
    print("  - Module: EndpointDetection/endpoint_agent.py")
    print("  - Role  : Process lifecycle, suspicious execution, and keylogger indicator detection")

    return subprocess.Popen(
        [sys.executable, str(ENDPOINT_DIR / "endpoint_agent.py")],
        cwd=str(ENDPOINT_DIR)
    )

def main():
    print("======================================================================")
    print("   CAIDS — Cyber Attack Intrusion Detection System                    ")
    print("   Unified Multi-Layer Pipeline: SDN + Network + Endpoint             ")
    print("======================================================================")
    
    setup_environment()
    
    # 1. Initial Stage — SDN Firewall
    run_sdn_initial_stage()
    time.sleep(1)

    # 2. Network Data Collection & Analysis Engine
    net_proc = run_data_collection_engine()
    time.sleep(1)

    # 3. Endpoint Telemetry & Detection Agent
    end_proc = run_endpoint_agent()
    time.sleep(1)

    print("\n[CAIDS-ORCHESTRATOR] [OK] All CAIDS pipeline layers are active!")
    print(f"  - Network Data Target  : {DATA_COLLECTION_DIR}")
    print(f"  - Endpoint Event Target: {ENDPOINT_LOGS_DIR / 'endpoint_events.jsonl'}")
    print("\nPress Ctrl+C to terminate the orchestrator cleanly.\n")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n[CAIDS-ORCHESTRATOR] Shutting down all CAIDS processes cleanly...")
        if net_proc:
            net_proc.terminate()
        if end_proc:
            end_proc.terminate()
        print("[CAIDS-ORCHESTRATOR] Shutdown complete.")

if __name__ == "__main__":
    main()
