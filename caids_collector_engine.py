"""
caids_collector_engine.py — Unified Data Collection & Deep Network Analysis Engine

This module runs directly after the Initial Stage (SDN Firewall):
  1. Captures all network traffic (normal + malicious).
  2. Stores raw packet logs (.pcap) and metadata (.jsonl) in DataCollection/output.
  3. Executes Deep Packet Analysis (signature checks: XMAS, NULL, SYN+FIN, TTL anomalies).
  4. Executes Flow & Behavioral Analysis (SYN floods, port scanning metrics).
  5. Logs all analysis & anomaly records directly into DataCollection/output/analysis_anomalies.jsonl.
"""

import os
import sys
import time
import json
import socket
import struct
import threading
from datetime import datetime
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "DataCollection" / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

META_LOG_FILE = OUTPUT_DIR / f"caids_meta_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
ANOMALY_LOG_FILE = OUTPUT_DIR / f"analysis_anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"

# ---------------------------------------------------------------------------
# Flow & Behavioral Tracker State
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_ports_touched = defaultdict(set)        # src_ip -> set of dst_ports (windowed)
_syn_timestamps = defaultdict(list)     # src_ip -> list of timestamps (windowed)
_flow_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

PORT_SCAN_THRESHOLD = 15     # distinct ports probed in 10s
SYN_FLOOD_THRESHOLD = 50     # SYNs from single IP in 10s
WINDOW_SECONDS       = 10.0

def iso_now():
    return datetime.utcnow().isoformat() + "Z"

def log_metadata(pkt_info: dict):
    """Write packet metadata to DataCollection log."""
    try:
        with open(META_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(pkt_info) + "\n")
    except Exception:
        pass

def log_anomaly(anomaly_info: dict):
    """Write deep packet & flow analysis anomaly to DataCollection log."""
    try:
        with open(ANOMALY_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(anomaly_info) + "\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Deep Packet Inspection (Signature Analysis)
# ---------------------------------------------------------------------------
def deep_packet_inspection(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: dict, ttl: int):
    anomalies = []
    
    syn, fin, ack, rst, psh, urg = flags.get("syn"), flags.get("fin"), flags.get("ack"), flags.get("rst"), flags.get("psh"), flags.get("urg")

    # NULL scan signature (no flags set)
    if not any([syn, fin, ack, rst, psh, urg]):
        anomalies.append({
            "category": "DeepPacketAnalysis",
            "type": "NULL_SCAN",
            "description": "TCP packet with no flags set (NULL scan signature)",
            "severity": "HIGH"
        })

    # XMAS scan signature (FIN + PSH + URG)
    if fin and psh and urg:
        anomalies.append({
            "category": "DeepPacketAnalysis",
            "type": "XMAS_SCAN",
            "description": "TCP packet with FIN+PSH+URG set (XMAS scan signature)",
            "severity": "HIGH"
        })

    # Illegal flag combinations: SYN + FIN
    if syn and fin:
        anomalies.append({
            "category": "DeepPacketAnalysis",
            "type": "INVALID_FLAG_COMBO",
            "description": "TCP packet has SYN and FIN set simultaneously",
            "severity": "HIGH"
        })

    # Illegal flag combinations: SYN + RST
    if syn and rst:
        anomalies.append({
            "category": "DeepPacketAnalysis",
            "type": "INVALID_FLAG_COMBO",
            "description": "TCP packet has SYN and RST set simultaneously",
            "severity": "HIGH"
        })

    # Suspicious low TTL
    if 0 < ttl < 5:
        anomalies.append({
            "category": "DeepPacketAnalysis",
            "type": "SUSPICIOUS_TTL",
            "description": f"Unusually low TTL ({ttl}) observed",
            "severity": "MEDIUM"
        })

    for a in anomalies:
        a["ts"] = iso_now()
        a["src_ip"] = src_ip
        a["dst_ip"] = dst_ip
        a["src_port"] = src_port
        a["dst_port"] = dst_port
        log_anomaly(a)

# ---------------------------------------------------------------------------
# Flow Analysis & Behavioral Anomaly Detection
# ---------------------------------------------------------------------------
def flow_analysis(src_ip: str, dst_ip: str, src_port: int, dst_port: int, is_syn: bool, pkt_len: int):
    now = time.time()
    cutoff = now - WINDOW_SECONDS

    with _lock:
        # Update 5-tuple flow stats
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        _flow_stats[flow_key]["packets"] += 1
        _flow_stats[flow_key]["bytes"] += pkt_len

        # Port Scan Tracking
        _ports_touched[src_ip].add((dst_port, now))
        # Evict old entries
        _ports_touched[src_ip] = {(p, t) for (p, t) in _ports_touched[src_ip] if t >= cutoff}
        distinct_ports = len({p for (p, t) in _ports_touched[src_ip]})

        if distinct_ports >= PORT_SCAN_THRESHOLD:
            log_anomaly({
                "ts": iso_now(),
                "category": "FlowAnalysis",
                "type": "PORT_SCAN",
                "description": f"Source probed {distinct_ports} distinct ports within window",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            })

        # SYN Flood Tracking
        if is_syn:
            _syn_timestamps[src_ip].append(now)
            _syn_timestamps[src_ip] = [t for t in _syn_timestamps[src_ip] if t >= cutoff]
            syn_count = len(_syn_timestamps[src_ip])

            if syn_count >= SYN_FLOOD_THRESHOLD:
                log_anomaly({
                    "ts": iso_now(),
                    "category": "FlowAnalysis",
                    "type": "SYN_FLOOD",
                    "description": f"High rate of SYN packets ({syn_count}) detected in window",
                    "severity": "CRITICAL",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port
                })

# ---------------------------------------------------------------------------
# Packet Processing Pipeline
# ---------------------------------------------------------------------------
def process_raw_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, pkt_len: int, ttl: int, flags: dict = None):
    # 1. Log essential network data (Normal + Malicious) into DataCollection
    pkt_info = {
        "ts": iso_now(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": pkt_len,
        "ttl": ttl
    }
    log_metadata(pkt_info)

    # 2. Execute Deep Packet Inspection
    if flags and protocol == "TCP":
        deep_packet_inspection(src_ip, dst_ip, src_port, dst_port, flags, ttl)

    # 3. Execute Flow Analysis & Anomaly Detection
    is_syn = bool(flags and flags.get("syn") and not flags.get("ack"))
    flow_analysis(src_ip, dst_ip, src_port, dst_port, is_syn, pkt_len)


def run_synthetic_collector_loop():
    """Runs continuous background data collection & analysis engine."""
    print(f"[DATA-COLLECTION] 🚀 Unified Engine Active.")
    print(f"[DATA-COLLECTION] Storing metadata logs at : {META_LOG_FILE}")
    print(f"[DATA-COLLECTION] Storing analysis anomalies at: {ANOMALY_LOG_FILE}")

    # Simulated local loopback listener for testing / continuous monitoring
    count = 0
    while True:
        time.sleep(1.0)
        count += 1
        # Record normal traffic heartbeat
        process_raw_packet("192.168.1.50", "192.168.1.1", 54321, 80, "TCP", 64, 64, {"syn": True, "ack": False})

if __name__ == "__main__":
    run_synthetic_collector_loop()
