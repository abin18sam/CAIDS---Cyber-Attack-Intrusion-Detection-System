"""
alert_engine.py — CAIDS Honeypot Alert Engine
Stores, reports, and forwards alerts to the CAIDS system.
"""

import json
import os
import threading
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLORS = {
    "LOW":      Fore.CYAN,
    "MEDIUM":   Fore.YELLOW,
    "HIGH":     Fore.RED,
    "CRITICAL": Fore.RED + Style.BRIGHT,
}

SEVERITY_EMOJI = {
    "LOW":      "🔵",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
ALERT_LOG_FILE = os.path.join(LOG_DIR, "alerts.jsonl")

# CAIDS alert bridge — writes to a shared JSON file that C++ can tail
CAIDS_BRIDGE_FILE = os.path.join(LOG_DIR, "caids_bridge.jsonl")


class AlertEngine:
    """Thread-safe alert storage and reporting engine."""

    def __init__(self):
        self._lock = threading.Lock()
        self._alerts: list[dict] = []
        self._alert_id_counter = 0

    def report(
        self,
        ip: str,
        severity: str,
        attack_type: str,
        description: str,
        endpoint: str = "",
        payload_snippet: str = "",
    ) -> dict:
        """Create, store, log, and print an alert."""
        with self._lock:
            self._alert_id_counter += 1
            alert = {
                "id": self._alert_id_counter,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "severity": severity,
                "attack_type": attack_type,
                "source_ip": ip,
                "endpoint": endpoint,
                "description": description,
                "payload_snippet": payload_snippet[:200] if payload_snippet else "",
            }
            self._alerts.append(alert)

        self._print_terminal(alert)
        self._write_log(alert)
        self._write_caids_bridge(alert)
        return alert

    def get_all(self) -> list[dict]:
        with self._lock:
            return list(reversed(self._alerts))

    def get_stats(self) -> dict:
        with self._lock:
            counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for a in self._alerts:
                counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            return {
                "total": len(self._alerts),
                "by_severity": counts,
                "unique_attackers": len({a["source_ip"] for a in self._alerts}),
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _print_terminal(self, alert: dict):
        color = SEVERITY_COLORS.get(alert["severity"], Fore.WHITE)
        emoji = SEVERITY_EMOJI.get(alert["severity"], "⚠️")
        ts = alert["timestamp"]
        print(
            f"\n{color}{'='*70}\n"
            f"{emoji}  [{ts}] HONEYPOT ALERT #{alert['id']}\n"
            f"   Severity  : {alert['severity']}\n"
            f"   Attack    : {alert['attack_type']}\n"
            f"   Source IP : {alert['source_ip']}\n"
            f"   Endpoint  : {alert['endpoint']}\n"
            f"   Details   : {alert['description']}\n"
            + (f"   Payload   : {alert['payload_snippet']}\n" if alert['payload_snippet'] else "")
            + f"{'='*70}{Style.RESET_ALL}"
        )

    def _write_log(self, alert: dict):
        try:
            with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
        except OSError:
            pass

    def _write_caids_bridge(self, alert: dict):
        """Write alert in CAIDS-compatible format for C++ tail-reader."""
        caids_alert = {
            "source": "honeypot",
            "timestamp_utc": alert["timestamp"],
            "severity": alert["severity"],
            "src_ip": alert["source_ip"],
            "attack_type": alert["attack_type"],
            "description": alert["description"],
            "endpoint": alert["endpoint"],
        }
        try:
            with open(CAIDS_BRIDGE_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(caids_alert) + "\n")
        except OSError:
            pass


# Global singleton
engine = AlertEngine()
