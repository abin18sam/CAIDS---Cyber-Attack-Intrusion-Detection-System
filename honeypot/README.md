# CAIDS Honeypot Module

## Overview

This module runs a **decoy AI model server** (honeypot) with a fake database credential secret embedded inside. A **Firewall Monitor** inspects every inbound connection and generates alerts for malicious activity.

---

## Quick Start

```bash
cd honeypot

# Install dependencies (once)
pip install -r requirements.txt

# Start the honeypot system
python run.py
```

- **Decoy Model API** → `http://localhost:5000`
- **Live Dashboard**  → `http://localhost:5001/dashboard`

---

## What's Inside the Model (The Secret)

A fake **database credential JSON** is encrypted using Fernet symmetric encryption and embedded in the model server:

```json
{
  "host":     "prod-db-01.internal.caids-corp.com",
  "port":     5432,
  "database": "caids_production",
  "username": "caids_admin",
  "password": "xK#9mP$2rLqN@vT7!bYu",
  "ssl_mode": "require"
}
```

Any attempt to access or exfiltrate this triggers a **CRITICAL** alert.

---

## Firewall Detection Rules

| Detection | Trigger | Severity |
|---|---|---|
| Secret Exfiltration | Accessing `/admin`, `/secret`, `/config`, `/.env`, `/credentials` | CRITICAL |
| Deep Honeypot Breach | Reaching `/admin/credentials` breadcrumb | CRITICAL |
| SQL Injection / XSS / Path Traversal / RCE | Malicious patterns in URL or body | HIGH |
| Brute-Force / Rate Flood | >10 requests / 10 seconds | HIGH |
| Suspicious Scanner UA | User-Agent matching sqlmap, nikto, nmap, etc. | MEDIUM |
| Endpoint Scanning | ≥5 distinct 404s in 30 seconds | MEDIUM |

---

## Alert Output

1. **Terminal** — colored, real-time with severity badges
2. **Web Dashboard** — `http://localhost:5001/dashboard` — auto-refreshes every 3s
3. **Log file** — `honeypot/logs/alerts.jsonl` (append-only JSON Lines)
4. **CAIDS Bridge** — `honeypot/logs/caids_bridge.jsonl` — C++ integration (see below)

---

## CAIDS C++ Integration

The honeypot writes all alerts to `honeypot/logs/caids_bridge.jsonl` in this format:

```json
{
  "source":        "honeypot",
  "timestamp_utc": "2024-11-15T10:23:01Z",
  "severity":      "CRITICAL",
  "src_ip":        "192.168.1.42",
  "attack_type":   "Secret Exfiltration / Honeypot Triggered",
  "description":   "...",
  "endpoint":      "/admin"
}
```

Your C++ `caids_nids` can tail this file and ingest honeypot alerts alongside packet-level alerts. A simple integration loop:

```cpp
// Pseudocode: tail caids_bridge.jsonl and parse each line as an Alert
std::ifstream bridge("honeypot/logs/caids_bridge.jsonl");
std::string line;
while (std::getline(bridge, line)) {
    auto alert = parseHoneypotAlert(line);  // map to your Alert struct
    alertSink.emit(alert);
}
```

---

## Simulate Attacks (for Testing)

Run these in a separate terminal while the honeypot is running:

```bash
# Trigger CRITICAL — honeypot endpoint
curl http://localhost:5000/admin
curl http://localhost:5000/secret
curl http://localhost:5000/.env

# Trigger CRITICAL — breadcrumb trail
curl http://localhost:5000/admin/credentials

# Trigger HIGH — SQL injection
curl "http://localhost:5000/query?q=' OR 1=1--"

# Trigger HIGH — rate flood (run 15 rapid requests)
for i in {1..15}; do curl -s http://localhost:5000/status; done

# Trigger MEDIUM — scanner user-agent
curl -A "sqlmap/1.0" http://localhost:5000/predict

# Trigger MEDIUM — endpoint scan (visit many unknown paths)
for path in /wp-admin /phpinfo.php /backup /.git /api/keys /db/dump; do
  curl -s http://localhost:5000$path
done
```
