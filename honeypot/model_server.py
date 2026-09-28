"""
model_server.py — CAIDS Honeypot Decoy AI Model Server
Runs on port 5000. Appears to be an AI inference API but is a trap.
The "secret" database credentials are encrypted at rest.
"""

import os
import json
import base64
import hashlib
import time
import threading
from datetime import datetime
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# Secret: encrypted fake database credentials
# ---------------------------------------------------------------------------

# The "secret" is a realistic-looking database credential object
_PLAINTEXT_SECRET = json.dumps({
    "host":     "prod-db-01.internal.caids-corp.com",
    "port":     5432,
    "database": "caids_production",
    "username": "caids_admin",
    "password": "xK#9mP$2rLqN@vT7!bYu",
    "ssl_mode": "require",
    "max_conn":  20,
    "note":     "CAIDS production database — DO NOT SHARE"
}, indent=2)

# Generate a stable encryption key from a passphrase (stored separately in reality)
_MASTER_PASSPHRASE = b"CAIDS-HONEYPOT-MASTER-KEY-v1"
_KEY_MATERIAL = hashlib.sha256(_MASTER_PASSPHRASE).digest()
_FERNET_KEY   = base64.urlsafe_b64encode(_KEY_MATERIAL)
_cipher       = Fernet(_FERNET_KEY)

# Encrypt the secret — this is what's "stored in the model"
_ENCRYPTED_SECRET = _cipher.encrypt(_PLAINTEXT_SECRET.encode())

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["PROPAGATE_EXCEPTIONS"] = False

# Import and register firewall middleware AFTER app is created
import firewall_monitor

app.before_request(firewall_monitor.before_request_hook)
app.after_request(firewall_monitor.after_request_hook)

# ---------------------------------------------------------------------------
# Fake model state (convincing cover story)
# ---------------------------------------------------------------------------

_model_metadata = {
    "name":    "CAIDS-ThreatClassifier-v2.1",
    "version": "2.1.4",
    "type":    "binary-classifier",
    "classes": ["benign", "malicious"],
    "accuracy": 0.9847,
    "deployed": "2024-11-15T09:00:00Z",
    "status":   "online",
}

_request_counter = 0
_start_time      = time.time()
_counter_lock    = threading.Lock()


def _tick():
    global _request_counter
    with _counter_lock:
        _request_counter += 1
        return _request_counter


# ---------------------------------------------------------------------------
# Public (benign-looking) endpoints
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "CAIDS Threat Classifier API",
        "version": _model_metadata["version"],
        "status":  "online",
        "docs":    "/api/v1/docs",
        "health":  "/status",
    })


@app.route("/status", methods=["GET"])
def status():
    uptime = round(time.time() - _start_time, 1)
    return jsonify({
        "status":           "healthy",
        "uptime_seconds":   uptime,
        "requests_served":  _request_counter,
        "model":            _model_metadata,
        "timestamp":        datetime.utcnow().isoformat() + "Z",
    })


@app.route("/predict", methods=["POST"])
def predict():
    _tick()
    payload = request.get_json(silent=True) or {}
    features = payload.get("features", [])

    if not isinstance(features, list) or len(features) == 0:
        return jsonify({"error": "Provide 'features' as a non-empty list."}), 400

    # Fake inference result
    score     = round(abs(hash(str(features)) % 1000) / 1000.0, 4)
    label     = "malicious" if score > 0.5 else "benign"
    return jsonify({
        "prediction":   label,
        "confidence":   score,
        "model":        _model_metadata["name"],
        "request_id":   f"req-{_tick():06d}",
        "processed_at": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/query", methods=["GET", "POST"])
def query():
    _tick()
    q = request.args.get("q", "") or (request.get_json(silent=True) or {}).get("q", "")
    return jsonify({
        "query":        q,
        "result":       "No matching records found.",
        "elapsed_ms":   12,
        "request_id":   f"qry-{_tick():06d}",
    })


@app.route("/api/v1/docs", methods=["GET"])
def docs():
    return jsonify({
        "endpoints": [
            {"path": "/predict",  "method": "POST", "description": "Run threat classification"},
            {"path": "/query",    "method": "GET",  "description": "Query detection history"},
            {"path": "/status",   "method": "GET",  "description": "Health check"},
        ]
    })


# ---------------------------------------------------------------------------
# HONEYPOT sensitive endpoints — accessible but always alert
# (firewall_monitor.py fires the alert; these return fake data to keep
#  the attacker engaged / gather more intelligence)
# ---------------------------------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin/", methods=["GET", "POST"])
def admin():
    # Deliberately slow response to simulate a real admin panel loading
    time.sleep(0.3)
    # Return a fake "access denied" that looks like it almost worked
    return jsonify({
        "error":   "Unauthorized",
        "message": "Admin access requires MFA token. Contact security@caids-corp.com.",
        "code":    403,
    }), 403


@app.route("/secret", methods=["GET"])
@app.route("/.env", methods=["GET"])
@app.route("/config", methods=["GET"])
def secret_endpoint():
    # Return convincing fake error — real attacker thinks they're close
    return jsonify({
        "error":   "Forbidden",
        "hint":    "Try /admin/credentials with valid session token.",
        "code":    403,
    }), 403


@app.route("/admin/credentials", methods=["GET", "POST"])
def credentials_trap():
    """Deep honeypot — attacker followed the breadcrumb trail."""
    from alert_engine import engine
    from firewall_monitor import _get_client_ip
    ip = _get_client_ip()
    # This triggers an ADDITIONAL critical alert for following the breadcrumb
    engine.report(
        ip=ip,
        severity="CRITICAL",
        attack_type="Deep Honeypot Breach — Credentials Endpoint",
        description=(
            "Attacker reached /admin/credentials after following the breadcrumb trail. "
            "They are actively attempting to exfiltrate the database credentials."
        ),
        endpoint="/admin/credentials",
    )
    # Return fake (but realistic-looking) encrypted blob — keeps attacker busy
    return jsonify({
        "data":      _ENCRYPTED_SECRET.decode()[:64] + "...[truncated]",
        "encoding":  "fernet",
        "expires":   "2024-12-31T23:59:59Z",
        "error":     "Session token expired. Re-authenticate to decrypt.",
    }), 401


# ---------------------------------------------------------------------------
# 404 catch-all (endpoint scan bait)
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    from colorama import Fore, Style, init
    init(autoreset=True)
    print(Fore.GREEN + Style.BRIGHT + """
+============================================================+
|         CAIDS HONEYPOT MODEL SERVER - ONLINE               |
|                                                            |
|  Decoy API  : http://localhost:5000                        |
|  Secret     : DB credentials (encrypted, embedded)        |
|  Firewall   : ACTIVE - all connections monitored           |
+============================================================+
""" + Style.RESET_ALL)
    app.run(host="0.0.0.0", port=5000, threaded=True)
