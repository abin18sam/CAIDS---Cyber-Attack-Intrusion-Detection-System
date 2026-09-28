"""
firewall_monitor.py — CAIDS Honeypot Firewall / IDS Layer
Inspects every inbound request before it reaches the decoy model.
"""

import re
import time
import threading
from collections import defaultdict
from flask import request, abort, g
from alert_engine import engine

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RATE_LIMIT_WINDOW_SECONDS = 10      # sliding window duration
RATE_LIMIT_MAX_REQUESTS   = 10      # requests allowed per window
SCAN_DISTINCT_ENDPOINTS   = 5       # distinct 404s before "scan" alert
SCAN_WINDOW_SECONDS       = 30      # window for endpoint scan detection

# Known malicious / scanning user-agent substrings (case-insensitive)
SUSPICIOUS_UA_PATTERNS = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "wfuzz", "hydra", "metasploit", "zgrab", "shodan", "censys",
    "python-requests", "go-http-client", "java/", "libwww-perl",
    "curl/", "wget/", "scrapy",
]

# Regex patterns for injection / traversal attempts in URLs and bodies
INJECTION_PATTERNS = [
    re.compile(r"('|--|;|\/\*|\*\/|xp_|exec\s*\(|union\s+select)", re.IGNORECASE),  # SQLi
    re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.IGNORECASE),     # XSS
    re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|etc/passwd|/proc/)", re.IGNORECASE),  # Path traversal
    re.compile(r"(\$\{|\{\{|<\?php|\beval\b|\bexec\b|\bbase64_decode\b)", re.IGNORECASE),  # RCE / SSTI
]

# Endpoints that are deliberately "sensitive" — any access is an alert
HONEYPOT_SENSITIVE_ENDPOINTS = {
    "/admin", "/admin/", "/secret", "/config", "/credentials",
    "/.env", "/backup", "/db", "/root", "/shell", "/api/v1/secret",
    "/api/keys", "/model/weights", "/internal",
}

# ---------------------------------------------------------------------------
# Per-IP state (in-memory, thread-safe)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_request_times: dict[str, list[float]] = defaultdict(list)   # IP → timestamps
_endpoint_hits:  dict[str, set[str]]   = defaultdict(set)    # IP → set of unknown endpoints
_endpoint_times: dict[str, float]      = defaultdict(float)   # IP → window start
_alerted_ips:   dict[str, set[str]]   = defaultdict(set)     # IP → set of already-fired alert types


def _get_client_ip() -> str:
    """Return the real client IP (honour X-Forwarded-For for proxies)."""
    xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return xff or request.remote_addr or "unknown"


def _already_alerted(ip: str, key: str) -> bool:
    """Rate-limit repeated identical alerts for the same IP + key."""
    with _lock:
        if key in _alerted_ips[ip]:
            return True
        # Store alert with a TTL-like rolling set (simple: cap at 50 entries)
        if len(_alerted_ips[ip]) > 50:
            _alerted_ips[ip].clear()
        _alerted_ips[ip].add(key)
        return False


# ---------------------------------------------------------------------------
# Individual detection checks
# ---------------------------------------------------------------------------

def _check_rate_limit(ip: str) -> bool:
    """Return True if IP has exceeded the request rate limit."""
    now = time.monotonic()
    with _lock:
        times = _request_times[ip]
        # Slide window
        times[:] = [t for t in times if now - t < RATE_LIMIT_WINDOW_SECONDS]
        times.append(now)
        count = len(times)

    if count > RATE_LIMIT_MAX_REQUESTS:
        key = "rate_limit"
        if not _already_alerted(ip, key):
            engine.report(
                ip=ip,
                severity="HIGH",
                attack_type="Brute-Force / Rate Flood",
                description=(
                    f"IP sent {count} requests in {RATE_LIMIT_WINDOW_SECONDS}s "
                    f"(limit: {RATE_LIMIT_MAX_REQUESTS}). Possible brute-force or DoS attack."
                ),
                endpoint=request.path,
            )
        return True
    return False


def _check_suspicious_ua(ip: str) -> bool:
    """Return True if the User-Agent matches known scanning/attack tools."""
    ua = (request.user_agent.string or "").lower()
    if not ua:
        return False
    matched = next((p for p in SUSPICIOUS_UA_PATTERNS if p in ua), None)
    if matched:
        key = f"ua_{matched}"
        if not _already_alerted(ip, key):
            engine.report(
                ip=ip,
                severity="MEDIUM",
                attack_type="Suspicious User-Agent / Scanner Tool",
                description=(
                    f"Request from '{ua}' matches known attack-tool fingerprint: '{matched}'."
                ),
                endpoint=request.path,
            )
        return True
    return False


def _check_injection(ip: str) -> bool:
    """Detect SQL injection, XSS, path traversal, and RCE in URL/body."""
    target_strings = [request.full_path or ""]

    # Check query-string values
    for v in request.args.values():
        target_strings.append(v)

    # Check JSON body
    try:
        body = request.get_json(silent=True, force=True) or {}
        if isinstance(body, dict):
            target_strings.extend(str(v) for v in body.values())
        elif isinstance(body, str):
            target_strings.append(body)
    except Exception:
        pass

    # Check raw body (if small)
    try:
        raw = request.get_data(as_text=True)
        if raw and len(raw) < 4096:
            target_strings.append(raw)
    except Exception:
        pass

    combined = " ".join(target_strings)
    for pattern in INJECTION_PATTERNS:
        m = pattern.search(combined)
        if m:
            snippet = combined[max(0, m.start()-20): m.end()+40]
            key = f"inject_{pattern.pattern[:20]}"
            if not _already_alerted(ip, key):
                engine.report(
                    ip=ip,
                    severity="HIGH",
                    attack_type="Injection Attack (SQLi / XSS / Path Traversal / RCE)",
                    description=f"Malicious pattern detected in request payload/URL.",
                    endpoint=request.path,
                    payload_snippet=snippet,
                )
            return True
    return False


def _check_honeypot_endpoint(ip: str) -> bool:
    """Alert when a sensitive honeypot endpoint is accessed."""
    path = request.path.rstrip("/") or "/"
    if path in HONEYPOT_SENSITIVE_ENDPOINTS or any(
        path.startswith(ep) for ep in HONEYPOT_SENSITIVE_ENDPOINTS
    ):
        key = f"honeypot_{path}"
        if not _already_alerted(ip, key):
            engine.report(
                ip=ip,
                severity="CRITICAL",
                attack_type="Secret Exfiltration / Honeypot Triggered",
                description=(
                    f"Attacker accessed protected honeypot endpoint '{path}'. "
                    "This is a deliberate trap — real secrets are stored here."
                ),
                endpoint=request.path,
            )
        return True
    return False


def _check_endpoint_scan(ip: str, is_404: bool) -> bool:
    """Detect endpoint enumeration / directory brute-force."""
    if not is_404:
        return False
    now = time.monotonic()
    with _lock:
        # Reset window if expired
        if now - _endpoint_times[ip] > SCAN_WINDOW_SECONDS:
            _endpoint_hits[ip].clear()
            _endpoint_times[ip] = now
        _endpoint_hits[ip].add(request.path)
        count = len(_endpoint_hits[ip])

    if count >= SCAN_DISTINCT_ENDPOINTS:
        key = "scan"
        if not _already_alerted(ip, key):
            engine.report(
                ip=ip,
                severity="MEDIUM",
                attack_type="Endpoint Scanning / Directory Brute-Force",
                description=(
                    f"IP probed {count} distinct unknown endpoints in {SCAN_WINDOW_SECONDS}s. "
                    "Possible directory brute-force (DirBuster / Gobuster)."
                ),
                endpoint=request.path,
            )
        return True
    return False


# ---------------------------------------------------------------------------
# Public middleware hooks (registered by model_server.py)
# ---------------------------------------------------------------------------

def before_request_hook():
    """Run all firewall checks before each request."""
    ip = _get_client_ip()
    g.client_ip = ip

    # Order matters: cheapest / highest-value checks first
    _check_honeypot_endpoint(ip)   # CRITICAL — always run
    _check_suspicious_ua(ip)       # MEDIUM
    _check_injection(ip)           # HIGH
    _check_rate_limit(ip)          # HIGH


def after_request_hook(response):
    """Post-request check: detect 404 scanning."""
    ip = getattr(g, "client_ip", _get_client_ip())
    _check_endpoint_scan(ip, is_404=(response.status_code == 404))
    return response
