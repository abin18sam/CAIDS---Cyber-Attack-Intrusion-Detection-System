"""
run.py — CAIDS Honeypot System Launcher
Starts the honeypot model server (port 5000) and dashboard (port 5001)
in parallel threads. Press Ctrl+C to shut down both.
"""

import sys
import io
import threading
import time
import os

# Force UTF-8 output on Windows to support box-drawing chars & emoji
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure imports from this directory
sys.path.insert(0, os.path.dirname(__file__))

from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.CYAN + Style.BRIGHT}
+======================================================================+
|                                                                      |
|   CAIDS - Cyber Attack Intrusion Detection System                    |
|           Honeypot Module                                            |
+======================================================================+
|                                                                      |
|  [Honeypot Model]  ->  http://localhost:5000                         |
|  [Live Dashboard]  ->  http://localhost:5001/dashboard               |
|  [Alert Log]       ->  honeypot/logs/alerts.jsonl                    |
|  [CAIDS Bridge]    ->  honeypot/logs/caids_bridge.jsonl              |
|                                                                      |
|  SECRET: Fake DB credentials (encrypted, embedded in model)          |
|  FIREWALL: ACTIVE - all connections inspected                        |
|                                                                      |
|  Press Ctrl+C to shut down.                                          |
+======================================================================+
{Style.RESET_ALL}"""


def _run_model_server():
    """Start the honeypot decoy model on port 5000."""
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)  # suppress Flask request logs to keep terminal clean

    import model_server
    model_server.app.run(host="0.0.0.0", port=5000, threaded=True, use_reloader=False)


def _run_dashboard():
    """Start the dashboard server on port 5001."""
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)

    import dashboard_server
    dashboard_server.dashboard_app.run(host="0.0.0.0", port=5001, threaded=True, use_reloader=False)


def main():
    print(BANNER)

    t_model = threading.Thread(target=_run_model_server, daemon=True, name="HoneypotModel")
    t_dash  = threading.Thread(target=_run_dashboard,    daemon=True, name="Dashboard")

    t_model.start()
    time.sleep(0.5)   # slight stagger so ports bind cleanly
    t_dash.start()

    print(Fore.GREEN + "[OK] Both servers started. Open your browser:")
    print(Fore.CYAN  + "     Dashboard -> http://localhost:5001/dashboard")
    print(Fore.YELLOW + "\n     To simulate attacks (run in another terminal):\n")
    print(Fore.WHITE + '     curl http://localhost:5000/admin')
    print(Fore.WHITE + '     curl http://localhost:5000/secret')
    print(Fore.WHITE + '     curl "http://localhost:5000/query?q=\' OR 1=1--"')
    print(Fore.WHITE + '     curl -A "sqlmap/1.0" http://localhost:5000/predict')
    print(Fore.WHITE + '     # Rate-flood: send 15 rapid requests')
    print(Fore.WHITE + '     for /L %i in (1,1,15) do curl -s http://localhost:5000/status')
    print(Style.RESET_ALL)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[STOP] Shutting down CAIDS Honeypot. Goodbye.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
