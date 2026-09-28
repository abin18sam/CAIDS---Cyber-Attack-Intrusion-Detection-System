"""
dashboard_server.py — CAIDS Honeypot Live Dashboard Server
Serves the real-time alert dashboard on port 5001.
"""

import os
from flask import Flask, jsonify, send_from_directory
from alert_engine import engine

dashboard_app = Flask(__name__)
_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))


@dashboard_app.route("/")
@dashboard_app.route("/dashboard")
def dashboard():
    return send_from_directory(_DASHBOARD_DIR, "dashboard.html")


@dashboard_app.route("/api/alerts")
def api_alerts():
    return jsonify(engine.get_all())


@dashboard_app.route("/api/stats")
def api_stats():
    return jsonify(engine.get_stats())


if __name__ == "__main__":
    dashboard_app.run(host="0.0.0.0", port=5001, threaded=True)
