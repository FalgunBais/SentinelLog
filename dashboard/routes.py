"""SentinelLog Web Application & REST API

Provides endpoints for the SOC dashboard, live SSE stream,
IP investigation, alert management, and data export.
"""

import json
import queue
import time
import os
from datetime import datetime
from typing import Optional, Dict, Any

from flask import Flask, render_template, request, jsonify, Response, send_file, current_app
from flask_cors import CORS

from database.database import Database
from core.parser import LogParser
from core.detector import ThreatDetector
from core.monitor import LogMonitor
from core.analyzer import RiskAnalyzer
from demo.generator import DemoLogGenerator
from exports.exporter import SecurityExporter


def create_app(
    database: Optional[Database] = None,
    monitor: Optional[LogMonitor] = None,
    demo_generator: Optional[DemoLogGenerator] = None,
    config: Optional[Dict[str, Any]] = None
) -> Flask:
    """Application factory for SentinelLog Dashboard."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    CORS(app)

    # Attach instances
    app.config["DB"] = database or Database()
    app.config["MONITOR"] = monitor
    app.config["DEMO"] = demo_generator
    app.config["EXPORTER"] = SecurityExporter(app.config["DB"])
    app.config["SETTINGS"] = config or {}

    # SSE Event Queues
    app.config["SSE_QUEUES"] = []

    # 1. Main Dashboard UI
    @app.route("/")
    def index():
        mode = app.config["SETTINGS"].get("app", {}).get("mode", "demo")
        stats = app.config["DB"].get_dashboard_stats()
        return render_template(
            "index.html",
            mode=mode,
            stats=stats,
            version=app.config["SETTINGS"].get("app", {}).get("version", "1.0.0")
        )

    # 2. REST API: Live Stats
    @app.route("/api/stats", methods=["GET"])
    def get_stats():
        stats = app.config["DB"].get_dashboard_stats()
        is_demo = app.config["DEMO"].is_running if app.config["DEMO"] else False
        is_monitor = app.config["MONITOR"].is_running if app.config["MONITOR"] else False
        stats["is_demo_running"] = is_demo
        stats["is_monitor_running"] = is_monitor
        return jsonify(stats)

    # 3. REST API: Events List (with filtering)
    @app.route("/api/events", methods=["GET"])
    def get_events():
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
        severity = request.args.get("severity")
        search = request.args.get("search")
        ip = request.args.get("ip")
        username = request.args.get("username")

        events = app.config["DB"].get_recent_events(
            limit=limit,
            offset=offset,
            severity=severity,
            search=search,
            ip=ip,
            username=username
        )
        return jsonify({"events": events, "count": len(events)})

    # 4. REST API: Alerts List
    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        limit = int(request.args.get("limit", 50))
        status = request.args.get("status")
        severity = request.args.get("severity")
        ip = request.args.get("ip")

        alerts = app.config["DB"].get_recent_alerts(
            limit=limit,
            status=status,
            severity=severity,
            ip=ip
        )
        return jsonify({"alerts": alerts, "count": len(alerts)})

    # 5. REST API: Acknowledge Alert
    @app.route("/api/alerts/<alert_id>/ack", methods=["POST"])
    def acknowledge_alert(alert_id):
        success = app.config["DB"].acknowledge_alert(alert_id)
        return jsonify({"success": success, "alert_id": alert_id})

    # 6. REST API: Clear Acknowledged Alerts
    @app.route("/api/alerts/clear-ack", methods=["POST"])
    def clear_acknowledged_alerts():
        count = app.config["DB"].clear_acknowledged_alerts()
        return jsonify({"success": True, "cleared_count": count})

    # 7. REST API: Deep IP Investigation
    @app.route("/api/ip/<ip>", methods=["GET"])
    def investigate_ip(ip):
        profile = app.config["DB"].get_ip_profile(ip)
        return jsonify(profile.to_dict())

    # 8. Server-Sent Events (SSE) Live Feed Stream
    @app.route("/api/stream", methods=["GET"])
    def event_stream():
        def stream_generator():
            q = queue.Queue(maxsize=100)
            if app.config["MONITOR"]:
                app.config["MONITOR"].add_subscriber(q)

            try:
                # Send initial ping
                yield f"data: {json.dumps({'type': 'ping', 'time': datetime.utcnow().isoformat()})}\n\n"
                while True:
                    try:
                        # Wait for message with timeout for heartbeat
                        payload = q.get(timeout=15.0)
                        data_str = json.dumps({"type": "event", "data": payload})
                        yield f"data: {data_str}\n\n"
                    except queue.Empty:
                        # Send periodic heartbeat
                        yield f"data: {json.dumps({'type': 'heartbeat', 'time': datetime.utcnow().isoformat()})}\n\n"
            finally:
                if app.config["MONITOR"]:
                    app.config["MONITOR"].remove_subscriber(q)

        return Response(
            stream_generator(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"
            }
        )

    # 9. REST API: Demo Controls
    @app.route("/api/demo/start", methods=["POST"])
    def start_demo():
        if app.config["DEMO"]:
            app.config["DEMO"].start()
            return jsonify({"success": True, "status": "started"})
        return jsonify({"success": False, "error": "Demo generator not initialized"}), 400

    @app.route("/api/demo/stop", methods=["POST"])
    def stop_demo():
        if app.config["DEMO"]:
            app.config["DEMO"].stop()
            return jsonify({"success": True, "status": "stopped"})
        return jsonify({"success": False, "error": "Demo generator not initialized"}), 400

    @app.route("/api/demo/trigger", methods=["POST"])
    def trigger_demo_scenario():
        scenario = request.json.get("scenario", "brute_force") if request.is_json else request.form.get("scenario", "brute_force")
        if app.config["DEMO"]:
            events = app.config["DEMO"].trigger_scenario(scenario)
            return jsonify({"success": True, "scenario": scenario, "events_triggered": len(events)})
        return jsonify({"success": False, "error": "Demo generator not initialized"}), 400

    # 10. REST API: Data Exports
    @app.route("/api/export/events", methods=["GET"])
    def export_events():
        filepath = "exports/sentinel_events.csv"
        app.config["EXPORTER"].export_events_csv(filepath)
        return send_file(filepath, as_attachment=True, download_name="sentinel_events.csv")

    @app.route("/api/export/alerts", methods=["GET"])
    def export_alerts():
        filepath = "exports/sentinel_alerts.json"
        app.config["EXPORTER"].export_alerts_json(filepath)
        return send_file(filepath, as_attachment=True, download_name="sentinel_alerts.json")

    @app.route("/api/export/report", methods=["GET"])
    def export_report():
        filepath = "exports/sentinel_security_report.md"
        app.config["EXPORTER"].generate_security_report_markdown(filepath)
        return send_file(filepath, as_attachment=True, download_name="sentinel_security_report.md")

    # 11. REST API: Clear / Reset Database
    @app.route("/api/clear", methods=["POST"])
    def clear_database():
        app.config["DB"].clear_all()
        return jsonify({"success": True, "message": "Database cleared successfully"})

    return app
