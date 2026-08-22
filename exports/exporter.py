"""SentinelLog Report and Data Exporter

Exports security logs, threat alerts, and analytical reports
in CSV, JSON, and Markdown formats.
"""

import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from database.database import Database


class SecurityExporter:
    """Handles formatted file exports and executive security summaries."""

    def __init__(self, database: Optional[Database] = None):
        self.database = database or Database()

    def export_events_csv(self, filepath: str, limit: int = 10000) -> int:
        """Export raw and parsed security events to CSV."""
        parent_dir = os.path.dirname(filepath)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        events = self.database.get_recent_events(limit=limit)
        if not events:
            # Write empty header
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["id", "timestamp", "ip", "username", "event_type", "auth_status", "service", "port", "severity", "risk_score", "message", "raw_log"])
            return 0

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            fieldnames = ["id", "timestamp", "ip", "username", "event_type", "auth_status", "service", "port", "severity", "risk_score", "message", "raw_log"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for ev in events:
                writer.writerow(ev)

        return len(events)

    def export_alerts_json(self, filepath: str, limit: int = 1000) -> int:
        """Export threat alerts to a structured JSON file."""
        parent_dir = os.path.dirname(filepath)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        alerts = self.database.get_recent_alerts(limit=limit)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "alert_count": len(alerts),
                "alerts": alerts
            }, f, indent=2)

        return len(alerts)

    def generate_security_report_markdown(self, filepath: Optional[str] = None) -> str:
        """Generate a formatted Executive Cybersecurity Incident & Threat Report in Markdown."""
        stats = self.database.get_dashboard_stats()
        alerts = self.database.get_recent_alerts(limit=20, status="ACTIVE")
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        md = [
            "# SentinelLog — Threat Intelligence & Incident Report",
            f"**Generated:** {now_str} | **System Status:** `{stats.get('system_status', 'UNKNOWN')}`",
            "",
            "## Executive Summary",
            "",
            "| Metric | Count |",
            "| :--- | :--- |",
            f"| **Total Processed Events** | `{stats.get('total_events', 0):,}` |",
            f"| **Successful Authentications** | `{stats.get('successful_logins', 0):,}` |",
            f"| **Failed Authentications** | `{stats.get('failed_logins', 0):,}` |",
            f"| **Invalid User Probes** | `{stats.get('invalid_logins', 0):,}` |",
            f"| **Active Security Threats** | `{stats.get('active_threats', 0):,}` |",
            f"| **High / Critical Alerts** | `{stats.get('high_critical_alerts', 0):,}` |",
            f"| **Unique Monitored IPs** | `{stats.get('unique_ips', 0):,}` |",
            "",
            "## Active Threat Alerts",
            ""
        ]

        if not alerts:
            md.append("*No active threats currently flagged in the system.*")
        else:
            md.append("| Alert ID | Severity | Threat Type | Source IP | Target User | Score | Reason |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for a in alerts:
                sev = a.get("severity", "LOW")
                aid = a.get("alert_id", "")
                ttype = a.get("threat_type", "")
                ip = a.get("source_ip", "")
                u = a.get("username", "")
                score = a.get("risk_score", 0)
                reason = a.get("reason", "").replace("|", "-")
                md.append(f"| `{aid}` | **{sev}** | `{ttype}` | `{ip}` | `{u}` | `{score}` | {reason} |")

        md.extend([
            "",
            "## Top Attacking / Suspicious Source IPs",
            "",
            "| IP Address | Total Requests | Failed Attempts | Max Risk Score |",
            "| :--- | :--- | :--- | :--- |"
        ])

        top_ips = stats.get("top_ips", [])
        if not top_ips:
            md.append("| *None* | 0 | 0 | 0 |")
        else:
            for ip_info in top_ips:
                md.append(f"| `{ip_info['ip']}` | {ip_info['total']} | {ip_info['failures']} | `{ip_info['max_risk']}` |")

        md.extend([
            "",
            "## Recommended Security Actions",
            "",
            "1. **Firewall Enforcement**: Block external IP addresses with risk scores >= 60.",
            "2. **Privilege Hardening**: Disable password authentication for SSH and enforce SSH key pairs.",
            "3. **Account Auditing**: Immediately investigate users involved in `SUSPICIOUS_SUCCESS` alerts.",
            "4. **Fail2Ban / Rate Limiting**: Ensure fail2ban or equivalent kernel iptables rate-limiting is active.",
            "",
            "---",
            "*Report generated automatically by SentinelLog Threat Analysis Engine.*"
        ])

        content = "\n".join(md)
        if filepath:
            parent_dir = os.path.dirname(filepath)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

        return content
