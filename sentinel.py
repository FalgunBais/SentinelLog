#!/usr/bin/env python3
"""
SentinelLog — Real-Time Security Log Analyzer & Threat Detection CLI

A professional command-line cybersecurity tool for continuous authentication
monitoring, brute-force & anomaly detection, IP investigations, and reporting.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional, Dict, Any, List

from core.models import LogEvent, ThreatAlert, Severity, ThreatType
from core.parser import LogParser
from core.detector import ThreatDetector
from core.analyzer import RiskAnalyzer
from core.monitor import LogMonitor
from database.database import Database
from demo.generator import DemoLogGenerator
from exports.exporter import SecurityExporter

# ANSI Color Codes
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    MAGENTA = "\033[35m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN = "\033[42m"


BANNER = f"""
{Color.CYAN}{Color.BOLD}
  ╔═════════════════════════════════════════════════════════════════════════╗
  ║   ____             _   _            _ _                 ____   ___   ____ ║
  ║  / ___|  ___ _ __ | |_(_)_ __   ___| | |    ___   __ _ / ___| / _ \ / ___|║
  ║  \___ \ / _ \ '_ \| __| | '_ \ / _ \ | |   / _ \ / _` | |  _ | | | | |    ║
  ║   ___) |  __/ | | | |_| | | | |  __/ | |__| (_) | (_| | |_| || |_| | |___ ║
  ║  |____/ \___|_| |_|\__|_|_| |_|\___|_|_____\___/ \__, |\____(_)___/ \____|║
  ║                                                  |___/                    ║
  ║        Real-Time Security Log Analyzer & Threat Detection Engine        ║
  ╚═════════════════════════════════════════════════════════════════════════╝
{Color.RESET}"""


def print_banner():
    print(BANNER)


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Load configuration file or return robust defaults."""
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"{Color.YELLOW}[!] Warning: Failed to parse {config_path}: {e}. Using defaults.{Color.RESET}")
    return {}


def format_severity(sev: str) -> str:
    """Return colorized severity string."""
    if sev == "CRITICAL":
        return f"{Color.RED}{Color.BOLD}[CRITICAL]{Color.RESET}"
    elif sev == "HIGH":
        return f"{Color.YELLOW}{Color.BOLD}[HIGH]    {Color.RESET}"
    elif sev == "MEDIUM":
        return f"{Color.YELLOW}[MEDIUM]  {Color.RESET}"
    return f"{Color.GREEN}[LOW]     {Color.RESET}"


def display_live_event(event: LogEvent, alerts: List[ThreatAlert]):
    """Print streaming event line and any triggered threat alert blocks."""
    ts_short = event.timestamp.split("T")[-1].rstrip("Z")[:12]
    sev_badge = format_severity(event.severity)
    status_color = Color.GREEN if event.auth_status == "SUCCESS" else Color.RED

    ip_str = f"{event.ip:<15}"
    user_str = f"{event.username:<12}"
    type_str = f"{event.event_type:<18}"
    status_str = f"{status_color}{event.auth_status:<8}{Color.RESET}"

    print(f"{Color.DIM}{ts_short}{Color.RESET} | {sev_badge} | {Color.CYAN}{ip_str}{Color.RESET} | {Color.WHITE}{user_str}{Color.RESET} | {type_str} | {status_str} | {event.message[:60]}", flush=True)

    # Display Alerts if triggered
    for alert in alerts:
        print(f"\n{Color.RED}{Color.BOLD}  ╔═══════════════════════ SECURITY ALERT TRIGGERED ═══════════════════════╗{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ ID:       {alert.alert_id:<60} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ THREAT:   {alert.threat_type:<60} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ SOURCE:   {alert.source_ip:<60} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ TARGET:   {alert.username:<60} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ SEVERITY: {alert.severity} (Score: {alert.risk_score}/100){' '*42} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ REASON:   {alert.reason[:60]:<60} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ║ RECOMMENDATION:{' '*56} ║{Color.RESET}", flush=True)
        for rec_line in alert.recommended_action.split("\n"):
            print(f"{Color.YELLOW}  ║   {rec_line[:58]:<58} ║{Color.RESET}", flush=True)
        print(f"{Color.RED}{Color.BOLD}  ╚═════════════════════════════════════════════════════════════════════════╝{Color.RESET}\n", flush=True)


def cmd_stats(db: Database):
    """Display SOC analytics summary in terminal."""
    stats = db.get_dashboard_stats()
    print_banner()
    print(f"{Color.BOLD}📊 SENTINELLOG SECURITY INTELLIGENCE SUMMARY{Color.RESET}")
    print(f"Status: {Color.GREEN if stats['system_status'] == 'SYSTEM_MONITORING' else Color.RED}{stats['system_status']}{Color.RESET}")
    print("═" * 70)
    print(f"  • Total Processed Events:    {Color.CYAN}{stats['total_events']:,}{Color.RESET}")
    print(f"  • Successful Logins:         {Color.GREEN}{stats['successful_logins']:,}{Color.RESET}")
    print(f"  • Failed Login Attempts:     {Color.RED}{stats['failed_logins']:,}{Color.RESET}")
    print(f"  • Invalid User Probes:       {Color.YELLOW}{stats['invalid_logins']:,}{Color.RESET}")
    print(f"  • Active Threat Alerts:      {Color.RED}{Color.BOLD}{stats['active_threats']}{Color.RESET}")
    print(f"  • High / Critical Severity:  {Color.RED}{stats['high_critical_alerts']}{Color.RESET}")
    print(f"  • Unique Source IPs:         {Color.CYAN}{stats['unique_ips']}{Color.RESET}")
    print("═" * 70)

    top_ips = stats.get("top_ips", [])
    if top_ips:
        print(f"\n{Color.BOLD}🔥 TOP SUSPICIOUS SOURCE IPS:{Color.RESET}")
        print(f"{'IP Address':<18} {'Total':<10} {'Failures':<12} {'Max Risk'}")
        print("-" * 50)
        for row in top_ips:
            print(f"{Color.CYAN}{row['ip']:<18}{Color.RESET} {row['total']:<10} {Color.RED}{row['failures']:<12}{Color.RESET} {row['max_risk']}/100")

    alerts = db.get_recent_alerts(limit=5, status="ACTIVE")
    if alerts:
        print(f"\n{Color.BOLD}🚨 RECENT ACTIVE THREAT ALERTS:{Color.RESET}")
        for a in alerts:
            print(f"  [{format_severity(a['severity'])}] {Color.BOLD}{a['threat_type']}{Color.RESET} from {Color.CYAN}{a['source_ip']}{Color.RESET} -> {a['reason']}")


def cmd_investigate_ip(db: Database, ip: str):
    """Display in-depth forensic investigation profile for a specific IP."""
    profile = db.get_ip_profile(ip)
    print_banner()
    print(f"{Color.BOLD}🔍 FORENSIC DOSSIER FOR SOURCE IP: {Color.CYAN}{ip}{Color.RESET}")
    print("═" * 70)
    print(f"  • Classification:     {Color.MAGENTA}{profile.classification}{Color.RESET}")
    print(f"  • Risk Score:         {format_severity(profile.severity)} {profile.risk_score} / 100")
    print(f"  • Total Attempts:     {profile.total_attempts}")
    print(f"  • Failed Logins:      {Color.RED}{profile.failed_attempts}{Color.RESET}")
    print(f"  • Invalid User Probes:{Color.YELLOW}{profile.invalid_user_attempts}{Color.RESET}")
    print(f"  • Successful Logins:  {Color.GREEN}{profile.successful_attempts}{Color.RESET}")
    print(f"  • First Seen:         {profile.first_seen}")
    print(f"  • Last Seen:          {profile.last_seen}")
    print(f"  • Targeted Users:     {', '.join(profile.targeted_usernames) if profile.targeted_usernames else 'None'}")
    print("═" * 70)

    if profile.alerts:
        print(f"\n{Color.BOLD}🚨 ASSOCIATED THREAT ALERTS ({len(profile.alerts)}):{Color.RESET}")
        for a in profile.alerts:
            print(f"  - [{a['severity']}] {a['threat_type']} ({a['timestamp']}): {a['reason']}")

    if profile.recent_events:
        print(f"\n{Color.BOLD}📋 RECENT EVENTS FROM {ip}:{Color.RESET}")
        for ev in profile.recent_events[:10]:
            print(f"  - {ev['timestamp']} | {ev['event_type']} | User: {ev['username']} | Status: {ev['auth_status']}")


def main():
    parser = argparse.ArgumentParser(
        description="SentinelLog — Real-Time Security Log Analyzer & Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--demo", action="store_true", help="Run SentinelLog in realistic simulation Demo Mode")
    parser.add_argument("--log", type=str, help="Path to authentication log file to monitor in Live Mode (e.g. /var/log/auth.log)")
    parser.add_argument("--web", action="store_true", help="Launch the Dark SOC Web Dashboard")
    parser.add_argument("--port", type=int, default=5000, help="Web dashboard server port (default: 5000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Web dashboard server host (default: 127.0.0.1)")
    parser.add_argument("--threshold", type=int, help="Override Brute-Force failed attempts threshold")
    parser.add_argument("--window", type=int, help="Override Brute-Force sliding time window in seconds")
    parser.add_argument("--stats", action="store_true", help="Display current security stats & threats from database")
    parser.add_argument("--investigate", type=str, metavar="IP", help="Display deep forensic investigation dossier for IP")
    parser.add_argument("--export-events", type=str, metavar="FILE.csv", help="Export processed security events to CSV")
    parser.add_argument("--export-alerts", type=str, metavar="FILE.json", help="Export threat alerts to JSON")
    parser.add_argument("--report", type=str, metavar="FILE.md", help="Generate Executive Cybersecurity Threat Report in Markdown")
    parser.add_argument("--config", type=str, default="config.json", help="Path to configuration file")
    parser.add_argument("--tail-start", action="store_true", help="Read log file from beginning instead of tailing end")
    parser.add_argument("--test", action="store_true", help="Run unit & integration test suite")

    args = parser.parse_args()
    config = load_config(args.config)

    # Apply CLI rule threshold overrides if provided
    if args.threshold:
        config.setdefault("detection", {}).setdefault("brute_force", {})["failed_attempts_threshold"] = args.threshold
    if args.window:
        config.setdefault("detection", {}).setdefault("brute_force", {})["time_window_seconds"] = args.window

    # Initialize Core Components
    db_path = config.get("database", {}).get("db_path", "sentinel.db")
    db = Database(db_path)
    log_parser = LogParser()
    analyzer = RiskAnalyzer(config)
    detector = ThreatDetector(config, analyzer=analyzer)

    # 1. Run Unit Tests
    if args.test:
        import unittest
        print_banner()
        print(f"{Color.CYAN}[*] Running SentinelLog Automated Test Suite...{Color.RESET}\n")
        suite = unittest.defaultTestLoader.discover("tests", pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    # 2. Stats Command
    if args.stats:
        cmd_stats(db)
        return

    # 3. IP Investigation Command
    if args.investigate:
        cmd_investigate_ip(db, args.investigate)
        return

    # 4. Exports
    exporter = SecurityExporter(db)
    if args.export_events:
        count = exporter.export_events_csv(args.export_events)
        print(f"{Color.GREEN}[✓] Exported {count} events to {args.export_events}{Color.RESET}")
        return

    if args.export_alerts:
        count = exporter.export_alerts_json(args.export_alerts)
        print(f"{Color.GREEN}[✓] Exported {count} alerts to {args.export_alerts}{Color.RESET}")
        return

    if args.report:
        exporter.generate_security_report_markdown(args.report)
        print(f"{Color.GREEN}[✓] Generated Security Threat Report at {args.report}{Color.RESET}")
        return

    # 5. Web Mode or Terminal Live Stream
    log_file_path = args.log or config.get("logging", {}).get("log_file", "sample_auth.log")
    tail_from_end = not args.tail_start

    monitor = LogMonitor(
        log_path=log_file_path,
        parser=log_parser,
        detector=detector,
        database=db,
        tail_from_end=tail_from_end
    )
    monitor.add_callback(display_live_event)

    demo_gen = None
    if args.demo or (not args.log and config.get("app", {}).get("mode") == "demo"):
        demo_interval = config.get("demo", {}).get("event_interval_seconds", 2.0)
        demo_prob = config.get("demo", {}).get("attack_probability", 0.35)
        demo_gen = DemoLogGenerator(
            monitor=monitor,
            parser=log_parser,
            interval_seconds=demo_interval,
            attack_probability=demo_prob,
            log_file_path=log_file_path if args.log else None
        )

    # If --web flag or default launcher
    if args.web:
        print_banner()
        mode_label = "DEMO MODE (Simulated Traffic)" if demo_gen else f"LIVE MODE ({log_file_path})"
        print(f"{Color.CYAN}[*] Starting SentinelLog Dark SOC Web Dashboard...{Color.RESET}")
        print(f"    • Mode:       {Color.YELLOW if demo_gen else Color.GREEN}{mode_label}{Color.RESET}")
        print(f"    • URL:        {Color.BOLD}{Color.WHITE}http://{args.host}:{args.port}{Color.RESET}")
        print(f"    • Database:   {Color.DIM}{db_path}{Color.RESET}")
        print(f"    • PID:        {Color.DIM}{os.getpid()}{Color.RESET}")
        print(f"\n{Color.GREEN}[✓] System operational. Press Ctrl+C to terminate.{Color.RESET}\n")

        monitor.start()
        if demo_gen:
            demo_gen.start()

        from dashboard.routes import create_app
        app = create_app(database=db, monitor=monitor, demo_generator=demo_gen, config=config)
        try:
            app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
        except (KeyboardInterrupt, SystemExit):
            print(f"\n{Color.YELLOW}[*] Shutting down SentinelLog...{Color.RESET}")
        finally:
            monitor.stop()
            if demo_gen:
                demo_gen.stop()
        return

    # CLI Terminal Streaming Mode
    print_banner()
    if demo_gen:
        print(f"{Color.YELLOW}{Color.BOLD}╔═════════════════════════════════════════════════════════════════════════╗{Color.RESET}")
        print(f"{Color.YELLOW}{Color.BOLD}║           DEMO MODE — SIMULATED SECURITY EVENTS (Testing Only)          ║{Color.RESET}")
        print(f"{Color.YELLOW}{Color.BOLD}╚═════════════════════════════════════════════════════════════════════════╝{Color.RESET}\n")
        print(f"{Color.CYAN}[*] Generating realistic authentication streams and attack sequences...{Color.RESET}")
        print(f"{Color.DIM}Press Ctrl+C to stop.\n{Color.RESET}")
        monitor.start()
        demo_gen.start()
    else:
        print(f"{Color.GREEN}{Color.BOLD}╔═════════════════════════════════════════════════════════════════════════╗{Color.RESET}")
        print(f"{Color.GREEN}{Color.BOLD}║               LIVE MODE — SYSTEM AUTHENTICATION MONITOR                 ║{Color.RESET}")
        print(f"{Color.GREEN}{Color.BOLD}╚═════════════════════════════════════════════════════════════════════════╝{Color.RESET}\n")
        print(f"{Color.CYAN}[*] Monitoring log file: {Color.BOLD}{log_file_path}{Color.RESET}")
        print(f"{Color.DIM}Press Ctrl+C to stop.\n{Color.RESET}")
        monitor.start()

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        print(f"\n{Color.YELLOW}[*] Stopping monitor...{Color.RESET}")
    finally:
        monitor.stop()
        if demo_gen:
            demo_gen.stop()
        print(f"{Color.GREEN}[✓] SentinelLog stopped cleanly.{Color.RESET}")


if __name__ == "__main__":
    main()
