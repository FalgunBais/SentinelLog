"""SentinelLog SQLite Storage Layer

Provides thread-safe persistence, indexing, analytical queries,
and IP profiling for security events and threat alerts.
"""

import sqlite3
import json
import threading
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple

from core.models import LogEvent, ThreatAlert, IPProfile, Severity, EventType


class Database:
    """Thread-safe SQLite Database Manager for SentinelLog."""

    def __init__(self, db_path: str = "sentinel.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        
        # Ensure parent directory exists if path has directories
        parent_dir = os.path.dirname(db_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
            
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a connection configured for concurrent reads and WAL mode."""
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        """Initialize database schema with tables and indexes."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # 1. Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                auth_status TEXT NOT NULL,
                service TEXT DEFAULT 'sshd',
                port INTEGER,
                severity TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                message TEXT,
                raw_log TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            );
            """)

            # 2. Alerts Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER DEFAULT 60,
                reason TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                event_count INTEGER DEFAULT 1,
                first_seen TEXT,
                last_seen TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT
            );
            """)

            # 3. System Config Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)

            # Performance Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_auth ON events(auth_status);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);")

            conn.commit()
            conn.close()

    def insert_event(self, event: LogEvent) -> int:
        """Insert a single security LogEvent into SQLite."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                details_json = json.dumps(event.details) if isinstance(event.details, dict) else "{}"
                cursor.execute("""
                INSERT INTO events (
                    timestamp, ip, username, event_type, auth_status,
                    service, port, severity, risk_score, message, raw_log, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp,
                    event.ip,
                    event.username,
                    event.event_type,
                    event.auth_status,
                    event.service,
                    event.port,
                    event.severity,
                    event.risk_score,
                    event.message,
                    event.raw_log,
                    details_json,
                    event.created_at
                ))
                event_id = cursor.lastrowid
                conn.commit()
                return event_id
            finally:
                conn.close()

    def insert_or_update_alert(self, alert: ThreatAlert) -> int:
        """Insert a new alert or update existing alert metrics (e.g. event count, score)."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                metadata_json = json.dumps(alert.metadata) if isinstance(alert.metadata, dict) else "{}"
                cursor.execute("""
                INSERT INTO alerts (
                    alert_id, timestamp, threat_type, source_ip, username,
                    severity, risk_score, reason, recommended_action, status,
                    event_count, first_seen, last_seen, metadata, created_at, acknowledged_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    event_count = excluded.event_count,
                    risk_score = excluded.risk_score,
                    severity = excluded.severity,
                    last_seen = excluded.last_seen,
                    reason = excluded.reason,
                    metadata = excluded.metadata
                """, (
                    alert.alert_id,
                    alert.timestamp,
                    alert.threat_type,
                    alert.source_ip,
                    alert.username,
                    alert.severity,
                    alert.risk_score,
                    alert.reason,
                    alert.recommended_action,
                    alert.status,
                    alert.event_count,
                    alert.first_seen or alert.timestamp,
                    alert.last_seen or alert.timestamp,
                    metadata_json,
                    alert.created_at,
                    alert.acknowledged_at
                ))
                alert_id = cursor.lastrowid
                conn.commit()
                return alert_id
            finally:
                conn.close()

    def get_recent_events(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        ip: Optional[str] = None,
        username: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent events matching filter criteria."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            query = "SELECT * FROM events WHERE 1=1"
            params: List[Any] = []

            if severity and severity.upper() != "ALL":
                query += " AND severity = ?"
                params.append(severity.upper())

            if ip:
                query += " AND ip = ?"
                params.append(ip)

            if username:
                query += " AND username = ?"
                params.append(username)

            if search:
                query += " AND (ip LIKE ? OR username LIKE ? OR message LIKE ? OR raw_log LIKE ?)"
                wildcard = f"%{search}%"
                params.extend([wildcard, wildcard, wildcard, wildcard])

            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            result = []
            for r in rows:
                d = dict(r)
                if d.get("details"):
                    try:
                        d["details"] = json.loads(d["details"])
                    except Exception:
                        pass
                result.append(d)
            return result
        finally:
            conn.close()

    def get_recent_alerts(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent threat alerts."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            query = "SELECT * FROM alerts WHERE 1=1"
            params: List[Any] = []

            if status and status.upper() != "ALL":
                query += " AND status = ?"
                params.append(status.upper())

            if severity and severity.upper() != "ALL":
                query += " AND severity = ?"
                params.append(severity.upper())

            if ip:
                query += " AND source_ip = ?"
                params.append(ip)

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            result = []
            for r in rows:
                d = dict(r)
                if d.get("metadata"):
                    try:
                        d["metadata"] = json.loads(d["metadata"])
                    except Exception:
                        pass
                result.append(d)
            return result
        finally:
            conn.close()

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                now_str = datetime.utcnow().isoformat() + "Z"
                cursor.execute("""
                UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_at = ?
                WHERE alert_id = ?
                """, (now_str, alert_id))
                updated = cursor.rowcount > 0
                conn.commit()
                return updated
            finally:
                conn.close()

    def clear_acknowledged_alerts(self) -> int:
        """Mark acknowledged alerts as CLEARED (or archive them) without deleting raw events."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("""
                UPDATE alerts SET status = 'CLEARED'
                WHERE status = 'ACKNOWLEDGED'
                """)
                count = cursor.rowcount
                conn.commit()
                return count
            finally:
                conn.close()

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Compute live aggregated metrics from the real SQLite database."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            # 1. Total events
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            # 2. Logins breakdown
            cursor.execute("SELECT COUNT(*) FROM events WHERE auth_status = 'SUCCESS'")
            successful_logins = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM events WHERE auth_status = 'FAILURE'")
            failed_logins = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM events WHERE auth_status = 'INVALID'")
            invalid_logins = cursor.fetchone()[0]

            # 3. Active & high-severity alerts
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'ACTIVE'")
            active_threats = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL') AND status = 'ACTIVE'")
            high_critical_alerts = cursor.fetchone()[0]

            # 4. Unique source IPs
            cursor.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ip != 'UNKNOWN'")
            unique_ips = cursor.fetchone()[0]

            # 5. Severity distribution
            cursor.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity")
            severity_rows = cursor.fetchall()
            severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for row in severity_rows:
                sev = row[0]
                if sev in severity_counts:
                    severity_counts[sev] = row[1]

            # 6. Top Attacking / Suspicious IPs
            cursor.execute("""
            SELECT 
                ip, 
                COUNT(*) as total,
                SUM(CASE WHEN auth_status IN ('FAILURE', 'INVALID') THEN 1 ELSE 0 END) as failures,
                MAX(risk_score) as max_risk
            FROM events
            WHERE ip != 'UNKNOWN' AND ip != '127.0.0.1' AND ip != 'localhost'
            GROUP BY ip
            ORDER BY failures DESC, total DESC
            LIMIT 5
            """)
            top_ips = [
                {"ip": r[0], "total": r[1], "failures": r[2], "max_risk": r[3]}
                for r in cursor.fetchall()
            ]

            # 7. Top Targeted Usernames
            cursor.execute("""
            SELECT 
                username, 
                COUNT(*) as total,
                SUM(CASE WHEN auth_status IN ('FAILURE', 'INVALID') THEN 1 ELSE 0 END) as failures
            FROM events
            WHERE username != 'UNKNOWN'
            GROUP BY username
            ORDER BY failures DESC, total DESC
            LIMIT 5
            """)
            top_usernames = [
                {"username": r[0], "total": r[1], "failures": r[2]}
                for r in cursor.fetchall()
            ]

            # 8. Timeline (Recent activity grouped into buckets)
            cursor.execute("""
            SELECT 
                SUBSTR(timestamp, 1, 16) as time_bucket,
                COUNT(*) as total,
                SUM(CASE WHEN auth_status = 'SUCCESS' THEN 1 ELSE 0 END) as successes,
                SUM(CASE WHEN auth_status IN ('FAILURE', 'INVALID') THEN 1 ELSE 0 END) as failures
            FROM events
            GROUP BY time_bucket
            ORDER BY time_bucket DESC
            LIMIT 12
            """)
            timeline_rows = cursor.fetchall()
            timeline = [
                {"time": r[0], "total": r[1], "success": r[2], "failure": r[3]}
                for r in reversed(timeline_rows)
            ]

            # System status logic
            if high_critical_alerts > 0:
                system_status = "THREATS_DETECTED"
            elif active_threats > 0 or failed_logins > 10:
                system_status = "WARNING"
            else:
                system_status = "SYSTEM_MONITORING"

            return {
                "total_events": total_events,
                "successful_logins": successful_logins,
                "failed_logins": failed_logins,
                "invalid_logins": invalid_logins,
                "active_threats": active_threats,
                "high_critical_alerts": high_critical_alerts,
                "unique_ips": unique_ips,
                "severity_counts": severity_counts,
                "top_ips": top_ips,
                "top_usernames": top_usernames,
                "timeline": timeline,
                "system_status": system_status
            }
        finally:
            conn.close()

    def get_ip_profile(self, ip: str) -> IPProfile:
        """Deep investigation dossier for a specific IP address."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            # Query attempts breakdown
            cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN auth_status = 'FAILURE' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN auth_status = 'SUCCESS' THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN auth_status = 'INVALID' THEN 1 ELSE 0 END) as invalid,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                MAX(risk_score) as max_score
            FROM events
            WHERE ip = ?
            """, (ip,))
            stat = cursor.fetchone()

            total = stat[0] or 0
            failed = stat[1] or 0
            success = stat[2] or 0
            invalid = stat[3] or 0
            first_seen = stat[4] or "N/A"
            last_seen = stat[5] or "N/A"
            max_score = stat[6] or 0

            # Distinct targeted usernames
            cursor.execute("SELECT DISTINCT username FROM events WHERE ip = ? AND username != 'UNKNOWN'", (ip,))
            users = [r[0] for r in cursor.fetchall()]

            # Associated alerts
            cursor.execute("SELECT * FROM alerts WHERE source_ip = ? ORDER BY id DESC", (ip,))
            alert_rows = cursor.fetchall()
            alerts = []
            for ar in alert_rows:
                ad = dict(ar)
                if ad.get("metadata"):
                    try:
                        ad["metadata"] = json.loads(ad["metadata"])
                    except Exception:
                        pass
                alerts.append(ad)

            # Recent events from this IP
            cursor.execute("SELECT * FROM events WHERE ip = ? ORDER BY id DESC LIMIT 15", (ip,))
            event_rows = cursor.fetchall()
            recent_events = [dict(er) for er in event_rows]

            # Calculate composite risk score
            # Score formula: base failure weight + invalid user weight + multi-user bonus + alert bonus
            calc_score = (failed * 10) + (invalid * 15)
            if len(users) > 1:
                calc_score += (len(users) - 1) * 20
            if alerts:
                calc_score += len(alerts) * 25
            final_risk = min(max(calc_score, max_score), 100)

            severity = Severity.from_score(final_risk).value

            profile = IPProfile(
                ip=ip,
                total_attempts=total,
                failed_attempts=failed,
                successful_attempts=success,
                invalid_user_attempts=invalid,
                targeted_usernames=users,
                first_seen=first_seen,
                last_seen=last_seen,
                risk_score=final_risk,
                severity=severity,
                active_threats=len([a for a in alerts if a.get("status") == "ACTIVE"]),
                alerts=alerts,
                recent_events=recent_events
            )
            return profile
        finally:
            conn.close()

    def clear_all(self):
        """Clear all events and alerts (for reset/tests)."""
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events;")
            cursor.execute("DELETE FROM alerts;")
            conn.commit()
            conn.close()
