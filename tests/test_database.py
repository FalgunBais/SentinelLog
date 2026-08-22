"""Integration Tests for SentinelLog SQLite Database"""

import unittest
import os
import tempfile
from core.models import LogEvent, ThreatAlert, EventType, Severity, ThreatType
from database.database import Database
from exports.exporter import SecurityExporter


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db = Database(self.temp_db.name)

    def tearDown(self):
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def test_insert_and_retrieve_event(self):
        ev = LogEvent(
            timestamp="2026-08-22T12:00:00Z",
            ip="198.51.100.42",
            username="admin",
            event_type=EventType.FAILED_LOGIN.value,
            auth_status="FAILURE",
            severity=Severity.LOW.value,
            risk_score=10,
            message="Failed login"
        )
        ev_id = self.db.insert_event(ev)
        self.assertGreater(ev_id, 0)

        events = self.db.get_recent_events(limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ip"], "198.51.100.42")
        self.assertEqual(events[0]["username"], "admin")

    def test_insert_and_acknowledge_alert(self):
        alert = ThreatAlert(
            alert_id="ALT-1001",
            timestamp="2026-08-22T12:00:00Z",
            threat_type=ThreatType.BRUTE_FORCE_ATTEMPT.value,
            source_ip="198.51.100.42",
            username="root",
            severity=Severity.HIGH.value,
            risk_score=75,
            reason="Multiple failures",
            recommended_action="Block IP"
        )
        self.db.insert_or_update_alert(alert)

        alerts = self.db.get_recent_alerts(status="ACTIVE")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_id"], "ALT-1001")

        # Acknowledge
        ack_res = self.db.acknowledge_alert("ALT-1001")
        self.assertTrue(ack_res)

        # Active alerts should now be empty
        active_alerts = self.db.get_recent_alerts(status="ACTIVE")
        self.assertEqual(len(active_alerts), 0)

        # Acknowledged alerts should contain it
        ack_alerts = self.db.get_recent_alerts(status="ACKNOWLEDGED")
        self.assertEqual(len(ack_alerts), 1)

    def test_dashboard_stats(self):
        # Insert success and fail
        self.db.insert_event(LogEvent(auth_status="SUCCESS", ip="192.168.1.50", username="user1"))
        self.db.insert_event(LogEvent(auth_status="FAILURE", ip="198.51.100.42", username="admin"))
        self.db.insert_event(LogEvent(auth_status="INVALID", ip="203.0.113.88", username="guest"))

        stats = self.db.get_dashboard_stats()
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual(stats["successful_logins"], 1)
        self.assertEqual(stats["failed_logins"], 1)
        self.assertEqual(stats["invalid_logins"], 1)
        self.assertEqual(stats["unique_ips"], 3)

    def test_ip_profile(self):
        self.db.insert_event(LogEvent(auth_status="FAILURE", ip="198.51.100.42", username="admin", timestamp="2026-08-22T10:00:00Z"))
        self.db.insert_event(LogEvent(auth_status="FAILURE", ip="198.51.100.42", username="root", timestamp="2026-08-22T10:05:00Z"))

        profile = self.db.get_ip_profile("198.51.100.42")
        self.assertEqual(profile.ip, "198.51.100.42")
        self.assertEqual(profile.total_attempts, 2)
        self.assertEqual(profile.failed_attempts, 2)
        self.assertEqual(set(profile.targeted_usernames), {"admin", "root"})
        self.assertEqual(profile.classification, "Public / External")

    def test_exporter(self):
        self.db.insert_event(LogEvent(auth_status="SUCCESS", ip="192.168.1.50", username="user1"))
        exporter = SecurityExporter(self.db)

        temp_csv = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        temp_csv.close()
        try:
            count = exporter.export_events_csv(temp_csv.name)
            self.assertEqual(count, 1)
            self.assertTrue(os.path.exists(temp_csv.name))
        finally:
            if os.path.exists(temp_csv.name):
                os.remove(temp_csv.name)


if __name__ == "__main__":
    unittest.main()
