"""Unit Tests for SentinelLog Threat Detector"""

import unittest
from datetime import datetime, timedelta
from core.models import LogEvent, EventType, ThreatType, Severity
from core.detector import ThreatDetector
from core.analyzer import RiskAnalyzer


class TestThreatDetector(unittest.TestCase):

    def setUp(self):
        self.config = {
            "detection": {
                "brute_force": {"failed_attempts_threshold": 5, "time_window_seconds": 300},
                "user_spraying": {"unique_users_threshold": 3, "time_window_seconds": 300},
                "rapid_spike": {"attempt_threshold": 6, "time_window_seconds": 30},
                "suspicious_success": {"prior_failures_threshold": 3, "time_window_seconds": 300},
                "invalid_user_probe": {"failed_attempts_threshold": 3, "time_window_seconds": 300}
            }
        }
        self.analyzer = RiskAnalyzer(self.config)
        self.detector = ThreatDetector(config=self.config, analyzer=self.analyzer)

    def test_brute_force_detection(self):
        ip = "198.51.100.42"
        now = datetime.utcnow()
        alerts = []

        # Generate 5 failed attempts
        for i in range(5):
            ts = (now + timedelta(seconds=i * 5)).isoformat() + "Z"
            ev = LogEvent(
                timestamp=ts,
                ip=ip,
                username="admin",
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE"
            )
            detected = self.detector.process_event(ev)
            alerts.extend(detected)

        # 5th failure should trigger BRUTE_FORCE_ATTEMPT
        bf_alerts = [a for a in alerts if a.threat_type == ThreatType.BRUTE_FORCE_ATTEMPT.value]
        self.assertTrue(len(bf_alerts) >= 1)
        self.assertEqual(bf_alerts[0].source_ip, ip)
        self.assertIn(bf_alerts[0].severity, (Severity.HIGH.value, Severity.CRITICAL.value))

    def test_user_spraying_detection(self):
        ip = "203.0.113.88"
        users = ["admin", "root", "oracle", "deploy"]
        now = datetime.utcnow()
        alerts = []

        for i, u in enumerate(users):
            ts = (now + timedelta(seconds=i * 5)).isoformat() + "Z"
            ev = LogEvent(
                timestamp=ts,
                ip=ip,
                username=u,
                event_type=EventType.INVALID_USER.value,
                auth_status="INVALID"
            )
            detected = self.detector.process_event(ev)
            alerts.extend(detected)

        spray_alerts = [a for a in alerts if a.threat_type == ThreatType.USER_SPRAYING.value]
        self.assertTrue(len(spray_alerts) >= 1)
        self.assertEqual(spray_alerts[0].source_ip, ip)

    def test_suspicious_success_detection(self):
        ip = "185.220.101.5"
        now = datetime.utcnow()
        alerts = []

        # 3 failed attempts
        for i in range(3):
            ts = (now + timedelta(seconds=i * 5)).isoformat() + "Z"
            ev = LogEvent(
                timestamp=ts,
                ip=ip,
                username="victim_user",
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE"
            )
            detected = self.detector.process_event(ev)
            alerts.extend(detected)

        # Immediately followed by successful login!
        ts_succ = (now + timedelta(seconds=20)).isoformat() + "Z"
        succ_ev = LogEvent(
            timestamp=ts_succ,
            ip=ip,
            username="victim_user",
            event_type=EventType.SUCCESSFUL_LOGIN.value,
            auth_status="SUCCESS"
        )
        detected_succ = self.detector.process_event(succ_ev)
        alerts.extend(detected_succ)

        comp_alerts = [a for a in alerts if a.threat_type == ThreatType.SUSPICIOUS_SUCCESS.value]
        self.assertEqual(len(comp_alerts), 1)
        self.assertEqual(comp_alerts[0].severity, Severity.CRITICAL.value)
        self.assertTrue(comp_alerts[0].risk_score >= 85)


if __name__ == "__main__":
    unittest.main()
