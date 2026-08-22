"""Unit Tests for SentinelLog Risk Analyzer"""

import unittest
from core.analyzer import RiskAnalyzer
from core.models import LogEvent, EventType, Severity, ThreatType


class TestRiskAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = RiskAnalyzer()

    def test_calculate_event_risk_benign(self):
        ev = LogEvent(event_type=EventType.SUCCESSFUL_LOGIN.value, auth_status="SUCCESS")
        score, sev = self.analyzer.calculate_event_risk(ev)
        self.assertEqual(score, 0)
        self.assertEqual(sev, Severity.LOW.value)

    def test_calculate_event_risk_failed(self):
        ev = LogEvent(event_type=EventType.FAILED_LOGIN.value, auth_status="FAILURE", username="testuser")
        score, sev = self.analyzer.calculate_event_risk(ev)
        self.assertEqual(score, 10)
        self.assertEqual(sev, Severity.LOW.value)

    def test_calculate_event_risk_high_value_target(self):
        ev = LogEvent(event_type=EventType.FAILED_LOGIN.value, auth_status="FAILURE", username="root")
        score, sev = self.analyzer.calculate_event_risk(ev)
        self.assertEqual(score, 15)  # 10 base + 5 target bonus

    def test_calculate_ip_threat_score(self):
        score, sev = self.analyzer.calculate_ip_threat_score(
            total_attempts=10,
            failed_attempts=8,
            invalid_user_attempts=2,
            unique_usernames_count=3,
            has_brute_force=True,
            has_suspicious_success=False,
            has_rapid_spike=True
        )
        self.assertTrue(score >= 85)
        self.assertEqual(sev, Severity.CRITICAL.value)

    def test_recommendation_generation(self):
        rec = self.analyzer.generate_recommendation(
            ThreatType.BRUTE_FORCE_ATTEMPT.value,
            "198.51.100.42",
            "root",
            {"failed_attempts": 10}
        )
        self.assertIn("firewall", rec.lower())
        self.assertIn("198.51.100.42", rec)


if __name__ == "__main__":
    unittest.main()
