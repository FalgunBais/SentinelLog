"""SentinelLog Risk Analysis and Threat Scoring Engine

Computes deterministic, explainable security risk scores, maps to severity tiers,
and provides actionable SOC recommendations.
"""

from typing import Dict, Any, List, Optional, Tuple
from core.models import Severity, ThreatType, EventType, ThreatAlert, LogEvent


class RiskAnalyzer:
    """Calculates risk scores and provides explainable security recommendations."""

    DEFAULT_BASE_SCORES = {
        "FAILED_LOGIN": 10,
        "INVALID_USER": 15,
        "RAPID_ATTEMPTS": 20,
        "MULTIPLE_USERS": 25,
        "BRUTE_FORCE": 40,
        "SUSPICIOUS_SUCCESS": 30,
        "SSH_AUTH_FAILURE": 10,
    }

    DEFAULT_SEVERITY_THRESHOLDS = {
        "LOW": 0,
        "MEDIUM": 30,
        "HIGH": 60,
        "CRITICAL": 85
    }

    # Common high-risk usernames targeted by attackers
    HIGH_VALUE_TARGETS = {"root", "admin", "administrator", "guest", "support", "test", "oracle", "postgres", "deploy", "ubuntu"}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        scoring_cfg = self.config.get("scoring", {})
        self.base_scores = scoring_cfg.get("base_scores", self.DEFAULT_BASE_SCORES)
        self.severity_thresholds = scoring_cfg.get("severity_thresholds", self.DEFAULT_SEVERITY_THRESHOLDS)

    def calculate_event_risk(self, event: LogEvent) -> Tuple[int, str]:
        """Compute base risk score and initial severity for an isolated event."""
        score = 0
        if event.event_type == EventType.INVALID_USER.value:
            score += self.base_scores.get("INVALID_USER", 15)
            if event.username.lower() in self.HIGH_VALUE_TARGETS:
                score += 10
        elif event.event_type in (EventType.FAILED_LOGIN.value, EventType.SSH_AUTH_FAILURE.value):
            score += self.base_scores.get("FAILED_LOGIN", 10)
            if event.username.lower() in self.HIGH_VALUE_TARGETS:
                score += 5
        elif event.event_type == EventType.SUCCESSFUL_LOGIN.value:
            score = 0
        else:
            score = 0

        severity = self.get_severity_for_score(score)
        return min(score, 100), severity

    def get_severity_for_score(self, score: int) -> str:
        """Map numeric score to severity tier."""
        return Severity.from_score(score, self.severity_thresholds).value

    def calculate_ip_threat_score(
        self,
        total_attempts: int,
        failed_attempts: int,
        invalid_user_attempts: int,
        unique_usernames_count: int,
        has_brute_force: bool,
        has_suspicious_success: bool,
        has_rapid_spike: bool
    ) -> Tuple[int, str]:
        """Compute holistic risk score for an IP based on its historical/sliding window activity."""
        score = 0

        # Base failure penalties
        score += failed_attempts * self.base_scores.get("FAILED_LOGIN", 10)
        score += invalid_user_attempts * self.base_scores.get("INVALID_USER", 15)

        # Multi-user spraying penalty
        if unique_usernames_count > 1:
            score += min((unique_usernames_count - 1) * self.base_scores.get("MULTIPLE_USERS", 25), 50)

        # Pattern penalties
        if has_brute_force:
            score += self.base_scores.get("BRUTE_FORCE", 40)
        if has_rapid_spike:
            score += self.base_scores.get("RAPID_ATTEMPTS", 20)
        if has_suspicious_success:
            score += self.base_scores.get("SUSPICIOUS_SUCCESS", 30)

        # Cap max score to 100
        final_score = min(score, 100)
        severity = self.get_severity_for_score(final_score)
        return final_score, severity

    def generate_recommendation(self, threat_type: str, ip: str, username: str, metrics: Dict[str, Any]) -> str:
        """Provide concise, context-aware SOC remediation steps."""
        if threat_type == ThreatType.BRUTE_FORCE_ATTEMPT.value:
            failures = metrics.get("failed_attempts", "multiple")
            return (
                f"1. Temporarily ban source IP {ip} via firewall/iptables.\n"
                f"2. Check if account '{username}' was compromised.\n"
                f"3. Enforce SSH key-only authentication or fail2ban jail policies."
            )
        elif threat_type == ThreatType.SUSPICIOUS_SUCCESS.value:
            failures = metrics.get("failed_attempts", "several")
            return (
                f"1. CRITICAL: Account '{username}' logged in successfully immediately following {failures} failed attempts from {ip}!\n"
                f"2. Terminate active session immediately for '{username}'.\n"
                f"3. Force password reset and require Multi-Factor Authentication (MFA).\n"
                f"4. Inspect authorized_keys and recent bash history on target host."
            )
        elif threat_type == ThreatType.USER_SPRAYING.value:
            users_str = ", ".join(metrics.get("usernames", [username]))
            return (
                f"1. Source IP {ip} is conducting a horizontal credential spray across users: {users_str}.\n"
                f"2. Block {ip} at network perimeter.\n"
                f"3. Audit all targeted accounts for weak passwords or unauthorized access."
            )
        elif threat_type == ThreatType.RAPID_SPIKE.value:
            rate = metrics.get("rate_per_sec", "high")
            return (
                f"1. Automated botnet/script detected executing high-frequency login attempts ({rate} attempts/sec).\n"
                f"2. Apply rate-limiting on SSH port 22 or switch SSH port.\n"
                f"3. Block subnet/IP {ip}."
            )
        elif threat_type == ThreatType.INVALID_USER_PROBE.value:
            return (
                f"1. Source IP {ip} is scanning for default or non-existent system accounts.\n"
                f"2. Ensure root login via SSH is disabled (`PermitRootLogin no`).\n"
                f"3. Monitor for escalation attempts."
            )
        return f"Investigate authentication logs for source IP {ip} and verify legitimacy of activity."
