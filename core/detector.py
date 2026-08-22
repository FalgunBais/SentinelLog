"""SentinelLog Stateful Threat Detection Engine

Maintains sliding-window metrics per IP/User to identify:
1. Brute-Force Attacks (repeated failures)
2. User Spraying (multiple usernames from single IP)
3. Rapid Velocity Spikes (high frequency login bursts)
4. Suspicious Successes (success following multiple failed attempts)
5. Invalid User Probes (enumeration of system accounts)
"""

import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict

from core.models import LogEvent, ThreatAlert, ThreatType, Severity, EventType
from core.analyzer import RiskAnalyzer


class ThreatDetector:
    """Stateful detection engine with sliding time-window correlation."""

    def __init__(self, config: Optional[Dict[str, Any]] = None, analyzer: Optional[RiskAnalyzer] = None):
        self.config = config or {}
        self.analyzer = analyzer or RiskAnalyzer(self.config)
        self.lock = threading.RLock()

        # Detection rule settings
        det_cfg = self.config.get("detection", {})
        
        # 1. Brute Force Rule
        bf_cfg = det_cfg.get("brute_force", {})
        self.bf_threshold = bf_cfg.get("failed_attempts_threshold", 5)
        self.bf_window = bf_cfg.get("time_window_seconds", 300)

        # 2. User Spraying Rule
        spray_cfg = det_cfg.get("user_spraying", {})
        self.spray_threshold = spray_cfg.get("unique_users_threshold", 3)
        self.spray_window = spray_cfg.get("time_window_seconds", 300)

        # 3. Rapid Spike Rule
        spike_cfg = det_cfg.get("rapid_spike", {})
        self.spike_threshold = spike_cfg.get("attempt_threshold", 8)
        self.spike_window = spike_cfg.get("time_window_seconds", 30)

        # 4. Suspicious Success Rule
        succ_cfg = det_cfg.get("suspicious_success", {})
        self.succ_prior_fail_threshold = succ_cfg.get("prior_failures_threshold", 3)
        self.succ_window = succ_cfg.get("time_window_seconds", 300)

        # 5. Invalid User Probe Rule
        invalid_cfg = det_cfg.get("invalid_user_probe", {})
        self.invalid_threshold = invalid_cfg.get("failed_attempts_threshold", 3)
        self.invalid_window = invalid_cfg.get("time_window_seconds", 300)

        # Sliding window event store: ip -> list of (timestamp_epoch, LogEvent)
        self.ip_events: Dict[str, List[Tuple[float, LogEvent]]] = defaultdict(list)

        # Active alert tracking to avoid alert storm: (ip, threat_type) -> ThreatAlert
        self.active_threats: Dict[Tuple[str, str], ThreatAlert] = {}
        self.last_alert_time: Dict[Tuple[str, str], float] = {}

    def process_event(self, event: LogEvent) -> List[ThreatAlert]:
        """Analyze a newly parsed LogEvent and return any triggered alerts."""
        alerts: List[ThreatAlert] = []
        if not event or event.ip == "UNKNOWN":
            return alerts

        with self.lock:
            now_epoch = self._parse_to_epoch(event.timestamp)
            ip = event.ip

            # Prune events older than maximum window (10 minutes)
            self._prune_ip_history(ip, now_epoch)

            # Record event in sliding window
            self.ip_events[ip].append((now_epoch, event))

            # Rule 1: Suspicious Success Check (Run first if this is a successful login)
            if event.event_type == EventType.SUCCESSFUL_LOGIN.value or event.auth_status == "SUCCESS":
                succ_alert = self._check_suspicious_success(ip, event, now_epoch)
                if succ_alert:
                    alerts.append(succ_alert)

            # Rule 2: Brute Force Detection
            bf_alert = self._check_brute_force(ip, event, now_epoch)
            if bf_alert:
                alerts.append(bf_alert)

            # Rule 3: User Spraying Detection
            spray_alert = self._check_user_spraying(ip, event, now_epoch)
            if spray_alert:
                alerts.append(spray_alert)

            # Rule 4: Rapid Velocity Spike
            spike_alert = self._check_rapid_spike(ip, event, now_epoch)
            if spike_alert:
                alerts.append(spike_alert)

            # Rule 5: Invalid User Probing
            if event.event_type == EventType.INVALID_USER.value:
                inv_alert = self._check_invalid_user_probe(ip, event, now_epoch)
                if inv_alert:
                    alerts.append(inv_alert)

        return alerts

    def _check_suspicious_success(self, ip: str, current_event: LogEvent, now_epoch: float) -> Optional[ThreatAlert]:
        """Trigger if success immediately follows multiple failures from the same IP."""
        window_start = now_epoch - self.succ_window
        recent_failures = [
            ev for ts, ev in self.ip_events[ip]
            if ts >= window_start and ev.auth_status in ("FAILURE", "INVALID")
        ]

        if len(recent_failures) >= self.succ_prior_fail_threshold:
            alert_key = (ip, ThreatType.SUSPICIOUS_SUCCESS.value)
            score = 90
            severity = Severity.CRITICAL.value
            reason = (
                f"Successful login for user '{current_event.username}' immediately following "
                f"{len(recent_failures)} failed login attempts from IP {ip} within {int(self.succ_window / 60)} minutes."
            )
            recommendation = self.analyzer.generate_recommendation(
                ThreatType.SUSPICIOUS_SUCCESS.value, ip, current_event.username, {"failed_attempts": len(recent_failures)}
            )

            alert_id = f"ALT-{int(now_epoch)}-{uuid.uuid4().hex[:6]}"
            alert = ThreatAlert(
                alert_id=alert_id,
                timestamp=current_event.timestamp,
                threat_type=ThreatType.SUSPICIOUS_SUCCESS.value,
                source_ip=ip,
                username=current_event.username,
                severity=severity,
                risk_score=score,
                reason=reason,
                recommended_action=recommendation,
                status="ACTIVE",
                event_count=len(recent_failures) + 1,
                first_seen=recent_failures[0].timestamp if recent_failures else current_event.timestamp,
                last_seen=current_event.timestamp,
                metadata={"prior_failures": len(recent_failures), "target_user": current_event.username}
            )
            self.active_threats[alert_key] = alert
            self.last_alert_time[alert_key] = now_epoch
            return alert
        return None

    def _check_brute_force(self, ip: str, current_event: LogEvent, now_epoch: float) -> Optional[ThreatAlert]:
        """Detect repeated failed attempts from single IP."""
        window_start = now_epoch - self.bf_window
        failures = [
            ev for ts, ev in self.ip_events[ip]
            if ts >= window_start and ev.auth_status in ("FAILURE", "INVALID")
        ]

        fail_count = len(failures)
        if fail_count >= self.bf_threshold:
            alert_key = (ip, ThreatType.BRUTE_FORCE_ATTEMPT.value)
            last_alerted = self.last_alert_time.get(alert_key, 0)

            # Suppress if alerted very recently and fail_count hasn't grown by at least 3
            existing_alert = self.active_threats.get(alert_key)
            if existing_alert and (now_epoch - last_alerted < 60) and (fail_count - existing_alert.event_count < 3):
                return None

            # Calculate escalating risk score based on attempt count
            base_score = 65
            escalated_score = min(base_score + (fail_count - self.bf_threshold) * 5, 95)
            severity = Severity.CRITICAL.value if escalated_score >= 85 else Severity.HIGH.value

            targeted_users = list({ev.username for ev in failures if ev.username != "UNKNOWN"})
            user_display = ", ".join(targeted_users[:5]) if targeted_users else current_event.username

            reason = (
                f"Brute-force attack detected: {fail_count} failed login attempts from source IP {ip} "
                f"within {int(self.bf_window / 60)} minutes (Targeted: {user_display})."
            )
            recommendation = self.analyzer.generate_recommendation(
                ThreatType.BRUTE_FORCE_ATTEMPT.value, ip, user_display, {"failed_attempts": fail_count}
            )

            alert_id = existing_alert.alert_id if existing_alert else f"ALT-{int(now_epoch)}-{uuid.uuid4().hex[:6]}"
            alert = ThreatAlert(
                alert_id=alert_id,
                timestamp=current_event.timestamp,
                threat_type=ThreatType.BRUTE_FORCE_ATTEMPT.value,
                source_ip=ip,
                username=user_display,
                severity=severity,
                risk_score=escalated_score,
                reason=reason,
                recommended_action=recommendation,
                status="ACTIVE",
                event_count=fail_count,
                first_seen=failures[0].timestamp if failures else current_event.timestamp,
                last_seen=current_event.timestamp,
                metadata={"failed_count": fail_count, "users": targeted_users}
            )
            self.active_threats[alert_key] = alert
            self.last_alert_time[alert_key] = now_epoch
            return alert
        return None

    def _check_user_spraying(self, ip: str, current_event: LogEvent, now_epoch: float) -> Optional[ThreatAlert]:
        """Detect horizontal credential spraying across multiple distinct usernames."""
        window_start = now_epoch - self.spray_window
        window_events = [ev for ts, ev in self.ip_events[ip] if ts >= window_start]
        unique_users = list({ev.username for ev in window_events if ev.username not in ("UNKNOWN", "")})

        if len(unique_users) >= self.spray_threshold:
            alert_key = (ip, ThreatType.USER_SPRAYING.value)
            last_alerted = self.last_alert_time.get(alert_key, 0)
            existing_alert = self.active_threats.get(alert_key)

            if existing_alert and (now_epoch - last_alerted < 60) and (len(unique_users) <= len(existing_alert.metadata.get("usernames", []))):
                return None

            score = min(70 + len(unique_users) * 5, 95)
            severity = Severity.HIGH.value if score < 85 else Severity.CRITICAL.value
            users_list_str = ", ".join(unique_users[:8])

            reason = (
                f"Credential spraying attack detected: Source IP {ip} probed {len(unique_users)} "
                f"distinct user accounts ({users_list_str}) within {int(self.spray_window / 60)} minutes."
            )
            recommendation = self.analyzer.generate_recommendation(
                ThreatType.USER_SPRAYING.value, ip, current_event.username, {"usernames": unique_users}
            )

            alert_id = existing_alert.alert_id if existing_alert else f"ALT-{int(now_epoch)}-{uuid.uuid4().hex[:6]}"
            alert = ThreatAlert(
                alert_id=alert_id,
                timestamp=current_event.timestamp,
                threat_type=ThreatType.USER_SPRAYING.value,
                source_ip=ip,
                username=f"{len(unique_users)} accounts ({unique_users[0]}...)",
                severity=severity,
                risk_score=score,
                reason=reason,
                recommended_action=recommendation,
                status="ACTIVE",
                event_count=len(window_events),
                first_seen=window_events[0].timestamp if window_events else current_event.timestamp,
                last_seen=current_event.timestamp,
                metadata={"usernames": unique_users, "user_count": len(unique_users)}
            )
            self.active_threats[alert_key] = alert
            self.last_alert_time[alert_key] = now_epoch
            return alert
        return None

    def _check_rapid_spike(self, ip: str, current_event: LogEvent, now_epoch: float) -> Optional[ThreatAlert]:
        """Detect automated high-velocity login bursts in short time windows."""
        window_start = now_epoch - self.spike_window
        recent_burst = [ev for ts, ev in self.ip_events[ip] if ts >= window_start]

        if len(recent_burst) >= self.spike_threshold:
            alert_key = (ip, ThreatType.RAPID_SPIKE.value)
            last_alerted = self.last_alert_time.get(alert_key, 0)
            if now_epoch - last_alerted < 45:
                return None

            rate = round(len(recent_burst) / max(self.spike_window, 1), 2)
            score = 75
            severity = Severity.HIGH.value
            reason = (
                f"Rapid authentication velocity spike detected: {len(recent_burst)} login attempts "
                f"in {self.spike_window}s (~{rate} req/sec) from source IP {ip}."
            )
            recommendation = self.analyzer.generate_recommendation(
                ThreatType.RAPID_SPIKE.value, ip, current_event.username, {"rate_per_sec": rate}
            )

            alert_id = f"ALT-{int(now_epoch)}-{uuid.uuid4().hex[:6]}"
            alert = ThreatAlert(
                alert_id=alert_id,
                timestamp=current_event.timestamp,
                threat_type=ThreatType.RAPID_SPIKE.value,
                source_ip=ip,
                username=current_event.username,
                severity=severity,
                risk_score=score,
                reason=reason,
                recommended_action=recommendation,
                status="ACTIVE",
                event_count=len(recent_burst),
                first_seen=recent_burst[0].timestamp if recent_burst else current_event.timestamp,
                last_seen=current_event.timestamp,
                metadata={"attempt_count": len(recent_burst), "window_seconds": self.spike_window}
            )
            self.active_threats[alert_key] = alert
            self.last_alert_time[alert_key] = now_epoch
            return alert
        return None

    def _check_invalid_user_probe(self, ip: str, current_event: LogEvent, now_epoch: float) -> Optional[ThreatAlert]:
        """Detect repeated attempts targeting invalid or non-existent usernames."""
        window_start = now_epoch - self.invalid_window
        invalid_events = [
            ev for ts, ev in self.ip_events[ip]
            if ts >= window_start and ev.event_type == EventType.INVALID_USER.value
        ]

        if len(invalid_events) >= self.invalid_threshold:
            alert_key = (ip, ThreatType.INVALID_USER_PROBE.value)
            last_alerted = self.last_alert_time.get(alert_key, 0)
            if now_epoch - last_alerted < 60:
                return None

            score = 55
            severity = Severity.MEDIUM.value
            probed_users = list({ev.username for ev in invalid_events})

            reason = (
                f"Repeated invalid username probing: {len(invalid_events)} attempts targeting "
                f"non-existent accounts ({', '.join(probed_users[:5])}) from {ip}."
            )
            recommendation = self.analyzer.generate_recommendation(
                ThreatType.INVALID_USER_PROBE.value, ip, current_event.username, {}
            )

            alert_id = f"ALT-{int(now_epoch)}-{uuid.uuid4().hex[:6]}"
            alert = ThreatAlert(
                alert_id=alert_id,
                timestamp=current_event.timestamp,
                threat_type=ThreatType.INVALID_USER_PROBE.value,
                source_ip=ip,
                username=current_event.username,
                severity=severity,
                risk_score=score,
                reason=reason,
                recommended_action=recommendation,
                status="ACTIVE",
                event_count=len(invalid_events),
                first_seen=invalid_events[0].timestamp if invalid_events else current_event.timestamp,
                last_seen=current_event.timestamp,
                metadata={"invalid_attempts": len(invalid_events), "users": probed_users}
            )
            self.active_threats[alert_key] = alert
            self.last_alert_time[alert_key] = now_epoch
            return alert
        return None

    def _prune_ip_history(self, ip: str, now_epoch: float, max_age_seconds: float = 600.0):
        """Remove events older than max_age_seconds from in-memory sliding window."""
        cutoff = now_epoch - max_age_seconds
        self.ip_events[ip] = [(ts, ev) for ts, ev in self.ip_events[ip] if ts >= cutoff]

    def _parse_to_epoch(self, ts_str: str) -> float:
        """Convert ISO 8601 string to epoch timestamp."""
        try:
            clean = ts_str.rstrip("Z")
            if "+" in clean:
                clean = clean.split("+")[0]
            dt = datetime.fromisoformat(clean)
            return dt.timestamp()
        except Exception:
            return time.time()
