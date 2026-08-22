"""SentinelLog Realistic Demo Log Generator

Generates authentic-looking authentication log streams for demonstration
and testing, simulating real-world benign traffic and realistic threat vectors.

NOTE: All generated records are for simulation and testing purposes only.
"""

import random
import time
import threading
from datetime import datetime
from typing import Optional, Callable, Dict, Any, List

from core.models import LogEvent, EventType, Severity
from core.parser import LogParser
from core.monitor import LogMonitor


class DemoLogGenerator:
    """Simulates realistic authentication traffic and attack scenarios."""

    BENIGN_USERS = ["ubuntu", "alice", "bob", "sysadmin", "dev_sarah", "lead_dan", "deploy_bot"]
    ATTACK_TARGET_USERS = ["root", "admin", "administrator", "guest", "test", "support", "oracle", "jenkins", "postgres", "ftpuser"]
    
    BENIGN_IPS = [
        "192.168.1.10", "192.168.1.25", "192.168.1.45",
        "10.0.0.15", "10.0.0.88", "172.16.4.12", "127.0.0.1"
    ]
    
    THREAT_IPS = [
        "198.51.100.42", "203.0.113.88", "185.220.101.5",
        "45.142.214.19", "91.240.118.172", "194.26.29.112",
        "103.152.220.4", "185.156.73.54"
    ]

    SERVICES = ["sshd", "pam_unix", "sudo"]

    def __init__(
        self,
        monitor: Optional[LogMonitor] = None,
        parser: Optional[LogParser] = None,
        interval_seconds: float = 2.0,
        attack_probability: float = 0.35,
        log_file_path: Optional[str] = None
    ):
        self.monitor = monitor
        self.parser = parser or LogParser()
        self.interval_seconds = interval_seconds
        self.attack_probability = attack_probability
        self.log_file_path = log_file_path

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self):
        """Start the background demo generation thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop demo generation."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    @property
    def is_running(self) -> bool:
        return self._running

    def trigger_scenario(self, scenario_name: str) -> List[LogEvent]:
        """Trigger an instant realistic multi-event attack scenario."""
        events: List[LogEvent] = []
        if scenario_name == "brute_force":
            events = self._generate_brute_force_sequence()
        elif scenario_name == "user_spraying":
            events = self._generate_spraying_sequence()
        elif scenario_name == "suspicious_success" or scenario_name == "compromise":
            events = self._generate_compromise_sequence()
        elif scenario_name == "rapid_spike":
            events = self._generate_rapid_spike_sequence()
        elif scenario_name == "invalid_probe":
            events = self._generate_invalid_probe_sequence()
        elif scenario_name == "benign":
            events = [self._generate_benign_event()]
        else:
            events = [self._generate_random_event()]

        for ev in events:
            self._dispatch_event(ev)
            # Short sleep between burst events to simulate micro-delays
            time.sleep(0.05)

        return events

    def _run_loop(self):
        """Continuous simulation loop."""
        while self._running:
            try:
                # Decide between benign traffic and structured attack scenario
                if random.random() < self.attack_probability:
                    scenario = random.choice([
                        "brute_force",
                        "user_spraying",
                        "suspicious_success",
                        "rapid_spike",
                        "invalid_probe"
                    ])
                    self.trigger_scenario(scenario)
                else:
                    event = self._generate_benign_event()
                    self._dispatch_event(event)

                # Sleep with realistic jitter
                jitter = random.uniform(0.7, 1.3)
                sleep_time = max(0.5, self.interval_seconds * jitter)
                
                # Check running flag frequently during sleep
                elapsed = 0.0
                while elapsed < sleep_time and self._running:
                    time.sleep(0.2)
                    elapsed += 0.2

            except Exception:
                time.sleep(1.0)

    def _dispatch_event(self, event: LogEvent):
        """Send event to monitor and optionally append to demo log file."""
        # Append to log file if specified
        if self.log_file_path and event.raw_log:
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(event.raw_log + "\n")
            except Exception:
                pass

        # Ingest directly through monitor pipeline
        if self.monitor:
            self.monitor.process_event_directly(event)

    def _generate_random_event(self) -> LogEvent:
        """Generate either benign or suspicious event."""
        if random.random() < 0.6:
            return self._generate_benign_event()
        return self._generate_failed_event()

    def _generate_benign_event(self) -> LogEvent:
        """Simulate authorized user successful login or session."""
        user = random.choice(self.BENIGN_USERS)
        ip = random.choice(self.BENIGN_IPS)
        port = random.randint(30000, 65000)
        ts_str = datetime.utcnow().isoformat() + "Z"
        method = random.choice(["publickey", "password"])
        pid = random.randint(10000, 32000)

        raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2"
        
        return LogEvent(
            timestamp=ts_str,
            ip=ip,
            username=user,
            event_type=EventType.SUCCESSFUL_LOGIN.value,
            auth_status="SUCCESS",
            service="sshd",
            port=port,
            severity=Severity.LOW.value,
            risk_score=0,
            message=f"Successful login for user '{user}' via {method} from {ip}",
            raw_log=raw,
            details={"auth_method": method, "simulated": True}
        )

    def _generate_failed_event(self) -> LogEvent:
        """Simulate a single failed login attempt."""
        user = random.choice(self.BENIGN_USERS + self.ATTACK_TARGET_USERS[:3])
        ip = random.choice(self.THREAT_IPS)
        port = random.randint(30000, 65000)
        ts_str = datetime.utcnow().isoformat() + "Z"
        pid = random.randint(10000, 32000)

        raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"

        return LogEvent(
            timestamp=ts_str,
            ip=ip,
            username=user,
            event_type=EventType.FAILED_LOGIN.value,
            auth_status="FAILURE",
            service="sshd",
            port=port,
            severity=Severity.LOW.value,
            risk_score=10,
            message=f"Failed login attempt for user '{user}' from {ip}",
            raw_log=raw,
            details={"reason": "Bad password", "simulated": True}
        )

    def _generate_brute_force_sequence(self) -> List[LogEvent]:
        """Simulate 6-8 rapid failed attempts against the same user from single IP."""
        attacker_ip = random.choice(self.THREAT_IPS)
        target_user = random.choice(["root", "admin", "sysadmin", "ubuntu"])
        count = random.randint(6, 8)
        events = []

        for _ in range(count):
            port = random.randint(30000, 65000)
            pid = random.randint(10000, 32000)
            ts_str = datetime.utcnow().isoformat() + "Z"
            raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Failed password for {target_user} from {attacker_ip} port {port} ssh2"
            
            ev = LogEvent(
                timestamp=ts_str,
                ip=attacker_ip,
                username=target_user,
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE",
                service="sshd",
                port=port,
                severity=Severity.LOW.value,
                risk_score=10,
                message=f"Failed login attempt for user '{target_user}' from {attacker_ip}",
                raw_log=raw,
                details={"reason": "Brute force sequence item", "simulated": True}
            )
            events.append(ev)
        return events

    def _generate_spraying_sequence(self) -> List[LogEvent]:
        """Simulate horizontal spraying across 4-6 distinct usernames."""
        attacker_ip = random.choice(self.THREAT_IPS)
        targets = random.sample(self.ATTACK_TARGET_USERS, k=random.randint(4, 6))
        events = []

        for user in targets:
            port = random.randint(30000, 65000)
            pid = random.randint(10000, 32000)
            ts_str = datetime.utcnow().isoformat() + "Z"
            raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Failed password for invalid user {user} from {attacker_ip} port {port} ssh2"

            ev = LogEvent(
                timestamp=ts_str,
                ip=attacker_ip,
                username=user,
                event_type=EventType.INVALID_USER.value,
                auth_status="INVALID",
                service="sshd",
                port=port,
                severity=Severity.MEDIUM.value,
                risk_score=15,
                message=f"Failed authentication for non-existent/invalid user '{user}' from {attacker_ip}",
                raw_log=raw,
                details={"reason": "Spraying sequence item", "simulated": True}
            )
            events.append(ev)
        return events

    def _generate_compromise_sequence(self) -> List[LogEvent]:
        """Simulate 4 failures followed immediately by a suspicious successful login."""
        attacker_ip = random.choice(self.THREAT_IPS)
        target_user = random.choice(["admin", "ubuntu", "root"])
        events = []

        # 4 failed attempts
        for _ in range(4):
            port = random.randint(30000, 65000)
            pid = random.randint(10000, 32000)
            ts_str = datetime.utcnow().isoformat() + "Z"
            raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Failed password for {target_user} from {attacker_ip} port {port} ssh2"
            events.append(LogEvent(
                timestamp=ts_str,
                ip=attacker_ip,
                username=target_user,
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE",
                service="sshd",
                port=port,
                severity=Severity.LOW.value,
                risk_score=10,
                message=f"Failed login attempt for user '{target_user}' from {attacker_ip}",
                raw_log=raw,
                details={"reason": "Compromise pre-attempt", "simulated": True}
            ))

        # Followed by success!
        port = random.randint(30000, 65000)
        pid = random.randint(10000, 32000)
        ts_str = datetime.utcnow().isoformat() + "Z"
        raw_succ = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Accepted password for {target_user} from {attacker_ip} port {port} ssh2"
        events.append(LogEvent(
            timestamp=ts_str,
            ip=attacker_ip,
            username=target_user,
            event_type=EventType.SUCCESSFUL_LOGIN.value,
            auth_status="SUCCESS",
            service="sshd",
            port=port,
            severity=Severity.LOW.value,
            risk_score=0,
            message=f"Successful login for user '{target_user}' via password from {attacker_ip}",
            raw_log=raw_succ,
            details={"auth_method": "password", "simulated": True}
        ))

        return events

    def _generate_rapid_spike_sequence(self) -> List[LogEvent]:
        """Simulate high-velocity burst of 9 attempts in rapid succession."""
        attacker_ip = random.choice(self.THREAT_IPS)
        target_user = random.choice(["root", "admin"])
        events = []

        for _ in range(9):
            port = random.randint(30000, 65000)
            pid = random.randint(10000, 32000)
            ts_str = datetime.utcnow().isoformat() + "Z"
            raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Failed password for {target_user} from {attacker_ip} port {port} ssh2"
            events.append(LogEvent(
                timestamp=ts_str,
                ip=attacker_ip,
                username=target_user,
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE",
                service="sshd",
                port=port,
                severity=Severity.LOW.value,
                risk_score=10,
                message=f"Failed login attempt for user '{target_user}' from {attacker_ip}",
                raw_log=raw,
                details={"reason": "Velocity spike item", "simulated": True}
            ))
        return events

    def _generate_invalid_probe_sequence(self) -> List[LogEvent]:
        """Simulate repeated probes against nonexistent accounts."""
        attacker_ip = random.choice(self.THREAT_IPS)
        weird_users = ["nagios", "postfix", "mysql", "nobody"]
        events = []

        for u in weird_users:
            port = random.randint(30000, 65000)
            pid = random.randint(10000, 32000)
            ts_str = datetime.utcnow().isoformat() + "Z"
            raw = f"Aug 22 14:32:10 srv-prod-01 sshd[{pid}]: Invalid user {u} from {attacker_ip} port {port}"
            events.append(LogEvent(
                timestamp=ts_str,
                ip=attacker_ip,
                username=u,
                event_type=EventType.INVALID_USER.value,
                auth_status="INVALID",
                service="sshd",
                port=port,
                severity=Severity.MEDIUM.value,
                risk_score=15,
                message=f"Invalid user lookup '{u}' from {attacker_ip}",
                raw_log=raw,
                details={"reason": "Invalid user probe", "simulated": True}
            ))
        return events
