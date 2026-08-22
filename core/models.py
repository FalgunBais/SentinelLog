"""SentinelLog Data Models and Type Definitions"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import ipaddress
import json


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: int, thresholds: Optional[Dict[str, int]] = None) -> "Severity":
        if thresholds is None:
            thresholds = {"LOW": 0, "MEDIUM": 30, "HIGH": 60, "CRITICAL": 85}
        
        if score >= thresholds.get("CRITICAL", 85):
            return cls.CRITICAL
        elif score >= thresholds.get("HIGH", 60):
            return cls.HIGH
        elif score >= thresholds.get("MEDIUM", 30):
            return cls.MEDIUM
        return cls.LOW


class EventType(str, Enum):
    SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
    FAILED_LOGIN = "FAILED_LOGIN"
    INVALID_USER = "INVALID_USER"
    SSH_AUTH_FAILURE = "SSH_AUTH_FAILURE"
    SESSION_OPENED = "SESSION_OPENED"
    SESSION_CLOSED = "SESSION_CLOSED"
    SUDO_COMMAND = "SUDO_COMMAND"
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    UNKNOWN = "UNKNOWN"


class ThreatType(str, Enum):
    BRUTE_FORCE_ATTEMPT = "BRUTE_FORCE_ATTEMPT"
    USER_SPRAYING = "USER_SPRAYING"
    RAPID_SPIKE = "RAPID_SPIKE"
    SUSPICIOUS_SUCCESS = "SUSPICIOUS_SUCCESS"
    INVALID_USER_PROBE = "INVALID_USER_PROBE"
    REPEATED_FAILURES = "REPEATED_FAILURES"


@dataclass
class LogEvent:
    id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    ip: str = "UNKNOWN"
    username: str = "UNKNOWN"
    event_type: str = EventType.UNKNOWN.value
    auth_status: str = "UNKNOWN"  # SUCCESS, FAILURE, INVALID, INFO
    service: str = "sshd"
    port: Optional[int] = None
    severity: str = Severity.LOW.value
    risk_score: int = 0
    message: str = ""
    raw_log: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEvent":
        clean_data = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        if isinstance(clean_data.get("details"), str):
            try:
                clean_data["details"] = json.loads(clean_data["details"])
            except Exception:
                clean_data["details"] = {}
        return cls(**clean_data)


@dataclass
class ThreatAlert:
    id: Optional[int] = None
    alert_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    threat_type: str = ThreatType.BRUTE_FORCE_ATTEMPT.value
    source_ip: str = "UNKNOWN"
    username: str = "UNKNOWN"
    severity: str = Severity.HIGH.value
    risk_score: int = 60
    reason: str = ""
    recommended_action: str = ""
    status: str = "ACTIVE"  # ACTIVE, ACKNOWLEDGED
    event_count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    acknowledged_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatAlert":
        clean_data = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        if isinstance(clean_data.get("metadata"), str):
            try:
                clean_data["metadata"] = json.loads(clean_data["metadata"])
            except Exception:
                clean_data["metadata"] = {}
        return cls(**clean_data)


@dataclass
class IPProfile:
    ip: str
    total_attempts: int = 0
    failed_attempts: int = 0
    successful_attempts: int = 0
    invalid_user_attempts: int = 0
    targeted_usernames: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    risk_score: int = 0
    severity: str = Severity.LOW.value
    is_private: bool = False
    classification: str = "Public"
    active_threats: int = 0
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    recent_events: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            if ip_obj.is_loopback:
                self.is_private = True
                self.classification = "Loopback"
            elif (
                ip_obj in ipaddress.ip_network("10.0.0.0/8") or
                ip_obj in ipaddress.ip_network("172.16.0.0/12") or
                ip_obj in ipaddress.ip_network("192.168.0.0/16")
            ):
                self.is_private = True
                self.classification = "Private / RFC1918"
            elif ip_obj.is_link_local:
                self.is_private = True
                self.classification = "Link-Local"
            elif ip_obj.is_multicast:
                self.is_private = False
                self.classification = "Multicast"
            else:
                self.is_private = False
                self.classification = "Public / External"
        except ValueError:
            self.is_private = False
            self.classification = "Unknown / Non-standard"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
