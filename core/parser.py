"""SentinelLog Multi-Format Authentication Log Parser

Supports:
- Debian/Ubuntu /var/log/auth.log
- RHEL/CentOS /var/log/secure
- OpenSSH daemon logs (sshd)
- PAM authentication logs (pam_unix)
- Sudo / Su execution logs
- Generic timestamped authentication logs
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any, List
import ipaddress
from core.models import LogEvent, EventType, Severity


class LogParser:
    """Parses raw log strings into structured LogEvent objects."""

    # Month mapping for legacy syslog format (e.g. 'Oct 14 12:34:56')
    MONTH_MAP = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    # Common IP regex
    IP_REGEX = r'(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)'

    # Compile regex patterns for high performance
    # Syslog header: "Oct 14 12:34:56 hostname service[pid]: message"
    SYSLOG_HEADER_RE = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\.\-]+)\s+(?P<service>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
    )

    # ISO8601 syslog header: "2026-08-22T14:30:00+00:00 hostname service[pid]: message"
    ISO_SYSLOG_HEADER_RE = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<hostname>[\w\.\-]+)\s+(?P<service>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
    )

    # 1. SSH Failed password for invalid user
    SSH_FAILED_INVALID_RE = re.compile(
        r'Failed\s+password\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(?P<port>\d+))?',
        re.IGNORECASE
    )

    # 2. SSH Failed password for valid user
    SSH_FAILED_VALID_RE = re.compile(
        r'Failed\s+(?:password|publickey|none)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(?P<port>\d+))?',
        re.IGNORECASE
    )

    # 3. SSH Accepted password or publickey
    SSH_ACCEPTED_RE = re.compile(
        r'Accepted\s+(?P<auth_method>password|publickey|keyboard-interactive|gssapi-with-mic)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(?P<port>\d+))?',
        re.IGNORECASE
    )

    # 4. SSH Invalid user line (e.g. "Invalid user admin from 1.2.3.4")
    SSH_INVALID_USER_RE = re.compile(
        r'Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(?P<port>\d+))?',
        re.IGNORECASE
    )

    # 5. SSH Disconnect / preauth authentication failure
    SSH_PREAUTH_FAIL_RE = re.compile(
        r'(?:Connection\s+closed\s+by|Disconnected\s+from)(?:\s+authenticating\s+user\s+(?P<user>\S+))?\s+(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(?P<port>\d+))?\s+\[preauth\]',
        re.IGNORECASE
    )

    # 6. PAM authentication failure (pam_unix)
    PAM_AUTH_FAIL_RE = re.compile(
        r'pam_unix\((?P<pam_service>[^:]+):auth\):\s*authentication failure;\s*logname=(?P<logname>\S*)\s*uid=(?P<uid>\d*)\s*euid=(?P<euid>\d*)\s*tty=(?P<tty>\S*)\s*ruser=(?P<ruser>\S*)\s*rhost=(?P<rhost>\S*)\s*(?:user=(?P<user>\S*))?',
        re.IGNORECASE
    )

    # 7. PAM Session opened / closed
    PAM_SESSION_OPEN_RE = re.compile(
        r'pam_unix\((?P<pam_service>[^:]+):session\):\s*session opened for user (?P<user>\S+)(?:\s+by\s+(?P<by>\S+))?',
        re.IGNORECASE
    )
    PAM_SESSION_CLOSE_RE = re.compile(
        r'pam_unix\((?P<pam_service>[^:]+):session\):\s*session closed for user (?P<user>\S+)',
        re.IGNORECASE
    )

    # 8. Sudo command execution
    SUDO_COMMAND_RE = re.compile(
        r'(?:sudo:\s+)?(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)',
        re.IGNORECASE
    )

    # 9. Generic key-value fallback (e.g. "timestamp=... user=admin ip=1.2.3.4 event=FAILED_LOGIN")
    KV_USER_RE = re.compile(r'\b(?:user|username|account)=([\'"]?)(?P<val>[a-zA-Z0-9_\-\.\@]+)\1', re.IGNORECASE)
    KV_IP_RE = re.compile(r'\b(?:ip|rhost|host|src_ip|src)=([\'"]?)(?P<val>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)\1', re.IGNORECASE)
    KV_EVENT_RE = re.compile(r'\b(?:event|action|type)=([\'"]?)(?P<val>[a-zA-Z0-9_\-]+)\1', re.IGNORECASE)
    KV_STATUS_RE = re.compile(r'\b(?:status|result)=([\'"]?)(?P<val>[a-zA-Z0-9_\-]+)\1', re.IGNORECASE)

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single log line into a LogEvent object."""
        if not line or not line.strip():
            return None

        line = line.strip()
        timestamp_str = datetime.utcnow().isoformat() + "Z"
        hostname = "localhost"
        service = "auth"
        message = line

        # Step 1: Extract syslog or ISO header if present
        syslog_match = self.SYSLOG_HEADER_RE.match(line)
        iso_match = self.ISO_SYSLOG_HEADER_RE.match(line)

        if iso_match:
            raw_ts = iso_match.group("timestamp")
            hostname = iso_match.group("hostname")
            service = iso_match.group("service")
            message = iso_match.group("message")
            timestamp_str = self._normalize_iso_timestamp(raw_ts)
        elif syslog_match:
            raw_ts = syslog_match.group("timestamp")
            hostname = syslog_match.group("hostname")
            service = syslog_match.group("service")
            message = syslog_match.group("message")
            timestamp_str = self._parse_syslog_timestamp(raw_ts)

        # Step 2: Parse message content based on security patterns
        event = self._parse_message(message, service=service, raw_log=line, timestamp_str=timestamp_str)
        if event:
            if hostname != "localhost":
                event.details["hostname"] = hostname
            return event

        # Step 3: Fallback generic parser for custom formats
        return self._parse_generic_fallback(line, timestamp_str=timestamp_str, service=service)

    def _parse_message(self, message: str, service: str, raw_log: str, timestamp_str: str) -> Optional[LogEvent]:
        """Examine message body with specialized security patterns."""

        # 1. SSH Failed password for invalid user
        m = self.SSH_FAILED_INVALID_RE.search(message)
        if m:
            user = m.group("user")
            ip = self._sanitize_ip(m.group("ip"))
            port = int(m.group("port")) if m.group("port") else None
            return LogEvent(
                timestamp=timestamp_str,
                ip=ip,
                username=user,
                event_type=EventType.INVALID_USER.value,
                auth_status="INVALID",
                service=service or "sshd",
                port=port,
                severity=Severity.MEDIUM.value,
                risk_score=15,
                message=f"Failed authentication for non-existent/invalid user '{user}' from {ip}",
                raw_log=raw_log,
                details={"reason": "Invalid user account", "service": service}
            )

        # 2. SSH Failed password / auth for valid user
        m = self.SSH_FAILED_VALID_RE.search(message)
        if m:
            user = m.group("user")
            ip = self._sanitize_ip(m.group("ip"))
            port = int(m.group("port")) if m.group("port") else None
            return LogEvent(
                timestamp=timestamp_str,
                ip=ip,
                username=user,
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE",
                service=service or "sshd",
                port=port,
                severity=Severity.LOW.value,
                risk_score=10,
                message=f"Failed login attempt for user '{user}' from {ip}",
                raw_log=raw_log,
                details={"reason": "Bad credentials", "service": service}
            )

        # 3. SSH Accepted login
        m = self.SSH_ACCEPTED_RE.search(message)
        if m:
            user = m.group("user")
            ip = self._sanitize_ip(m.group("ip"))
            port = int(m.group("port")) if m.group("port") else None
            method = m.group("auth_method")
            return LogEvent(
                timestamp=timestamp_str,
                ip=ip,
                username=user,
                event_type=EventType.SUCCESSFUL_LOGIN.value,
                auth_status="SUCCESS",
                service=service or "sshd",
                port=port,
                severity=Severity.LOW.value,
                risk_score=0,
                message=f"Successful login for user '{user}' via {method} from {ip}",
                raw_log=raw_log,
                details={"auth_method": method, "service": service}
            )

        # 4. SSH Invalid user probe (e.g., "Invalid user guest from 1.2.3.4")
        m = self.SSH_INVALID_USER_RE.search(message)
        if m:
            user = m.group("user")
            ip = self._sanitize_ip(m.group("ip"))
            port = int(m.group("port")) if m.group("port") else None
            return LogEvent(
                timestamp=timestamp_str,
                ip=ip,
                username=user,
                event_type=EventType.INVALID_USER.value,
                auth_status="INVALID",
                service=service or "sshd",
                port=port,
                severity=Severity.MEDIUM.value,
                risk_score=15,
                message=f"Invalid user lookup '{user}' from {ip}",
                raw_log=raw_log,
                details={"reason": "Unknown username query", "service": service}
            )

        # 5. SSH Preauth failure / connection closed
        m = self.SSH_PREAUTH_FAIL_RE.search(message)
        if m:
            user = m.group("user") or "UNKNOWN"
            ip = self._sanitize_ip(m.group("ip"))
            port = int(m.group("port")) if m.group("port") else None
            return LogEvent(
                timestamp=timestamp_str,
                ip=ip,
                username=user,
                event_type=EventType.SSH_AUTH_FAILURE.value,
                auth_status="FAILURE",
                service=service or "sshd",
                port=port,
                severity=Severity.LOW.value,
                risk_score=10,
                message=f"SSH pre-authentication drop from {ip}",
                raw_log=raw_log,
                details={"reason": "Preauth disconnect", "service": service}
            )

        # 6. PAM auth failure
        m = self.PAM_AUTH_FAIL_RE.search(message)
        if m:
            user = m.group("user") or m.group("ruser") or "UNKNOWN"
            rhost = m.group("rhost") or "127.0.0.1"
            ip = self._sanitize_ip(rhost) if rhost else "127.0.0.1"
            pam_service = m.group("pam_service")
            return LogEvent(
                timestamp=timestamp_str,
                ip=ip,
                username=user,
                event_type=EventType.FAILED_LOGIN.value,
                auth_status="FAILURE",
                service=pam_service or service or "pam",
                severity=Severity.LOW.value,
                risk_score=10,
                message=f"PAM authentication failure for user '{user}' from {ip}",
                raw_log=raw_log,
                details={"pam_service": pam_service, "uid": m.group("uid")}
            )

        # 7. PAM Session Opened / Closed
        m = self.PAM_SESSION_OPEN_RE.search(message)
        if m:
            user = m.group("user")
            pam_service = m.group("pam_service")
            return LogEvent(
                timestamp=timestamp_str,
                ip="127.0.0.1",
                username=user,
                event_type=EventType.SESSION_OPENED.value,
                auth_status="SUCCESS",
                service=pam_service or service or "pam",
                severity=Severity.LOW.value,
                risk_score=0,
                message=f"Session opened for user '{user}'",
                raw_log=raw_log,
                details={"pam_service": pam_service}
            )

        m = self.PAM_SESSION_CLOSE_RE.search(message)
        if m:
            user = m.group("user")
            pam_service = m.group("pam_service")
            return LogEvent(
                timestamp=timestamp_str,
                ip="127.0.0.1",
                username=user,
                event_type=EventType.SESSION_CLOSED.value,
                auth_status="INFO",
                service=pam_service or service or "pam",
                severity=Severity.LOW.value,
                risk_score=0,
                message=f"Session closed for user '{user}'",
                raw_log=raw_log,
                details={"pam_service": pam_service}
            )

        # 8. Sudo command
        m = self.SUDO_COMMAND_RE.search(message)
        if m:
            user = m.group("user")
            target_user = m.group("target_user")
            cmd = m.group("command")
            return LogEvent(
                timestamp=timestamp_str,
                ip="127.0.0.1",
                username=user,
                event_type=EventType.SUDO_COMMAND.value,
                auth_status="SUCCESS",
                service="sudo",
                severity=Severity.LOW.value,
                risk_score=0,
                message=f"User '{user}' executed sudo as '{target_user}': {cmd}",
                raw_log=raw_log,
                details={"target_user": target_user, "command": cmd, "tty": m.group("tty")}
            )

        return None

    def _parse_generic_fallback(self, line: str, timestamp_str: str, service: str) -> Optional[LogEvent]:
        """Generic heuristic parser for structured or key-value custom log lines."""
        # Find IP
        ip_match = self.KV_IP_RE.search(line)
        ip = "127.0.0.1"
        if ip_match:
            ip = self._sanitize_ip(ip_match.group("val"))
        else:
            # Try raw IP extraction
            raw_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if raw_ips:
                ip = raw_ips[0]

        # Find user
        user_match = self.KV_USER_RE.search(line)
        username = user_match.group("val") if user_match else "UNKNOWN"

        lower_line = line.lower()
        if "fail" in lower_line or "denied" in lower_line or "bad" in lower_line or "error" in lower_line:
            event_type = EventType.FAILED_LOGIN.value
            auth_status = "FAILURE"
            severity = Severity.LOW.value
            risk_score = 10
            msg = f"Failed authentication event detected: {line[:80]}"
        elif "invalid user" in lower_line:
            event_type = EventType.INVALID_USER.value
            auth_status = "INVALID"
            severity = Severity.MEDIUM.value
            risk_score = 15
            msg = f"Invalid user login attempt: {line[:80]}"
        elif "accept" in lower_line or "success" in lower_line or "opened" in lower_line:
            event_type = EventType.SUCCESSFUL_LOGIN.value
            auth_status = "SUCCESS"
            severity = Severity.LOW.value
            risk_score = 0
            msg = f"Successful authentication event: {line[:80]}"
        else:
            event_type = EventType.UNKNOWN.value
            auth_status = "INFO"
            severity = Severity.LOW.value
            risk_score = 0
            msg = line[:100]

        return LogEvent(
            timestamp=timestamp_str,
            ip=ip,
            username=username,
            event_type=event_type,
            auth_status=auth_status,
            service=service or "custom",
            severity=severity,
            risk_score=risk_score,
            message=msg,
            raw_log=line,
            details={"type": "generic_parsed"}
        )

    def _parse_syslog_timestamp(self, ts_str: str) -> str:
        """Convert 'Oct 14 12:34:56' into ISO 8601 string 'YYYY-MM-DDTHH:MM:SSZ'."""
        try:
            parts = ts_str.split()
            if len(parts) >= 3:
                month = self.MONTH_MAP.get(parts[0], datetime.utcnow().month)
                day = int(parts[1])
                time_parts = [int(p) for p in parts[2].split(":")]
                current_year = datetime.utcnow().year
                dt = datetime(current_year, month, day, time_parts[0], time_parts[1], time_parts[2])
                return dt.isoformat() + "Z"
        except Exception:
            pass
        return datetime.utcnow().isoformat() + "Z"

    def _normalize_iso_timestamp(self, ts_str: str) -> str:
        """Ensure ISO timestamp has uniform ISO 8601 formatting."""
        try:
            # Replace space with T
            ts_str = ts_str.replace(" ", "T")
            if not ts_str.endswith("Z") and "+" not in ts_str and "-" not in ts_str[10:]:
                ts_str += "Z"
            return ts_str
        except Exception:
            return datetime.utcnow().isoformat() + "Z"

    def _sanitize_ip(self, ip_candidate: str) -> str:
        """Validate and clean IP address string."""
        if not ip_candidate:
            return "UNKNOWN"
        clean = ip_candidate.strip().strip("[](),:;")
        try:
            ipaddress.ip_address(clean)
            return clean
        except ValueError:
            return "UNKNOWN"
