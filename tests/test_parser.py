"""Unit Tests for SentinelLog Parser"""

import unittest
from core.parser import LogParser
from core.models import EventType, Severity


class TestLogParser(unittest.TestCase):

    def setUp(self):
        self.parser = LogParser()

    def test_parse_ssh_accepted_publickey(self):
        line = "Oct 14 12:34:50 srv01 sshd[10234]: Accepted publickey for ubuntu from 192.168.1.50 port 54322 ssh2: RSA SHA256:abc123"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "ubuntu")
        self.assertEqual(ev.ip, "192.168.1.50")
        self.assertEqual(ev.event_type, EventType.SUCCESSFUL_LOGIN.value)
        self.assertEqual(ev.auth_status, "SUCCESS")
        self.assertEqual(ev.port, 54322)

    def test_parse_ssh_failed_password(self):
        line = "Oct 14 12:35:00 srv01 sshd[10235]: Failed password for root from 198.51.100.42 port 48210 ssh2"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "root")
        self.assertEqual(ev.ip, "198.51.100.42")
        self.assertEqual(ev.event_type, EventType.FAILED_LOGIN.value)
        self.assertEqual(ev.auth_status, "FAILURE")
        self.assertEqual(ev.port, 48210)

    def test_parse_ssh_invalid_user(self):
        line = "Oct 14 12:36:00 srv01 sshd[10241]: Failed password for invalid user admin from 203.0.113.88 port 39120 ssh2"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "admin")
        self.assertEqual(ev.ip, "203.0.113.88")
        self.assertEqual(ev.event_type, EventType.INVALID_USER.value)
        self.assertEqual(ev.auth_status, "INVALID")

    def test_parse_ssh_invalid_user_probe(self):
        line = "Oct 14 12:36:05 srv01 sshd[10242]: Invalid user test from 10.0.0.15 port 44321"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "test")
        self.assertEqual(ev.ip, "10.0.0.15")
        self.assertEqual(ev.event_type, EventType.INVALID_USER.value)
        self.assertEqual(ev.auth_status, "INVALID")

    def test_parse_sudo_command(self):
        line = "Oct 14 12:38:00 srv01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "ubuntu")
        self.assertEqual(ev.event_type, EventType.SUDO_COMMAND.value)
        self.assertEqual(ev.details.get("target_user"), "root")

    def test_parse_pam_failure(self):
        line = "Oct 14 12:39:00 srv01 sshd[123]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.42 user=admin"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "admin")
        self.assertEqual(ev.ip, "198.51.100.42")
        self.assertEqual(ev.event_type, EventType.FAILED_LOGIN.value)

    def test_parse_generic_fallback(self):
        line = "2026-08-22 14:00:00 [AUTH] FAILED_LOGIN user=badactor ip=192.0.2.1 password check failed"
        ev = self.parser.parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.username, "badactor")
        self.assertEqual(ev.ip, "192.0.2.1")
        self.assertEqual(ev.event_type, EventType.FAILED_LOGIN.value)


if __name__ == "__main__":
    unittest.main()
