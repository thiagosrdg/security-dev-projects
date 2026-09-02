"""Tests for the log parsers, using sanitised log lines."""

import unittest

from logsentinel.parsers import parse_line

YEAR = 2026


class TestParsers(unittest.TestCase):

    def test_ssh_failed_password(self):
        line = ("Sep  2 10:15:01 srv01 sshd[2011]: Failed password for root "
                "from 192.0.2.10 port 40122 ssh2")
        event = parse_line(line, YEAR)
        self.assertEqual(event.source, "auth")
        self.assertEqual(event.outcome, "failure")
        self.assertEqual(event.ip, "192.0.2.10")
        self.assertEqual(event.user, "root")
        self.assertEqual(event.timestamp.hour, 10)

    def test_ssh_invalid_user_is_a_failure(self):
        line = ("Sep  2 10:15:04 srv01 sshd[2013]: Failed password for invalid "
                "user admin from 192.0.2.10 port 40125 ssh2")
        event = parse_line(line, YEAR)
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.outcome, "failure")

    def test_ssh_accepted_password(self):
        line = ("Sep  2 11:04:59 srv01 sshd[2100]: Accepted password for backup "
                "from 198.51.100.77 port 33010 ssh2")
        event = parse_line(line, YEAR)
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.user, "backup")

    def test_firewall_block(self):
        line = ("Sep  2 13:58:02 srv01 kernel: [UFW BLOCK] IN=eth0 OUT= "
                "SRC=203.0.113.9 DST=192.0.2.5 PROTO=TCP SPT=45000 DPT=22")
        event = parse_line(line, YEAR)
        self.assertEqual(event.source, "firewall")
        self.assertEqual(event.action, "block")
        self.assertEqual(event.ip, "203.0.113.9")
        self.assertEqual(event.port, 22)

    def test_http_access_line(self):
        line = ('203.0.113.9 - - [02/Sep/2026:14:03:11 +0000] '
                '"GET /.env HTTP/1.1" 403 162 "-" "curl/8.5.0"')
        event = parse_line(line, YEAR)
        self.assertEqual(event.source, "http")
        self.assertEqual(event.path, "/.env")
        self.assertEqual(event.status, 403)
        self.assertEqual(event.outcome, "failure")

    def test_application_line(self):
        line = ("2026-09-02 16:40:05 WARNING login_failed user=support "
                "ip=198.51.100.23 path=/api/login")
        event = parse_line(line, YEAR)
        self.assertEqual(event.source, "app")
        self.assertEqual(event.user, "support")
        self.assertEqual(event.outcome, "failure")

    def test_unknown_line_is_ignored(self):
        self.assertIsNone(parse_line("this line has no known format", YEAR))
        self.assertIsNone(parse_line("   ", YEAR))


if __name__ == "__main__":
    unittest.main()
