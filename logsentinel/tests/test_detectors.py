"""Tests for the detection rules."""

import unittest
from datetime import datetime, timedelta

from logsentinel.detectors import busiest_window, run_detectors
from logsentinel.models import Event
from logsentinel.rules import load_rules

START = datetime(2026, 9, 2, 10, 0, 0)


def auth_event(offset_seconds, ip, user, outcome):
    """Build one authentication event `offset_seconds` after START."""
    return Event(timestamp=START + timedelta(seconds=offset_seconds),
                 source="auth", raw="", ip=ip, user=user, outcome=outcome)


def rules_by_name(findings):
    return {finding.rule for finding in findings}


class TestWindow(unittest.TestCase):

    def test_busiest_window_keeps_only_the_closest_events(self):
        events = [auth_event(0, "192.0.2.10", "root", "failure"),
                  auth_event(60, "192.0.2.10", "root", "failure"),
                  auth_event(120, "192.0.2.10", "root", "failure"),
                  auth_event(6000, "192.0.2.10", "root", "failure")]
        self.assertEqual(len(busiest_window(events, 5)), 3)


class TestDetectors(unittest.TestCase):

    def setUp(self):
        self.config = load_rules()

    def test_brute_force_is_detected(self):
        events = [auth_event(i * 5, "192.0.2.10", "root", "failure")
                  for i in range(12)]
        findings = run_detectors(events, self.config)
        self.assertIn("excessive_auth_failures", rules_by_name(findings))

    def test_few_failures_produce_no_finding(self):
        events = [auth_event(i * 5, "192.0.2.10", "root", "failure")
                  for i in range(3)]
        self.assertEqual(run_detectors(events, self.config), [])

    def test_allowlisted_ip_is_skipped(self):
        events = [auth_event(i * 5, "192.0.2.10", "root", "failure")
                  for i in range(20)]
        self.config["allowlist"].append("192.0.2.0/24")
        self.assertEqual(run_detectors(events, self.config), [])

    def test_multiple_accounts_are_detected(self):
        users = ["root", "admin", "test", "oracle"]
        events = [auth_event(i * 5, "192.0.2.10", users[i % 4], "failure")
                  for i in range(8)]
        findings = run_detectors(events, self.config)
        self.assertIn("account_targeting", rules_by_name(findings))

    def test_success_after_failures_is_detected(self):
        events = [auth_event(i * 10, "192.0.2.10", "backup", "failure")
                  for i in range(6)]
        events.append(auth_event(70, "192.0.2.10", "backup", "success"))
        findings = run_detectors(events, self.config)
        self.assertIn("success_after_failures", rules_by_name(findings))

    def test_http_errors_and_suspicious_paths(self):
        events = [Event(timestamp=START + timedelta(seconds=i * 5), source="http",
                        raw="", ip="203.0.113.9", path="/admin", status=404)
                  for i in range(20)]
        findings = run_detectors(events, self.config)
        self.assertIn("http_error_flood", rules_by_name(findings))
        self.assertIn("suspicious_paths", rules_by_name(findings))
        # Two rules on the same IP also raise the correlation rule.
        self.assertIn("anomalous_ip", rules_by_name(findings))

    def test_port_scan_is_detected(self):
        events = [Event(timestamp=START + timedelta(seconds=i * 5),
                        source="firewall", raw="", ip="203.0.113.9",
                        port=20 + i, action="block") for i in range(15)]
        findings = run_detectors(events, self.config)
        self.assertIn("port_scan", rules_by_name(findings))

    def test_off_hours_activity_is_detected(self):
        night = datetime(2026, 9, 2, 3, 0, 0)
        events = [Event(timestamp=night + timedelta(minutes=i * 3), source="auth",
                        raw="", ip="203.0.113.45", user="svc", outcome="success")
                  for i in range(4)]
        findings = run_detectors(events, self.config)
        self.assertIn("off_hours_activity", rules_by_name(findings))

    def test_disabled_rule_produces_no_finding(self):
        events = [auth_event(i * 5, "192.0.2.10", "root", "failure")
                  for i in range(12)]
        self.config["rules"]["excessive_auth_failures"]["enabled"] = False
        self.assertNotIn("excessive_auth_failures",
                         rules_by_name(run_detectors(events, self.config)))


if __name__ == "__main__":
    unittest.main()
