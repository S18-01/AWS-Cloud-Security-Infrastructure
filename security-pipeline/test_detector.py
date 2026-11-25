import unittest

from detector import detect_findings


FAILURE = {"event_type": "ssh_login_failed", "source_ip": "192.0.2.10"}
OTHER_IP = dict(FAILURE, source_ip="192.0.2.20")
SUCCESS = dict(FAILURE, event_type="ssh_login_succeeded")


class DetectorTests(unittest.TestCase):
    def test_counts_failures_separately_for_each_ip(self):
        self.assertEqual(detect_findings([FAILURE] * 4 + [OTHER_IP]), [])

    def test_ignores_successful_logins(self):
        self.assertEqual(detect_findings([FAILURE] * 4 + [SUCCESS]), [])

    def test_creates_finding_at_threshold(self):
        self.assertEqual(detect_findings([FAILURE] * 5 + [OTHER_IP]), [{
            "rule_id": "repeated_ssh_login_failures",
            "severity": "MEDIUM",
            "source_ip": "192.0.2.10",
            "failed_attempts": 5,
        }])
