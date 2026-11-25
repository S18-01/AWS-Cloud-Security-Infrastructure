from collections import Counter

SSH_FAILURE_THRESHOLD = 5


def detect_findings(events):
    failures_by_ip = Counter()

    for event in events:
        source_ip = event.get("source_ip")
        if event.get("event_type") == "ssh_login_failed" and source_ip:
            failures_by_ip[source_ip] += 1

    return [
        {
            "rule_id": "repeated_ssh_login_failures",
            "severity": "MEDIUM",
            "source_ip": source_ip,
            "failed_attempts": attempts,
        }
        for source_ip, attempts in sorted(failures_by_ip.items())
        if attempts >= SSH_FAILURE_THRESHOLD
    ]
