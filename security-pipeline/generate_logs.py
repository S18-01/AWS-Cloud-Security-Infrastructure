import json
from datetime import datetime, timezone


def generate_events():
    timestamp = datetime.now(timezone.utc).isoformat()
    scenarios = (
        ("ssh_login_failed", "192.0.2.10", 5),
        ("ssh_login_failed", "192.0.2.20", 2),
        ("ssh_login_succeeded", "192.0.2.30", 1),
    )
    return [
        {"timestamp": timestamp, "event_type": event_type,
         "source_ip": source_ip, "synthetic": True}
        for event_type, source_ip, count in scenarios
        for _ in range(count)
    ]


if __name__ == "__main__":
    print(json.dumps(generate_events()))
