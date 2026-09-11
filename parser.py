
import re

raw_log = "Nov 17 15:08:39 localhost sshd[621893]: Failed password for nemo from 192.168.0.7 port 8132 ssh2"

pattern = r"Failed password for (?P<user>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"

match = re.search(pattern, raw_log)

if match:
    # Mapping the extracted data directly into our Day 1 Schema
    normalized_event = {
        "log_source": "linux-auth",
        "event_type": "authentication",
        "source_ip": match.group("source_ip"),
        "user": match.group("user"),
        "action": "failure",
        "severity": "medium",
        "raw_log": raw_log
    }

    print("\n========== NORMALIZED EVENT ==========")
    print("Log Source :", normalized_event["log_source"])
    print("Event Type :", normalized_event["event_type"])
    print("Source IP  :", normalized_event["source_ip"])
    print("User       :", normalized_event["user"])
    print("Action     :", normalized_event["action"])
    print("Severity   :", normalized_event["severity"])
    print("Raw Log    :", normalized_event["raw_log"])
    print("======================================")


