import re
import uuid

# IPv4 group shared by all sshd/pam patterns
_IP = r"(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"

# Ordered most-specific first. Each pattern maps a Linux auth.log line to a
# normalized event: event_type / action / baseline severity.
PATTERNS = [
    # sshd brute force against accounts that do not exist (classic spray signature)
    {
        "regex": rf"Failed password for invalid user (?P<user>\S+) from {_IP}",
        "event_type": "authentication", "action": "failure", "severity": "high",
    },
    # sshd "Invalid user" notice (often precedes the failed-password line)
    {
        "regex": rf"Invalid user (?P<user>\S+) from {_IP}",
        "event_type": "authentication", "action": "failure", "severity": "high",
    },
    # classic failed password attempt against a valid username
    {
        "regex": rf"Failed password for (?P<user>\S+) from {_IP}",
        "event_type": "authentication", "action": "failure", "severity": "medium",
    },
    # successful logins — possible payoff of a brute force
    {
        "regex": rf"Accepted password for (?P<user>\S+) from {_IP}",
        "event_type": "authentication", "action": "success", "severity": "low",
    },
    {
        "regex": rf"Accepted publickey for (?P<user>\S+) from {_IP}",
        "event_type": "authentication", "action": "success", "severity": "low",
    },
    # pam_unix authentication failures
    {
        "regex": rf"authentication failure;.*rhost={_IP}(?:\s+user=(?P<user>\S+))?",
        "event_type": "authentication", "action": "failure", "severity": "medium",
    },
    # sudo privilege escalation (keeps the executed command as process_name)
    {
        "regex": r"sudo:\s+(?P<user>\S+)\s+:\s+.*USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)$",
        "event_type": "privilege_escalation", "action": "execute", "severity": "medium",
    },
]


def parse_linux_auth(raw_log):
    """Takes a single raw log line and returns a normalized dictionary (or None).

    Understands the common auth.log event families: failed/invalid-user SSH
    attempts, accepted password/publickey logins, pam_unix failures, and sudo
    privilege escalation.
    """
    # TRICK: syslog timestamps ("Oct  2 01:36:38") live in the first 15 chars
    extracted_time = raw_log[:15]

    # The hostname (the actual machine) is the first token after the timestamp
    rest = raw_log[15:].strip()
    host_token = rest.split(" ", 1)[0] if rest else ""
    host = host_token if host_token and ":" not in host_token else None

    for pattern in PATTERNS:
        match = re.search(pattern["regex"], raw_log)
        if not match:
            continue

        groups = match.groupdict()
        normalized_event = {
            "timestamp": extracted_time,
            "log_source": "linux-auth",
            "event_type": pattern["event_type"],
            "source_ip": groups.get("source_ip"),
            "user": groups.get("user"),
            "host": host,
            "action": pattern["action"],
            "severity": pattern["severity"],
            "raw_log": raw_log.strip(),
            "event_id": str(uuid.uuid4()),
        }
        if groups.get("command"):
            normalized_event["process_name"] = groups["command"].strip()
        return normalized_event

    return None
