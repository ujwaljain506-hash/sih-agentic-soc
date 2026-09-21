import re

def parse_linux_auth(raw_log):
    """Takes a single raw log line and returns a normalized dictionary."""
    # TRICK: Grab exactly the first 15 characters of the string
    extracted_time = raw_log[:15]
    
    pattern = r"Failed password for (?P<user>\w+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
    
    match = re.search(pattern, raw_log)
    if match:
        normalized_event = {
            "timestamp": extracted_time,  # <--- Now mapping our extracted time!
            "log_source": "linux-auth",
            "event_type": "authentication",
            "source_ip": match.group("source_ip"),
            "user": match.group("user"),
            "action": "failure",
            "severity": "medium",
            "raw_log": raw_log.strip()
        }
        return normalized_event
        
    return None