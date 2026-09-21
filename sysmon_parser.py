import json

def parse_sysmon(raw_json_string):
    """Takes a raw JSON string and returns a normalized dictionary."""
    try:
        log_data = json.loads(raw_json_string)
        
        normalized_event = {
            "timestamp": log_data.get("UtcTime"),
            "log_source": "windows-sysmon",
            "event_type": "process_creation",
            "host": log_data.get("Computer"),
            "user": log_data.get("User"),
            "process_name": log_data.get("Image"),
            "action": "execute",
            "severity": "low",
            "raw_log": raw_json_string.strip()
        }
        return normalized_event
    except json.JSONDecodeError:
        # If the log is corrupted and isn't valid JSON, fail gracefully
        return None