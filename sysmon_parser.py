import json

raw_json_string = '''
{
    "EventID": 1,
    "UtcTime": "2024-04-28 22:08:22.025",
    "Computer": "DESKTOP-SIH-01",
    "User": "NT AUTHORITY\\\\NETWORK SERVICE",
    "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami"
}
'''

# Parse the JSON string
log_data = json.loads(raw_json_string)

# Map directly into our Day 1 Normalized Schema
normalized_event = {
    "timestamp": log_data.get("UtcTime"),
    "log_source": "windows-sysmon",
    "event_type": "process_creation",
    "host": log_data.get("Computer"),
    "user": log_data.get("User"),
    "process_name": log_data.get("Image"),
    "action": "execute",
    "severity": "low",  # Process execution is normal, unless flagged later by rules/ML
    "raw_log": raw_json_string.strip()
}

print("Normalized Sysmon Event:")
print(json.dumps(normalized_event, indent=2))