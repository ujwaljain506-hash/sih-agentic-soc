# Normalized Log Schema

- **timestamp**: The exact date and time the event occurred (typically in ISO 8601 format), essential for timeline reconstruction and grouping events.

- **event_id**: A unique identifier (UUID) for the log entry, used to track the event as it moves through the pipeline and agents.

- **log_source**: The origin of the log (e.g., `linux-auth`, `windows-sysmon`, `aws-cloudtrail`), helping the system identify how to process it.

- **event_type**: The category of the activity (e.g., `authentication`, `network_connection`, `process_creation`), used for quick filtering and routing.

- **source_ip / dest_ip**: The IP address initiating the connection (source) and the system receiving it (destination). 

- **source_port / dest_port**: The network ports used for the connection, crucial for spotting unusual traffic like data exfiltration.

- **user**: The account or username associated with the action, helping track identity theft or brute-force attempts.

- **host**: The name or ID of the machine where the event took place.

- **process_name**: The specific application or executable triggering the action, key for detecting malware or unauthorized tools.

- **action**: The outcome of the event (e.g., `success`, `failure`, `blocked`, `allowed`), vital for distinguishing between an attack attempt and a successful breach.

- **severity**: The baseline threat level (e.g., `low`, `medium`, `high`, `critical`), used by the dashboard to prioritize alerts.

- **raw_log**: The original, unaltered log string, permanently stored as evidence for the Investigation Agent and final incident reports.
