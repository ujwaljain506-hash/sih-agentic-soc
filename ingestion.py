import os
import linux_auth_parser
import sysmon_parser
import database

LOG_DIR = "sample_logs"

database.setup_database()  # ensures logs + ingestion_state tables exist


def process_file(filename, file_path):
    last_line_read = database.get_last_line_read(filename)

    with open(file_path, "r") as file:
        lines = file.readlines()

    new_lines = lines[last_line_read:]
    if not new_lines:
        return

    print(f"\n--- Reading {filename} ({len(new_lines)} new line(s)) ---")

    for line in new_lines:
        line = line.strip()
        if not line:
            continue

        if filename.endswith(".json"):
            event = sysmon_parser.parse_sysmon(line)
            if event:
                database.insert_log(event)
                print(f"Saved Sysmon event to DB from host: {event.get('host')}")

        elif filename.endswith(".log"):
            event = linux_auth_parser.parse_linux_auth(line)
            if event:
                database.insert_log(event)
                print(f"Saved Linux event to DB for user: {event.get('user')}")

    database.update_last_line_read(filename, len(lines))


def process_directory(directory_path):
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            process_file(filename, file_path)


if __name__ == "__main__":
    process_directory(LOG_DIR)
    print("\n=== Incremental Ingestion Complete ===")