import os
import parser
import sysmon_parser
import database  # Bring in our database powers

LOG_DIR = "sample_logs"

def process_directory(directory_path):
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        
        if not os.path.isfile(file_path):
            continue
            
        print(f"\n--- Reading {filename} ---")
        
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue 
                    
                if filename.endswith(".json"):
                    event = sysmon_parser.parse_sysmon(line)
                    if event:
                        database.insert_log(event) # Writing to disk!
                        print(f"Saved Sysmon event to DB from host: {event.get('host')}")
                        
                elif filename.endswith(".log"):
                    event = parser.parse_linux_auth(line)
                    if event:
                        database.insert_log(event) # Writing to disk!
                        print(f"Saved Linux event to DB for user: {event.get('user')}")

# Run the engine
process_directory(LOG_DIR)
print("\n=== Batch Ingestion to Database Complete ===")