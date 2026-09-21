import os

LOG_DIR = "sample_logs"

def process_directory(directory_path):
    normalized_events = []
    
    # Loop through every file in the directory
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        
        # Skip if it's a directory (we only want files)
        if not os.path.isfile(file_path):
            continue
            
        print(f"Reading file: {filename}")
        
        # Open and read the file
        with open(file_path, "r") as file:
            # Here is where we route the file to the parsers we built
            if filename.endswith(".json"):
                print(" -> Routing to Sysmon Parser")
                # (We will connect sysmon_parser.py here later)
            elif filename.endswith(".log"):
                print(" -> Routing to Linux Auth Parser")
                # (We will connect parser.py here later)
            else:
                print(" -> Unknown log type, skipping.")
                
    return normalized_events

# Run the batch ingestion
process_directory(LOG_DIR)