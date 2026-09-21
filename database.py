import sqlite3

def setup_database():
    # This connects to the file (or creates it if it doesn't exist)
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    
    # Create a table mapping directly to our Day 1 Schema
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id TEXT,
            log_source TEXT,
            event_type TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            source_port TEXT,
            dest_port TEXT,
            user TEXT,
            host TEXT,
            process_name TEXT,
            action TEXT,
            severity TEXT,
            raw_log TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Database and 'logs' table successfully created.")

setup_database()     