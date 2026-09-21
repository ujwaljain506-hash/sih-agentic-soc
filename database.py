import sqlite3

def setup_database():
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    
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

def insert_log(event):
    """Inserts a single normalized event dictionary into the database."""
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    
    # The SQL query to insert data
    sql = '''
        INSERT INTO logs (
            timestamp, event_id, log_source, event_type, source_ip, 
            dest_ip, source_port, dest_port, user, host, 
            process_name, action, severity, raw_log
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    
    # Map the dictionary keys directly to the 14 question marks above
    values = (
        event.get("timestamp"),
        event.get("event_id"),
        event.get("log_source"),
        event.get("event_type"),
        event.get("source_ip"),
        event.get("dest_ip"),
        event.get("source_port"),
        event.get("dest_port"),
        event.get("user"),
        event.get("host"),
        event.get("process_name"),
        event.get("action"),
        event.get("severity"),
        event.get("raw_log")
    )
    
    cursor.execute(sql, values)
    conn.commit()
    conn.close()

# Only run setup if we execute this file directly
if __name__ == "__main__":
    setup_database()
    print("Database and 'logs' table successfully created.")