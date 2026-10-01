import sqlite3

def setup_database():
    """Initializes the database table and handles schema migrations."""
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, event_id TEXT, log_source TEXT, event_type TEXT,
            source_ip TEXT, dest_ip TEXT, source_port TEXT, dest_port TEXT,
            user TEXT, host TEXT, process_name TEXT, action TEXT,
            severity TEXT, raw_log TEXT,
            threat_level TEXT, analysis_reasoning TEXT, response_actions TEXT
        )
    ''')
    conn.commit()
    conn.close()
    
    # Safely migrate existing tables if columns are missing
    upgrade_schema()

def upgrade_schema():
    """Ensures existing tables have the agent result columns added."""
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(logs)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = ["threat_level", "analysis_reasoning", "response_actions"]
    for col in new_columns:
        if col not in existing_columns:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {col} TEXT")
            print(f"[DB Migration] Added missing column '{col}' to logs table.")
            
    conn.commit()
    conn.close()

def insert_log(event):
    """Inserts normalized log dictionary into SQLite using parameterized query."""
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    sql = '''
        INSERT INTO logs (
            timestamp, event_id, log_source, event_type, source_ip, 
            dest_ip, source_port, dest_port, user, host, 
            process_name, action, severity, raw_log
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    '''
    values = (
        event.get("timestamp"), event.get("event_id"), event.get("log_source"),
        event.get("event_type"), event.get("source_ip"), event.get("dest_ip"),
        event.get("source_port"), event.get("dest_port"), event.get("user"),
        event.get("host"), event.get("process_name"), event.get("action"),
        event.get("severity"), event.get("raw_log")
    )
    cursor.execute(sql, values)
    conn.commit()
    conn.close()

def update_agent_results(log_id: int, threat_level: str, analysis_reasoning: str, response_actions: str):
    """Saves AI Agent evaluation output back to the log entry in SQLite."""
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    sql = '''
        UPDATE logs 
        SET threat_level = ?, analysis_reasoning = ?, response_actions = ?
        WHERE id = ?
    '''
    cursor.execute(sql, (threat_level, analysis_reasoning, response_actions, log_id))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
    print("Database setup and schema migration complete.")