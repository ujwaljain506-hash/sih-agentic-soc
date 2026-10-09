import sqlite3

def setup_database():
    """Initializes the database table and handles schema migrations."""
    conn = sqlite3.connect("soc_events.db", timeout=10)
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
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.commit()
    conn.close()
    
    # Safely migrate existing tables if columns are missing
    upgrade_schema()
    setup_ingestion_state_table()

def upgrade_schema():
    """Ensures existing tables have the agent result columns added."""
    conn = sqlite3.connect("soc_events.db", timeout=10)
    cursor = conn.cursor()
    
    cursor.execute("PRAGMA table_info(logs)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    new_columns = {
        "threat_level": "TEXT", "analysis_reasoning": "TEXT", "response_actions": "TEXT",
        "mitre_technique": "TEXT", "risk_score": "INTEGER", "correlated_event_count": "INTEGER",
    }
    for col, col_type in new_columns.items():
        if col not in existing_columns:
            cursor.execute(f"ALTER TABLE logs ADD COLUMN {col} {col_type}")
            print(f"[DB Migration] Added missing column '{col}' to logs table.")
            
    conn.commit()
    conn.close()


def setup_ingestion_state_table():
    """Tracks how many lines of each log file have already been ingested."""
    conn = sqlite3.connect("soc_events.db", timeout=10)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ingestion_state (
            filename TEXT PRIMARY KEY,
            last_line_read INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


def get_last_line_read(filename: str) -> int:
    """Returns how many lines of this file were already processed (0 if never seen)."""
    conn = sqlite3.connect("soc_events.db", timeout=10)
    cursor = conn.cursor()
    cursor.execute("SELECT last_line_read FROM ingestion_state WHERE filename = ?", (filename,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0


def update_last_line_read(filename: str, line_number: int):
    """Records that we've now processed up to line_number for this file."""
    conn = sqlite3.connect("soc_events.db", timeout=10)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ingestion_state (filename, last_line_read)
        VALUES (?, ?)
        ON CONFLICT(filename) DO UPDATE SET last_line_read = excluded.last_line_read
    ''', (filename, line_number))
    conn.commit()
    conn.close()


def insert_log(event):
    """Inserts normalized log dictionary into SQLite using parameterized query."""
    conn = sqlite3.connect("soc_events.db", timeout=10)
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
    log_id = cursor.lastrowid
    conn.close()
    return log_id


def get_recent_related_count(source_ip=None, user=None, exclude_log_id=None, window=200):
    """Counts other events in a recent id-window sharing the same source_ip or user.

    Used by the Threat Investigator to correlate an event with related activity
    (e.g. repeated brute-force attempts from one IP against one account).
    """
    if not source_ip and not user:
        return 0

    conn = sqlite3.connect("soc_events.db", timeout=10)
    cursor = conn.cursor()

    where = []
    params = []
    if exclude_log_id is not None:
        where.append("id != ?")
        params.append(exclude_log_id)
        where.append("id > ?")
        params.append(max(exclude_log_id - window, 0))

    related = []
    if source_ip:
        related.append("source_ip = ?")
        params.append(source_ip)
    if user:
        related.append("user = ?")
        params.append(user)
    where.append("(" + " OR ".join(related) + ")")

    cursor.execute(f"SELECT COUNT(*) FROM logs WHERE {' AND '.join(where)}", params)
    count = cursor.fetchone()[0]
    conn.close()
    return count

def update_agent_results(log_id: int, threat_level: str, analysis_reasoning: str, response_actions: str,
                          mitre_technique: str = None, risk_score: int = None, correlated_event_count: int = None):
    conn = sqlite3.connect("soc_events.db", timeout=10)
    cursor = conn.cursor()
    sql = '''
        UPDATE logs 
        SET threat_level = ?, analysis_reasoning = ?, response_actions = ?,
            mitre_technique = ?, risk_score = ?, correlated_event_count = ?
        WHERE id = ?
    '''
    cursor.execute(sql, (threat_level, analysis_reasoning, response_actions,
                          mitre_technique, risk_score, correlated_event_count, log_id))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()
    print("Database setup and schema migration complete.")