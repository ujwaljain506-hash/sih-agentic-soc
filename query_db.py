import sqlite3

def view_logs():
    conn = sqlite3.connect("soc_events.db")
    cursor = conn.cursor()
    
    # We don't need all 14 fields for a quick dashboard, just the highlights
    cursor.execute("SELECT id, timestamp, log_source, user, process_name FROM logs")
    rows = cursor.fetchall()
    
    print(f"--- Database contains {len(rows)} events ---")
    for row in rows:
        # row[0] is id, row[1] is timestamp, etc. based on the SELECT order
        print(f"ID: {row[0]} | Time: {row[1]} | Source: {row[2]} | User: {row[3]} | Process: {row[4]}")
        
    conn.close()

if __name__ == "__main__":
    view_logs()