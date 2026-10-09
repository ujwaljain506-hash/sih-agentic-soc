import os
import sqlite3
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query, Header, Depends
from pydantic import BaseModel
from dotenv import load_dotenv
import database
from agent import app as langgraph_app, AgentState

load_dotenv()

API_KEY = os.getenv("API_KEY")


def verify_api_key(x_api_key: str = Header(None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

# 1. Initialize FastAPI App
app = FastAPI(
    title="Agentic SOC SIEM REST API",
    description="REST API interface for querying security logs, threat metrics, and triggering AI re-analysis.",
    version="1.0.0"
)

DB_PATH = "soc_events.db"

# Ensure database schema is ready on startup
@app.on_event("startup")
def startup_event():
    database.setup_database()

# 2. Pydantic Response Schemas
class LogItem(BaseModel):
    id: int
    timestamp: Optional[str] = None
    log_source: Optional[str] = None
    event_type: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    severity: Optional[str] = None
    raw_log: Optional[str] = None
    threat_level: Optional[str] = None
    analysis_reasoning: Optional[str] = None
    response_actions: Optional[str] = None

class StatsResponse(BaseModel):
    total_logs: int
    suspicious_logs: int
    severity_breakdown: dict
    log_source_breakdown: dict

# 3. Health Check Endpoint
@app.get("/")
def read_root():
    return {
        "system": "Autonomous Agentic SOC SIEM API",
        "status": "online",
        "docs_url": "/docs"
    }

# 4. GET /logs — List Logs with Pagination and Filtering
@app.get("/logs", response_model=List[LogItem], dependencies=[Depends(verify_api_key)])
def get_logs(
    limit: int = Query(20, ge=1, le=100, description="Number of logs to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    source: Optional[str] = Query(None, description="Filter by log_source (e.g. linux-auth, windows-sysmon)"),
    severity: Optional[str] = Query(None, description="Filter by threat level (e.g. LOW, MEDIUM, HIGH, CRITICAL)")
):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if source:
        query += " AND log_source = ?"
        params.append(source)
    if severity:
        query += " AND (UPPER(threat_level) = ? OR UPPER(severity) = ?)"
        params.extend([severity.upper(), severity.upper()])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

# 5. GET /logs/{log_id} — Fetch Single Log Entry
@app.get("/logs/{log_id}", response_model=LogItem, dependencies=[Depends(verify_api_key)])
def get_log_by_id(log_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Log ID #{log_id} not found.")

    return dict(row)

# 6. GET /stats — SIEM Threat Metrics Summary
@app.get("/stats", response_model=StatsResponse, dependencies=[Depends(verify_api_key)])
def get_threat_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total log count
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]

    # Suspicious logs count
    cursor.execute("""
        SELECT COUNT(*) FROM logs 
        WHERE LOWER(threat_level) IN ('medium', 'high', 'critical') 
           OR LOWER(severity) IN ('medium', 'high', 'critical')
    """)
    suspicious_logs = cursor.fetchone()[0]

    # Severity breakdown
    cursor.execute("""
        SELECT COALESCE(threat_level, severity, 'UNANALYZED') AS sev, COUNT(*) 
        FROM logs 
        GROUP BY sev
    """)
    severity_breakdown = dict(cursor.fetchall())

    # Source breakdown
    cursor.execute("SELECT log_source, COUNT(*) FROM logs GROUP BY log_source")
    source_breakdown = dict(cursor.fetchall())

    conn.close()

    return {
        "total_logs": total_logs,
        "suspicious_logs": suspicious_logs,
        "severity_breakdown": severity_breakdown,
        "log_source_breakdown": source_breakdown
    }

# 7. POST /analyze/{log_id} — Trigger Manual AI Re-Analysis
@app.post("/analyze/{log_id}", dependencies=[Depends(verify_api_key)])
def reanalyze_log(log_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Log ID #{log_id} not found.")

    log_dict = dict(row)

    initial_state: AgentState = {
        "log_id": log_id,
        "raw_log": log_dict.get("raw_log") or "",
        "log_source": log_dict.get("log_source") or "unknown",
        "user": log_dict.get("user") or "Unknown",
        "source_ip": log_dict.get("source_ip") or "Unknown",
        "process_name": log_dict.get("process_name"),
        "is_suspicious": False,
        "threat_level": "UNKNOWN",
        "analysis_reasoning": "",
        "mitre_technique": "",
        "risk_score": 0,
        "correlated_event_count": 0,
        "response_actions": ""
    }

    try:
        final_state = langgraph_app.invoke(initial_state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI Agent evaluation failed: {str(e)}")

    threat_level = final_state.get("threat_level", "LOW").upper()
    reasoning = final_state.get("analysis_reasoning", "")
    actions = final_state.get("response_actions", "N/A - Event evaluated as non-suspicious.")
    mitre = final_state.get("mitre_technique")
    risk_score = final_state.get("risk_score")
    correlated = final_state.get("correlated_event_count")

    database.update_agent_results(
        log_id=log_id, threat_level=threat_level, analysis_reasoning=reasoning,
        response_actions=actions, mitre_technique=mitre, risk_score=risk_score,
        correlated_event_count=correlated
    )

    return {
        "status": "success",
        "message": f"Log #{log_id} successfully re-analyzed.",
        "log_id": log_id,
        "threat_level": threat_level,
        "analysis_reasoning": reasoning,
        "response_actions": actions,
        "mitre_technique": mitre,
        "risk_score": risk_score,
        "correlated_event_count": correlated
    }