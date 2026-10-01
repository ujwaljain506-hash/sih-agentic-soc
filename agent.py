import os
import sqlite3
from typing import TypedDict, Optional
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
import database

# 1. Load Environment Variables
load_dotenv()

# Ensure database table and columns exist
database.setup_database()

# 2. Define Shared State Schema
class AgentState(TypedDict):
    log_id: int
    raw_log: str
    log_source: str
    user: Optional[str]
    source_ip: Optional[str]
    is_suspicious: bool
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    analysis_reasoning: str
    response_actions: str

# 3. Initialize Groq LLM
llm = ChatGroq(
    temperature=0,
    model_name="openai/gpt-oss-120b"
)

# 4. Agent Node 1: Log Analyzer
def log_analyzer_node(state: AgentState) -> dict:
    prompt = f"""
You are an expert Security Operations Center (SOC) Tier-1 Analyst.
Analyze the following security event log and determine if it indicates suspicious or malicious activity.

Log Source: {state.get('log_source')}
User: {state.get('user', 'Unknown')}
Source IP: {state.get('source_ip', 'Unknown')}
Raw Log: {state.get('raw_log')}

Provide your assessment in this exact format:
SUSPICIOUS: [YES or NO]
SEVERITY: [LOW, MEDIUM, HIGH, or CRITICAL]
REASON: [Brief 1-2 sentence explanation]
"""

    response = llm.invoke([
        SystemMessage(content="You are an automated SIEM threat analysis agent."),
        HumanMessage(content=prompt)
    ])

    content = response.content.strip()
    is_suspicious = "SUSPICIOUS: YES" in content.upper()
    
    threat_level = "LOW"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if f"SEVERITY: {level}" in content.upper():
            threat_level = level
            break

    print(f"\n[Agent 1: Log Analyzer Output]")
    print(content)

    return {
        "is_suspicious": is_suspicious,
        "threat_level": threat_level,
        "analysis_reasoning": content
    }

# 5. Agent Node 2: Incident Responder
def incident_responder_node(state: AgentState) -> dict:
    prompt = f"""
You are an automated Incident Response Agent in a Security Operations Center.
A suspicious security event has been identified:

Log Source: {state.get('log_source')}
User: {state.get('user', 'Unknown')}
Source IP: {state.get('source_ip', 'Unknown')}
Threat Level: {state.get('threat_level')}
Analysis: {state.get('analysis_reasoning')}

Provide 3 concrete, immediate remediation actions for the system administrator in this exact format:
1. [Action 1]
2. [Action 2]
3. [Action 3]
"""

    response = llm.invoke([
        SystemMessage(content="You are an automated SIEM incident response agent."),
        HumanMessage(content=prompt)
    ])

    content = response.content.strip()
    print(f"\n[Agent 2: Incident Responder Output]")
    print(content)

    return {"response_actions": content}

# 6. Conditional Router Logic
def route_threat(state: AgentState) -> str:
    if state.get("is_suspicious"):
        return "responder"
    return END

# 7. Construct & Compile Graph
workflow = StateGraph(AgentState)
workflow.add_node("analyzer", log_analyzer_node)
workflow.add_node("responder", incident_responder_node)

workflow.add_edge(START, "analyzer")
workflow.add_conditional_edges(
    "analyzer",
    route_threat,
    {
        "responder": "responder",
        END: END
    }
)
workflow.add_edge("responder", END)

app = workflow.compile()

# 8. Fetch Logs from SQLite
def fetch_logs_from_db(db_path: str = "soc_events.db", limit: int = 5):
    """Retrieves stored logs from soc_events.db."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, log_source, user, source_ip, raw_log 
        FROM logs 
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

# 9. Main Pipeline Execution Loop
if __name__ == "__main__":
    print("--- Starting DB-Integrated LangGraph SOC Pipeline with Persistence ---")
    
    # Populates database with sample logs if empty
    os.system("python3 ingestion.py")
    
    # Fetch logs from database
    logs = fetch_logs_from_db(limit=5)
    print(f"Loaded {len(logs)} logs from database for multi-agent evaluation.\n")

    # Process logs through the agent network and persist results
    for row in logs:
        log_id, log_source, user, source_ip, raw_log = row
        print(f"\n==================== Processing Log ID #{log_id} ====================")
        
        initial_state: AgentState = {
            "log_id": log_id,
            "raw_log": raw_log or "",
            "log_source": log_source or "unknown",
            "user": user or "Unknown",
            "source_ip": source_ip or "Unknown",
            "is_suspicious": False,
            "threat_level": "UNKNOWN",
            "analysis_reasoning": "",
            "response_actions": ""
        }

        # Run multi-agent graph
        final_state = app.invoke(initial_state)

        # Persist findings back into SQLite
        database.update_agent_results(
            log_id=log_id,
            threat_level=final_state.get("threat_level", "LOW"),
            analysis_reasoning=final_state.get("analysis_reasoning", ""),
            response_actions=final_state.get("response_actions", "N/A - Event evaluated as non-suspicious.")
        )
        print(f"✅ Saved Agent Verdict for Log #{log_id} back to soc_events.db")