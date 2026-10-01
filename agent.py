import os
import time
import sqlite3
from typing import TypedDict, Optional
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
import database

# 1. Load Environment Variables
load_dotenv()

# Initialize database schema if not already set up
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

# 8. Query Unanalyzed Logs
def fetch_unanalyzed_logs(db_path: str = "soc_events.db", batch_size: int = 5):
    """Retrieves logs where AI evaluation is pending (threat_level IS NULL)."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, log_source, user, source_ip, raw_log 
        FROM logs 
        WHERE threat_level IS NULL OR threat_level = 'UNKNOWN'
        ORDER BY id ASC
        LIMIT ?
    """, (batch_size,))
    rows = cursor.fetchall()
    conn.close()
    return rows

# 9. Continuous Monitoring Loop
def run_continuous_agent_loop(poll_interval: int = 3):
    print("==================================================")
    print("🤖 Continuous Autonomous SOC Engine Started")
    print("Target DB        : soc_events.db")
    print(f"Polling Interval : Every {poll_interval} seconds")
    print("Press Ctrl+C to stop execution")
    print("==================================================\n")

    try:
        while True:
            # Parse any fresh raw logs from sample_logs/ into DB
            os.system("python3 ingestion.py > /dev/null 2>&1")

            # Fetch up to 5 unanalyzed records
            pending_logs = fetch_unanalyzed_logs(batch_size=5)

            if pending_logs:
                print(f"\n⚡ Found {len(pending_logs)} pending log(s). Running AI Evaluation...")
                
                for row in pending_logs:
                    log_id, log_source, user, source_ip, raw_log = row
                    print(f"\n==================== Evaluating Log ID #{log_id} ====================")
                    
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

                    # Execute multi-agent graph
                    final_state = app.invoke(initial_state)

                    # Persist findings to SQLite
                    database.update_agent_results(
                        log_id=log_id,
                        threat_level=final_state.get("threat_level", "LOW"),
                        analysis_reasoning=final_state.get("analysis_reasoning", ""),
                        response_actions=final_state.get("response_actions", "N/A - Event evaluated as non-suspicious.")
                    )
                    print(f"✅ Saved Agent Verdict for Log #{log_id} to soc_events.db")
            else:
                # Pulse indicator while idle
                print(".", end="", flush=True)

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n[!] Agent Loop stopped by user.")

if __name__ == "__main__":
    run_continuous_agent_loop(poll_interval=3)