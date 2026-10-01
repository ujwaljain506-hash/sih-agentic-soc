import os
import time
import json
import sqlite3
import requests
from typing import TypedDict, Optional
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from groq import RateLimitError
import database

# 1. Load Environment Variables
load_dotenv()

WEBHOOK_URL = os.getenv("WEBHOOK_URL")

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

# 3. Initialize Primary & Fallback Groq LLMs
PRIMARY_MODEL = "openai/gpt-oss-120b"
FALLBACK_MODEL = "llama-3.3-70b-versatile"

def get_llm(model_name: str = PRIMARY_MODEL):
    return ChatGroq(temperature=0, model_name=model_name)

llm = get_llm(PRIMARY_MODEL)

# 4. Webhook Notification Alert Function
def send_webhook_alert(state: AgentState):
    """Sends a rich alert notification to Discord or Slack for HIGH/CRITICAL threats."""
    if not WEBHOOK_URL:
        return

    threat_level = state.get("threat_level", "UNKNOWN").upper()
    log_id = state.get("log_id")
    log_source = state.get("log_source", "Unknown")
    user = state.get("user", "Unknown")
    source_ip = state.get("source_ip", "Unknown")
    reasoning = state.get("analysis_reasoning", "No detailed reasoning provided.")
    actions = state.get("response_actions", "No remediation actions specified.")

    color = 16711680 if threat_level == "CRITICAL" else 16747520

    payload = {
        "username": "SIEM Agentic SOC Alert Bot",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/1063/1063376.png",
        "embeds": [
            {
                "title": f"🚨 {threat_level} THREAT DETECTED — Log #{log_id}",
                "description": f"An automated threat has been flagged by the **LangGraph AI SOC Pipeline**.",
                "color": color,
                "fields": [
                    {"name": "Log Source", "value": f"`{log_source}`", "inline": True},
                    {"name": "Target User", "value": f"`{user}`", "inline": True},
                    {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
                    {"name": "AI Analysis", "value": reasoning[:1000]},
                    {"name": "Remediation Actions", "value": actions[:1000]}
                ],
                "footer": {"text": "Autonomous Agentic SOC SIEM • Live Protection"}
            }
        ]
    }

    try:
        requests.post(
            WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5
        )
    except Exception as e:
        print(f"❌ Error dispatching webhook alert: {e}")

# 5. Agent Node 1: Log Analyzer
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

# 6. Agent Node 2: Incident Responder
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

# 7. Conditional Router Logic
def route_threat(state: AgentState) -> str:
    if state.get("is_suspicious"):
        return "responder"
    return END

# 8. Construct & Compile Graph
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

# 9. Query Unanalyzed Logs
def fetch_unanalyzed_logs(db_path: str = "soc_events.db", batch_size: int = 5):
    """Retrieves logs where AI evaluation is pending."""
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

# 10. Continuous Monitoring Loop with Exception Recovery
def run_continuous_agent_loop(poll_interval: int = 3):
    global llm
    print("==================================================")
    print("🤖 Continuous Autonomous SOC Engine Started")
    print("Target DB        : soc_events.db")
    print(f"Primary Model    : {PRIMARY_MODEL}")
    print(f"Fallback Model   : {FALLBACK_MODEL}")
    print("==================================================\n")

    try:
        while True:
            os.system("python3 ingestion.py > /dev/null 2>&1")
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

                    try:
                        # Execute graph
                        final_state = app.invoke(initial_state)

                        threat_level = final_state.get("threat_level", "LOW").upper()

                        # Persist findings
                        database.update_agent_results(
                            log_id=log_id,
                            threat_level=threat_level,
                            analysis_reasoning=final_state.get("analysis_reasoning", ""),
                            response_actions=final_state.get("response_actions", "N/A - Event evaluated as non-suspicious.")
                        )
                        print(f"✅ Saved Agent Verdict for Log #{log_id} to soc_events.db")

                        if threat_level in ["HIGH", "CRITICAL"]:
                            send_webhook_alert(final_state)

                    except RateLimitError as rle:
                        print(f"\n⚠️️ Groq Rate Limit Reached for current model. Attempting fallback model ({FALLBACK_MODEL})...")
                        try:
                            # Switch LLM instance to fallback model
                            llm = get_llm(FALLBACK_MODEL)
                            final_state = app.invoke(initial_state)
                            
                            threat_level = final_state.get("threat_level", "LOW").upper()
                            database.update_agent_results(
                                log_id=log_id,
                                threat_level=threat_level,
                                analysis_reasoning=final_state.get("analysis_reasoning", ""),
                                response_actions=final_state.get("response_actions", "N/A")
                            )
                            print(f"✅ [Fallback Model] Saved Agent Verdict for Log #{log_id}")
                        except Exception as inner_err:
                            print(f"⏳ Rate limit active across models. Pausing engine for 180 seconds before retry...\n")
                            time.sleep(180)
                            break
                    except Exception as err:
                        print(f"❌ Unexpected error processing log #{log_id}: {err}")
                        time.sleep(5)

            else:
                print(".", end="", flush=True)

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n[!] Agent Loop stopped by user.")

if __name__ == "__main__":
    run_continuous_agent_loop(poll_interval=3)