import os
import re
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

load_dotenv()
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
database.setup_database()

class AgentState(TypedDict):
    log_id: int
    raw_log: str
    log_source: str
    user: Optional[str]
    source_ip: Optional[str]
    process_name: Optional[str]
    is_suspicious: bool
    threat_level: str
    analysis_reasoning: str
    mitre_technique: str
    risk_score: int
    correlated_event_count: int
    response_actions: str

PRIMARY_MODEL = "openai/gpt-oss-120b"
FALLBACK_MODEL = "llama-3.3-70b-versatile"

def get_llm(model_name: str = PRIMARY_MODEL):
    return ChatGroq(temperature=0, model_name=model_name)

llm = get_llm(PRIMARY_MODEL)

SOC_SYSTEM_PROMPT = """You are an elite, autonomous Level 3 SOC Analyst.
Your objective is to analyze incoming security logs and immediately output strict, actionable terminal commands to neutralize the threat.

CRITICAL RULES:
1. NEVER provide generic advice (e.g., "You should block this IP").
2. ALWAYS provide the exact, copy-pasteable terminal command.
3. If the log source is 'linux-auth', generate standard Linux commands (e.g., iptables, ufw, or kill).
4. If the log source is 'windows-sysmon', generate strict PowerShell commands (e.g., New-NetFirewallRule or Stop-Process)."""

MITRE_TECHNIQUE_MAP = {
    "linux-auth": {"id": "T1110", "name": "Brute Force"},
    "windows-sysmon": {"id": "T1059", "name": "Command and Scripting Interpreter"},
}

def map_mitre_technique(log_source: str, process_name: Optional[str] = None) -> dict:
    if log_source == "windows-sysmon" and process_name and "powershell" in process_name.lower():
        return {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell"}
    return MITRE_TECHNIQUE_MAP.get(log_source, {"id": "T1078", "name": "Valid Accounts"})

SEVERITY_WEIGHTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def calculate_risk_score(threat_level: str, correlated_count: int) -> int:
    severity_weight = SEVERITY_WEIGHTS.get((threat_level or "LOW").upper(), 1)
    correlation_factor = min(correlated_count * 10, 40)
    return min(severity_weight * 15 + correlation_factor, 100)

DANGEROUS_COMMAND_PATTERNS = [
    r"rm\s+-rf\s+/(?!\S)", r"rm\s+-rf\s+/\*", r"mkfs\.",
    r"dd\s+if=.*of=/dev/", r":\(\)\{.*\};:", r"shutdown", r"format\s+[cC]:",
]


def contains_dangerous_command(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in DANGEROUS_COMMAND_PATTERNS)

def send_webhook_alert(state: AgentState):
    if not WEBHOOK_URL:
        return

    threat_level = state.get("threat_level", "UNKNOWN").upper()
    log_id = state.get("log_id")
    log_source = state.get("log_source", "Unknown")
    user = state.get("user", "Unknown")
    source_ip = state.get("source_ip", "Unknown")
    reasoning = state.get("analysis_reasoning", "No detailed reasoning provided.")
    actions = state.get("response_actions", "No remediation actions specified.")
    mitre = state.get("mitre_technique", "N/A")
    risk_score = state.get("risk_score", 0)
    correlated = state.get("correlated_event_count", 0)

    color = 16711680 if threat_level == "CRITICAL" else 16747520

    payload = {
        "username": "SIEM Agentic SOC Alert Bot",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/1063/1063376.png",
        "embeds": [
            {
                "title": f"🚨 {threat_level} THREAT DETECTED — Log #{log_id}",
                "description": "An automated threat has been flagged by the **LangGraph AI SOC Pipeline**.",
                "color": color,
                "fields": [
                    {"name": "Log Source", "value": f"`{log_source}`", "inline": True},
                    {"name": "Target User", "value": f"`{user}`", "inline": True},
                    {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
                    {"name": "MITRE ATT&CK", "value": f"`{mitre}`", "inline": True},
                    {"name": "Risk Score", "value": f"`{risk_score}/100`", "inline": True},
                    {"name": "Correlated Events", "value": f"`{correlated}`", "inline": True},
                    {"name": "AI Analysis", "value": reasoning[:1000]},
                    {"name": "Remediation Actions", "value": actions[:1000]}
                ],
                "footer": {"text": "Autonomous Agentic SOC SIEM • Live Protection"}
            }
        ]
    }

    try:
        requests.post(WEBHOOK_URL, data=json.dumps(payload),
                       headers={"Content-Type": "application/json"}, timeout=5)
    except Exception as e:
        print(f"❌ Error dispatching webhook alert: {e}")

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
    messages = [SystemMessage(content=SOC_SYSTEM_PROMPT), HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    content = response.content.strip()
    is_suspicious = "SUSPICIOUS: YES" in content.upper()

    threat_level = "LOW"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if f"SEVERITY: {level}" in content.upper():
            threat_level = level
            break

    print(f"\n[Agent 1: Log Analyzer Output]")
    print(content)

    return {"is_suspicious": is_suspicious, "threat_level": threat_level, "analysis_reasoning": content}

def threat_investigator_node(state: AgentState) -> dict:
    correlated_count = database.get_recent_related_count(
        source_ip=state.get("source_ip"), user=state.get("user"), exclude_log_id=state.get("log_id")
    )
    mitre = map_mitre_technique(state.get("log_source"), state.get("process_name"))
    mitre_label = f"{mitre['id']} - {mitre['name']}"
    risk_score = calculate_risk_score(state.get("threat_level", "LOW"), correlated_count)

    print(f"\n[Agent 2: Threat Investigator Output]")
    print(f"Correlated related events (recent window): {correlated_count}")
    print(f"MITRE ATT&CK Technique: {mitre_label}")
    print(f"Calculated Risk Score: {risk_score}/100")

    return {"correlated_event_count": correlated_count, "mitre_technique": mitre_label, "risk_score": risk_score}

def incident_responder_node(state: AgentState) -> dict:
    prompt = f"""
You are an automated Incident Response Agent in a Security Operations Center.
A suspicious security event has been identified:

Log Source: {state.get('log_source')}
User: {state.get('user', 'Unknown')}
Source IP: {state.get('source_ip', 'Unknown')}
Threat Level: {state.get('threat_level')}
MITRE ATT&CK Technique: {state.get('mitre_technique', 'N/A')}
Correlated Related Events: {state.get('correlated_event_count', 0)}
Risk Score: {state.get('risk_score', 0)}/100
Analysis: {state.get('analysis_reasoning')}

Based on the OS of the log source, provide the strict remediation steps.
FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:
**Analysis:** [1-2 sentences explaining the exact attack vector]
**Remediation Command:**
```bash
[Executable Command Here]
```
"""
    messages = [SystemMessage(content=SOC_SYSTEM_PROMPT), HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    content = response.content.strip()
    if contains_dangerous_command(content):
        content = (
            "⚠️ SAFETY OVERRIDE: AI-generated command blocked — contained a potentially "
            "destructive pattern. Manual analyst review required.\n\nOriginal (blocked) suggestion:\n"
            f"{content}"
        )
    print(f"\n[Agent 3: Incident Responder Output]")
    print(content)
    return {"response_actions": content}

def route_threat(state: AgentState) -> str:
    if state.get("is_suspicious"):
        return "investigator"
    return END

workflow = StateGraph(AgentState)
workflow.add_node("analyzer", log_analyzer_node)
workflow.add_node("investigator", threat_investigator_node)
workflow.add_node("responder", incident_responder_node)

workflow.add_edge(START, "analyzer")
workflow.add_conditional_edges("analyzer", route_threat, {"investigator": "investigator", END: END})
workflow.add_edge("investigator", "responder")
workflow.add_edge("responder", END)

app = workflow.compile()

def fetch_unanalyzed_logs(db_path: str = "soc_events.db", batch_size: int = 5):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, log_source, user, source_ip, process_name, raw_log
        FROM logs
        WHERE threat_level IS NULL OR threat_level = 'UNKNOWN'
        ORDER BY id ASC
        LIMIT ?
    """, (batch_size,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def run_continuous_agent_loop(poll_interval: int = 3):
    global llm
    print("==")
    print("🤖 Continuous Autonomous SOC Engine Started")
    print("Target DB        : soc_events.db")
    print(f"Primary Model    : {PRIMARY_MODEL}")
    print(f"Fallback Model   : {FALLBACK_MODEL}")
    print("==\n")

    try:
        while True:
            os.system("python3 ingestion.py > /dev/null 2>&1")
            pending_logs = fetch_unanalyzed_logs(batch_size=5)

            if pending_logs:
                print(f"\n⚡ Found {len(pending_logs)} pending log(s). Running AI Evaluation...")

                for row in pending_logs:
                    log_id, log_source, user, source_ip, process_name, raw_log = row
                    print(f"\n==================== Evaluating Log ID #{log_id} ====================")

                    initial_state: AgentState = {
                        "log_id": log_id, "raw_log": raw_log or "", "log_source": log_source or "unknown",
                        "user": user or "Unknown", "source_ip": source_ip or "Unknown",
                        "process_name": process_name, "is_suspicious": False, "threat_level": "UNKNOWN",
                        "analysis_reasoning": "", "mitre_technique": "", "risk_score": 0,
                        "correlated_event_count": 0, "response_actions": ""
                    }

                    try:
                        final_state = app.invoke(initial_state)
                        threat_level = final_state.get("threat_level", "LOW").upper()

                        database.update_agent_results(
                            log_id=log_id, threat_level=threat_level,
                            analysis_reasoning=final_state.get("analysis_reasoning", ""),
                            response_actions=final_state.get("response_actions", "N/A - Event evaluated as non-suspicious."),
                            mitre_technique=final_state.get("mitre_technique"),
                            risk_score=final_state.get("risk_score"),
                            correlated_event_count=final_state.get("correlated_event_count")
                        )
                        print(f"✅ Saved Agent Verdict for Log #{log_id} to soc_events.db")

                        if threat_level in ["HIGH", "CRITICAL"]:
                            send_webhook_alert(final_state)

                    except RateLimitError:
                        print(f"\n⚠ Groq Rate Limit Reached. Attempting fallback model ({FALLBACK_MODEL})...")
                        try:
                            llm = get_llm(FALLBACK_MODEL)
                            final_state = app.invoke(initial_state)
                            threat_level = final_state.get("threat_level", "LOW").upper()
                            database.update_agent_results(
                                log_id=log_id, threat_level=threat_level,
                                analysis_reasoning=final_state.get("analysis_reasoning", ""),
                                response_actions=final_state.get("response_actions", "N/A"),
                                mitre_technique=final_state.get("mitre_technique"),
                                risk_score=final_state.get("risk_score"),
                                correlated_event_count=final_state.get("correlated_event_count")
                            )
                            print(f"✅ [Fallback Model] Saved Agent Verdict for Log #{log_id}")
                        except Exception:
                            print("⏳ Rate limit active across models. Pausing engine for 180 seconds...\n")
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