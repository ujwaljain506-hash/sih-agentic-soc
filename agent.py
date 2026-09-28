import os
from typing import TypedDict, Optional
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END

# Load environment variables from .env
load_dotenv()

# 1. Define the Shared State Schema
class AgentState(TypedDict):
    log_id: int
    raw_log: str
    log_source: str
    user: Optional[str]
    source_ip: Optional[str]
    is_suspicious: bool
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    analysis_reasoning: str

# 2. Initialize the Groq LLM
llm = ChatGroq(
    temperature=0,
    model_name="openai/gpt-oss-120b"
)

# 3. Define Agent Node 1: Log Analyzer
def log_analyzer_node(state: AgentState) -> dict:
    """Analyzes a security log entry to determine if it represents malicious activity."""
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

    # Simple parsing logic from LLM response
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

# 4. Build the Graph
workflow = StateGraph(AgentState)

# Add our Analyzer Node
workflow.add_node("analyzer", log_analyzer_node)

# Set Graph Entry and Exit Points
workflow.add_edge(START, "analyzer")
workflow.add_edge("analyzer", END)

# Compile Graph
app = workflow.compile()

# 5. Local Test Execution
if __name__ == "__main__":
    test_state: AgentState = {
        "log_id": 1,
        "raw_log": "Failed password for root from 192.168.1.105 port 22 ssh2",
        "log_source": "linux-auth",
        "user": "root",
        "source_ip": "192.168.1.105",
        "is_suspicious": False,
        "threat_level": "UNKNOWN",
        "analysis_reasoning": ""
    }

    print("--- Testing LangGraph Log Analyzer Node ---")
    app.invoke(test_state)