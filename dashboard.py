import sqlite3
import pandas as pd
import plotly.express as px
import streamlit as st

# 1. Page Configuration
st.set_page_config(
    page_title="AI-Agentic SOC SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = "soc_events.db"

# 2. Database Fetching Helper
def load_data():
    """Fetches log events from soc_events.db into a Pandas DataFrame."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Error loading database: {e}")
        return pd.DataFrame()

# 3. Sidebar Controls & Auto-Refresh
st.sidebar.title("🛡️ SOC Operations")
st.sidebar.markdown("Real-Time SIEM Monitoring & AI Incident Response")

if st.sidebar.button("🔄 Refresh Data", use_container_width=True):
    st.rerun()

log_source_filter = st.sidebar.multiselect(
    "Filter Log Source:",
    options=["linux-auth", "windows-sysmon"],
    default=["linux-auth", "windows-sysmon"]
)
def render_severity_badge(severity):
    colors = {
        "CRITICAL": "#ff4b4b", # Red
        "HIGH": "#ffa421",     # Orange
        "MEDIUM": "#ffe312",   # Yellow
        "LOW": "#00d46a"       # Green
    }
    color = colors.get(severity.upper(), "#808080")
    
    st.markdown(f"""
        <div style="background-color: {color}; padding: 10px; border-radius: 5px; color: black; font-weight: bold; text-align: center; margin-bottom: 10px;">
            🤖 AI ASSESSED THREAT LEVEL: {severity.upper()}
        </div>
    """, unsafe_allow_html=True)
# 4. Load Data
df = load_data()

st.title("🛡️ Autonomous Agentic SOC Operations Center")
st.caption("Real-time log ingestion, threat classification, and LLM remediation tracking")

if df.empty:
    st.warning("No log data found in `soc_events.db`. Run `python3 ingestion.py` or `python3 agent.py` to populate logs.")
    st.stop()

# Apply Filters
if log_source_filter:
    df_filtered = df[df['log_source'].isin(log_source_filter)]
else:
    df_filtered = df

# Unified severity: prefer the AI verdict (threat_level), fall back to the
# parser's baseline severity for events the agent hasn't evaluated yet.
df_filtered['display_severity'] = (
    df_filtered['threat_level']
    .where(
        df_filtered['threat_level'].notna()
        & (df_filtered['threat_level'].fillna('').str.upper() != 'UNKNOWN'),
        df_filtered['severity'],
    )
    .fillna('low')
    .str.lower()
)

# 5. Top KPI Summary Metrics
m1, m2, m3, m4 = st.columns(4)

total_logs = len(df_filtered)
suspicious_count = len(df_filtered[df_filtered['display_severity'].isin(['medium', 'high', 'critical'])])
top_ip = df_filtered['source_ip'].value_counts().index[0] if 'source_ip' in df_filtered and not df_filtered['source_ip'].dropna().empty else "N/A"
top_user = df_filtered['user'].value_counts().index[0] if 'user' in df_filtered and not df_filtered['user'].dropna().empty else "N/A"

m1.metric("Total Ingested Logs", total_logs)
m2.metric("Flagged Threats", suspicious_count, delta=f"{suspicious_count} Actionable", delta_color="inverse")
m3.metric("Top Source IP", top_ip)
m4.metric("Active User Target", top_user)

st.markdown("---")

# 6. Visualizations Section
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("AI Threat Level Breakdown")
    severity_counts = df_filtered['display_severity'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    fig_sev = px.pie(
        severity_counts, 
        values='Count', 
        names='Severity', 
        hole=0.4,
        color='Severity',
        color_discrete_map={'low': '#2ec4b6', 'medium': '#ff9f1c', 'high': '#e71d36', 'critical': '#7209b7'}
    )
    st.plotly_chart(fig_sev, use_container_width=True)

with col_chart2:
    st.subheader("Log Volume by Source")
    source_counts = df_filtered['log_source'].value_counts().reset_index()
    source_counts.columns = ['Log Source', 'Count']
    fig_source = px.bar(
        source_counts, 
        x='Log Source', 
        y='Count', 
        color='Log Source',
        color_discrete_sequence=['#3a86ff', '#8338ec']
    )
    st.plotly_chart(fig_source, use_container_width=True)

st.markdown("---")

# 7. Live Log Event Table & Detailed Inspection
st.subheader("📋 Ingested Security Events")

display_cols = [c for c in ['id', 'timestamp', 'log_source', 'event_type', 'user', 'source_ip'] if c in df_filtered.columns]
table_df = df_filtered[display_cols].copy()
table_df['ai_threat_level'] = df_filtered['display_severity'].str.upper()
st.dataframe(table_df, use_container_width=True, height=220)

st.markdown("### 📥 Generate Incident Report")
csv = df_filtered.to_csv(index=False).encode('utf-8')

st.download_button(
    label="Download Threat Logs as CSV",
    data=csv,
    file_name='sih_agentic_soc_report.csv',
    mime='text/csv',
    use_container_width=True
)

st.markdown("### 🔍 Threat Deep Dive & Agent Remediation Steps")
selected_id = st.selectbox("Select Event ID to Inspect:", df_filtered['id'].tolist())

if selected_id:
    selected_row = df_filtered[df_filtered['id'] == selected_id].iloc[0]
    
    col_details, col_agent = st.columns(2)
    
    with col_details:
        st.markdown("**Event Metadata**")
        st.json({
            "Log ID": int(selected_row['id']),
            "Timestamp": str(selected_row.get('timestamp', 'N/A')),
            "Source": str(selected_row.get('log_source', 'N/A')),
            "User": str(selected_row.get('user', 'N/A')),
            "Source IP": str(selected_row.get('source_ip', 'N/A')),
            "Severity": str(selected_row.get('severity', 'N/A'))
        })
        st.markdown("**Raw Log String:**")
        st.code(str(selected_row.get('raw_log', '')), language='text')

    with col_agent:
        st.markdown("**🤖 LangGraph AI Multi-Agent Verdict**")
        
        # Show the AI-assessed threat level (falls back to parser baseline if unanalyzed)
        sev = str(selected_row.get('display_severity', 'low')).upper()
        
        # Render the dynamic colored badge!
        render_severity_badge(sev)
        
        if 'analysis_reasoning' in selected_row and pd.notna(selected_row['analysis_reasoning']):
            st.markdown("**Analysis Reasoning:**")
            st.info(selected_row['analysis_reasoning'])
        else:
            st.markdown("*Run `python3 agent.py` to trigger LangGraph evaluation.*")
            
        if 'response_actions' in selected_row and pd.notna(selected_row['response_actions']):
            st.markdown("**Automated Remediation Plan:**")
            st.warning(selected_row['response_actions'])

        if 'mitre_technique' in selected_row and pd.notna(selected_row['mitre_technique']):
            st.markdown("**MITRE ATT&CK Technique:**")
            st.code(selected_row['mitre_technique'])
        if 'risk_score' in selected_row and pd.notna(selected_row['risk_score']):
            st.metric("Risk Score", f"{int(selected_row['risk_score'])}/100")
        if 'correlated_event_count' in selected_row and pd.notna(selected_row['correlated_event_count']):
            st.caption(f"Correlated with {int(selected_row['correlated_event_count'])} other recent event(s)")