import sqlite3
import pandas as pd
import plotly.express as px
import streamlit as st

# ─────────────────────────────────────────────────────────────────────────────
# 1. Page Configuration
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = "soc_events.db"

# ─────────────────────────────────────────────────────────────────────────────
# 2. Friendly styling (cards, chips, live pill)
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .soc-card {
    background: linear-gradient(135deg, #0e1b2c 0%, #16283f 100%);
    border: 1px solid #23415f;
    border-radius: 14px;
    padding: 18px 20px 14px 20px;
    height: 130px;
  }
  .soc-card-label { color: #8fb3d9; font-size: 0.85rem; letter-spacing: 0.03em; }
  .soc-card-value { color: #ffffff; font-size: 2.1rem; font-weight: 700; margin: 4px 0 2px 0; }
  .soc-card-sub   { color: #7d97b6; font-size: 0.78rem; }
  .chip {
    display: inline-block; padding: 2px 12px; border-radius: 999px;
    font-size: 0.75rem; font-weight: 700; letter-spacing: 0.04em;
  }
  .chip-critical { background: #ff4b4b; color: #2b0000; }
  .chip-high     { background: #ffa421; color: #3a2000; }
  .chip-medium   { background: #ffe312; color: #3a3000; }
  .chip-low      { background: #00d46a; color: #003318; }
  .live-dot {
    display: inline-block; width: 10px; height: 10px; border-radius: 50%;
    background: #00d46a; margin-right: 8px;
    animation: soc-pulse 1.6s infinite;
  }
  @keyframes soc-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(0, 212, 106, 0.6); }
    70%  { box-shadow: 0 0 0 10px rgba(0, 212, 106, 0); }
    100% { box-shadow: 0 0 0 0 rgba(0, 212, 106, 0); }
  }
  .hero-title { color: #ffffff; font-size: 1.9rem; font-weight: 800; margin-bottom: 0; }
  .hero-sub   { color: #8fb3d9; font-size: 0.95rem; margin-top: 4px; }
</style>
""", unsafe_allow_html=True)

SEV_CHIP = {
    "critical": ("chip-critical", "🔴"),
    "high": ("chip-high", "🟠"),
    "medium": ("chip-medium", "🟡"),
    "low": ("chip-low", "🟢"),
}

MITRE_PLAIN = {
    "T1110": "Brute-force password guessing",
    "T1110.001": "Password guessing against one account",
    "T1110.003": "Password spraying across many accounts",
    "T1059": "Running scripted commands",
    "T1059.001": "PowerShell abuse",
    "T1078": "Using valid (possibly stolen) accounts",
    "T1548": "Privilege escalation abuse",
    "T1021": "Remote services / lateral movement",
}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Data + plain-English helpers
# ─────────────────────────────────────────────────────────────────────────────
def load_data():
    """Fetches log events from soc_events.db into a Pandas DataFrame."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Could not read the security database: {e}")
        return pd.DataFrame()


def safe(val, default="—"):
    """NaN-safe string for display."""
    if val is None:
        return default
    if isinstance(val, float) and pd.isna(val):
        return default
    s = str(val).strip()
    return s if s and s.lower() != "nan" else default


def human_summary(row) -> str:
    """Turns one raw event into a sentence a non-technical person understands."""
    source = safe(row.get("log_source"), "")
    action = safe(row.get("action"), "")
    event_type = safe(row.get("event_type"), "")
    user = safe(row.get("user"), "someone")
    ip = safe(row.get("source_ip"), "unknown IP")
    host = safe(row.get("host"), "a Windows PC")
    proc = safe(row.get("process_name"), "")
    raw = safe(row.get("raw_log"), "").lower()

    if source == "linux-auth":
        if event_type == "privilege_escalation":
            return f"🔑 **{user}** ran a command with admin rights (`{proc or 'command'}`)"
        if action == "failure":
            if "invalid user" in raw:
                return f"🕵️ Someone tried a **fake username** (`{user}`) from `{ip}`"
            return f"🔐 Failed login attempt for **{user}** from `{ip}`"
        if action == "success":
            return f"✅ Successful login for **{user}** from `{ip}`"
        return f"🔐 Login activity for **{user}** from `{ip}`"

    if source == "windows-sysmon":
        blob = f"{proc} {raw}"
        if "encodedcommand" in blob.lower():
            return f"🧬 **Hidden/encoded PowerShell** launched on **{host}**"
        if "powershell" in blob.lower():
            return f"⚠️ Suspicious **PowerShell** activity on **{host}**"
        if "invoke-webrequest" in blob.lower() or "download" in blob.lower():
            return f"⬇️ A program **downloaded a file** on **{host}**"
        return f"🖥️ A program ran on **{host}** (`{proc or 'process'} `)"

    return f"📄 Security event from `{source or 'unknown source'}`"


def mitre_plain_label(mitre: str) -> str:
    """Adds a human explanation next to a MITRE technique ID."""
    text = safe(mitre, "")
    if not text:
        return "Not classified yet"
    for tid, meaning in MITRE_PLAIN.items():
        if text.startswith(tid):
            return f"{text} — *{meaning}*"
    return text


def sev_chip(sev: str) -> str:
    key = (sev or "low").lower()
    cls, emoji = SEV_CHIP.get(key, SEV_CHIP["low"])
    return f'<span class="chip {cls}">{emoji} {key.upper()}</span>'


# ─────────────────────────────────────────────────────────────────────────────
# 4. Sidebar
# ─────────────────────────────────────────────────────────────────────────────
st.sidebar.markdown("## 🛡️ AI SOC\n### Command Center")
st.sidebar.markdown('<span class="live-dot"></span>**SYSTEM ACTIVE — watching every event**', unsafe_allow_html=True)

if st.sidebar.button("🔄 Refresh data", width="stretch"):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**Show events from:**")
log_source_filter = st.sidebar.multiselect(
    "Log sources",
    options=["linux-auth", "windows-sysmon"],
    default=["linux-auth", "windows-sysmon"],
    label_visibility="collapsed",
    format_func=lambda s: "🐧 Linux servers" if s == "linux-auth" else "🪟 Windows computers",
)

with st.sidebar.expander("🤔 What is this system?"):
    st.markdown(
        "An **AI security team in software form**:\n\n"
        "1. 📥 It watches every login and program on your servers\n"
        "2. 🧠 AI agents judge each event — is it an attack? how dangerous?\n"
        "3. 🛠️ It writes the exact command to stop the attacker\n\n"
        "Everything below is generated live, automatically."
    )

# ─────────────────────────────────────────────────────────────────────────────
# 5. Hero header
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="hero-title">🛡️ Autonomous Security Operations Center</div>', unsafe_allow_html=True)
st.markdown('<div class="hero-sub">AI watches every event, ranks the danger, and writes the fix — automatically, 24/7.</div>', unsafe_allow_html=True)
st.markdown("")

# ─────────────────────────────────────────────────────────────────────────────
# 6. Load + prepare data
# ─────────────────────────────────────────────────────────────────────────────
df = load_data()

if df.empty:
    st.info("🌱 **No events yet — the system is warming up.** Events appear here within seconds of the log sources starting.")
    st.stop()

if log_source_filter:
    df_filtered = df[df["log_source"].isin(log_source_filter)].copy()
else:
    df_filtered = df.copy()

# Unified severity: prefer the AI verdict (threat_level), fall back to the
# parser's baseline severity for events the agent hasn't evaluated yet.
df_filtered["display_severity"] = (
    df_filtered["threat_level"]
    .where(
        df_filtered["threat_level"].notna()
        & (df_filtered["threat_level"].fillna("").str.upper() != "UNKNOWN"),
        df_filtered["severity"],
    )
    .fillna("low")
    .str.lower()
)

total_logs = len(df_filtered)
suspicious_count = int(df_filtered["display_severity"].isin(["medium", "high", "critical"]).sum())
top_ip = df_filtered["source_ip"].value_counts().index[0] if not df_filtered["source_ip"].dropna().empty else "N/A"
top_user = df_filtered["user"].value_counts().index[0] if not df_filtered["user"].dropna().empty else "N/A"

tab_overview, tab_investigation, tab_reports = st.tabs(
    ["📊 Overview", "🔍 Investigation", "📑 Reports"]
)

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW (for everyone)
# ═════════════════════════════════════════════════════════════════════════════
with tab_overview:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="soc-card">
          <div class="soc-card-label">📥 EVENTS MONITORED</div>
          <div class="soc-card-value">{total_logs:,}</div>
          <div class="soc-card-sub">live counter — grows as events arrive</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="soc-card">
          <div class="soc-card-label">🚨 THREATS CAUGHT</div>
          <div class="soc-card-value">{suspicious_count:,}</div>
          <div class="soc-card-sub">flagged dangerous by the AI agents</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="soc-card">
          <div class="soc-card-label">🎯 TOP ATTACKER IP</div>
          <div class="soc-card-value" style="font-size:1.4rem; margin-top:12px;">{safe(top_ip)}</div>
          <div class="soc-card-sub">most frequent source of trouble</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
        <div class="soc-card">
          <div class="soc-card-label">👤 MOST TARGETED ACCOUNT</div>
          <div class="soc-card-value" style="font-size:1.4rem; margin-top:12px;">{safe(top_user)}</div>
          <div class="soc-card-sub">attackers aim at this account most</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("")
    st.caption(
        "📈 **Counters update continuously** as new events flow in from the monitored systems — "
        "steady growth during an attack is expected and healthy."
    )
    chart1, chart2 = st.columns(2)

    with chart1:
        st.subheader("🎚️ How dangerous are the events?")
        sev_counts = (
            df_filtered["display_severity"]
            .value_counts()
            .reindex(["critical", "high", "medium", "low"])
            .fillna(0)
            .reset_index()
        )
        sev_counts.columns = ["Severity", "Count"]
        fig_sev = px.pie(
            sev_counts, values="Count", names="Severity", hole=0.55,
            color="Severity",
            color_discrete_map={"low": "#00d46a", "medium": "#ffe312", "high": "#ffa421", "critical": "#ff4b4b"},
        )
        fig_sev.update_layout(margin=dict(t=10, b=10, l=10, r=10), legend_title_text="")
        st.plotly_chart(fig_sev, width="stretch")

    with chart2:
        st.subheader("🌍 Where do events come from?")
        source_counts = df_filtered["log_source"].value_counts().reset_index()
        source_counts.columns = ["Source", "Count"]
        source_counts["Source"] = source_counts["Source"].map(
            {"linux-auth": "🐧 Linux servers", "windows-sysmon": "🪟 Windows computers"}
        ).fillna(source_counts["Source"])
        fig_src = px.bar(
            source_counts, x="Source", y="Count", color="Source",
            color_discrete_map={"🐧 Linux servers": "#3a86ff", "🪟 Windows computers": "#8338ec"},
        )
        fig_src.update_layout(margin=dict(t=10, b=10, l=10, r=10), showlegend=False)
        st.plotly_chart(fig_src, width="stretch")

    st.markdown("---")
    st.subheader("⚡ Live attack feed")
    st.caption(
        "The latest security events, translated into plain language. Newest first. "
        "Seeing similar lines repeat is **normal** — a brute-force attack produces "
        "dozens of near-identical login attempts by design."
    )

    feed_cols = ["id", "timestamp", "log_source", "source_ip", "user", "process_name", "raw_log",
                 "action", "event_type", "host", "display_severity", "threat_level", "severity"]
    feed = df_filtered[[c for c in feed_cols if c in df_filtered.columns]].head(8)

    for _, row in feed.iterrows():
        sev = safe(row.get("display_severity"), "low")
        chip = sev_chip(sev)
        summary = human_summary(row)
        when = safe(row.get("timestamp"), "")
        st.markdown(
            f'<div style="display:flex; align-items:center; gap:12px; padding:8px 4px; border-bottom:1px solid #1c2c40;">'
            f'{chip}'
            f'<div style="flex:1;">{summary}</div>'
            f'<div style="color:#7d97b6; font-size:0.78rem;">{when} &nbsp;·&nbsp; event #{int(row["id"]) if pd.notna(row["id"]) else "?"}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("")
    st.markdown(
        "🧠 **How it works:** 1️⃣ the AI reads every event → 2️⃣ scores how dangerous it is → "
        "3️⃣ writes the exact command to stop it. Open the **🔍 Investigation** tab to see the full reasoning behind any event."
    )

# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — INVESTIGATION (analyst deep-dive)
# ═════════════════════════════════════════════════════════════════════════════
with tab_investigation:
    st.subheader("🔍 Threat investigation")
    st.caption("Pick any event to see the raw evidence, the AI's full reasoning, and the recommended fix.")

    ids = df_filtered["id"].tolist()

    def picker_label(i):
        row = df_filtered[df_filtered["id"] == i]
        if row.empty:
            return f"#{i}"
        r = row.iloc[0]
        sev = safe(r.get("display_severity"), "low")
        emoji = SEV_CHIP.get(sev, ("", "🟢"))[1]
        return f"#{i} · {emoji} {sev.upper()} · {human_summary(r)[:70]}"

    selected_id = st.selectbox("Event to investigate", ids, format_func=picker_label)

    if selected_id:
        selected_row = df_filtered[df_filtered["id"] == selected_id].iloc[0]
        sev = safe(selected_row.get("display_severity"), "low").upper()

        st.markdown(f'<div style="margin:6px 0 16px 0;">{sev_chip(sev.lower())}</div>', unsafe_allow_html=True)

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("#### 📋 What happened")
            st.markdown(human_summary(selected_row))

            m1, m2, m3 = st.columns(3)
            m1.metric("Event ID", f"#{int(selected_row['id'])}")
            m2.metric("Source", "🐧 Linux" if safe(selected_row.get("log_source")) == "linux-auth" else "🪟 Windows")
            m3.metric("When", safe(selected_row.get("timestamp"), "—"))

            m4, m5 = st.columns(2)
            m4.metric("Account", safe(selected_row.get("user")))
            m5.metric("Source IP", safe(selected_row.get("source_ip")))

            with st.expander("🔬 Technical details (raw evidence)"):
                st.markdown(f"**Log source:** `{safe(selected_row.get('log_source'))}` · "
                            f"**Event type:** `{safe(selected_row.get('event_type'))}` · "
                            f"**Host:** `{safe(selected_row.get('host'))}`")
                st.code(safe(selected_row.get("raw_log"), "(no raw log stored)"), language="text")

        with col_right:
            st.markdown("#### 🤖 What the AI decided")

            analyzed = pd.notna(selected_row.get("analysis_reasoning")) and "non-suspicious" not in safe(selected_row.get("response_actions"), "")[:40]
            if pd.notna(selected_row.get("threat_level")) and safe(selected_row.get("threat_level")) != "UNKNOWN":
                st.markdown(f"**AI threat level:** {sev_chip(sev.lower())}", unsafe_allow_html=True)
            else:
                st.info("⏳ This event is queued for AI analysis — verdict will appear within seconds.")

            risk = selected_row.get("risk_score")
            if pd.notna(risk):
                risk_val = int(risk)
                st.markdown(f"**Risk score: {risk_val}/100**")
                st.progress(min(max(risk_val / 100, 0.0), 1.0))
                st.caption(
                    "Low concern" if risk_val < 35 else
                    "Medium concern" if risk_val < 70 else
                    "⚠️ High concern — act soon"
                )

            mitre = selected_row.get("mitre_technique")
            if pd.notna(mitre) and safe(mitre):
                st.markdown("**Known attack pattern (MITRE ATT&CK):**")
                st.code(safe(mitre), language="text")
                st.caption(mitre_plain_label(safe(mitre)))

            corr = selected_row.get("correlated_event_count")
            if pd.notna(corr):
                st.caption(f"🔗 Seen **{int(corr)}** related event(s) recently — this is not an isolated incident." if int(corr) > 0
                           else "🔗 No related events found — looks isolated.")

            if pd.notna(selected_row.get("analysis_reasoning")):
                st.markdown("**🧠 AI reasoning:**")
                st.info(safe(selected_row.get("analysis_reasoning")))

            if pd.notna(selected_row.get("response_actions")):
                st.markdown("**🛠️ Recommended fix — copy & run on the affected machine:**")
                st.warning(safe(selected_row.get("response_actions")))

        with st.expander("🗃️ Full raw database record"):
            st.json({
                "Log ID": int(selected_row["id"]),
                "Timestamp": str(selected_row.get("timestamp", "N/A")),
                "Source": str(selected_row.get("log_source", "N/A")),
                "Event type": str(selected_row.get("event_type", "N/A")),
                "User": str(selected_row.get("user", "N/A")),
                "Source IP": str(selected_row.get("source_ip", "N/A")),
                "Host": str(selected_row.get("host", "N/A")),
                "Baseline severity": str(selected_row.get("severity", "N/A")),
                "AI threat level": str(selected_row.get("threat_level", "N/A")),
                "MITRE": str(selected_row.get("mitre_technique", "N/A")),
                "Risk score": str(selected_row.get("risk_score", "N/A")),
            })

# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 — REPORTS
# ═════════════════════════════════════════════════════════════════════════════
with tab_reports:
    st.subheader("📑 Incident reports")
    st.markdown(
        "Export everything the system has seen and decided — ready for compliance, "
        "audits, or your incident review meeting."
    )

    r1, r2 = st.columns(2)
    with r1:
        st.markdown("**What's inside the report:**")
        st.markdown(
            "- 📥 Every monitored event with timestamps\n"
            "- 🚨 AI threat level and risk score per event\n"
            "- 🧠 The AI's reasoning for each verdict\n"
            "- 🛠️ The recommended remediation command\n"
            "- 🔗 MITRE ATT&CK classification"
        )
    with r2:
        summary_table = (
            df_filtered["display_severity"]
            .value_counts()
            .reindex(["critical", "high", "medium", "low"])
            .fillna(0)
            .reset_index()
        )
        summary_table.columns = ["Threat level", "Events"]
        summary_table["Threat level"] = summary_table["Threat level"].str.title()
        st.markdown("**Report summary:**")
        st.dataframe(summary_table, width="stretch", hide_index=True)

    csv = df_filtered.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Download full incident report (CSV)",
        data=csv,
        file_name="sih_agentic_soc_report.csv",
        mime="text/csv",
        width="stretch",
    )
    st.caption("The report reflects the filters currently selected in the sidebar.")
