"""
AI SOC Command Center — beautiful dark dashboard for Streamlit.

One self-contained file. Reads live events from soc_events.db and renders
the polished command-center UI (Overview / Investigation / Reports tabs).

Run:  streamlit run dashboard.py   (or: docker compose up dashboard)
"""
import json
import os
import sqlite3

import streamlit as st
from streamlit.components.v1 import html as component_html

st.set_page_config(
    page_title="AI SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DB_PATH = "soc_events.db"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Load live events from the database
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=5)
def load_events(limit: int = 200):
    """Return the newest log rows as a list of dicts (empty DB → empty list)."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def build_page(events) -> str:
    """Inject the live events into the dashboard HTML template."""
    events_json = json.dumps(events, default=str).replace("</", "<\\/")
    return PAGE_HTML.replace("__EVENTS_JSON__", events_json)


def main():
    """Sidebar + dashboard render. Must run AFTER PAGE_HTML is defined below."""
    with st.sidebar:
        st.markdown("## 🛡️ AI SOC Command Center")
        events = load_events()
        st.markdown(f"**{len(events)}** events loaded from the live database.")
        if st.button("🔄 Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()
        st.caption("The dashboard re-reads the database every 5 seconds.")
    component_html(build_page(load_events()), height=1650, scrolling=True)


# ─────────────────────────────────────────────────────────────────────────────
# 4. The dashboard template (self-contained HTML/CSS/JS — no CDNs, no network)
# ─────────────────────────────────────────────────────────────────────────────
PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ AI SOC Command Center</title>
<style>
  :root {
    --bg: #0b1220;
    --card1: #0e1b2c;
    --card2: #16283f;
    --border: #23415f;
    --text: #ffffff;
    --muted: #8fb3d9;
    --dim: #7d97b6;
    --critical: #ff4b4b;
    --high: #ffa421;
    --medium: #ffe312;
    --low: #00d46a;
    --accent: #3a86ff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background:
      radial-gradient(1200px 500px at 80% -10%, rgba(58,134,255,0.14), transparent 60%),
      radial-gradient(900px 400px at 10% 110%, rgba(114,9,183,0.12), transparent 60%),
      var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    min-height: 100vh;
    padding-bottom: 50px;
  }

  header {
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 14px;
    padding: 26px 36px 10px;
  }
  .hero-title { font-size: 1.75rem; font-weight: 800; letter-spacing: -0.02em; }
  .hero-sub { color: var(--muted); font-size: 0.92rem; margin-top: 5px; }
  .header-right { display: flex; align-items: center; gap: 12px; }
  .live-pill {
    display: inline-flex; align-items: center;
    background: rgba(0,212,106,0.12); border: 1px solid rgba(0,212,106,0.35);
    color: var(--low); padding: 8px 16px; border-radius: 999px;
    font-size: 0.8rem; font-weight: 700; letter-spacing: 0.03em;
  }
  .live-dot {
    width: 9px; height: 9px; border-radius: 50%; background: var(--low);
    margin-right: 9px; animation: pulse 1.6s infinite;
  }
  @keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(0,212,106,0.55); }
    70% { box-shadow: 0 0 0 9px rgba(0,212,106,0); }
    100% { box-shadow: 0 0 0 0 rgba(0,212,106,0); }
  }
  .clock { color: var(--dim); font-size: 0.82rem; font-variant-numeric: tabular-nums; }

  nav { display: flex; gap: 8px; padding: 22px 36px 6px; flex-wrap: wrap; }
  .tab-btn {
    background: transparent; border: 1px solid transparent; color: var(--muted);
    padding: 11px 22px; border-radius: 11px; cursor: pointer;
    font-size: 0.92rem; font-weight: 700;
  }
  .tab-btn:hover { color: var(--text); background: rgba(255,255,255,0.04); }
  .tab-btn.active {
    background: linear-gradient(135deg, var(--card1), var(--card2));
    border-color: var(--border); color: var(--text);
    box-shadow: 0 4px 18px rgba(0,0,0,0.25);
  }

  main { padding: 10px 36px; }
  .tab-page { display: none; animation: fadeIn 0.28s ease; }
  .tab-page.active { display: block; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

  .kpi-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px; margin: 14px 0 22px;
  }
  .kpi {
    background: linear-gradient(135deg, var(--card1) 0%, var(--card2) 100%);
    border: 1px solid var(--border); border-radius: 15px;
    padding: 20px 22px 16px; transition: transform 0.18s ease, box-shadow 0.18s ease;
  }
  .kpi:hover { transform: translateY(-3px); box-shadow: 0 12px 28px rgba(0,0,0,0.35); }
  .kpi-label { color: var(--muted); font-size: 0.76rem; letter-spacing: 0.06em; font-weight: 700; }
  .kpi-value { font-size: 2.05rem; font-weight: 800; margin: 8px 0 4px; letter-spacing: -0.02em; }
  .kpi-value.small { font-size: 1.35rem; margin-top: 13px; }
  .kpi-sub { color: var(--dim); font-size: 0.76rem; }

  .charts {
    display: grid; grid-template-columns: 1fr 1.2fr; gap: 16px; margin-bottom: 22px;
  }
  @media (max-width: 980px) { .charts { grid-template-columns: 1fr; } }
  .panel {
    background: linear-gradient(135deg, var(--card1) 0%, var(--card2) 100%);
    border: 1px solid var(--border); border-radius: 15px; padding: 22px;
  }
  .panel h3 { font-size: 1.02rem; margin-bottom: 4px; }
  .panel .cap { color: var(--dim); font-size: 0.78rem; margin-bottom: 16px; }

  .donut-wrap { display: flex; align-items: center; gap: 26px; flex-wrap: wrap; }
  .donut-center-label { font-size: 0.68rem; fill: var(--dim); }
  .legend { display: flex; flex-direction: column; gap: 10px; }
  .legend-row { display: flex; align-items: center; gap: 10px; font-size: 0.86rem; }
  .dot { width: 11px; height: 11px; border-radius: 50%; flex-shrink: 0; }
  .legend-row .n { margin-left: auto; color: var(--muted); font-weight: 700; font-variant-numeric: tabular-nums; }

  .bar-row { display: grid; grid-template-columns: 130px 1fr 46px; align-items: center; gap: 12px; margin: 11px 0; }
  .bar-name { font-size: 0.82rem; color: var(--muted); text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { background: rgba(255,255,255,0.06); border-radius: 8px; height: 13px; overflow: hidden; }
  .bar-fill {
    height: 100%; border-radius: 8px;
    background: linear-gradient(90deg, var(--accent), #8338ec);
    transition: width 0.7s cubic-bezier(0.2, 0.7, 0.3, 1);
  }
  .bar-count { font-size: 0.82rem; color: var(--muted); font-weight: 700; font-variant-numeric: tabular-nums; }

  .feed-row {
    display: flex; align-items: center; gap: 14px;
    padding: 11px 6px; border-bottom: 1px solid rgba(35,65,95,0.5);
  }
  .feed-row:last-child { border-bottom: none; }
  .feed-text { flex: 1; font-size: 0.89rem; color: #d7e4f3; line-height: 1.45; }
  .feed-text b { color: var(--text); }
  .feed-meta { color: var(--dim); font-size: 0.74rem; white-space: nowrap; }

  .chip {
    display: inline-block; padding: 3px 13px; border-radius: 999px;
    font-size: 0.71rem; font-weight: 800; letter-spacing: 0.05em; white-space: nowrap;
  }
  .chip-critical { background: var(--critical); color: #2b0000; }
  .chip-high     { background: var(--high); color: #3a2000; }
  .chip-medium   { background: var(--medium); color: #3a3000; }
  .chip-low      { background: var(--low); color: #003318; }

  .explainer {
    margin: 22px 0 8px; padding: 16px 20px; border-radius: 13px;
    background: rgba(58,134,255,0.08); border: 1px solid rgba(58,134,255,0.22);
    color: var(--muted); font-size: 0.88rem; line-height: 1.6;
  }

  .invest-grid { display: grid; grid-template-columns: 340px 1fr; gap: 16px; }
  @media (max-width: 980px) { .invest-grid { grid-template-columns: 1fr; } }
  .event-list { max-height: 640px; overflow-y: auto; padding-right: 6px; }
  .event-list::-webkit-scrollbar { width: 8px; }
  .event-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 8px; }
  .event-item {
    width: 100%; text-align: left; cursor: pointer;
    background: rgba(255,255,255,0.025); border: 1px solid transparent;
    border-radius: 11px; padding: 12px 14px; margin-bottom: 9px; color: var(--text);
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .event-item:hover { background: rgba(255,255,255,0.05); }
  .event-item.selected { border-color: var(--accent); background: rgba(58,134,255,0.10); }
  .event-item .idline { display: flex; align-items: center; gap: 8px; margin-bottom: 5px; }
  .event-item .sum { font-size: 0.78rem; color: var(--muted); line-height: 1.4; }

  .detail-block h4 { font-size: 0.95rem; margin-bottom: 12px; }
  .metric-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px; }
  .metric {
    background: rgba(255,255,255,0.035); border: 1px solid var(--border);
    border-radius: 11px; padding: 11px 13px;
  }
  .metric .m-label { color: var(--dim); font-size: 0.68rem; letter-spacing: 0.05em; font-weight: 700; }
  .metric .m-value { font-size: 0.92rem; font-weight: 800; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .summary-big { font-size: 1.02rem; line-height: 1.6; color: #d7e4f3; margin-bottom: 16px; }
  .summary-big b { color: var(--text); }

  .risk-track { background: rgba(255,255,255,0.08); height: 13px; border-radius: 8px; overflow: hidden; margin: 8px 0 5px; }
  .risk-fill { height: 100%; border-radius: 8px; transition: width 0.6s ease; }
  .cap-small { color: var(--dim); font-size: 0.76rem; margin-bottom: 14px; }

  .mitre-box, .reason-box, .fix-box {
    border-radius: 11px; padding: 13px 15px; margin-bottom: 13px; font-size: 0.86rem; line-height: 1.55;
  }
  .mitre-box  { background: rgba(114,9,183,0.12); border: 1px solid rgba(114,9,183,0.3); }
  .reason-box { background: rgba(58,134,255,0.08); border: 1px solid rgba(58,134,255,0.22); color: #cfe0f2; }
  .fix-box    { background: rgba(255,75,75,0.07); border: 1px solid rgba(255,75,75,0.25); }

  .cmd {
    position: relative; background: #08101c; border: 1px solid var(--border);
    border-radius: 10px; padding: 13px 52px 13px 15px; margin-top: 10px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 0.8rem; color: #9fe8ff; white-space: pre-wrap; word-break: break-all; line-height: 1.55;
  }
  .copy-btn {
    position: absolute; top: 9px; right: 9px;
    background: rgba(255,255,255,0.08); border: 1px solid var(--border);
    color: var(--muted); border-radius: 7px; padding: 5px 10px; cursor: pointer; font-size: 0.72rem;
  }
  .copy-btn:hover { color: var(--text); border-color: var(--accent); }

  details.raw { margin-top: 4px; }
  details.raw summary {
    cursor: pointer; color: var(--muted); font-size: 0.83rem; font-weight: 700;
    padding: 10px 0; list-style: none;
  }
  details.raw summary::before { content: "▸ "; }
  details.raw[open] summary::before { content: "▾ "; }

  .pending-pill {
    display: inline-block; background: rgba(255,227,18,0.1); border: 1px solid rgba(255,227,18,0.3);
    color: var(--medium); border-radius: 9px; padding: 8px 14px; font-size: 0.82rem; margin-bottom: 13px;
  }

  .empty-state {
    display: none; text-align: center; padding: 70px 20px; color: var(--muted);
  }
  .empty-state .big { font-size: 2.6rem; margin-bottom: 12px; }

  .reports-grid { display: grid; grid-template-columns: 1.2fr 1fr; gap: 16px; }
  @media (max-width: 980px) { .reports-grid { grid-template-columns: 1fr; } }
  .checklist { list-style: none; margin: 10px 0 20px; }
  .checklist li { padding: 8px 0; font-size: 0.92rem; color: #d7e4f3; }
  .checklist li::before { content: "✅ "; }
  table.rep { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  table.rep th, table.rep td { text-align: left; padding: 11px 13px; border-bottom: 1px solid var(--border); }
  table.rep th { color: var(--dim); font-size: 0.72rem; letter-spacing: 0.06em; }
  .big-btn {
    background: linear-gradient(135deg, var(--accent), #8338ec); border: none; color: #fff;
    padding: 16px 26px; border-radius: 13px; cursor: pointer; font-size: 1rem; font-weight: 800;
    box-shadow: 0 10px 26px rgba(58,134,255,0.3);
  }
  .big-btn:hover { filter: brightness(1.13); transform: translateY(-2px); transition: 0.15s; }

  footer {
    text-align: center; color: var(--dim); font-size: 0.78rem;
    margin-top: 46px; line-height: 1.8;
  }
  .col-accent { color: var(--accent); font-weight: 700; }
</style>
</head>
<body>

<header>
  <div>
    <div class="hero-title">🛡️ Autonomous Security Operations Center</div>
    <div class="hero-sub">AI watches every event, ranks the danger, and writes the fix — automatically, 24/7.</div>
  </div>
  <div class="header-right">
    <div class="clock" id="clock">--:--:--</div>
    <div class="live-pill"><span class="live-dot"></span>SYSTEM ACTIVE — LIVE</div>
  </div>
</header>

<nav>
  <button class="tab-btn active" data-tab="overview" onclick="switchTab('overview')">📊 Overview</button>
  <button class="tab-btn" data-tab="investigation" onclick="switchTab('investigation')">🔍 Investigation</button>
  <button class="tab-btn" data-tab="reports" onclick="switchTab('reports')">📑 Reports</button>
</nav>

<main>
  <!-- ═══════════ OVERVIEW ═══════════ -->
  <section class="tab-page active" id="tab-overview">
    <div class="empty-state" id="emptyState">
      <div class="big">🌱</div>
      <h3>No events yet — the system is warming up.</h3>
      <p>Start the simulator to generate security events:<br><code>python simulate_attacks.py</code></p>
    </div>

    <div class="kpi-grid" id="kpiGrid"></div>

    <div class="charts">
      <div class="panel">
        <h3>🎚️ How dangerous are the events?</h3>
        <div class="cap">AI-assessed threat levels across all monitored activity</div>
        <div class="donut-wrap">
          <svg width="190" height="190" viewBox="0 0 190 190" id="donutSvg"></svg>
          <div class="legend" id="donutLegend"></div>
        </div>
      </div>
      <div class="panel">
        <h3>🏠 Which machines are under attack?</h3>
        <div class="cap">The actual places being targeted — not just the operating system</div>
        <div id="machineBars"></div>
      </div>
    </div>

    <div class="panel">
      <h3>⚡ Live attack feed</h3>
      <div class="cap">The latest security events, translated into plain language. Seeing similar lines repeat is normal — a brute-force attack produces dozens of near-identical login attempts by design.</div>
      <div id="feed"></div>
    </div>

    <div class="explainer">
      🧠 <b>How it works:</b> 1️⃣ the AI reads every event &nbsp;→&nbsp; 2️⃣ scores how dangerous it is &nbsp;→&nbsp; 3️⃣ writes the exact command to stop it.
      Open the <b>🔍 Investigation</b> tab to see the full reasoning behind any event.
    </div>
  </section>

  <!-- ═══════════ INVESTIGATION ═══════════ -->
  <section class="tab-page" id="tab-investigation">
    <div class="invest-grid">
      <div class="panel">
        <h3>📋 Events</h3>
        <div class="cap">Select any event to investigate</div>
        <div class="event-list" id="eventList"></div>
      </div>
      <div class="panel detail-block" id="detailPanel"></div>
    </div>
  </section>

  <!-- ═══════════ REPORTS ═══════════ -->
  <section class="tab-page" id="tab-reports">
    <div class="reports-grid">
      <div class="panel">
        <h3>📑 Incident reports</h3>
        <div class="cap">Export everything the system has seen and decided — ready for compliance, audits, or your incident review meeting.</div>
        <ul class="checklist">
          <li>Every monitored event with timestamps</li>
          <li>AI threat level and risk score per event</li>
          <li>The AI's reasoning for each verdict</li>
          <li>The recommended remediation command</li>
          <li>MITRE ATT&CK classification</li>
        </ul>
        <button class="big-btn" onclick="downloadCSV()">📥 Download full incident report (CSV)</button>
      </div>
      <div class="panel">
        <h3>Report summary</h3>
        <div class="cap">Event counts per threat level</div>
        <table class="rep" id="reportTable"></table>
      </div>
    </div>
  </section>
</main>

<script>
/* ════════════════════════════════════════════════════════════
   AI SOC Command Center — zero-dependency dashboard
   Live data is injected by Python (dashboard.py) below.
   ════════════════════════════════════════════════════════════ */

const SEV_EMOJI = { critical: "🔴", high: "🟠", medium: "🟡", low: "🟢" };
const SEV_ORDER = ["critical", "high", "medium", "low"];
const SEV_COLORS = { critical: "#ff4b4b", high: "#ffa421", medium: "#ffe312", low: "#00d46a" };

const MITRE_PLAIN = {
  "T1110": "Brute-force password guessing",
  "T1110.001": "Password guessing against one account",
  "T1110.003": "Password spraying across many accounts",
  "T1059": "Running scripted commands",
  "T1059.001": "PowerShell abuse",
  "T1078": "Using valid (possibly stolen) accounts",
  "T1548": "Privilege escalation abuse",
};

const state = {
  events: [],
  selected: null,
};

/* ── Live data injected by dashboard.py ── */
state.events = __EVENTS_JSON__;
/* Prefer the newest event the AI has already judged (keeps the verdict panel populated) */
{
  const firstAnalyzed = state.events.find((e) => e.threat_level && e.threat_level !== "UNKNOWN");
  state.selected = (firstAnalyzed || state.events[0] || {}).id ?? null;
}

/* ── Helpers ─────────────────────────────────────── */
const $ = (s) => document.querySelector(s);

function displaySeverity(e) {
  const t = (e.threat_level && e.threat_level !== "UNKNOWN" ? e.threat_level : e.severity || "low").toLowerCase();
  return SEV_ORDER.includes(t) ? t : "low";
}

function chip(sev) {
  return `<span class="chip chip-${sev}">${SEV_EMOJI[sev]} ${sev.toUpperCase()}</span>`;
}

function esc(s) {
  return String(s ?? "—").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function translate(e) {
  const ip = esc(e.source_ip), user = esc(e.user), host = esc(e.host);
  const where = host && host !== "—" ? ` on <b>${host}</b>` : "";
  const raw = (e.raw_log || "").toLowerCase();
  const isFail = e.action === "failure" ||
    ((e.action === undefined || e.action === null) && (raw.includes("failed") || raw.includes("invalid user")));
  if (e.log_source === "linux-auth") {
    if (e.event_type === "privilege_escalation")
      return `🔑 <b>${user}</b> ran a command with admin rights${where}`;
    if (isFail) {
      if (raw.includes("invalid user"))
        return `🕵️ Someone tried a <b>fake username</b> (<code>${user}</code>) from <code>${ip}</code>${where}`;
      return `🔐 Failed login attempt for <b>${user}</b> from <code>${ip}</code>${where}`;
    }
    return `✅ Successful login for <b>${user}</b> from <code>${ip}</code>${where}`;
  }
  if (raw.includes("encodedcommand"))
    return `🧬 <b>Hidden/encoded PowerShell</b> launched${where}`;
  if (raw.includes("invoke-webrequest") || raw.includes("downloadstring"))
    return `⬇️ A program <b>downloaded a file</b>${where}`;
  if (raw.includes("powershell"))
    return `⚠️ Suspicious <b>PowerShell</b> activity${where}`;
  return `🖥️ A program ran${where}`;
}

function mitrePlain(mitre) {
  if (!mitre) return "Not classified yet";
  for (const [id, meaning] of Object.entries(MITRE_PLAIN)) {
    if (mitre.startsWith(id)) return `${esc(mitre)} — <i>${meaning}</i>`;
  }
  return esc(mitre);
}

function commandFromActions(actions) {
  const m = (actions || "").match(/```(?:bash|powershell|sh)?\n([\s\S]*?)```/);
  return m ? m[1].trim() : (actions || "").trim();
}

/* ── Rendering ───────────────────────────────────── */
function renderKPIs() {
  const ev = state.events;
  const total = ev.length;
  const threats = ev.filter((e) => ["medium", "high", "critical"].includes(displaySeverity(e))).length;
  const freq = (key) => {
    const counts = {};
    ev.forEach((e) => { const v = e[key]; if (v && v !== "—") counts[v] = (counts[v] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || "N/A";
  };
  $("#kpiGrid").innerHTML = [
    ["📥 EVENTS MONITORED", total.toLocaleString(), "live counter — grows as events arrive"],
    ["🚨 THREATS CAUGHT", threats.toLocaleString(), "flagged dangerous by the AI agents"],
    ["🎯 TOP ATTACKER IP", esc(freq("source_ip")), "most frequent source of trouble"],
    ["👤 MOST TARGETED ACCOUNT", esc(freq("user")), "attackers aim at this account most"],
  ].map(([label, value, sub]) => `
    <div class="kpi">
      <div class="kpi-label">${label}</div>
      <div class="kpi-value ${value.length > 12 ? "small" : ""}">${value}</div>
      <div class="kpi-sub">${sub}</div>
    </div>`).join("");
}

function renderDonut() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  state.events.forEach((e) => counts[displaySeverity(e)]++);
  const total = state.events.length || 1;
  const r = 70, C = 2 * Math.PI * r;
  let offset = 0;
  const segs = SEV_ORDER.map((sev) => {
    const frac = counts[sev] / total;
    const seg = `<circle cx="95" cy="95" r="${r}" fill="none"
      stroke="${SEV_COLORS[sev]}" stroke-width="26"
      stroke-dasharray="${frac * C} ${C}"
      stroke-dashoffset="${-offset}"
      transform="rotate(-90 95 95)" stroke-linecap="butt"></circle>`;
    offset += frac * C;
    return seg;
  }).join("");
  $("#donutSvg").innerHTML = `
    <circle cx="95" cy="95" r="${r}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="26"></circle>
    ${segs}
    <text x="95" y="90" text-anchor="middle" fill="#fff" font-size="26" font-weight="800">${state.events.length}</text>
    <text x="95" y="112" text-anchor="middle" class="donut-center-label">TOTAL EVENTS</text>`;
  $("#donutLegend").innerHTML = SEV_ORDER.map((sev) => `
    <div class="legend-row">
      <span class="dot" style="background:${SEV_COLORS[sev]}"></span>
      <span>${SEV_EMOJI[sev]} ${sev[0].toUpperCase() + sev.slice(1)}</span>
      <span class="n">${counts[sev]}</span>
    </div>`).join("");
}

function renderMachines() {
  const counts = {};
  state.events.forEach((e) => {
    const h = e.host && e.host !== "—" ? e.host : "unknown machine";
    counts[h] = (counts[h] || 0) + 1;
  });
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = rows[0]?.[1] || 1;
  $("#machineBars").innerHTML = rows.map(([name, n]) => `
    <div class="bar-row">
      <div class="bar-name" title="${esc(name)}">${esc(name)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(n / max) * 100}%"></div></div>
      <div class="bar-count">${n}</div>
    </div>`).join("");
}

function renderFeed() {
  if (!state.events.length) {
    $("#feed").innerHTML = `<div style="color:var(--dim);padding:18px 4px;">🌱 No events yet — run the simulator to see live attacks here.</div>`;
    return;
  }
  $("#feed").innerHTML = state.events.slice(0, 8).map((e) => `
    <div class="feed-row">
      ${chip(displaySeverity(e))}
      <div class="feed-text">${translate(e)}</div>
      <div class="feed-meta">${esc(e.timestamp)} · event #${e.id}</div>
    </div>`).join("");
}

function renderEventList() {
  $("#eventList").innerHTML = state.events.map((e) => {
    const sev = displaySeverity(e);
    return `<button class="event-item ${state.selected === e.id ? "selected" : ""}" onclick="selectEvent(${e.id})">
      <div class="idline">${chip(sev)} <b style="font-size:0.8rem;">#${e.id}</b></div>
      <div class="sum">${translate(e)}</div>
    </button>`;
  }).join("");
}

function renderDetail() {
  const e = state.events.find((x) => x.id === state.selected) || state.events[0];
  if (!e) { $("#detailPanel").innerHTML = "<p>No events yet — the system is warming up.</p>"; return; }
  state.selected = e.id;
  const sev = displaySeverity(e);
  const analyzed = e.threat_level && e.threat_level !== "UNKNOWN";
  const risk = e.risk_score;
  const riskKnown = risk !== null && risk !== undefined;
  const riskColor = risk >= 70 ? "var(--critical)" : risk >= 35 ? "var(--high)" : riskKnown ? "var(--low)" : "var(--border)";
  const riskCap = !riskKnown ? "🧠 The AI is assessing this event — the score appears within seconds."
    : risk >= 70 ? "⚠️ High concern — act soon" : risk >= 35 ? "Medium concern" : "Low concern";
  const cmd = commandFromActions(e.response_actions);

  $("#detailPanel").innerHTML = `
    <h4>🤖 What the AI decided &nbsp; ${chip(sev)}</h4>
    ${analyzed ? "" : `<div class="pending-pill">⏳ This event is queued for AI analysis — verdict will appear within seconds.</div>`}
    <div class="summary-big">${translate(e)}</div>
    <div class="metric-grid">
      <div class="metric"><div class="m-label">EVENT ID</div><div class="m-value">#${e.id}</div></div>
      <div class="metric"><div class="m-label">MACHINE</div><div class="m-value">${esc(e.host)}</div></div>
      <div class="metric"><div class="m-label">WHEN</div><div class="m-value">${esc(e.timestamp)}</div></div>
      <div class="metric"><div class="m-label">ACCOUNT</div><div class="m-value">${esc(e.user)}</div></div>
      <div class="metric"><div class="m-label">SOURCE IP</div><div class="m-value">${esc(e.source_ip)}</div></div>
      <div class="metric"><div class="m-label">PLATFORM</div><div class="m-value">${e.log_source === "windows-sysmon" ? "🪟 Windows" : "🐧 Linux"}</div></div>
    </div>
    <div style="font-size:0.88rem;font-weight:700;">Risk score: ${riskKnown ? risk + "/100" : "—/100"}</div>
    <div class="risk-track"><div class="risk-fill" style="width:${riskKnown ? risk : 3}%;background:${riskColor};"></div></div>
    <div class="cap-small">${riskCap}</div>
    <div class="mitre-box">
      <b>Known attack pattern (MITRE ATT&CK):</b><br>${
        e.mitre_technique ? mitrePlain(e.mitre_technique)
        : "<i>Classification will appear when the AI finishes its analysis.</i>"}
    </div>
    <div class="cap-small">${
      e.correlated_event_count !== null && e.correlated_event_count !== undefined
        ? `🔗 Seen <b>${e.correlated_event_count}</b> related event(s) recently — ${e.correlated_event_count > 0 ? "this is not an isolated incident." : "looks isolated."}`
        : "🔗 Checking for related events…"}</div>
    <div class="reason-box"><b>🧠 AI reasoning:</b><br>${
      e.analysis_reasoning ? esc(e.analysis_reasoning)
      : "<i>The AI is writing its explanation — it appears within seconds.</i>"}</div>
    <div class="fix-box">
      <b>🛠️ Recommended fix</b> — ${cmd ? "copy &amp; run on the affected machine:" : "will appear once the analysis completes:"}
      ${cmd
        ? `<div class="cmd">${esc(cmd)}<button class="copy-btn" onclick="copyCmd(this)">📋 copy</button></div>`
        : `<div class="cmd" style="opacity:0.55;">Waiting for the AI to write the remediation command…</div>`}
    </div>
    <details class="raw">
      <summary>🔬 Technical details (raw evidence)</summary>
      <div class="cmd" style="margin-top:6px;">${esc(e.raw_log)}</div>
    </details>`;
}

function renderReports() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  state.events.forEach((e) => counts[displaySeverity(e)]++);
  $("#reportTable").innerHTML = `
    <tr><th>THREAT LEVEL</th><th>EVENTS</th></tr>
    ${SEV_ORDER.map((s) => `<tr><td>${chip(s)}</td><td><b>${counts[s]}</b></td></tr>`).join("")}
    <tr><td><b>Total</b></td><td><b>${state.events.length}</b></td></tr>`;
}

function renderAll() {
  $("#emptyState").style.display = state.events.length ? "none" : "block";
  renderKPIs(); renderDonut(); renderMachines(); renderFeed();
  renderEventList(); renderDetail(); renderReports();
}

/* ── Interactions ────────────────────────────────── */
function switchTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab-page").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
}

function selectEvent(id) { state.selected = id; renderEventList(); renderDetail(); }

function copyCmd(btn) {
  const text = btn.parentElement.textContent.replace("📋 copy", "").trim();
  navigator.clipboard?.writeText(text);
  btn.textContent = "✓ copied!";
  setTimeout(() => (btn.textContent = "📋 copy"), 1500);
}

function downloadCSV() {
  const cols = ["id", "timestamp", "log_source", "event_type", "source_ip", "user", "host",
    "severity", "threat_level", "mitre_technique", "risk_score", "correlated_event_count",
    "analysis_reasoning", "response_actions", "raw_log"];
  const cell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const csv = [cols.join(",")].concat(
    state.events.map((e) => cols.map((c) => cell(e[c])).join(","))
  ).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "sih_agentic_soc_report.csv";
  a.click();
}

/* ── Boot ────────────────────────────────────────── */
setInterval(() => {
  $("#clock").textContent = new Date().toLocaleTimeString();
}, 1000);
$("#clock").textContent = new Date().toLocaleTimeString();
renderAll();
</script>
</body>
</html>
"""

# Run the app after the template is defined
main()
