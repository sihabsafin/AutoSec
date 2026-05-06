import streamlit as st
import streamlit.components.v1 as components
import json
from datetime import datetime

st.set_page_config(
    page_title="Threat Dashboard — AutoSEC",
    page_icon="📊",
    layout="wide",
)

from utils.styles import inject_styles, show_disclaimer
inject_styles()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "threat_result":    {},
    "vuln_result":      {},
    "response_result":  {},
    "report_result":    {},
    "parsed_target":    {},
    "security_context": {},
    "org_name":         "",
    "compliance_scope": [],
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------

components.html("""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
.page-header {
    background: linear-gradient(135deg, #0a0805, #0a0a1a);
    border: 1px solid rgba(139,92,246,0.2);
    border-left: 4px solid #8b5cf6;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
    position: relative;
    overflow: hidden;
}
.page-header::before {
    content: '';
    position: absolute;
    top: 0; right: 0;
    width: 200px; height: 100%;
    background-image:
        linear-gradient(rgba(139,92,246,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(139,92,246,0.04) 1px, transparent 1px);
    background-size: 20px 20px;
}
.page-phase {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #8b5cf6;
    letter-spacing: 0.15em;
    margin-bottom: 0.3rem;
}
.page-title {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.8rem;
    color: #f5f0eb;
    margin: 0;
}
.page-sub {
    font-family: 'DM Sans', sans-serif;
    font-size: 0.85rem;
    color: rgba(245,240,235,0.5);
    margin-top: 0.3rem;
}
.live-dot {
    display: inline-block;
    width: 8px; height: 8px;
    background: #22c55e;
    border-radius: 50%;
    animation: pulse 2s infinite;
    margin-right: 6px;
}
</style>
<div class="page-header">
    <div class="page-phase">
        <span class="live-dot"></span>
        SOC DASHBOARD // THREAT ANALYTICS
    </div>
    <div class="page-title">📊 Threat Dashboard</div>
    <div class="page-sub">
        Real-time analytics from your analysis pipeline.
        No crew needed — reads from session state.
        Severity distribution · ATT&CK coverage · IOC timeline · Compliance status.
    </div>
</div>
""", height=130)

show_disclaimer()

# ---------------------------------------------------------------------------
# Collect all data from session state
# ---------------------------------------------------------------------------

threat_result   = st.session_state.get("threat_result",   {})
vuln_result     = st.session_state.get("vuln_result",     {})
response_result = st.session_state.get("response_result", {})
report_result   = st.session_state.get("report_result",   {})
parsed_target   = st.session_state.get("parsed_target",   {})
context         = st.session_state.get("security_context",{})
org_name        = st.session_state.get("org_name",        "Unknown")

# Check if we have any data
has_data = any([
    bool(threat_result),
    bool(vuln_result),
    bool(response_result),
    bool(report_result),
])

if not has_data:
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(139,92,246,0.2);
            border-radius:12px;padding:2rem;text-align:center;">
    <div style="font-size:3rem;margin-bottom:1rem;">📊</div>
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:1.2rem;color:#8b5cf6;margin-bottom:0.5rem;">
        No Analysis Data Yet
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.85rem;
                color:rgba(245,240,235,0.55);line-height:1.6;">
        Run the analysis pipeline first:<br>
        Phase 1 (Target Intake) → Phase 2 (Threat Detection) →
        Phase 3 (Vulnerability) → Phase 4 (Incident Response) →
        Phase 5 (Report)<br><br>
        This dashboard will populate automatically.
    </div>
</div>
""", height=220)

    # Show DB stats if available
    try:
        from utils.database import get_dashboard_stats, is_connected
        if is_connected():
            st.markdown("### 📦 Historical Data from Database")
            db_stats = get_dashboard_stats()
            d1, d2, d3, d4 = st.columns(4)
            with d1:
                st.metric("Targets Analyzed",  db_stats.get("targets_analyzed",  0))
            with d2:
                st.metric("Threats Detected",  db_stats.get("threats_detected",  0))
            with d3:
                st.metric("Critical Findings", db_stats.get("critical_findings", 0))
            with d4:
                st.metric("Reports Generated", db_stats.get("reports_generated", 0))
    except Exception:
        pass

    st.stop()

# ---------------------------------------------------------------------------
# Extract metrics
# ---------------------------------------------------------------------------

# Threat metrics
severity_counts  = threat_result.get("severity_counts", {})
critical_t  = severity_counts.get("critical", 0)
high_t      = severity_counts.get("high",     0)
medium_t    = severity_counts.get("medium",   0)
low_t       = severity_counts.get("low",      0)
info_t      = severity_counts.get("info",     0)
total_threats = critical_t + high_t + medium_t + low_t + info_t

# Vulnerability metrics
total_cves  = vuln_result.get("total_cves",    0)
crit_cves   = vuln_result.get("critical_cves", 0)
high_cves   = vuln_result.get("high_cves",     0)
exp_score   = vuln_result.get("exposure_score", 0)

# Incident metrics
priority    = response_result.get("priority",      "N/A")
inc_type    = response_result.get("incident_type", "N/A")
p1_items    = response_result.get("p1_items",      0)

# Report metrics
risk_score  = report_result.get("risk_score", 0)

# MITRE data
threats_cls = threat_result.get("threat_classification", {})
mitre_map   = threats_cls.get("mitre_attack_mapping", {})

# IOC data
ioc_data    = threat_result.get("ioc_analysis", {})
susp_ips    = ioc_data.get("suspicious_ips",   [])
susp_agents = ioc_data.get("suspicious_user_agents", [])

# Compliance data
compliance  = report_result.get("compliance_mapping", {})
fw_assess   = compliance.get("framework_assessments", {})

# ---------------------------------------------------------------------------
# Section 1 — KPI Row
# ---------------------------------------------------------------------------

st.markdown("### 🎯 Security KPIs")

risk_color = (
    "#ef4444" if risk_score >= 75 else
    "#f97316" if risk_score >= 50 else
    "#f59e0b" if risk_score >= 25 else
    "#22c55e"
)
risk_label = (
    "CRITICAL" if risk_score >= 75 else
    "HIGH"     if risk_score >= 50 else
    "MEDIUM"   if risk_score >= 25 else
    "LOW"
)
p_color = {
    "P1": "#ef4444", "P2": "#f97316",
    "P3": "#f59e0b", "P4": "#3b82f6",
}.get(priority, "#64748b")

exp_color = (
    "#ef4444" if exp_score >= 75 else
    "#f97316" if exp_score >= 50 else
    "#f59e0b" if exp_score >= 25 else
    "#22c55e"
)

kpi_cols = st.columns(5)
kpis = [
    ("RISK SCORE",       f"{risk_score}/100",  risk_label,  risk_color),
    ("TOTAL THREATS",    str(total_threats),   f"{critical_t} critical", "#ef4444"),
    ("TOTAL CVEs",       str(total_cves),      f"{crit_cves} critical",  "#f97316"),
    ("EXPOSURE SCORE",   f"{exp_score}/100",   "attack surface",         exp_color),
    ("PRIORITY",         priority,             inc_type[:20],            p_color),
]

for col, (label, val, sub, color) in zip(kpi_cols, kpis):
    with col:
        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {color}33;
            border-top:3px solid {color};border-radius:10px;
            padding:0.9rem 0.8rem;text-align:center;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;
                margin-bottom:4px;">{label}</div>
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:1.7rem;color:{color};line-height:1;">{val}</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.35);margin-top:3px;">{sub}</div>
</div>
""", height=100)

st.markdown("---")

# ---------------------------------------------------------------------------
# Section 2 — Severity Distribution Chart (pure HTML/CSS)
# ---------------------------------------------------------------------------

st.markdown("### 📊 Severity Distribution")

dash_col1, dash_col2 = st.columns([3, 2])

with dash_col1:
    # Bar chart — pure HTML/CSS, no plotly
    total_display = max(total_threats, 1)
    bars_data = [
        ("CRITICAL", critical_t, "#ef4444"),
        ("HIGH",     high_t,     "#f97316"),
        ("MEDIUM",   medium_t,   "#f59e0b"),
        ("LOW",      low_t,      "#3b82f6"),
        ("INFO",     info_t,     "#64748b"),
    ]

    bars_html = ""
    for label, count, color in bars_data:
        pct = int((count / total_display) * 100) if total_display > 0 else 0
        bars_html += f"""
<div style="margin-bottom:10px;">
    <div style="display:flex;justify-content:space-between;align-items:center;
                margin-bottom:4px;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                     color:{color};letter-spacing:0.08em;">{label}</span>
        <span style="font-family:'Syne',sans-serif;font-weight:700;
                     font-size:0.9rem;color:{color};">{count}</span>
    </div>
    <div style="background:rgba(0,0,0,0.3);border-radius:6px;
                height:20px;overflow:hidden;position:relative;">
        <div style="background:linear-gradient(90deg,{color}cc,{color});
                    width:{max(pct,2 if count>0 else 0)}%;height:100%;
                    border-radius:6px;transition:width 0.5s ease;
                    display:flex;align-items:center;justify-content:flex-end;
                    padding-right:6px;">
            {f'<span style="font-family:JetBrains Mono,monospace;font-size:0.6rem;color:#fff;font-weight:700;">{pct}%</span>' if pct > 8 else ''}
        </div>
    </div>
</div>"""

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.15);
            border-radius:10px;padding:1.2rem 1.3rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;
                margin-bottom:1rem;">THREAT SEVERITY DISTRIBUTION</div>
    {bars_html}
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                color:rgba(245,240,235,0.2);margin-top:8px;text-align:right;">
        TOTAL: {total_threats} threats analyzed
    </div>
</div>
""", height=260)

with dash_col2:
    # Donut-style summary (HTML/CSS circles)
    cve_bars = [
        ("Critical CVEs", crit_cves, "#ef4444"),
        ("High CVEs",     high_cves, "#f97316"),
        ("Other CVEs",    max(0, total_cves - crit_cves - high_cves), "#64748b"),
    ]

    cve_html = ""
    total_cve_disp = max(total_cves, 1)
    for label, count, color in cve_bars:
        pct = int((count / total_cve_disp) * 100) if total_cve_disp > 0 else 0
        cve_html += f"""
<div style="margin-bottom:8px;">
    <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
        <span style="font-family:'DM Sans',sans-serif;font-size:0.75rem;
                     color:rgba(245,240,235,0.6);">{label}</span>
        <span style="font-family:'Syne',sans-serif;font-weight:700;
                     font-size:0.85rem;color:{color};">{count}</span>
    </div>
    <div style="background:rgba(0,0,0,0.3);border-radius:4px;height:10px;overflow:hidden;">
        <div style="background:{color};width:{max(pct,2 if count>0 else 0)}%;
                    height:100%;border-radius:4px;"></div>
    </div>
</div>"""

    # Exposure gauge
    exp_pct = min(100, max(0, exp_score))
    exp_color_gauge = (
        "#ef4444" if exp_score >= 75 else
        "#f97316" if exp_score >= 50 else
        "#f59e0b" if exp_score >= 25 else "#22c55e"
    )

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(249,115,22,0.15);
            border-radius:10px;padding:1.2rem 1.3rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;
                margin-bottom:1rem;">CVE BREAKDOWN</div>
    {cve_html}
    <div style="margin-top:1rem;padding-top:0.8rem;
                border-top:1px solid rgba(239,68,68,0.1);">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                    color:rgba(245,240,235,0.35);margin-bottom:6px;">
            EXPOSURE SCORE
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
            <div style="font-family:'Syne',sans-serif;font-weight:800;
                        font-size:1.8rem;color:{exp_color_gauge};">
                {exp_score}
            </div>
            <div style="flex:1;">
                <div style="background:rgba(0,0,0,0.3);border-radius:6px;
                            height:12px;overflow:hidden;">
                    <div style="background:linear-gradient(90deg,#22c55e,#f59e0b,#ef4444);
                                width:{exp_pct}%;height:100%;border-radius:6px;">
                    </div>
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                            color:rgba(245,240,235,0.3);margin-top:2px;">
                    /100 attack surface
                </div>
            </div>
        </div>
    </div>
</div>
""", height=260)

st.markdown("---")

# ---------------------------------------------------------------------------
# Section 3 — MITRE ATT&CK Heatmap
# ---------------------------------------------------------------------------

st.markdown("### ⚔️ MITRE ATT&CK Coverage Heatmap")

TACTICS = [
    ("Initial Access",       "TA0001"),
    ("Execution",            "TA0002"),
    ("Persistence",          "TA0003"),
    ("Privilege Escalation", "TA0004"),
    ("Defense Evasion",      "TA0005"),
    ("Credential Access",    "TA0006"),
    ("Discovery",            "TA0007"),
    ("Lateral Movement",     "TA0008"),
    ("Collection",           "TA0009"),
    ("Exfiltration",         "TA0010"),
    ("Command and Control",  "TA0011"),
    ("Impact",               "TA0040"),
]

TACTIC_COLORS = {
    "Initial Access":       "#ef4444",
    "Execution":            "#f97316",
    "Persistence":          "#f59e0b",
    "Privilege Escalation": "#eab308",
    "Defense Evasion":      "#84cc16",
    "Credential Access":    "#22c55e",
    "Discovery":            "#0891b2",
    "Lateral Movement":     "#6366f1",
    "Collection":           "#8b5cf6",
    "Exfiltration":         "#a855f7",
    "Command and Control":  "#ec4899",
    "Impact":               "#f43f5e",
}

heatmap_cells = ""
for tactic_name, tactic_id in TACTICS:
    tdata     = mitre_map.get(tactic_name, {})
    detected  = tdata.get("detected", False)
    techs     = tdata.get("techniques", [])
    tech_cnt  = len(techs)
    color     = TACTIC_COLORS.get(tactic_name, "#64748b")

    # Intensity based on technique count
    if detected and tech_cnt >= 3:
        intensity = "FF"
        text_col  = "#fff"
    elif detected and tech_cnt == 2:
        intensity = "CC"
        text_col  = "#fff"
    elif detected:
        intensity = "88"
        text_col  = "#fff"
    else:
        intensity = "00"
        text_col  = "rgba(245,240,235,0.2)"

    bg_color  = f"{color}{intensity}" if detected else "rgba(245,240,235,0.03)"
    brd_color = color if detected else "rgba(245,240,235,0.06)"

    tech_names = ""
    if detected and techs:
        for t in techs[:2]:
            if isinstance(t, dict):
                t_id   = t.get("id",   "")
                t_name = t.get("name", "")
                tech_names += f"""
<div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
            color:rgba(255,255,255,0.7);margin-top:1px;">
    {t_id}
</div>"""

    alert_icon = "⚡" if detected else "○"

    heatmap_cells += f"""
<div style="background:{bg_color};border:1px solid {brd_color};
            border-radius:6px;padding:0.6rem 0.5rem;
            min-height:90px;position:relative;overflow:hidden;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.55rem;
                color:{text_col if detected else 'rgba(245,240,235,0.2)'};
                letter-spacing:0.06em;margin-bottom:2px;">
        {alert_icon} {tactic_id}
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                font-size:0.7rem;
                color:{text_col if detected else 'rgba(245,240,235,0.2)'};
                line-height:1.3;margin-bottom:3px;">
        {tactic_name}
    </div>
    {f'<div style="font-family:Syne,sans-serif;font-weight:800;font-size:1rem;color:{text_col};">{tech_cnt}</div>' if detected else ''}
    {tech_names}
    {f'<div style="position:absolute;bottom:4px;right:6px;font-family:JetBrains Mono,monospace;font-size:0.55rem;color:rgba(255,255,255,0.4);">technique{"s" if tech_cnt!=1 else ""}</div>' if detected else ''}
</div>"""

components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(139,92,246,0.15);
            border-radius:10px;padding:1rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;margin-bottom:0.8rem;">
        MITRE ATT&CK TACTIC COVERAGE — DETECTED TACTICS HIGHLIGHTED
    </div>
    <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:0.5rem;">
        {heatmap_cells}
    </div>
    <div style="margin-top:0.8rem;font-family:'JetBrains Mono',monospace;
                font-size:0.58rem;color:rgba(245,240,235,0.2);">
        ⚡ = Detected &nbsp;|&nbsp; Brightness = number of techniques &nbsp;|&nbsp;
        ○ = Not detected
    </div>
</div>
""", height=320)

st.markdown("---")

# ---------------------------------------------------------------------------
# Section 4 — Top IOCs Table
# ---------------------------------------------------------------------------

st.markdown("### 🎯 Top Indicators of Compromise")

ioc_col1, ioc_col2 = st.columns(2)

with ioc_col1:
    st.markdown("#### 🔴 Suspicious IPs")

    if susp_ips:
        ip_rows = ""
        for i, ip_data in enumerate(susp_ips[:8]):
            if isinstance(ip_data, dict):
                ip_addr  = ip_data.get("ip",             "Unknown")
                ip_class = ip_data.get("classification", "Unknown")
                ip_sev   = ip_data.get("severity",       "Medium")
                ip_act   = ip_data.get("activity",       "")[:60]
            else:
                ip_addr  = str(ip_data)
                ip_class = "Suspicious"
                ip_sev   = "Medium"
                ip_act   = ""

            row_bg = "rgba(239,68,68,0.06)" if i % 2 == 0 else "transparent"
            s_color = {
                "Critical": "#ef4444",
                "High":     "#f97316",
                "Medium":   "#f59e0b",
                "Low":      "#3b82f6",
            }.get(ip_sev, "#64748b")

            ip_rows += f"""
<div style="display:grid;grid-template-columns:1.5fr 1fr 1fr;
            gap:8px;padding:7px 10px;background:{row_bg};
            border-bottom:1px solid rgba(239,68,68,0.06);
            font-family:'DM Sans',sans-serif;font-size:0.78rem;
            align-items:center;">
    <span style="font-family:'JetBrains Mono',monospace;
                 color:#f5f0eb;font-size:0.75rem;">{ip_addr}</span>
    <span style="color:rgba(245,240,235,0.5);font-size:0.72rem;">
        {ip_class[:20]}
    </span>
    <span style="background:{s_color};color:#fff;font-size:0.6rem;
                 font-weight:700;padding:1px 5px;border-radius:3px;
                 text-align:center;display:inline-block;">
        {ip_sev.upper()}
    </span>
</div>"""

        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.15);
            border-radius:10px;overflow:hidden;">
    <div style="display:grid;grid-template-columns:1.5fr 1fr 1fr;
                gap:8px;padding:7px 10px;
                background:rgba(239,68,68,0.1);
                font-family:'JetBrains Mono',monospace;
                font-size:0.6rem;color:rgba(245,240,235,0.4);
                letter-spacing:0.08em;">
        <span>IP ADDRESS</span>
        <span>CLASSIFICATION</span>
        <span>SEVERITY</span>
    </div>
    {ip_rows}
</div>
""", height=max(100, len(susp_ips[:8]) * 40 + 45))
    else:
        components.html("""
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.1);
            border-radius:10px;padding:1.5rem;text-align:center;
            font-family:'DM Sans',sans-serif;font-size:0.82rem;
            color:rgba(245,240,235,0.35);">
    No suspicious IPs detected
</div>
""", height=80)

with ioc_col2:
    st.markdown("#### 🤖 Attack Tools Detected")

    if susp_agents:
        agent_rows = ""
        for i, agent_data in enumerate(susp_agents[:8]):
            if isinstance(agent_data, dict):
                ua_str  = agent_data.get("agent", "")[:40]
                ua_tool = agent_data.get("tool",  "Unknown")[:30]
                ua_sev  = agent_data.get("severity","High")
                ua_ip   = agent_data.get("source_ip","")
            else:
                ua_str  = str(agent_data)[:40]
                ua_tool = "Attack tool"
                ua_sev  = "High"
                ua_ip   = ""

            row_bg  = "rgba(249,115,22,0.04)" if i % 2 == 0 else "transparent"
            a_color = {
                "Critical": "#ef4444",
                "High":     "#f97316",
                "Medium":   "#f59e0b",
            }.get(ua_sev, "#64748b")

            agent_rows += f"""
<div style="display:grid;grid-template-columns:1.2fr 1fr 0.8fr;
            gap:6px;padding:7px 10px;background:{row_bg};
            border-bottom:1px solid rgba(249,115,22,0.06);
            align-items:center;">
    <span style="font-family:'JetBrains Mono',monospace;
                 color:#f97316;font-size:0.7rem;">{ua_str}</span>
    <span style="font-family:'DM Sans',sans-serif;font-size:0.72rem;
                 color:rgba(245,240,235,0.5);">{ua_tool}</span>
    <span style="background:{a_color};color:#fff;font-size:0.6rem;
                 font-weight:700;padding:1px 5px;border-radius:3px;
                 text-align:center;display:inline-block;">
        {ua_sev.upper()}
    </span>
</div>"""

        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(249,115,22,0.15);
            border-radius:10px;overflow:hidden;">
    <div style="display:grid;grid-template-columns:1.2fr 1fr 0.8fr;
                gap:6px;padding:7px 10px;
                background:rgba(249,115,22,0.1);
                font-family:'JetBrains Mono',monospace;
                font-size:0.6rem;color:rgba(245,240,235,0.4);
                letter-spacing:0.08em;">
        <span>USER AGENT</span>
        <span>TOOL</span>
        <span>SEVERITY</span>
    </div>
    {agent_rows}
</div>
""", height=max(100, len(susp_agents[:8]) * 40 + 45))
    else:
        components.html("""
<div style="background:#120f0a;border:1px solid rgba(249,115,22,0.1);
            border-radius:10px;padding:1.5rem;text-align:center;
            font-family:'DM Sans',sans-serif;font-size:0.82rem;
            color:rgba(245,240,235,0.35);">
    No attack tools detected
</div>
""", height=80)

st.markdown("---")

# ---------------------------------------------------------------------------
# Section 5 — Compliance Status Dashboard
# ---------------------------------------------------------------------------

st.markdown("### ⚖️ Compliance Status Overview")

if fw_assess:
    comp_cards_html = ""
    for fw_name, fw_data in fw_assess.items():
        if isinstance(fw_data, dict):
            fw_status = fw_data.get("status",               "Unknown")
            fw_pct    = fw_data.get("compliance_percentage", 0)
            fw_viols  = fw_data.get("violations",            [])
            v_cnt     = len(fw_viols)
        else:
            fw_status = str(fw_data)
            fw_pct    = 0
            v_cnt     = 0

        fw_color = {
            "Compliant":     "#22c55e",
            "Partial":       "#f59e0b",
            "Non-Compliant": "#ef4444",
            "N/A":           "#64748b",
        }.get(fw_status, "#64748b")

        status_icon = "✅" if fw_status == "Compliant" else \
                      "⚠️" if fw_status == "Partial" else \
                      "❌" if fw_status == "Non-Compliant" else "○"

        comp_cards_html += f"""
<div style="background:#120f0a;border:1px solid {fw_color}33;
            border-top:4px solid {fw_color};border-radius:10px;
            padding:1rem;text-align:center;">
    <div style="font-size:1.3rem;margin-bottom:4px;">{status_icon}</div>
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:0.78rem;color:#f5f0eb;margin-bottom:4px;">
        {fw_name}
    </div>
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:0.85rem;color:{fw_color};margin-bottom:6px;">
        {fw_status}
    </div>
    <div style="background:rgba(0,0,0,0.3);border-radius:6px;
                height:8px;overflow:hidden;margin-bottom:6px;">
        <div style="background:{fw_color};width:{fw_pct}%;
                    height:100%;border-radius:6px;"></div>
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);">
        {fw_pct}% &nbsp;|&nbsp; {v_cnt} violation(s)
    </div>
</div>"""

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="display:grid;grid-template-columns:repeat(5,1fr);
            gap:0.7rem;">
    {comp_cards_html}
</div>
""", height=220)
else:
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(139,92,246,0.15);
            border-radius:10px;padding:1.2rem;text-align:center;
            font-family:'DM Sans',sans-serif;font-size:0.82rem;
            color:rgba(245,240,235,0.35);">
    Run Phase 5 (Security Report) to see compliance assessment
</div>
""", height=80)

st.markdown("---")

# ---------------------------------------------------------------------------
# Section 6 — Attack Chain Timeline
# ---------------------------------------------------------------------------

anomaly_data = threat_result.get("anomaly_detection", {})
attack_chain = anomaly_data.get("attack_chain", [])

if attack_chain:
    st.markdown("### ⛓️ Detected Attack Chain Timeline")

    chain_items_html = ""
    chain_colors = [
        "#ef4444","#f97316","#f59e0b","#eab308",
        "#84cc16","#22c55e","#0891b2","#8b5cf6"
    ]

    for i, step in enumerate(attack_chain[:8]):
        if isinstance(step, dict):
            s_num    = step.get("step",   i+1)
            s_action = step.get("action", "")
            s_detail = step.get("detail", "")
        else:
            s_num    = i+1
            s_action = str(step)
            s_detail = ""

        color   = chain_colors[i % len(chain_colors)]
        is_last = i == len(attack_chain[:8]) - 1

        chain_items_html += f"""
<div style="display:flex;align-items:flex-start;gap:0;">
    <div style="display:flex;flex-direction:column;align-items:center;
                min-width:40px;flex-shrink:0;">
        <div style="background:{color};color:#fff;
                    font-family:'Syne',sans-serif;font-weight:800;
                    font-size:0.78rem;width:32px;height:32px;
                    border-radius:50%;display:flex;align-items:center;
                    justify-content:center;z-index:1;
                    box-shadow:0 0 10px {color}66;">
            {s_num}
        </div>
        {'' if is_last else f'<div style="width:2px;height:40px;background:linear-gradient({color},{chain_colors[(i+1) % len(chain_colors)]});margin-top:0;"></div>'}
    </div>
    <div style="flex:1;background:#120f0a;border:1px solid {color}22;
                border-left:3px solid {color};border-radius:0 8px 8px 0;
                padding:0.7rem 1rem;margin-left:0;
                margin-bottom:{'0' if is_last else '0'};">
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    font-size:0.85rem;color:{color};margin-bottom:3px;">
            {s_action}
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.77rem;
                    color:rgba(245,240,235,0.55);">
            {s_detail[:150]}
        </div>
    </div>
</div>
{'<div style="height:0px;"></div>' if not is_last else ''}"""

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:#0a0805;border:1px solid rgba(239,68,68,0.12);
            border-radius:10px;padding:1.2rem 1.5rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;
                margin-bottom:1rem;">
        RECONSTRUCTED ATTACK CHAIN — {len(attack_chain)} STEPS
    </div>
    {chain_items_html}
</div>
""", height=max(200, len(attack_chain[:8]) * 80 + 60))

    st.markdown("---")

# ---------------------------------------------------------------------------
# Section 7 — Target Profile Summary
# ---------------------------------------------------------------------------

st.markdown("### 🎯 Target Profile")

target_type    = context.get("target_type",    "Unknown")
ctx_summary    = context.get("context_summary","")
risk_estimate  = context.get("initial_risk_estimate", {})
actor_profile  = context.get("threat_actor_profile",  {})
data_sens      = context.get("data_sensitivity",       {})

t_col1, t_col2, t_col3 = st.columns(3)

with t_col1:
    actor_type  = actor_profile.get("actor_type",          "Unknown")
    actor_soph  = actor_profile.get("sophistication",      "Unknown")
    actor_motiv = actor_profile.get("likely_motivation",   "Unknown")

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.12);
            border-radius:10px;padding:1rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.3);letter-spacing:0.1em;
                margin-bottom:8px;">TARGET PROFILE</div>
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:1rem;color:#f5f0eb;margin-bottom:6px;">
        {target_type}
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.78rem;
                color:rgba(245,240,235,0.55);line-height:1.5;">
        {ctx_summary[:180]}
    </div>
</div>
""", height=150)

with t_col2:
    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(245,158,11,0.15);
            border-radius:10px;padding:1rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.3);letter-spacing:0.1em;
                margin-bottom:8px;">THREAT ACTOR</div>
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:1rem;color:#f59e0b;margin-bottom:8px;">
        {actor_type}
    </div>
    <div style="display:flex;flex-direction:column;gap:4px;">
        <div style="display:flex;justify-content:space-between;
                    font-family:'DM Sans',sans-serif;font-size:0.75rem;">
            <span style="color:rgba(245,240,235,0.4);">Sophistication</span>
            <span style="color:#f5f0eb;font-weight:600;">{actor_soph}</span>
        </div>
        <div style="display:flex;justify-content:space-between;
                    font-family:'DM Sans',sans-serif;font-size:0.75rem;">
            <span style="color:rgba(245,240,235,0.4);">Motivation</span>
            <span style="color:#f5f0eb;font-weight:600;">{actor_motiv}</span>
        </div>
    </div>
</div>
""", height=150)

with t_col3:
    data_level = data_sens.get("sensitivity_level", "Unknown")
    pii        = data_sens.get("pii_likely",          False)
    financial  = data_sens.get("financial_data_likely",False)
    health     = data_sens.get("health_data_likely",   False)

    flags = []
    if pii:       flags.append("🔴 PII")
    if financial: flags.append("🔴 Financial")
    if health:    flags.append("🔴 Health")
    flags_str = "  ".join(flags) if flags else "No sensitive flags"

    dl_color = {
        "Critical": "#ef4444",
        "High":     "#f97316",
        "Medium":   "#f59e0b",
        "Low":      "#22c55e",
    }.get(data_level, "#64748b")

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {dl_color}22;
            border-radius:10px;padding:1rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.3);letter-spacing:0.1em;
                margin-bottom:8px;">DATA SENSITIVITY</div>
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:1rem;color:{dl_color};margin-bottom:8px;">
        {data_level}
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.75rem;
                color:rgba(245,240,235,0.6);">
        {flags_str}
    </div>
</div>
""", height=150)

st.markdown("---")

# ---------------------------------------------------------------------------
# Section 8 — Quick Actions
# ---------------------------------------------------------------------------

st.markdown("### ⚡ Quick Actions")

qa_col1, qa_col2, qa_col3, qa_col4 = st.columns(4)

with qa_col1:
    if st.button("🔄 Refresh Dashboard", use_container_width=True):
        st.rerun()

with qa_col2:
    # Export dashboard summary as JSON
    dashboard_summary = {
        "timestamp":     datetime.now().isoformat(),
        "organization":  org_name,
        "risk_score":    risk_score,
        "total_threats": total_threats,
        "severity_counts": severity_counts,
        "total_cves":    total_cves,
        "exposure_score":exp_score,
        "priority":      priority,
        "incident_type": inc_type,
        "mitre_tactics_detected": [
            t for t, _ in TACTICS
            if mitre_map.get(t, {}).get("detected", False)
        ],
        "top_iocs": [
            ip.get("ip", str(ip)) if isinstance(ip, dict) else str(ip)
            for ip in susp_ips[:5]
        ],
    }
    st.download_button(
        "📊 Export Dashboard JSON",
        data=json.dumps(dashboard_summary, indent=2),
        file_name=f"autosec_dashboard_{org_name.replace(' ','_')}.json",
        mime="application/json",
        use_container_width=True,
    )

with qa_col3:
    # Text summary
    tactics_detected = [
        t for t, _ in TACTICS
        if mitre_map.get(t, {}).get("detected", False)
    ]
    summary_txt = f"""AUTOSEC DASHBOARD SUMMARY
Organization: {org_name}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}

RISK SCORE: {risk_score}/100 — {risk_label}

THREAT SUMMARY:
  Total Threats: {total_threats}
  Critical: {critical_t}
  High: {high_t}
  Medium: {medium_t}

VULNERABILITY SUMMARY:
  Total CVEs: {total_cves}
  Critical CVEs: {crit_cves}
  Exposure Score: {exp_score}/100

INCIDENT:
  Priority: {priority}
  Type: {inc_type}

MITRE ATT&CK:
  Tactics Detected: {len(tactics_detected)}
  {chr(10).join('  - ' + t for t in tactics_detected)}

TOP SUSPICIOUS IPs:
{chr(10).join('  - ' + (ip.get('ip','') if isinstance(ip,dict) else str(ip)) for ip in susp_ips[:5])}

DISCLAIMER: AI-generated findings — require expert review before action.
"""
    st.download_button(
        "📝 Export Summary TXT",
        data=summary_txt,
        file_name=f"autosec_summary_{org_name.replace(' ','_')}.txt",
        mime="text/plain",
        use_container_width=True,
    )

with qa_col4:
    if st.button("🗑️ Clear All Data", use_container_width=True):
        keys_to_clear = [
            "threat_result", "vuln_result", "response_result",
            "report_result", "parsed_target", "security_context",
            "raw_input", "target_id",
        ]
        for k in keys_to_clear:
            st.session_state[k] = {} if k != "raw_input" else ""
        st.success("Session cleared!")
        st.rerun()

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.markdown("---")
components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@300&display=swap" rel="stylesheet">
<div style="text-align:center;padding:0.8rem 0;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.2);letter-spacing:0.15em;
                margin-bottom:4px;">
        AUTOSEC v1.0 // SOC DASHBOARD // DEFENSIVE SECURITY ONLY
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.72rem;
                color:rgba(245,240,235,0.25);">
        Dashboard refreshed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} &nbsp;|&nbsp;
        Organization: {org_name or 'Not specified'} &nbsp;|&nbsp;
        Risk Score: {risk_score}/100
    </div>
</div>
""", height=60)