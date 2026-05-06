import streamlit as st
import streamlit.components.v1 as components
import json

st.set_page_config(
    page_title="Threat Detection — AutoSEC",
    page_icon="🔍",
    layout="wide",
)

from utils.styles import inject_styles, show_disclaimer
inject_styles()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "parsed_target":   {},
    "security_context": {},
    "threat_result":   {},
    "threats_detected":  0,
    "critical_findings": 0,
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
.page-header {
    background: linear-gradient(135deg, #0a0805, #1a0f08);
    border: 1px solid rgba(249,115,22,0.2);
    border-left: 4px solid #f97316;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
}
.page-phase {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #f97316;
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
</style>
<div class="page-header">
    <div class="page-phase">PHASE 02 // THREAT DETECTION</div>
    <div class="page-title">🔍 Threat Detection</div>
    <div class="page-sub">
        MITRE ATT&CK mapping · IOC analysis · Behavioral anomaly detection.
        3 AI agents classify every threat indicator with severity ratings.
    </div>
</div>
""", height=130)

show_disclaimer()

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------

if not st.session_state.get("parsed_target"):
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="
    background:rgba(245,158,11,0.08);
    border:1px solid rgba(245,158,11,0.25);
    border-left:4px solid #f59e0b;
    border-radius:8px;
    padding:1.2rem 1.5rem;
    font-family:'DM Sans',sans-serif;
">
    <div style="color:#f59e0b;font-weight:700;font-size:0.9rem;margin-bottom:0.3rem;">
        ⚠ Prerequisites Not Met
    </div>
    <div style="color:rgba(245,240,235,0.7);font-size:0.85rem;">
        Please complete <strong style="color:#f5f0eb;">Phase 1: Target Intake</strong>
        first. Navigate to Target Intake in the sidebar, paste your security data,
        and run the analysis before continuing.
    </div>
</div>
""", height=100)
    st.stop()

# ---------------------------------------------------------------------------
# Run button
# ---------------------------------------------------------------------------

st.markdown("### 🚀 Run Threat Detection")

parsed  = st.session_state["parsed_target"]
context = st.session_state["security_context"]

# Show what we have
inp_type = parsed.get("input_type", "unknown")
susp_cnt = len(parsed.get("suspicious_ips", []))
pat_cnt  = len(parsed.get("suspicious_patterns", []))

components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:0.8rem;
    margin-bottom:1rem;
">
    <div style="background:#120f0a;border:1px solid rgba(249,115,22,0.2);
                border-radius:8px;padding:0.7rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                    color:rgba(245,240,235,0.35);letter-spacing:0.1em;">INPUT TYPE</div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    color:#f97316;font-size:0.9rem;margin-top:2px;">
            {inp_type.replace('_',' ').upper()}
        </div>
    </div>
    <div style="background:#120f0a;border:1px solid rgba(249,115,22,0.2);
                border-radius:8px;padding:0.7rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                    color:rgba(245,240,235,0.35);letter-spacing:0.1em;">SUSPICIOUS IPs</div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    color:#ef4444;font-size:0.9rem;margin-top:2px;">
            {susp_cnt} detected
        </div>
    </div>
    <div style="background:#120f0a;border:1px solid rgba(249,115,22,0.2);
                border-radius:8px;padding:0.7rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                    color:rgba(245,240,235,0.35);letter-spacing:0.1em;">THREAT PATTERNS</div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    color:#ef4444;font-size:0.9rem;margin-top:2px;">
            {pat_cnt} found
        </div>
    </div>
</div>
""", height=100)

run_col, _ = st.columns([1, 3])
with run_col:
    run_btn = st.button(
        "🔍 Run Threat Detection",
        use_container_width=True,
        type="primary",
    )

if run_btn:
    st.markdown("---")
    st.markdown("### 🖥️ Detection Execution Log")

    log_placeholder = st.empty()
    try:
        from utils.execution_log import stream_execution_log
        stream_execution_log(log_placeholder, "detection", 0.1, 0.22)
    except Exception:
        with log_placeholder.container():
            st.info("Running threat detection...")

    with st.spinner("AI agents analyzing threats — 60-120 seconds..."):
        try:
            from crews.crews import run_detection_crew
            result = run_detection_crew(parsed, context)
            st.session_state["threat_result"] = result

            # Update counters
            sc = result.get("severity_counts", {})
            st.session_state["threats_detected"]  += result.get("total_threats", 0)
            st.session_state["critical_findings"] += sc.get("critical", 0)

        except Exception as e:
            st.error(f"Detection crew error: {e}")
            st.session_state["threat_result"] = {
                "threat_classification": {"raw_output": str(e)},
                "ioc_analysis":          {},
                "anomaly_detection":     {},
                "severity_counts":       {},
                "overall_severity":      "Unknown",
            }

    # Save findings to DB
    try:
        from utils.database import save_threat_findings
        if st.session_state.get("target_id"):
            save_threat_findings(
                st.session_state["target_id"],
                "threat_detection",
                result.get("overall_severity", "Unknown"),
                result,
            )
    except Exception:
        pass

    st.success("✅ Threat detection complete!")
    st.rerun()

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

if st.session_state.get("threat_result"):
    result   = st.session_state["threat_result"]
    threats  = result.get("threat_classification", {})
    iocs     = result.get("ioc_analysis", {})
    anomalies= result.get("anomaly_detection", {})
    sc       = result.get("severity_counts", {})

    # Severity summary row
    st.markdown("---")
    st.markdown("### 📊 Severity Summary")

    sev_cols = st.columns(5)
    sev_data = [
        ("🔴 CRITICAL", sc.get("critical", 0), "#ef4444"),
        ("🟠 HIGH",     sc.get("high",     0), "#f97316"),
        ("🟡 MEDIUM",   sc.get("medium",   0), "#f59e0b"),
        ("🔵 LOW",      sc.get("low",      0), "#3b82f6"),
        ("⚪ INFO",     sc.get("info",     0), "#64748b"),
    ]

    for col, (label, count, color) in zip(sev_cols, sev_data):
        with col:
            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid {color}33;
    border-top:3px solid {color};
    border-radius:8px;
    padding:0.8rem;
    text-align:center;
">
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:1.8rem;color:{color};">{count}</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.45);letter-spacing:0.08em;
                margin-top:2px;">{label}</div>
</div>
""", height=90)

    st.markdown("---")
    st.markdown("### 🔬 Detection Results")

    tab1, tab2, tab3 = st.tabs([
        "⚔️ MITRE ATT&CK Mapping",
        "🎯 IOC Analysis",
        "👁️ Anomaly Report",
    ])

    # -------------------------------------------------------------------------
    # Tab 1 — MITRE ATT&CK
    # -------------------------------------------------------------------------
    with tab1:

        overall_sev     = threats.get("overall_severity", "Unknown")
        threat_summary  = threats.get("threat_summary", "")
        mitre_map       = threats.get("mitre_attack_mapping", {})
        top_threats     = threats.get("top_threats", [])

        sev_color = {
            "Critical": "#ef4444",
            "High":     "#f97316",
            "Medium":   "#f59e0b",
            "Low":      "#3b82f6",
        }.get(overall_sev, "#64748b")

        # Overall severity banner
        if overall_sev != "Unknown":
            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:rgba({','.join(str(int(sev_color.lstrip('#')[i:i+2],16)) for i in (0,2,4))},0.1);
    border:1px solid {sev_color}44;
    border-left:4px solid {sev_color};
    border-radius:8px;
    padding:0.9rem 1.2rem;
    display:flex;
    align-items:center;
    gap:1rem;
    margin-bottom:1rem;
">
    <div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                    color:rgba(245,240,235,0.4);letter-spacing:0.1em;">
            OVERALL THREAT SEVERITY
        </div>
        <div style="font-family:'Syne',sans-serif;font-weight:800;
                    font-size:1.4rem;color:{sev_color};">
            {overall_sev.upper()}
        </div>
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.85rem;
                color:rgba(245,240,235,0.7);flex:1;">
        {threat_summary[:200]}
    </div>
</div>
""", height=100)

        # MITRE tactic cards
        if mitre_map:
            st.markdown("#### ATT&CK Tactic Coverage")

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

            # Build tactic grid HTML
            tactic_cards = ""
            for tactic, color in TACTIC_COLORS.items():
                tdata    = mitre_map.get(tactic, {})
                detected = tdata.get("detected", False)
                techs    = tdata.get("techniques", [])
                tech_cnt = len(techs)

                bg_color  = f"{color}22" if detected else "rgba(245,240,235,0.03)"
                brd_color = color if detected else "rgba(245,240,235,0.08)"
                txt_color = color if detected else "rgba(245,240,235,0.25)"
                status    = f"⚡ {tech_cnt} technique{'s' if tech_cnt!=1 else ''}" \
                            if detected else "— not detected"

                tactic_cards += f"""
<div style="
    background:{bg_color};
    border:1px solid {brd_color};
    border-radius:6px;
    padding:0.6rem 0.7rem;
">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                color:{txt_color};letter-spacing:0.08em;margin-bottom:2px;">
        {'⚠' if detected else '○'} {tactic.upper()}
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.72rem;
                color:{'rgba(245,240,235,0.6)' if detected else 'rgba(245,240,235,0.2)'};
                ">
        {status}
    </div>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:0.5rem;
    margin-bottom:1rem;
">
    {tactic_cards}
</div>
""", height=360)

        # Top threats list
        if top_threats:
            st.markdown("#### 🔥 Top Threats")

            for threat in top_threats[:8]:
                sev   = threat.get("severity", "Low")
                title = threat.get("title", "Unknown Threat")
                tactic= threat.get("mitre_tactic", "")
                tech  = threat.get("mitre_technique", "")
                desc  = threat.get("description", "")
                evid  = threat.get("evidence", "")

                t_color = {
                    "Critical": "#ef4444",
                    "High":     "#f97316",
                    "Medium":   "#f59e0b",
                    "Low":      "#3b82f6",
                }.get(sev, "#64748b")

                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.12);
    border-left:3px solid {t_color};
    border-radius:8px;
    padding:0.9rem 1rem;
    margin-bottom:0.6rem;
">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="
            background:{t_color};color:#fff;
            font-family:'DM Sans',sans-serif;font-weight:700;
            font-size:0.65rem;padding:2px 7px;border-radius:3px;
            letter-spacing:0.06em;
        ">{sev.upper()}</span>
        <span style="font-family:'Syne',sans-serif;font-weight:700;
                     font-size:0.9rem;color:#f5f0eb;">{title}</span>
        <span style="
            margin-left:auto;
            background:rgba(139,92,246,0.15);
            border:1px solid rgba(139,92,246,0.25);
            color:#8b5cf6;
            font-family:'JetBrains Mono',monospace;
            font-size:0.65rem;padding:1px 6px;border-radius:3px;
        ">{tech}</span>
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.78rem;
                color:rgba(245,240,235,0.6);margin-bottom:4px;">
        {tactic} — {desc[:150]}
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                color:rgba(245,240,235,0.4);background:rgba(0,0,0,0.3);
                padding:4px 8px;border-radius:4px;">
        Evidence: {evid[:120]}
    </div>
</div>
""", height=130)

        with st.expander("🔧 Raw Threat Classification JSON"):
            st.json(threats)

    # -------------------------------------------------------------------------
    # Tab 2 — IOC Analysis
    # -------------------------------------------------------------------------
    with tab2:

        ioc_summary   = iocs.get("ioc_summary", {})
        susp_ips_list = iocs.get("suspicious_ips", [])
        mal_domains   = iocs.get("malicious_domains", [])
        susp_agents   = iocs.get("suspicious_user_agents", [])
        auth_anom     = iocs.get("auth_anomalies", [])
        susp_paths    = iocs.get("suspicious_paths", [])
        net_anom      = iocs.get("network_anomalies", [])

        # IOC summary row
        ioc_cols = st.columns(4)
        ioc_metrics = [
            ("Total IOCs",       ioc_summary.get("total_iocs",    0), "#f97316"),
            ("Critical IOCs",    ioc_summary.get("critical_iocs", 0), "#ef4444"),
            ("Suspicious IPs",   len(susp_ips_list),                  "#ef4444"),
            ("Attack Tools",     len(susp_agents),                    "#f59e0b"),
        ]
        for col, (label, val, color) in zip(ioc_cols, ioc_metrics):
            with col:
                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {color}33;
            border-top:2px solid {color};border-radius:8px;
            padding:0.7rem;text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:1.6rem;color:{color};">{val}</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                color:rgba(245,240,235,0.4);margin-top:2px;">{label.upper()}</div>
</div>
""", height=80)

        st.markdown("---")

        ioc_col1, ioc_col2 = st.columns(2)

        # Suspicious IPs
        with ioc_col1:
            st.markdown("#### 🔴 Suspicious IP Addresses")
            if susp_ips_list:
                for ip_data in susp_ips_list[:8]:
                    if isinstance(ip_data, dict):
                        ip_addr  = ip_data.get("ip",             "Unknown")
                        ip_class = ip_data.get("classification", "Unknown")
                        ip_act   = ip_data.get("activity",       "")
                        ip_sev   = ip_data.get("severity",       "Medium")
                        ip_cnt   = ip_data.get("request_count",  0)
                    else:
                        ip_addr  = str(ip_data)
                        ip_class = "Suspicious"
                        ip_act   = ""
                        ip_sev   = "Medium"
                        ip_cnt   = 0

                    s_color = {
                        "Critical": "#ef4444",
                        "High":     "#f97316",
                        "Medium":   "#f59e0b",
                        "Low":      "#3b82f6",
                    }.get(ip_sev, "#64748b")

                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.12);
    border-left:3px solid {s_color};
    border-radius:6px;
    padding:0.6rem 0.8rem;
    margin-bottom:0.5rem;
">
    <div style="display:flex;align-items:center;justify-content:space-between;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;
                     color:#f5f0eb;font-weight:500;">{ip_addr}</span>
        <span style="background:{s_color};color:#fff;font-size:0.62rem;
                     font-weight:700;padding:1px 6px;border-radius:3px;">
            {ip_sev.upper()}
        </span>
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.75rem;
                color:rgba(245,240,235,0.5);margin-top:3px;">
        {ip_class} — {ip_act[:80]}
    </div>
    {f'<div style="font-size:0.7rem;color:rgba(245,240,235,0.35);">Requests: {ip_cnt}</div>' if ip_cnt else ''}
</div>
""", height=95)
            else:
                st.info("No suspicious IPs identified.")

        # Suspicious user agents + auth anomalies
        with ioc_col2:
            st.markdown("#### 🤖 Attack Tools Detected")
            if susp_agents:
                for agent_data in susp_agents[:6]:
                    if isinstance(agent_data, dict):
                        ua_str  = agent_data.get("agent", "")
                        ua_tool = agent_data.get("tool",  "Unknown tool")
                        ua_sev  = agent_data.get("severity", "High")
                        ua_ip   = agent_data.get("source_ip", "")
                    else:
                        ua_str  = str(agent_data)
                        ua_tool = "Attack tool"
                        ua_sev  = "High"
                        ua_ip   = ""

                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid rgba(249,115,22,0.2);
    border-left:3px solid #f97316;
    border-radius:6px;
    padding:0.6rem 0.8rem;
    margin-bottom:0.5rem;
">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                color:#f97316;margin-bottom:2px;">{ua_str[:60]}</div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.75rem;
                color:rgba(245,240,235,0.6);">{ua_tool}</div>
    {f'<div style="font-size:0.7rem;color:rgba(245,240,235,0.35);">Source: {ua_ip}</div>' if ua_ip else ''}
</div>
""", height=85)
            else:
                st.info("No attack tools detected in user agents.")

            # Auth anomalies
            if auth_anom:
                st.markdown("#### 🔑 Authentication Anomalies")
                for anom in auth_anom[:4]:
                    if isinstance(anom, dict):
                        a_type = anom.get("type",       "Auth Anomaly")
                        a_ip   = anom.get("source_ip",  "")
                        a_cnt  = anom.get("attempt_count", 0)
                        a_succ = anom.get("success",    False)
                        a_sev  = anom.get("severity",   "High")
                    else:
                        a_type = str(anom)
                        a_ip   = ""
                        a_cnt  = 0
                        a_succ = False
                        a_sev  = "High"

                    a_color = "#ef4444" if a_succ else "#f59e0b"
                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:rgba(239,68,68,0.08);
    border:1px solid rgba(239,68,68,0.2);
    border-radius:6px;
    padding:0.6rem 0.8rem;
    margin-bottom:0.5rem;
    font-family:'DM Sans',sans-serif;
">
    <div style="color:{a_color};font-weight:600;font-size:0.8rem;">
        {'🚨 SUCCESS — BREACH' if a_succ else '⚠ ' + a_type}
    </div>
    <div style="font-size:0.75rem;color:rgba(245,240,235,0.55);margin-top:2px;">
        {f'IP: {a_ip}  |  ' if a_ip else ''}
        {f'Attempts: {a_cnt}' if a_cnt else ''}
    </div>
</div>
""", height=80)

        # Suspicious paths
        if susp_paths:
            st.markdown("#### 📂 Suspicious File Paths")
            paths_html = ""
            for path_data in susp_paths[:10]:
                if isinstance(path_data, dict):
                    p_path = path_data.get("path", "")
                    p_type = path_data.get("type", "")
                    p_sev  = path_data.get("severity", "High")
                    p_ip   = path_data.get("source_ip", "")
                else:
                    p_path = str(path_data)
                    p_type = "Suspicious path"
                    p_sev  = "High"
                    p_ip   = ""

                p_color = {"Critical":"#ef4444","High":"#f97316",
                           "Medium":"#f59e0b","Low":"#3b82f6"}.get(p_sev,"#64748b")
                paths_html += f"""
<div style="display:flex;align-items:center;gap:8px;padding:5px 0;
            border-bottom:1px solid rgba(239,68,68,0.07);">
    <span style="background:{p_color};color:#fff;font-size:0.6rem;
                 padding:1px 5px;border-radius:3px;font-weight:700;
                 white-space:nowrap;">{p_sev.upper()}</span>
    <span style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;
                 color:#f5f0eb;flex:1;">{p_path}</span>
    <span style="font-size:0.7rem;color:rgba(245,240,235,0.4);">{p_type}</span>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.15);
            border-radius:8px;padding:0.8rem 1rem;">
    {paths_html}
</div>
""", height=max(80, len(susp_paths[:10]) * 38 + 30))

        with st.expander("🔧 Raw IOC Analysis JSON"):
            st.json(iocs)

    # -------------------------------------------------------------------------
    # Tab 3 — Anomaly Report
    # -------------------------------------------------------------------------
    with tab3:

        anom_summary  = anomalies.get("anomaly_summary", {})
        attack_narr   = anomalies.get("attack_narrative", "")
        attack_chain  = anomalies.get("attack_chain", [])
        temp_anoms    = anomalies.get("temporal_anomalies", [])
        data_anoms    = anomalies.get("data_anomalies", [])
        app_anoms     = anomalies.get("application_anomalies", [])
        net_anoms     = anomalies.get("network_anomalies", [])
        auth_anoms2   = anomalies.get("authentication_anomalies", [])

        active_attack  = anom_summary.get("active_attack",      False)
        breach_likely  = anom_summary.get("data_breach_likely", False)
        chain_detected = anom_summary.get("attack_chain_detected", False)

        # Status banners
        banner_items = []
        if active_attack:
            banner_items.append(("🚨 ACTIVE ATTACK DETECTED", "#ef4444"))
        if breach_likely:
            banner_items.append(("💀 DATA BREACH LIKELY", "#ef4444"))
        if chain_detected:
            banner_items.append(("⛓️ ATTACK CHAIN CONFIRMED", "#f97316"))

        if banner_items:
            banners_html = "".join(f"""
<div style="
    background:{color}15;
    border:1px solid {color}44;
    border-left:4px solid {color};
    border-radius:6px;
    padding:0.6rem 1rem;
    margin-bottom:0.5rem;
    font-family:'Syne',sans-serif;
    font-weight:700;
    font-size:0.85rem;
    color:{color};
">{label}</div>""" for label, color in banner_items)

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&display=swap" rel="stylesheet">
{banners_html}
""", height=len(banner_items) * 60 + 10)

        # Attack narrative
        if attack_narr:
            st.markdown("#### 📖 Attack Narrative")
            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid rgba(245,158,11,0.2);
    border-left:4px solid #f59e0b;
    border-radius:8px;
    padding:1rem 1.2rem;
    font-family:'DM Sans',sans-serif;
    font-size:0.85rem;
    color:rgba(245,240,235,0.8);
    line-height:1.7;
">{attack_narr[:800]}</div>
""", height=max(100, len(attack_narr[:800])//4))

        # Attack chain
        if attack_chain:
            st.markdown("#### ⛓️ Attack Chain")
            chain_html = ""
            for i, step in enumerate(attack_chain[:8]):
                if isinstance(step, dict):
                    s_num    = step.get("step",    i+1)
                    s_action = step.get("action",  "")
                    s_detail = step.get("detail",  "")
                else:
                    s_num    = i+1
                    s_action = str(step)
                    s_detail = ""

                colors_chain = [
                    "#ef4444","#f97316","#f59e0b","#eab308",
                    "#84cc16","#22c55e","#0891b2","#6366f1"
                ]
                c = colors_chain[i % len(colors_chain)]

                chain_html += f"""
<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px;">
    <div style="
        background:{c};color:#fff;
        font-family:'JetBrains Mono',monospace;
        font-size:0.7rem;font-weight:700;
        min-width:24px;height:24px;
        border-radius:50%;
        display:flex;align-items:center;justify-content:center;
        flex-shrink:0;
    ">{s_num}</div>
    <div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    font-size:0.82rem;color:{c};">{s_action}</div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.75rem;
                    color:rgba(245,240,235,0.55);">{s_detail[:120]}</div>
    </div>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.15);
            border-radius:8px;padding:1rem;">
    {chain_html}
</div>
""", height=max(100, len(attack_chain[:8]) * 50 + 30))

        # Anomaly categories
        all_anom_cats = [
            ("⏰ Temporal Anomalies",     temp_anoms),
            ("💾 Data Anomalies",         data_anoms),
            ("🌐 Network Anomalies",      net_anoms),
            ("🖥️ Application Anomalies", app_anoms),
            ("🔑 Auth Anomalies",         auth_anoms2),
        ]

        for cat_title, cat_items in all_anom_cats:
            if cat_items:
                st.markdown(f"#### {cat_title}")
                for item in cat_items[:4]:
                    if isinstance(item, dict):
                        i_type   = item.get("type",   cat_title)
                        i_detail = item.get("detail", "")
                        i_sev    = item.get("severity","Medium")
                        i_evid   = item.get("evidence","")
                    else:
                        i_type   = str(item)
                        i_detail = ""
                        i_sev    = "Medium"
                        i_evid   = ""

                    i_color = {
                        "Critical":"#ef4444","High":"#f97316",
                        "Medium":"#f59e0b","Low":"#3b82f6",
                    }.get(i_sev,"#64748b")

                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.1);
            border-left:3px solid {i_color};border-radius:6px;
            padding:0.7rem 0.9rem;margin-bottom:0.5rem;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
        <span style="background:{i_color};color:#fff;font-size:0.6rem;
                     font-weight:700;padding:1px 5px;border-radius:3px;">
            {i_sev.upper()}
        </span>
        <span style="font-family:'DM Sans',sans-serif;font-weight:600;
                     font-size:0.82rem;color:#f5f0eb;">{i_type}</span>
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.78rem;
                color:rgba(245,240,235,0.6);">{i_detail[:150]}</div>
    {f'<div style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:rgba(245,240,235,0.35);margin-top:3px;">Evidence: {i_evid[:100]}</div>' if i_evid else ''}
</div>
""", height=100)

        with st.expander("🔧 Raw Anomaly Detection JSON"):
            st.json(anomalies)

    # Next step
    st.markdown("---")
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="
    background:rgba(249,115,22,0.08);
    border:1px solid rgba(249,115,22,0.2);
    border-radius:8px;
    padding:1rem 1.2rem;
    text-align:center;
    font-family:'DM Sans',sans-serif;
">
    <div style="color:#f97316;font-weight:600;font-size:0.9rem;margin-bottom:0.3rem;">
        ✅ Threat Detection Complete
    </div>
    <div style="color:rgba(245,240,235,0.6);font-size:0.82rem;">
        Navigate to <strong style="color:#f5f0eb;">
        🛡️ Vulnerability Assessment</strong>
        in the sidebar to continue.
    </div>
</div>
""", height=90)