import streamlit as st
import streamlit.components.v1 as components
import json
import time

st.set_page_config(
    page_title="Target Intake — AutoSEC",
    page_icon="🎯",
    layout="wide",
)

from utils.styles import inject_styles, show_disclaimer, section_header
inject_styles()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "raw_input":        "",
    "parsed_target":    {},
    "security_context": {},
    "target_id":        None,
    "compliance_scope": ["OWASP Top 10", "NIST CSF", "ISO 27001", "PCI-DSS", "GDPR"],
    "org_name":         "",
    "target_type":      "Web Application",
    "targets_analyzed": 0,
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
    background: linear-gradient(135deg, #0a0805, #1a0808);
    border: 1px solid rgba(239,68,68,0.2);
    border-left: 4px solid #ef4444;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
}
.page-phase {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #ef4444;
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
    <div class="page-phase">PHASE 01 // TARGET INTAKE</div>
    <div class="page-title">🎯 Target Intake</div>
    <div class="page-sub">
        Parse logs, scan output, IPs, domains — build your security context profile.
        Supports Nmap, Apache/Nginx, CloudTrail, firewall logs, and free-text incidents.
    </div>
</div>
""", height=130)

show_disclaimer()

# ---------------------------------------------------------------------------
# Input section — 3 tabs
# ---------------------------------------------------------------------------

st.markdown("### 📥 Input Target Data")

tab_paste, tab_upload, tab_manual = st.tabs([
    "📋 Paste Text",
    "📁 Upload File",
    "✏️ Manual Entry",
])

raw_input = ""

# --- Tab 1: Paste Text ---
with tab_paste:
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:rgba(239,68,68,0.06);
    border:1px solid rgba(239,68,68,0.15);
    border-radius:6px;
    padding:0.6rem 1rem;
    margin-bottom:0.8rem;
    font-family:'DM Sans',sans-serif;
    font-size:0.8rem;
    color:rgba(245,240,235,0.6);
">
    💡 Paste any security data: Apache/Nginx logs, Nmap scan output,
    Windows Event Logs, CloudTrail JSON, firewall logs,
    or a free-text incident description.
</div>
""", height=60)

    paste_input = st.text_area(
        "Paste your security data here",
        height=280,
        placeholder="""Examples:
- Apache access log lines
- Nmap scan output
- Windows Event Log entries
- AWS CloudTrail JSON
- Firewall deny logs
- Free-text incident description

Paste any format — AutoSEC will detect it automatically.""",
        key="paste_input_area",
    )
    if paste_input:
        raw_input = paste_input

# --- Tab 2: Upload File ---
with tab_upload:
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:rgba(239,68,68,0.06);
    border:1px solid rgba(239,68,68,0.15);
    border-radius:6px;
    padding:0.6rem 1rem;
    margin-bottom:0.8rem;
    font-family:'DM Sans',sans-serif;
    font-size:0.8rem;
    color:rgba(245,240,235,0.6);
">
    📁 Supported formats: .txt, .log, .csv, .json, .pdf
    (PDF log files supported via PyMuPDF)
</div>
""", height=60)

    uploaded = st.file_uploader(
        "Upload log file or scan output",
        type=["txt", "log", "csv", "json", "pdf"],
        key="file_uploader",
    )
    if uploaded:
        try:
            from utils.input_parser import extract_text_from_file
            file_content = extract_text_from_file(uploaded)
            raw_input    = file_content
            st.success(
                f"✅ File loaded: **{uploaded.name}** "
                f"({len(file_content):,} characters)"
            )
            with st.expander("Preview file content (first 500 chars)"):
                st.code(file_content[:500], language="text")
        except Exception as e:
            st.error(f"File read error: {e}")

# --- Tab 3: Manual Entry ---
with tab_manual:
    col_a, col_b = st.columns(2)

    with col_a:
        manual_target = st.text_input(
            "Target Domain / IP / CIDR",
            placeholder="e.g. example.com, 192.168.1.0/24, 203.0.113.45",
            key="manual_target",
        )
        manual_type = st.selectbox(
            "Target Type",
            ["Web Application", "Network Infrastructure",
             "Endpoint / Server", "Cloud Environment", "Mixed"],
            key="manual_type",
        )
        manual_services = st.text_area(
            "Known Services & Versions",
            placeholder="e.g.\nApache 2.4.51\nOpenSSH 7.2p2\nMySQL 5.7.35\nPHP 7.4.3",
            height=120,
            key="manual_services",
        )

    with col_b:
        manual_vulns = st.text_area(
            "Known Vulnerabilities / CVEs",
            placeholder="e.g.\nCVE-2021-44228 (Log4Shell)\nCVE-2022-22965 (Spring4Shell)\nUnpatched Apache",
            height=120,
            key="manual_vulns",
        )
        manual_incident = st.text_area(
            "Incident Description",
            placeholder="Describe any suspicious activity, symptoms, or security concerns...",
            height=120,
            key="manual_incident",
        )

    if manual_target or manual_incident:
        parts = []
        if manual_target:
            parts.append(f"Target: {manual_target}")
        if manual_type:
            parts.append(f"Target Type: {manual_type}")
        if manual_services:
            parts.append(f"Known Services:\n{manual_services}")
        if manual_vulns:
            parts.append(f"Known Vulnerabilities:\n{manual_vulns}")
        if manual_incident:
            parts.append(f"Incident Description:\n{manual_incident}")
        raw_input = "\n\n".join(parts)

# ---------------------------------------------------------------------------
# Config section
# ---------------------------------------------------------------------------

st.markdown("---")
st.markdown("### ⚙️ Analysis Configuration")

cfg_col1, cfg_col2 = st.columns(2)

with cfg_col1:
    org_name = st.text_input(
        "Organization Name (optional)",
        value=st.session_state["org_name"],
        placeholder="e.g. ACME Corporation",
        key="org_name_input",
    )
    st.session_state["org_name"] = org_name

    target_type = st.selectbox(
        "Confirm Target Type",
        ["Web Application", "Network Infrastructure",
         "Endpoint / Server", "Cloud Environment", "Mixed / Unknown"],
        key="target_type_select",
    )
    st.session_state["target_type"] = target_type

with cfg_col2:
    compliance_scope = st.multiselect(
        "Compliance Frameworks to Check",
        ["OWASP Top 10", "NIST CSF", "ISO 27001",
         "PCI-DSS", "HIPAA", "GDPR", "SOC 2"],
        default=st.session_state["compliance_scope"],
        key="compliance_select",
    )
    st.session_state["compliance_scope"] = compliance_scope

# ---------------------------------------------------------------------------
# Run button
# ---------------------------------------------------------------------------

st.markdown("---")

if not raw_input:
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:rgba(239,68,68,0.06);
    border:1px solid rgba(239,68,68,0.2);
    border-radius:8px;
    padding:1rem 1.2rem;
    text-align:center;
    font-family:'DM Sans',sans-serif;
    font-size:0.85rem;
    color:rgba(245,240,235,0.5);
">
    ⬆ Paste text, upload a file, or fill in manual entry above to begin analysis
</div>
""", height=70)

else:
    # Show input preview
    with st.expander(
        f"📄 Input Preview — {len(raw_input):,} characters",
        expanded=False
    ):
        st.code(raw_input[:600] + ("..." if len(raw_input) > 600 else ""),
                language="text")

    run_col, _ = st.columns([1, 3])
    with run_col:
        run_btn = st.button(
            "🎯 Run Target Intake Analysis",
            use_container_width=True,
            type="primary",
        )

    if run_btn:
        st.markdown("---")
        st.markdown("### 🖥️ Analysis Execution Log")

        log_placeholder = st.empty()

        # Stream execution log
        try:
            from utils.execution_log import stream_execution_log
            stream_execution_log(log_placeholder, "intake", 0.1, 0.25)
        except Exception:
            with log_placeholder.container():
                st.info("Running analysis...")

        # Run local parser first (fast, no LLM)
        st.markdown("### 🔬 Parsing Input...")
        with st.spinner("Parsing target data..."):
            try:
                from utils.input_parser import parse_target_input
                local_parsed = parse_target_input(raw_input)
            except Exception as e:
                local_parsed = {"error": str(e), "raw_input": raw_input[:500]}

        # Run intake crew (LLM agents)
        with st.spinner("Running AI agents — this takes 30-90 seconds..."):
            try:
                from crews.crews import run_intake_crew
                crew_result = run_intake_crew(raw_input)
                parsed_target    = crew_result["parsed_target"]
                security_context = crew_result["security_context"]

                # Merge local parser results into crew output
                for key in ("suspicious_ips", "suspicious_patterns",
                            "open_ports", "domains", "public_ips",
                            "private_ips", "brute_force", "cve_references"):
                    if key in local_parsed and key not in parsed_target:
                        parsed_target[key] = local_parsed[key]

            except Exception as e:
                st.error(f"Crew error: {e}")
                parsed_target    = local_parsed
                security_context = {
                    "target_type":   target_type,
                    "compliance_scope": {
                        "applicable_frameworks": compliance_scope
                    },
                    "context_summary": "Context built from local parser (LLM unavailable).",
                }

        # Save to session state
        st.session_state["raw_input"]        = raw_input
        st.session_state["parsed_target"]    = parsed_target
        st.session_state["security_context"] = security_context
        st.session_state["targets_analyzed"] += 1

        # Save to Supabase
        try:
            from utils.database import save_scan_target
            tid = save_scan_target(
                raw_input[:5000],
                target_type,
                parsed_target,
                security_context,
            )
            if tid:
                st.session_state["target_id"] = tid
        except Exception:
            pass

        st.success("✅ Target intake complete! Scroll down to see results.")
        st.rerun()

# ---------------------------------------------------------------------------
# Results section
# ---------------------------------------------------------------------------

if st.session_state.get("parsed_target"):
    st.markdown("---")
    st.markdown("### 📊 Intake Results")

    parsed  = st.session_state["parsed_target"]
    context = st.session_state["security_context"]

    res_tab1, res_tab2 = st.tabs([
        "🔍 Parsed Indicators",
        "🏗️ Security Context",
    ])

    # --- Tab 1: Parsed Indicators ---
    with res_tab1:

        # Key metrics row
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            total_ips = len(parsed.get("public_ips", [])) + \
                        len(parsed.get("private_ips", []))
            st.metric("🌐 IPs Found", total_ips)
        with m2:
            st.metric("🚪 Open Ports",
                      len(parsed.get("open_ports", [])))
        with m3:
            st.metric("⚠️ Suspicious IPs",
                      len(parsed.get("suspicious_ips", [])))
        with m4:
            st.metric("🔴 Threat Patterns",
                      len(parsed.get("suspicious_patterns", [])))

        st.markdown("---")

        col_left, col_right = st.columns(2)

        # IPs
        with col_left:
            pub_ips  = parsed.get("public_ips",  [])
            priv_ips = parsed.get("private_ips", [])

            if pub_ips or priv_ips:
                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
.ind-card {{
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.15);
    border-radius:8px;
    padding:0.8rem 1rem;
    margin-bottom:0.8rem;
}}
.ind-title {{
    font-family:'Syne',sans-serif;
    font-weight:700;
    font-size:0.8rem;
    color:#f59e0b;
    margin-bottom:0.5rem;
    letter-spacing:0.05em;
}}
.ip-chip {{
    display:inline-block;
    background:rgba(239,68,68,0.1);
    border:1px solid rgba(239,68,68,0.2);
    color:#f5f0eb;
    font-family:'JetBrains Mono',monospace;
    font-size:0.72rem;
    padding:2px 8px;
    border-radius:4px;
    margin:2px;
}}
.ip-chip.priv {{
    background:rgba(59,130,246,0.1);
    border-color:rgba(59,130,246,0.2);
}}
</style>
<div class="ind-card">
    <div class="ind-title">🌐 PUBLIC IPs ({len(pub_ips)})</div>
    {''.join(f'<span class="ip-chip">{ip}</span>' for ip in pub_ips[:15])}
</div>
<div class="ind-card">
    <div class="ind-title">🔒 PRIVATE IPs ({len(priv_ips)})</div>
    {''.join(f'<span class="ip-chip priv">{ip}</span>' for ip in priv_ips[:15])}
</div>
""", height=220)

        # Suspicious patterns
        with col_right:
            patterns = parsed.get("suspicious_patterns", [])
            susp_ips = parsed.get("suspicious_ips", [])

            if patterns or susp_ips:
                pat_html = ""
                for p in patterns[:10]:
                    pat_html += f"""
<div style="
    display:flex;align-items:center;gap:8px;
    padding:4px 0;
    border-bottom:1px solid rgba(239,68,68,0.08);
    font-family:'DM Sans',sans-serif;
    font-size:0.8rem;
    color:#f5f0eb;
">
    <span style="color:#ef4444;">⚠</span> {p}
</div>"""

                susp_html = "".join(
                    f'<span style="display:inline-block;background:rgba(239,68,68,0.12);'
                    f'border:1px solid rgba(239,68,68,0.25);color:#ef4444;'
                    f'font-family:JetBrains Mono,monospace;font-size:0.7rem;'
                    f'padding:2px 8px;border-radius:4px;margin:2px;">{ip}</span>'
                    for ip in susp_ips[:10]
                )

                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<style>
.ind-card2 {{
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.15);
    border-radius:8px;
    padding:0.8rem 1rem;
    margin-bottom:0.8rem;
}}
.ind-title2 {{
    font-family:'Syne',sans-serif;
    font-weight:700;
    font-size:0.8rem;
    color:#ef4444;
    margin-bottom:0.5rem;
}}
</style>
<div class="ind-card2">
    <div class="ind-title2">🚨 THREAT PATTERNS ({len(patterns)})</div>
    {pat_html if pat_html else '<div style="color:rgba(245,240,235,0.4);font-size:0.8rem;">None detected</div>'}
</div>
<div class="ind-card2">
    <div class="ind-title2">🔴 SUSPICIOUS IPs ({len(susp_ips)})</div>
    {susp_html if susp_html else '<div style="color:rgba(245,240,235,0.4);font-size:0.8rem;">None detected</div>'}
</div>
""", height=220)

        # Open ports table
        open_ports = parsed.get("open_ports", [])
        if open_ports:
            st.markdown("#### 🚪 Open Ports")
            import pandas as pd
            ports_df = pd.DataFrame(open_ports[:20])
            st.dataframe(
                ports_df,
                use_container_width=True,
                hide_index=True,
            )

        # Brute force
        bf = parsed.get("brute_force", {})
        if bf.get("brute_force_detected"):
            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="
    background:rgba(239,68,68,0.1);
    border:1px solid rgba(239,68,68,0.35);
    border-left:4px solid #ef4444;
    border-radius:8px;
    padding:0.8rem 1.2rem;
    margin-top:0.8rem;
    font-family:'DM Sans',sans-serif;
">
    <div style="color:#ef4444;font-weight:700;font-size:0.85rem;margin-bottom:4px;">
        🚨 BRUTE FORCE DETECTED
    </div>
    <div style="color:rgba(245,240,235,0.75);font-size:0.82rem;">
        {bf.get('total_failed_attempts', 0)} failed attempts detected.
        Offending IPs: {', '.join(list(bf.get('offending_ips', {}).keys())[:5])}
    </div>
</div>
""", height=90)

        # Raw JSON toggle
        with st.expander("🔧 Raw Parsed JSON"):
            st.json(parsed)

    # --- Tab 2: Security Context ---
    with res_tab2:

        ctx_type    = context.get("target_type", "Unknown")
        ctx_summary = context.get("context_summary", "")
        ctx_risk    = context.get("initial_risk_estimate", {})
        ctx_threat  = context.get("threat_actor_profile", {})
        ctx_data    = context.get("data_sensitivity", {})
        ctx_comp    = context.get("compliance_scope", {})

        # Context summary card
        if ctx_summary:
            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid rgba(245,240,235,0.1);
    border-left:4px solid #0891b2;
    border-radius:8px;
    padding:1rem 1.2rem;
    margin-bottom:1rem;
    font-family:'DM Sans',sans-serif;
">
    <div style="color:#0891b2;font-weight:700;font-size:0.75rem;
                letter-spacing:0.08em;margin-bottom:0.4rem;">
        CONTEXT SUMMARY
    </div>
    <div style="color:#f5f0eb;font-size:0.9rem;line-height:1.6;">
        {ctx_summary}
    </div>
</div>
""", height=120)

        ctx_col1, ctx_col2 = st.columns(2)

        with ctx_col1:
            # Target type + risk
            risk_rating  = ctx_risk.get("rating", "Unknown")
            risk_urgency = ctx_risk.get("urgency", "")
            risk_color   = {
                "Critical": "#ef4444",
                "High":     "#f97316",
                "Medium":   "#f59e0b",
                "Low":      "#22c55e",
            }.get(risk_rating, "#64748b")

            risk_factors = ctx_risk.get("key_risk_factors", [])
            factors_html = "".join(
                f'<div style="padding:2px 0;font-size:0.78rem;color:rgba(245,240,235,0.7);">'
                f'• {f}</div>'
                for f in risk_factors[:5]
            )

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<style>
.ctx-card {{
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.12);
    border-radius:8px;
    padding:0.9rem 1rem;
    margin-bottom:0.8rem;
}}
.ctx-label {{
    font-family:'JetBrains Mono',monospace;
    font-size:0.62rem;
    color:rgba(245,240,235,0.35);
    letter-spacing:0.1em;
    margin-bottom:0.3rem;
}}
.ctx-value {{
    font-family:'Syne',sans-serif;
    font-weight:700;
    font-size:1rem;
    color:#f5f0eb;
}}
</style>
<div class="ctx-card">
    <div class="ctx-label">TARGET TYPE</div>
    <div class="ctx-value">{ctx_type}</div>
</div>
<div class="ctx-card" style="border-left:3px solid {risk_color};">
    <div class="ctx-label">INITIAL RISK ESTIMATE</div>
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:1.2rem;color:{risk_color};">
        {risk_rating}
    </div>
    <div style="font-size:0.75rem;color:rgba(245,240,235,0.5);margin-top:2px;">
        Urgency: {risk_urgency}
    </div>
    <div style="margin-top:6px;">{factors_html}</div>
</div>
""", height=280)

        with ctx_col2:
            # Threat actor + compliance
            actor_type   = ctx_threat.get("actor_type", "Unknown")
            actor_soph   = ctx_threat.get("sophistication", "Unknown")
            actor_motiv  = ctx_threat.get("likely_motivation", "Unknown")
            actor_evid   = ctx_threat.get("evidence", "")
            comp_frames  = ctx_comp.get("applicable_frameworks", [])
            comp_risk    = ctx_comp.get("compliance_risk", "")

            frames_html = "".join(
                f'<span style="display:inline-block;background:rgba(8,145,178,0.12);'
                f'border:1px solid rgba(8,145,178,0.25);color:#0891b2;'
                f'font-size:0.7rem;padding:2px 8px;border-radius:4px;margin:2px;">'
                f'{f}</span>'
                for f in comp_frames
            )

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<style>
.ctx-card2 {{
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.12);
    border-radius:8px;
    padding:0.9rem 1rem;
    margin-bottom:0.8rem;
}}
.ctx-label2 {{
    font-family:'JetBrains Mono',monospace;
    font-size:0.62rem;
    color:rgba(245,240,235,0.35);
    letter-spacing:0.1em;
    margin-bottom:0.4rem;
}}
</style>
<div class="ctx-card2">
    <div class="ctx-label2">THREAT ACTOR PROFILE</div>
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                color:#f59e0b;font-size:0.95rem;">
        {actor_type}
    </div>
    <div style="font-size:0.78rem;color:rgba(245,240,235,0.6);margin-top:4px;">
        Sophistication: {actor_soph} &nbsp;|&nbsp; Motivation: {actor_motiv}
    </div>
    <div style="font-size:0.75rem;color:rgba(245,240,235,0.45);margin-top:4px;">
        {actor_evid[:120]}
    </div>
</div>
<div class="ctx-card2">
    <div class="ctx-label2">COMPLIANCE SCOPE</div>
    <div style="margin-bottom:6px;">{frames_html}</div>
    <div style="font-size:0.75rem;color:rgba(245,240,235,0.5);">
        {comp_risk[:150]}
    </div>
</div>
""", height=280)

        # Data sensitivity
        data_sens  = ctx_data.get("sensitivity_level", "Unknown")
        data_types = ctx_data.get("likely_data_types", [])
        pii        = ctx_data.get("pii_likely", False)
        financial  = ctx_data.get("financial_data_likely", False)
        health     = ctx_data.get("health_data_likely", False)

        if data_types:
            flags = []
            if pii:       flags.append("🔴 PII Data")
            if financial: flags.append("🔴 Financial Data")
            if health:    flags.append("🔴 Health Data")
            flags_str = " &nbsp;|&nbsp; ".join(flags) if flags else "No sensitive data flags"

            types_html = "".join(
                f'<span style="display:inline-block;'
                f'background:rgba(239,68,68,0.08);'
                f'border:1px solid rgba(239,68,68,0.15);'
                f'color:rgba(245,240,235,0.7);'
                f'font-size:0.72rem;padding:2px 8px;'
                f'border-radius:4px;margin:2px;">{t}</span>'
                for t in data_types[:8]
            )

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="
    background:#120f0a;
    border:1px solid rgba(239,68,68,0.12);
    border-radius:8px;
    padding:0.9rem 1rem;
">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;margin-bottom:0.4rem;">
        DATA SENSITIVITY — {data_sens.upper()}
    </div>
    <div style="margin-bottom:6px;">{types_html}</div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.78rem;
                color:rgba(245,240,235,0.55);">{flags_str}</div>
</div>
""", height=110)

        with st.expander("🔧 Raw Context JSON"):
            st.json(context)

    # ---------------------------------------------------------------------------
    # Next step prompt
    # ---------------------------------------------------------------------------

    st.markdown("---")
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="
    background:rgba(239,68,68,0.08);
    border:1px solid rgba(239,68,68,0.2);
    border-radius:8px;
    padding:1rem 1.2rem;
    text-align:center;
    font-family:'DM Sans',sans-serif;
">
    <div style="color:#ef4444;font-weight:600;font-size:0.9rem;margin-bottom:0.3rem;">
        ✅ Target Intake Complete
    </div>
    <div style="color:rgba(245,240,235,0.6);font-size:0.82rem;">
        Navigate to <strong style="color:#f5f0eb;">🔍 Threat Detection</strong>
        in the sidebar to continue the analysis pipeline.
    </div>
</div>
""", height=90)