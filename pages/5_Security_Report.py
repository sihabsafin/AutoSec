import streamlit as st
import streamlit.components.v1 as components
import json

st.set_page_config(
    page_title="Security Report — AutoSEC",
    page_icon="📋",
    layout="wide",
)

from utils.styles import inject_styles, show_disclaimer
inject_styles()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "parsed_target":    {},
    "security_context": {},
    "threat_result":    {},
    "vuln_result":      {},
    "response_result":  {},
    "report_result":    {},
    "org_name":         "",
    "compliance_scope": ["OWASP Top 10", "NIST CSF", "ISO 27001", "PCI-DSS", "GDPR"],
    "reports_generated": 0,
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
    background: linear-gradient(135deg, #0a0805, #080a1a);
    border: 1px solid rgba(8,145,178,0.2);
    border-left: 4px solid #0891b2;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
}
.page-phase {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #0891b2;
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
    <div class="page-phase">PHASE 05 // SECURITY REPORT</div>
    <div class="page-title">📋 Security Report</div>
    <div class="page-sub">
        Executive summary · Technical findings · Compliance mapping · PDF export.
        3 AI agents produce your complete security intelligence package.
    </div>
</div>
""", height=130)

show_disclaimer()

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------

if not st.session_state.get("parsed_target"):
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.25);
            border-left:4px solid #f59e0b;border-radius:8px;padding:1.2rem 1.5rem;
            font-family:'DM Sans',sans-serif;">
    <div style="color:#f59e0b;font-weight:700;font-size:0.9rem;margin-bottom:0.3rem;">
        ⚠ Prerequisites Not Met
    </div>
    <div style="color:rgba(245,240,235,0.7);font-size:0.85rem;">
        Complete <strong style="color:#f5f0eb;">Phase 1: Target Intake</strong> first.
        All previous phases recommended before generating the final report.
    </div>
</div>
""", height=90)
    st.stop()

# ---------------------------------------------------------------------------
# Run button
# ---------------------------------------------------------------------------

st.markdown("### 🚀 Generate Security Report")

threat_result   = st.session_state.get("threat_result",   {})
vuln_result     = st.session_state.get("vuln_result",     {})
response_result = st.session_state.get("response_result", {})
context         = st.session_state.get("security_context",{})
org_name        = st.session_state.get("org_name",        "Unknown Organization")
comp_scope      = st.session_state.get("compliance_scope", [])

# Pipeline status check
phases_done = {
    "Threat Detection":       bool(threat_result),
    "Vulnerability Assessment":bool(vuln_result),
    "Incident Response":       bool(response_result),
}

status_html = ""
for phase_name, done in phases_done.items():
    color = "#22c55e" if done else "#64748b"
    icon  = "✅" if done else "⭕"
    status_html += f"""
<div style="display:flex;align-items:center;gap:6px;padding:3px 0;
            font-family:'DM Sans',sans-serif;font-size:0.8rem;color:{color};">
    {icon} {phase_name}
</div>"""

components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">
    <div style="background:#120f0a;border:1px solid rgba(8,145,178,0.2);
                border-radius:8px;padding:0.9rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                    color:rgba(245,240,235,0.35);margin-bottom:6px;">
            PIPELINE STATUS
        </div>
        {status_html}
    </div>
    <div style="background:#120f0a;border:1px solid rgba(8,145,178,0.2);
                border-radius:8px;padding:0.9rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                    color:rgba(245,240,235,0.35);margin-bottom:6px;">
            REPORT CONFIGURATION
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.8rem;
                    color:rgba(245,240,235,0.7);">
            Organization: <strong style="color:#f5f0eb;">
            {org_name or 'Not specified'}</strong>
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.78rem;
                    color:rgba(245,240,235,0.5);margin-top:3px;">
            Frameworks: {', '.join(comp_scope[:3])}
            {'...' if len(comp_scope) > 3 else ''}
        </div>
    </div>
</div>
""", height=130)

run_col, _ = st.columns([1, 3])
with run_col:
    run_btn = st.button(
        "📋 Generate Security Report",
        use_container_width=True,
        type="primary",
    )

if run_btn:
    st.markdown("---")
    st.markdown("### 🖥️ Report Generation Log")

    log_placeholder = st.empty()
    try:
        from utils.execution_log import stream_execution_log
        stream_execution_log(log_placeholder, "report", 0.1, 0.22)
    except Exception:
        with log_placeholder.container():
            st.info("Generating security report...")

    with st.spinner("AI agents writing report — 60-120 seconds..."):
        try:
            from crews.crews import run_report_crew
            result = run_report_crew(
                threat_result,
                vuln_result,
                response_result,
                context,
                org_name=org_name,
                compliance_scope=comp_scope,
            )
            st.session_state["report_result"]    = result
            st.session_state["reports_generated"] += 1
        except Exception as e:
            st.error(f"Report crew error: {e}")
            st.session_state["report_result"] = {
                "executive_summary":  f"Report generation error: {e}",
                "technical_report":   f"Report generation error: {e}",
                "compliance_mapping": {},
                "risk_score":         0,
            }
            result = st.session_state["report_result"]

    # Save to DB
    try:
        from utils.database import save_security_report
        if st.session_state.get("target_id"):
            save_security_report(
                st.session_state["target_id"],
                result.get("executive_summary",  "")[:10000],
                result.get("technical_report",   "")[:10000],
                result.get("compliance_mapping", {}),
                result.get("risk_score",         0),
            )
    except Exception:
        pass

    st.success("✅ Security report generated!")
    st.rerun()

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

if st.session_state.get("report_result"):
    result     = st.session_state["report_result"]
    exec_sum   = result.get("executive_summary",  "")
    tech_rep   = result.get("technical_report",   "")
    compliance = result.get("compliance_mapping", {})
    risk_score = result.get("risk_score",         0)

    # Risk score banner
    st.markdown("---")

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
    risk_desc = (
        "Immediate action required — significant risk of breach"
        if risk_score >= 75 else
        "Urgent remediation needed within 24-72 hours"
        if risk_score >= 50 else
        "Remediation recommended within 1-2 weeks"
        if risk_score >= 25 else
        "Low risk — maintain current security posture"
    )

    pct = min(100, max(0, risk_score))

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:{risk_color}10;border:2px solid {risk_color}55;
            border-radius:12px;padding:1.2rem 1.5rem;
            display:flex;align-items:center;gap:2rem;margin-bottom:1rem;">
    <div style="text-align:center;min-width:80px;">
        <div style="font-family:'Syne',sans-serif;font-weight:800;
                    font-size:3rem;color:{risk_color};line-height:1;">
            {risk_score}
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                    color:rgba(245,240,235,0.35);margin-top:2px;">
            /100 RISK
        </div>
    </div>
    <div style="flex:1;">
        <div style="font-family:'Syne',sans-serif;font-weight:800;
                    font-size:1.3rem;color:{risk_color};">{risk_label}</div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.85rem;
                    color:rgba(245,240,235,0.65);margin:4px 0 8px;">
            {risk_desc}
        </div>
        <div style="background:rgba(0,0,0,0.3);border-radius:6px;
                    height:10px;overflow:hidden;">
            <div style="background:linear-gradient(90deg,#22c55e,#f59e0b,#ef4444);
                        width:{pct}%;height:100%;border-radius:6px;"></div>
        </div>
    </div>
    <div style="text-align:right;min-width:120px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                    color:rgba(245,240,235,0.35);margin-bottom:4px;">
            ORGANIZATION
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.85rem;
                    color:#f5f0eb;font-weight:600;">
            {org_name or 'Not specified'}
        </div>
    </div>
</div>
""", height=130)

    st.markdown("### 📊 Security Intelligence Package")

    tab1, tab2, tab3 = st.tabs([
        "👔 Executive Summary",
        "🔬 Technical Report",
        "⚖️ Compliance Mapping",
    ])

    # -------------------------------------------------------------------------
    # Tab 1 — Executive Summary
    # -------------------------------------------------------------------------
    with tab1:

        if exec_sum:
            # Parse sections from the report text
            sections = []
            current_section = {"title": "", "content": []}

            for line in exec_sum.split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("===") or line.startswith("---"):
                    continue
                if (line.isupper() and len(line) > 5) or line.startswith("##"):
                    if current_section["content"]:
                        sections.append(current_section)
                    current_section = {
                        "title":   line.lstrip("#").strip(),
                        "content": []
                    }
                else:
                    current_section["content"].append(line)

            if current_section["content"]:
                sections.append(current_section)

            if sections:
                for sec in sections:
                    title   = sec["title"]
                    content = "\n".join(sec["content"])

                    if not content.strip():
                        continue

                    # Choose card color based on section title
                    sec_color = "#0891b2"
                    title_lower = title.lower()
                    if any(w in title_lower for w in
                           ["risk", "critical", "urgent", "breach"]):
                        sec_color = "#ef4444"
                    elif any(w in title_lower for w in
                             ["impact", "business", "financial"]):
                        sec_color = "#f97316"
                    elif any(w in title_lower for w in
                             ["recommend", "action", "invest"]):
                        sec_color = "#22c55e"
                    elif any(w in title_lower for w in
                             ["timeline", "today", "week"]):
                        sec_color = "#f59e0b"

                    content_html = ""
                    for para in content.split("\n"):
                        para = para.strip()
                        if para:
                            if para.startswith("Finding") or \
                               para.startswith("Recommendation"):
                                content_html += f"""
<div style="background:rgba(0,0,0,0.2);border-radius:4px;
            padding:6px 10px;margin:4px 0;font-weight:600;
            color:#f5f0eb;">{para}</div>"""
                            else:
                                content_html += f"""
<div style="padding:3px 0;color:rgba(245,240,235,0.75);
            line-height:1.65;">{para}</div>"""

                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.12);
            border-left:4px solid {sec_color};border-radius:8px;
            padding:1rem 1.2rem;margin-bottom:0.8rem;">
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:0.9rem;color:{sec_color};
                margin-bottom:0.5rem;letter-spacing:0.03em;">
        {title}
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.85rem;">
        {content_html}
    </div>
</div>
""", height=max(100, len(content)//3 + 80))

            else:
                # Fallback — show raw text
                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(8,145,178,0.2);
            border-radius:8px;padding:1.2rem;
            font-family:'DM Sans',sans-serif;font-size:0.85rem;
            color:rgba(245,240,235,0.8);line-height:1.7;
            white-space:pre-wrap;">
{exec_sum[:3000]}
</div>
""", height=400)
        else:
            st.info("Executive summary not yet generated.")

        # Download executive summary as text
        if exec_sum:
            st.download_button(
                "📥 Download Executive Summary (.txt)",
                data=exec_sum,
                file_name=f"autosec_executive_summary_{org_name.replace(' ','_')}.txt",
                mime="text/plain",
            )

    # -------------------------------------------------------------------------
    # Tab 2 — Technical Report
    # -------------------------------------------------------------------------
    with tab2:

        if tech_rep:
            # Render with syntax highlighting for commands
            sections = []
            current  = {"title": "", "content": [], "type": "text"}

            for line in tech_rep.split("\n"):
                stripped = line.strip()
                if not stripped:
                    current["content"].append("")
                    continue

                if stripped.startswith("===") or stripped.startswith("---"):
                    continue
                elif stripped.startswith("# ") or \
                     (stripped.isupper() and len(stripped) > 5 and
                      len(stripped) < 60):
                    if current["content"]:
                        sections.append(current)
                    current = {
                        "title":   stripped.lstrip("#").strip(),
                        "content": [],
                        "type":    "header1"
                    }
                elif stripped.startswith("## ") or \
                     stripped.startswith("[CRITICAL]") or \
                     stripped.startswith("[HIGH]") or \
                     stripped.startswith("[MEDIUM]"):
                    if current["content"]:
                        sections.append(current)
                    sev = "CRITICAL" if "[CRITICAL]" in stripped else \
                          "HIGH"     if "[HIGH]"     in stripped else \
                          "MEDIUM"   if "[MEDIUM]"   in stripped else ""
                    current = {
                        "title":   stripped.lstrip("#").strip(),
                        "content": [],
                        "type":    f"finding_{sev.lower()}" if sev else "header2"
                    }
                else:
                    current["content"].append(line)

            if current["content"]:
                sections.append(current)

            for sec in sections:
                title   = sec.get("title",   "")
                content = sec.get("content", [])
                stype   = sec.get("type",    "text")

                if not any(c.strip() for c in content):
                    continue

                # Finding severity color
                if "critical" in stype:
                    border_color = "#ef4444"
                elif "high" in stype:
                    border_color = "#f97316"
                elif "medium" in stype:
                    border_color = "#f59e0b"
                elif "header" in stype:
                    border_color = "#0891b2"
                else:
                    border_color = "rgba(239,68,68,0.2)"

                content_html = ""
                for line in content:
                    stripped = line.strip()
                    if not stripped:
                        content_html += "<div style='height:4px;'></div>"
                    elif stripped.startswith("$") or \
                         stripped.startswith("sudo") or \
                         stripped.startswith("apt") or \
                         stripped.startswith("nmap") or \
                         stripped.startswith("curl"):
                        content_html += f"""
<div style="background:#050402;border:1px solid rgba(34,197,94,0.2);
            border-radius:4px;padding:5px 10px;margin:4px 0;
            font-family:'JetBrains Mono',monospace;font-size:0.75rem;
            color:#22c55e;">$ {stripped}</div>"""
                    elif stripped.startswith("CVE-"):
                        content_html += f"""
<span style="background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.25);
             color:#ef4444;font-family:'JetBrains Mono',monospace;
             font-size:0.75rem;padding:1px 6px;border-radius:3px;
             margin:2px;">{stripped}</span><br>"""
                    elif stripped.startswith("T1") and len(stripped) < 20:
                        content_html += f"""
<span style="background:rgba(139,92,246,0.12);border:1px solid rgba(139,92,246,0.25);
             color:#8b5cf6;font-family:'JetBrains Mono',monospace;
             font-size:0.75rem;padding:1px 6px;border-radius:3px;
             margin:2px;">{stripped}</span><br>"""
                    else:
                        content_html += f"""
<div style="font-family:'DM Sans',sans-serif;font-size:0.82rem;
            color:rgba(245,240,235,0.75);line-height:1.55;
            padding:2px 0;">{stripped}</div>"""

                est_height = max(80, len(content) * 18 + 60)

                if title and "header" in stype:
                    with st.expander(title, expanded=("SUMMARY" in title.upper())):
                        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#0a0805;border:1px solid {border_color}22;
            border-top:2px solid {border_color};border-radius:8px;
            padding:0.9rem;">{content_html}</div>
""", height=min(600, est_height))
                elif title:
                    with st.expander(title, expanded=("critical" in stype)):
                        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#0a0805;border:1px solid {border_color}22;
            border-left:3px solid {border_color};border-radius:8px;
            padding:0.9rem;">{content_html}</div>
""", height=min(500, est_height))
                else:
                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.1);
            border-radius:8px;padding:0.9rem;margin-bottom:0.5rem;">
    {content_html}
</div>
""", height=min(300, est_height))

        else:
            st.info("Technical report not yet generated.")

        # Download technical report
        if tech_rep:
            st.download_button(
                "📥 Download Technical Report (.txt)",
                data=tech_rep,
                file_name=f"autosec_technical_report_{org_name.replace(' ','_')}.txt",
                mime="text/plain",
            )

    # -------------------------------------------------------------------------
    # Tab 3 — Compliance Mapping
    # -------------------------------------------------------------------------
    with tab3:

        comp_summary  = compliance.get("compliance_summary",   {})
        framework_asm = compliance.get("framework_assessments",{})
        comp_roadmap  = compliance.get("compliance_roadmap",   [])
        breach_notif  = compliance.get("breach_notification_required", {})

        # Overall compliance status
        if comp_summary:
            overall_status = comp_summary.get("overall_compliance_status", "Unknown")
            crit_viol      = comp_summary.get("critical_violations",       0)
            pen_risk       = comp_summary.get("regulatory_penalty_risk",   "Unknown")
            fine_exp       = comp_summary.get("estimated_fine_exposure",   "")

            status_color = {
                "Non-Compliant": "#ef4444",
                "Partial":       "#f59e0b",
                "Compliant":     "#22c55e",
            }.get(overall_status, "#64748b")

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:{status_color}10;border:1px solid {status_color}44;
            border-radius:10px;padding:1rem 1.5rem;
            display:flex;align-items:center;gap:2rem;margin-bottom:1rem;">
    <div style="text-align:center;">
        <div style="font-family:'Syne',sans-serif;font-weight:800;
                    font-size:1.1rem;color:{status_color};">
            {overall_status.upper()}
        </div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.55rem;
                    color:rgba(245,240,235,0.35);">COMPLIANCE STATUS</div>
    </div>
    <div style="border-left:1px solid {status_color}33;padding-left:1.5rem;">
        <div style="font-size:0.8rem;color:rgba(245,240,235,0.65);">
            Critical Violations: <strong style="color:#ef4444;">{crit_viol}</strong>
            &nbsp;|&nbsp;
            Penalty Risk: <strong style="color:{status_color};">{pen_risk}</strong>
        </div>
        {f'<div style="font-size:0.78rem;color:rgba(245,240,235,0.5);margin-top:3px;">{fine_exp[:150]}</div>' if fine_exp else ''}
    </div>
</div>
""", height=100)

        # Framework assessments
        if framework_asm:
            st.markdown("#### 📊 Framework Assessment")

            # Status grid
            frame_cards_html = ""
            for fw_name, fw_data in framework_asm.items():
                if isinstance(fw_data, dict):
                    fw_status = fw_data.get("status",               "Unknown")
                    fw_pct    = fw_data.get("compliance_percentage", 0)
                    fw_viols  = fw_data.get("violations",            [])
                    fw_viol_c = len(fw_viols)
                else:
                    fw_status = str(fw_data)
                    fw_pct    = 0
                    fw_viol_c = 0

                fw_color = {
                    "Compliant":     "#22c55e",
                    "Partial":       "#f59e0b",
                    "Non-Compliant": "#ef4444",
                    "N/A":           "#64748b",
                }.get(fw_status, "#64748b")

                frame_cards_html += f"""
<div style="background:#120f0a;border:1px solid {fw_color}33;
            border-top:3px solid {fw_color};border-radius:8px;
            padding:0.9rem;text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                font-size:0.8rem;color:#f5f0eb;margin-bottom:4px;">
        {fw_name}
    </div>
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:1.1rem;color:{fw_color};margin-bottom:2px;">
        {fw_status}
    </div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;
                color:rgba(245,240,235,0.4);">{fw_pct}% compliant</div>
    <div style="background:rgba(0,0,0,0.3);border-radius:4px;
                height:5px;overflow:hidden;margin:6px 0;">
        <div style="background:{fw_color};width:{fw_pct}%;
                    height:100%;border-radius:4px;"></div>
    </div>
    <div style="font-size:0.68rem;color:rgba(245,240,235,0.35);">
        {fw_viol_c} violation(s)
    </div>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="display:grid;grid-template-columns:repeat(3,1fr);
            gap:0.7rem;margin-bottom:1rem;">
    {frame_cards_html}
</div>
""", height=220)

            # Detailed violations per framework
            st.markdown("#### 🔍 Detailed Violations")

            for fw_name, fw_data in framework_asm.items():
                if not isinstance(fw_data, dict):
                    continue

                fw_status = fw_data.get("status",     "Unknown")
                fw_viols  = fw_data.get("violations", [])
                fw_comp   = fw_data.get("compliant_controls", [])

                if not fw_viols:
                    continue

                fw_color = {
                    "Compliant":     "#22c55e",
                    "Partial":       "#f59e0b",
                    "Non-Compliant": "#ef4444",
                }.get(fw_status, "#64748b")

                with st.expander(
                    f"{fw_name} — {fw_status} — {len(fw_viols)} violation(s)",
                    expanded=(fw_status == "Non-Compliant")
                ):
                    viols_html = ""
                    for viol in fw_viols[:8]:
                        if isinstance(viol, dict):
                            v_ctrl = viol.get("control",      "")
                            v_stat = viol.get("status",       "")
                            v_find = viol.get("finding",      "")
                            v_evid = viol.get("evidence",     "")
                            v_rem  = viol.get("remediation",  "")
                            v_pri  = viol.get("priority",     "")
                        else:
                            v_ctrl = str(viol)
                            v_stat = ""
                            v_find = ""
                            v_evid = ""
                            v_rem  = ""
                            v_pri  = ""

                        v_color = {
                            "Non-Compliant": "#ef4444",
                            "Partial":       "#f59e0b",
                        }.get(v_stat, "#f97316")

                        viols_html += f"""
<div style="background:#0a0805;border:1px solid {v_color}22;
            border-left:3px solid {v_color};border-radius:6px;
            padding:0.7rem 0.9rem;margin-bottom:0.5rem;">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
        <span style="background:{v_color};color:#fff;font-size:0.62rem;
                     font-weight:700;padding:1px 6px;border-radius:3px;">
            {v_stat or 'VIOLATION'}
        </span>
        <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;
                     color:{v_color};font-weight:600;">{v_ctrl}</span>
        {f'<span style="margin-left:auto;font-size:0.65rem;color:rgba(245,240,235,0.35);">{v_pri}</span>' if v_pri else ''}
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.78rem;
                color:rgba(245,240,235,0.65);margin-bottom:3px;">
        {v_find[:150]}
    </div>
    {f'<div style="font-size:0.72rem;color:rgba(245,240,235,0.4);">Evidence: {v_evid[:100]}</div>' if v_evid else ''}
    {f'<div style="font-size:0.72rem;color:#22c55e;margin-top:3px;">Fix: {v_rem[:100]}</div>' if v_rem else ''}
</div>"""

                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {fw_color}22;
            border-radius:8px;padding:0.8rem;">
    {viols_html}
</div>
""", height=max(100, len(fw_viols[:8]) * 100 + 20))

                    if fw_comp:
                        comp_html = "".join(
                            f'<span style="display:inline-block;background:rgba(34,197,94,0.1);'
                            f'border:1px solid rgba(34,197,94,0.2);color:#22c55e;'
                            f'font-size:0.68rem;padding:1px 6px;border-radius:3px;margin:2px;">'
                            f'✅ {c}</span>'
                            for c in fw_comp[:8]
                        )
                        components.html(f"""
<div style="margin-top:8px;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:rgba(245,240,235,0.3);margin-bottom:4px;">
        COMPLIANT CONTROLS:
    </div>
    {comp_html}
</div>
""", height=60)

        # Compliance roadmap
        if comp_roadmap:
            st.markdown("#### 🗺️ Compliance Roadmap")
            for i, item in enumerate(comp_roadmap[:6], 1):
                if isinstance(item, dict):
                    r_action  = item.get("action",                "")
                    r_frames  = item.get("frameworks_addressed",  [])
                    r_time    = item.get("timeline",              "")
                    r_improve = item.get("compliance_improvement","")
                else:
                    r_action  = str(item)
                    r_frames  = []
                    r_time    = ""
                    r_improve = ""

                frames_html = "".join(
                    f'<span style="display:inline-block;background:rgba(8,145,178,0.1);'
                    f'border:1px solid rgba(8,145,178,0.2);color:#0891b2;'
                    f'font-size:0.65rem;padding:1px 5px;border-radius:3px;margin:1px;">'
                    f'{f}</span>'
                    for f in r_frames[:4]
                )

                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(8,145,178,0.15);
            border-left:3px solid #0891b2;border-radius:6px;
            padding:0.7rem 0.9rem;margin-bottom:0.5rem;
            display:flex;gap:10px;align-items:flex-start;">
    <div style="background:#0891b2;color:#fff;font-family:'Syne',sans-serif;
                font-weight:800;font-size:0.8rem;min-width:24px;height:24px;
                border-radius:50%;display:flex;align-items:center;
                justify-content:center;flex-shrink:0;">{i}</div>
    <div style="flex:1;">
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    font-size:0.85rem;color:#f5f0eb;margin-bottom:3px;">
            {r_action}
        </div>
        <div style="margin-bottom:4px;">{frames_html}</div>
        <div style="display:flex;gap:12px;font-size:0.72rem;
                    color:rgba(245,240,235,0.45);">
            {f'<span>⏱ {r_time}</span>' if r_time else ''}
            {f'<span>📈 {r_improve[:80]}</span>' if r_improve else ''}
        </div>
    </div>
</div>
""", height=95)

        # Breach notification
        if breach_notif:
            notif_items = []
            for k, v in breach_notif.items():
                if k == "details":
                    continue
                if v is True:
                    notif_items.append(k.replace("_", " ").upper())

            if notif_items:
                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.35);
            border-left:4px solid #ef4444;border-radius:8px;
            padding:0.9rem 1.2rem;margin-top:1rem;">
    <div style="font-family:'Syne',sans-serif;font-weight:700;
                color:#ef4444;font-size:0.85rem;margin-bottom:4px;">
        🚨 BREACH NOTIFICATIONS REQUIRED
    </div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.8rem;
                color:rgba(245,240,235,0.7);">
        {' | '.join(notif_items)}
    </div>
    <div style="font-size:0.75rem;color:rgba(245,240,235,0.45);margin-top:4px;">
        {breach_notif.get('details','')[:200]}
    </div>
</div>
""", height=100)

        with st.expander("🔧 Raw Compliance JSON"):
            st.json(compliance)

    # -------------------------------------------------------------------------
    # Downloads section
    # -------------------------------------------------------------------------

    st.markdown("---")
    st.markdown("### 📥 Download Reports")

    dl_col1, dl_col2, dl_col3 = st.columns(3)

    # PDF Report
    with dl_col1:
        st.markdown("#### 📄 PDF Report")
        if st.button("🔄 Generate PDF", use_container_width=True):
            with st.spinner("Building PDF report..."):
                try:
                    from utils.pdf_report import generate_pdf_report

                    # Extract findings list from vulnerability map
                    vuln_list = []
                    vm = vuln_result.get("vulnerability_map", {})
                    for v in vm.get("vulnerabilities", [])[:10]:
                        if isinstance(v, dict):
                            vuln_list.append({
                                "severity": v.get("severity", "Medium"),
                                "title":    v.get("title",    v.get("cve_id", "Unknown")),
                                "cve":      v.get("cve_id",  "N/A"),
                            })

                    # Get remediation text
                    rem_text = ""
                    rem_items = response_result.get(
                        "remediation", {}
                    ).get("remediation_items", [])
                    for item in rem_items[:5]:
                        if isinstance(item, dict):
                            rem_text += f"\n# {item.get('title','')}\n"
                            for step in item.get("steps", [])[:3]:
                                if isinstance(step, dict):
                                    rem_text += f"{step.get('action','')}\n"
                                    if step.get("command"):
                                        rem_text += f"$ {step['command']}\n"

                    pdf_bytes = generate_pdf_report(
                        target=", ".join(
                            st.session_state.get("parsed_target", {})
                            .get("targets", ["Unknown Target"])[:3]
                        ),
                        org_name=org_name or "Unknown",
                        risk_score=risk_score,
                        executive_summary=exec_sum or "Not generated",
                        technical_report=tech_rep  or "Not generated",
                        compliance_mapping=compliance,
                        findings=vuln_list,
                        remediation=rem_text,
                    )

                    st.download_button(
                        "📥 Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"autosec_report_{org_name.replace(' ','_')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                    st.success(f"PDF ready — {len(pdf_bytes):,} bytes")
                except Exception as e:
                    st.error(f"PDF generation error: {e}")

    # JSON Export
    with dl_col2:
        st.markdown("#### 📊 JSON Export")
        full_export = {
            "metadata": {
                "organization":  org_name,
                "risk_score":    risk_score,
                "generated_at":  __import__("datetime").datetime.now().isoformat(),
                "tool":          "AutoSEC v1.0",
            },
            "executive_summary":  exec_sum,
            "technical_report":   tech_rep,
            "compliance_mapping": compliance,
            "threat_findings":    threat_result,
            "vulnerability_findings": vuln_result,
            "incident_response":  response_result,
        }
        st.download_button(
            "📥 Download Full JSON Export",
            data=json.dumps(full_export, indent=2, default=str),
            file_name=f"autosec_full_export_{org_name.replace(' ','_')}.json",
            mime="application/json",
            use_container_width=True,
        )

    # Text reports
    with dl_col3:
        st.markdown("#### 📝 Text Reports")
        combined = f"""AUTOSEC SECURITY REPORT
Organization: {org_name}
Risk Score: {risk_score}/100
Generated: {__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M UTC")}

{'='*60}
EXECUTIVE SUMMARY
{'='*60}
{exec_sum}

{'='*60}
TECHNICAL REPORT
{'='*60}
{tech_rep}

{'='*60}
DISCLAIMER
{'='*60}
This report was generated by AutoSEC AI platform.
All findings require review by a qualified security professional.
Only use findings on systems you own or have permission to test.
"""
        st.download_button(
            "📥 Download Combined Report (.txt)",
            data=combined,
            file_name=f"autosec_combined_{org_name.replace(' ','_')}.txt",
            mime="text/plain",
            use_container_width=True,
        )

    # Final disclaimer
    st.markdown("---")
    show_disclaimer()

    # Next step
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:rgba(8,145,178,0.08);border:1px solid rgba(8,145,178,0.2);
            border-radius:8px;padding:1rem 1.2rem;text-align:center;
            font-family:'DM Sans',sans-serif;">
    <div style="color:#0891b2;font-weight:600;font-size:0.9rem;margin-bottom:0.3rem;">
        ✅ Security Report Complete — Full Analysis Package Ready
    </div>
    <div style="color:rgba(245,240,235,0.6);font-size:0.82rem;">
        Navigate to <strong style="color:#f5f0eb;">
        📊 Threat Dashboard</strong> in the sidebar to view
        analytics and visualizations.
    </div>
</div>
""", height=90)