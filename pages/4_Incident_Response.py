import streamlit as st
import streamlit.components.v1 as components
import json

st.set_page_config(
    page_title="Incident Response — AutoSEC",
    page_icon="🚨",
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
    background: linear-gradient(135deg, #0a0805, #0a1a0a);
    border: 1px solid rgba(34,197,94,0.2);
    border-left: 4px solid #22c55e;
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
    margin-bottom: 1rem;
}
.page-phase {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #22c55e;
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
    <div class="page-phase">PHASE 04 // INCIDENT RESPONSE</div>
    <div class="page-title">🚨 Incident Response</div>
    <div class="page-sub">
        Incident classification · NIST SP 800-61 playbook · Technical remediation guide.
        3 AI agents build your complete response plan with exact commands.
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
        Phases 2 and 3 are recommended before running Incident Response.
    </div>
</div>
""", height=90)
    st.stop()

# ---------------------------------------------------------------------------
# Run button
# ---------------------------------------------------------------------------

st.markdown("### 🚀 Run Incident Response Analysis")

threat_result = st.session_state.get("threat_result", {})
vuln_result   = st.session_state.get("vuln_result",   {})

# Show what feeds into this phase
t_sev   = threat_result.get("overall_severity", "Not run")
exp_sc  = vuln_result.get("exposure_score",    0)
inc_pri = st.session_state.get("response_result", {}).get("priority", "Not run")

components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="display:grid;grid-template-columns:repeat(3,1fr);
            gap:0.8rem;margin-bottom:1rem;">
    <div style="background:#120f0a;border:1px solid rgba(34,197,94,0.2);
                border-radius:8px;padding:0.7rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                    color:rgba(245,240,235,0.35);letter-spacing:0.1em;">
            THREAT SEVERITY
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    color:#ef4444;font-size:0.9rem;margin-top:2px;">
            {t_sev}
        </div>
    </div>
    <div style="background:#120f0a;border:1px solid rgba(34,197,94,0.2);
                border-radius:8px;padding:0.7rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                    color:rgba(245,240,235,0.35);letter-spacing:0.1em;">
            EXPOSURE SCORE
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    color:#f59e0b;font-size:0.9rem;margin-top:2px;">
            {exp_sc}/100
        </div>
    </div>
    <div style="background:#120f0a;border:1px solid rgba(34,197,94,0.2);
                border-radius:8px;padding:0.7rem 1rem;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                    color:rgba(245,240,235,0.35);letter-spacing:0.1em;">
            INCIDENT PRIORITY
        </div>
        <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                    color:#22c55e;font-size:0.9rem;margin-top:2px;">
            {inc_pri}
        </div>
    </div>
</div>
""", height=95)

run_col, _ = st.columns([1, 3])
with run_col:
    run_btn = st.button(
        "🚨 Run Incident Response",
        use_container_width=True,
        type="primary",
    )

if run_btn:
    st.markdown("---")
    st.markdown("### 🖥️ Response Execution Log")

    log_placeholder = st.empty()
    try:
        from utils.execution_log import stream_execution_log
        stream_execution_log(log_placeholder, "response", 0.1, 0.22)
    except Exception:
        with log_placeholder.container():
            st.info("Running incident response analysis...")

    with st.spinner("AI agents building response plan — 60-120 seconds..."):
        try:
            from crews.crews import run_response_crew
            result = run_response_crew(threat_result, vuln_result)
            st.session_state["response_result"] = result
        except Exception as e:
            st.error(f"Response crew error: {e}")
            st.session_state["response_result"] = {
                "incident_classification": {"raw_output": str(e)},
                "playbook":                {},
                "remediation":             {},
                "priority":                "P3",
                "incident_type":           "Unknown",
                "p1_items":                0,
                "total_remediation_items": 0,
            }
            result = st.session_state["response_result"]

    # Save to DB
    try:
        from utils.database import save_incident_response
        if st.session_state.get("target_id"):
            save_incident_response(
                st.session_state["target_id"],
                result.get("incident_type",  "Unknown"),
                result.get("priority",       "P3"),
                result.get("playbook",       {}),
                result.get("remediation",    {}),
            )
    except Exception:
        pass

    st.success("✅ Incident response plan complete!")
    st.rerun()

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

if st.session_state.get("response_result"):
    result      = st.session_state["response_result"]
    inc_class   = result.get("incident_classification", {})
    playbook    = result.get("playbook",                 {})
    remediation = result.get("remediation",              {})

    priority    = result.get("priority",      "P3")
    inc_type    = result.get("incident_type", "Unknown")
    p1_items    = result.get("p1_items",      0)
    total_rem   = result.get("total_remediation_items", 0)

    # Priority banner
    st.markdown("---")

    priority_colors = {
        "P1": "#ef4444",
        "P2": "#f97316",
        "P3": "#f59e0b",
        "P4": "#3b82f6",
    }
    priority_labels = {
        "P1": "CRITICAL — Immediate Response Required",
        "P2": "HIGH — Response Within 4 Hours",
        "P3": "MEDIUM — Response Within 24 Hours",
        "P4": "LOW — Scheduled Response",
    }
    p_color = priority_colors.get(priority, "#64748b")
    p_label = priority_labels.get(priority, "Unknown Priority")

    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:{p_color}15;border:2px solid {p_color};
            border-radius:10px;padding:1rem 1.5rem;
            display:flex;align-items:center;gap:1.5rem;
            margin-bottom:1rem;">
    <div style="text-align:center;min-width:60px;">
        <div style="font-family:'Syne',sans-serif;font-weight:800;
                    font-size:2rem;color:{p_color};">{priority}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:0.55rem;
                    color:rgba(245,240,235,0.4);">PRIORITY</div>
    </div>
    <div style="border-left:1px solid {p_color}44;padding-left:1.5rem;flex:1;">
        <div style="font-family:'Syne',sans-serif;font-weight:700;
                    font-size:1rem;color:{p_color};">{p_label}</div>
        <div style="font-family:'DM Sans',sans-serif;font-size:0.85rem;
                    color:rgba(245,240,235,0.65);margin-top:4px;">
            Incident Type: {inc_type} &nbsp;|&nbsp;
            P1 Actions: {p1_items} &nbsp;|&nbsp;
            Total Remediation Items: {total_rem}
        </div>
    </div>
</div>
""", height=110)

    st.markdown("### 📋 Response Plan")

    tab1, tab2, tab3 = st.tabs([
        "🔖 Incident Classification",
        "📖 Response Playbook",
        "🔧 Remediation Guide",
    ])

    # -------------------------------------------------------------------------
    # Tab 1 — Incident Classification
    # -------------------------------------------------------------------------
    with tab1:

        scope      = inc_class.get("incident_scope",       {})
        reg_obs    = inc_class.get("regulatory_obligations",{})
        imm_acts   = inc_class.get("immediate_actions_60min",[])
        summary    = inc_class.get("incident_summary",     "")
        rationale  = inc_class.get("classification_rationale","")
        confidence = inc_class.get("classification_confidence","")

        # Incident summary card
        if summary:
            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.15);
            border-left:4px solid {p_color};border-radius:8px;
            padding:1rem 1.2rem;margin-bottom:1rem;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
                color:rgba(245,240,235,0.35);letter-spacing:0.1em;
                margin-bottom:0.4rem;">INCIDENT SUMMARY</div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.88rem;
                color:rgba(245,240,235,0.85);line-height:1.65;">
        {summary[:500]}
    </div>
    {f'<div style="margin-top:8px;font-size:0.75rem;color:rgba(245,240,235,0.4);">Confidence: {confidence} | Rationale: {rationale[:100]}</div>' if rationale else ''}
</div>
""", height=max(120, len(summary[:500])//4 + 80))

        cls_col1, cls_col2 = st.columns(2)

        # Scope
        with cls_col1:
            st.markdown("#### 🎯 Incident Scope")

            attacker_active = scope.get("attacker_active",    False)
            data_exfil      = scope.get("data_exfiltration",  "Not Detected")
            containment     = scope.get("containment_status", "Unknown")
            spread_risk     = scope.get("spread_risk",        "Unknown")
            inc_phase       = scope.get("incident_phase",     "Unknown")

            scope_items = [
                ("Attacker Active",    str(attacker_active),
                 "#ef4444" if attacker_active else "#22c55e"),
                ("Data Exfiltration",  data_exfil,
                 "#ef4444" if "Confirm" in data_exfil else
                 "#f59e0b" if "Suspect" in data_exfil else "#22c55e"),
                ("Containment",        containment,
                 "#22c55e" if "Contained" in containment else "#ef4444"),
                ("Spread Risk",        spread_risk,
                 {"High":"#ef4444","Medium":"#f59e0b","Low":"#22c55e"}.get(
                     spread_risk,"#64748b")),
                ("Incident Phase",     inc_phase, "#0891b2"),
            ]

            scope_html = ""
            for s_label, s_val, s_color in scope_items:
                scope_html += f"""
<div style="display:flex;justify-content:space-between;align-items:center;
            padding:7px 0;border-bottom:1px solid rgba(239,68,68,0.07);">
    <span style="font-family:'DM Sans',sans-serif;font-size:0.8rem;
                 color:rgba(245,240,235,0.55);">{s_label}</span>
    <span style="font-family:'DM Sans',sans-serif;font-weight:600;
                 font-size:0.8rem;color:{s_color};">{s_val}</span>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.12);
            border-radius:8px;padding:0.9rem 1rem;">
    {scope_html}
</div>
""", height=210)

        # Regulatory
        with cls_col2:
            st.markdown("#### ⚖️ Regulatory Obligations")

            gdpr_req  = reg_obs.get("gdpr_notification_required", False)
            gdpr_dl   = reg_obs.get("gdpr_deadline",              "")
            pci_req   = reg_obs.get("pci_dss_triggered",          False)
            hipaa_req = reg_obs.get("hipaa_triggered",            False)
            le_rec    = reg_obs.get("law_enforcement_recommended", False)
            not_sum   = reg_obs.get("notification_summary",       "")

            reg_items = [
                ("GDPR 72h Notification",
                 "REQUIRED" if gdpr_req else "Not triggered",
                 "#ef4444" if gdpr_req else "#22c55e"),
                ("PCI-DSS Incident Response",
                 "TRIGGERED" if pci_req else "Not triggered",
                 "#ef4444" if pci_req else "#22c55e"),
                ("HIPAA Breach Notification",
                 "TRIGGERED" if hipaa_req else "Not triggered",
                 "#ef4444" if hipaa_req else "#22c55e"),
                ("Law Enforcement",
                 "RECOMMENDED" if le_rec else "Not recommended",
                 "#f59e0b" if le_rec else "#22c55e"),
            ]

            reg_html = ""
            for r_label, r_val, r_color in reg_items:
                reg_html += f"""
<div style="display:flex;justify-content:space-between;align-items:center;
            padding:7px 0;border-bottom:1px solid rgba(239,68,68,0.07);">
    <span style="font-family:'DM Sans',sans-serif;font-size:0.8rem;
                 color:rgba(245,240,235,0.55);">{r_label}</span>
    <span style="font-family:'DM Sans',sans-serif;font-weight:700;
                 font-size:0.75rem;color:{r_color};">{r_val}</span>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.12);
            border-radius:8px;padding:0.9rem 1rem;">
    {reg_html}
    {f'<div style="margin-top:8px;font-family:DM Sans,sans-serif;font-size:0.75rem;color:rgba(245,240,235,0.45);line-height:1.5;">{not_sum[:200]}</div>' if not_sum else ''}
</div>
""", height=230)

        # Immediate actions
        if imm_acts:
            st.markdown("#### ⚡ Immediate Actions — Next 60 Minutes")
            act_html = ""
            for i, action in enumerate(imm_acts[:8], 1):
                act_html += f"""
<div style="display:flex;gap:10px;padding:8px 0;
            border-bottom:1px solid rgba(239,68,68,0.07);">
    <div style="background:#ef4444;color:#fff;
                font-family:'JetBrains Mono',monospace;font-weight:700;
                font-size:0.7rem;min-width:24px;height:24px;
                border-radius:50%;display:flex;align-items:center;
                justify-content:center;flex-shrink:0;">{i}</div>
    <div style="font-family:'DM Sans',sans-serif;font-size:0.82rem;
                color:rgba(245,240,235,0.8);line-height:1.5;">
        {str(action)[:200]}
    </div>
</div>"""

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400&family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(239,68,68,0.15);
            border-left:4px solid #ef4444;border-radius:8px;
            padding:0.9rem 1rem;">
    {act_html}
</div>
""", height=max(100, len(imm_acts[:8]) * 50 + 20))

        with st.expander("🔧 Raw Incident Classification JSON"):
            st.json(inc_class)

    # -------------------------------------------------------------------------
    # Tab 2 — Response Playbook
    # -------------------------------------------------------------------------
    with tab2:

        pb_meta   = playbook.get("playbook_metadata", {})
        phases    = playbook.get("phases",             {})
        comm_plan = playbook.get("communication_plan", {})
        decisions = playbook.get("decision_points",    [])

        # Playbook metadata
        if pb_meta:
            duration = pb_meta.get("estimated_total_duration", "")
            team     = pb_meta.get("team_required", [])

            team_html = "".join(
                f'<span style="display:inline-block;background:rgba(8,145,178,0.12);'
                f'border:1px solid rgba(8,145,178,0.25);color:#0891b2;'
                f'font-size:0.7rem;padding:2px 8px;border-radius:4px;margin:2px;">'
                f'{t}</span>'
                for t in team
            )

            components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(8,145,178,0.2);
            border-radius:8px;padding:0.9rem 1rem;margin-bottom:1rem;">
    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:6px;">
        <div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                        color:rgba(245,240,235,0.35);">ESTIMATED DURATION</div>
            <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                        font-size:0.9rem;color:#0891b2;">{duration}</div>
        </div>
        <div style="flex:1;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                        color:rgba(245,240,235,0.35);margin-bottom:4px;">TEAM REQUIRED</div>
            <div>{team_html}</div>
        </div>
    </div>
</div>
""", height=100)

        # Phase cards
        PHASE_ORDER = [
            ("preparation",    "🛡️ Phase 1: Preparation",    "#ef4444"),
            ("identification", "🔍 Phase 2: Identification",  "#f97316"),
            ("containment",    "🔒 Phase 3: Containment",     "#f59e0b"),
            ("eradication",    "🧹 Phase 4: Eradication",     "#22c55e"),
            ("recovery",       "🔄 Phase 5: Recovery",        "#0891b2"),
            ("lessons_learned","📚 Phase 6: Lessons Learned", "#8b5cf6"),
        ]

        for phase_key, phase_title, phase_color in PHASE_ORDER:
            phase_data = phases.get(phase_key, {})
            if not phase_data:
                continue

            # Handle containment sub-phases
            if phase_key == "containment":
                short_term = phase_data.get("short_term", phase_data)
                long_term  = phase_data.get("long_term",  {})
                steps      = short_term.get("steps", [])
                lt_steps   = long_term.get("steps",  [])
                duration   = short_term.get("duration", "")
            else:
                steps    = phase_data.get("steps",    [])
                lt_steps = []
                duration = phase_data.get("duration", "")

            owner = phase_data.get("owner", "")

            steps_html = ""
            for step in steps[:6]:
                if isinstance(step, dict):
                    s_num    = step.get("step",       "")
                    s_action = step.get("action",     "")
                    s_detail = step.get("detail",     "")
                    s_owner  = step.get("owner",      "")
                    s_time   = step.get("timeline",   "")
                    s_tools  = step.get("tools_needed",[])
                else:
                    s_num    = ""
                    s_action = str(step)
                    s_detail = ""
                    s_owner  = ""
                    s_time   = ""
                    s_tools  = []

                tools_html = "".join(
                    f'<span style="background:rgba(139,92,246,0.12);'
                    f'border:1px solid rgba(139,92,246,0.2);color:#8b5cf6;'
                    f'font-size:0.6rem;padding:1px 5px;border-radius:3px;'
                    f'margin-right:3px;">{t}</span>'
                    for t in s_tools[:3]
                ) if s_tools else ""

                steps_html += f"""
<div style="background:#0a0805;border:1px solid rgba(239,68,68,0.08);
            border-radius:6px;padding:0.7rem 0.9rem;margin-bottom:0.5rem;">
    <div style="display:flex;align-items:flex-start;gap:8px;">
        <span style="background:{phase_color};color:#fff;
                     font-family:'JetBrains Mono',monospace;
                     font-size:0.65rem;font-weight:700;
                     min-width:22px;height:22px;border-radius:50%;
                     display:flex;align-items:center;justify-content:center;
                     flex-shrink:0;">{s_num}</span>
        <div style="flex:1;">
            <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                        font-size:0.83rem;color:#f5f0eb;margin-bottom:2px;">
                {s_action}
            </div>
            {f'<div style="font-size:0.77rem;color:rgba(245,240,235,0.55);margin-bottom:3px;">{s_detail[:150]}</div>' if s_detail else ''}
            <div style="display:flex;gap:8px;font-size:0.68rem;
                        color:rgba(245,240,235,0.35);flex-wrap:wrap;">
                {f'<span>Owner: {s_owner}</span>' if s_owner else ''}
                {f'<span>⏱ {s_time}</span>' if s_time else ''}
            </div>
            {f'<div style="margin-top:4px;">{tools_html}</div>' if tools_html else ''}
        </div>
    </div>
</div>"""

            with st.expander(
                f"{phase_title} — {duration} | Owner: {owner}",
                expanded=(phase_key in ("preparation","identification","containment"))
            ):
                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {phase_color}22;
            border-top:2px solid {phase_color};border-radius:8px;
            padding:0.9rem;">
    {steps_html if steps_html else '<div style="color:rgba(245,240,235,0.35);font-size:0.8rem;">No steps defined</div>'}
</div>
""", height=max(100, len(steps[:6]) * 100 + 30))

                # Long-term containment
                if lt_steps:
                    st.markdown("**Long-Term Containment:**")
                    lt_html = ""
                    for step in lt_steps[:4]:
                        if isinstance(step, dict):
                            lt_html += f"""
<div style="padding:5px 0;border-bottom:1px solid rgba(239,68,68,0.07);">
    <div style="font-family:'DM Sans',sans-serif;font-size:0.8rem;color:#f5f0eb;">
        {step.get('action','')}</div>
    <div style="font-size:0.75rem;color:rgba(245,240,235,0.5);">
        {step.get('detail','')[:100]}</div>
</div>"""
                    components.html(f"""
<div style="background:#120f0a;border:1px solid rgba(245,158,11,0.15);
            border-radius:6px;padding:0.8rem;">{lt_html}</div>
""", height=max(80, len(lt_steps[:4]) * 55 + 20))

        # Communication plan
        if comm_plan:
            st.markdown("#### 📢 Communication Plan")
            int_notif = comm_plan.get("internal_notifications", [])
            ext_notif = comm_plan.get("external_notifications", [])
            pub_comm  = comm_plan.get("public_communications",  "")

            comm_col1, comm_col2 = st.columns(2)
            with comm_col1:
                if int_notif:
                    st.markdown("**Internal:**")
                    for n in int_notif[:5]:
                        st.markdown(
                            f'<div style="font-size:0.8rem;padding:3px 0;'
                            f'color:rgba(245,240,235,0.7);">• {n}</div>',
                            unsafe_allow_html=True
                        )
            with comm_col2:
                if ext_notif:
                    st.markdown("**External:**")
                    for n in ext_notif[:5]:
                        st.markdown(
                            f'<div style="font-size:0.8rem;padding:3px 0;'
                            f'color:rgba(245,240,235,0.7);">• {n}</div>',
                            unsafe_allow_html=True
                        )

        # Decision points
        if decisions:
            st.markdown("#### 🤔 Key Decision Points")
            for dp in decisions[:4]:
                if isinstance(dp, dict):
                    d_dec  = dp.get("decision",  "")
                    d_crit = dp.get("criteria",  "")
                    d_own  = dp.get("owner",     "")
                else:
                    d_dec  = str(dp)
                    d_crit = ""
                    d_own  = ""

                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(245,158,11,0.2);
            border-left:3px solid #f59e0b;border-radius:6px;
            padding:0.7rem 0.9rem;margin-bottom:0.5rem;">
    <div style="font-family:'DM Sans',sans-serif;font-weight:600;
                font-size:0.85rem;color:#f59e0b;margin-bottom:4px;">
        ❓ {d_dec}
    </div>
    <div style="font-size:0.78rem;color:rgba(245,240,235,0.6);margin-bottom:3px;">
        {d_crit[:150]}
    </div>
    {f'<div style="font-size:0.7rem;color:rgba(245,240,235,0.35);">Owner: {d_own}</div>' if d_own else ''}
</div>
""", height=95)

        with st.expander("🔧 Raw Playbook JSON"):
            st.json(playbook)

    # -------------------------------------------------------------------------
    # Tab 3 — Remediation Guide
    # -------------------------------------------------------------------------
    with tab3:

        rem_summary = remediation.get("remediation_summary",  {})
        rem_items   = remediation.get("remediation_items",    [])
        fw_rules    = remediation.get("firewall_rules",       [])
        mon_rules   = remediation.get("monitoring_rules",     [])

        # Summary metrics
        rem_cols = st.columns(4)
        rem_metrics = [
            ("P1 Critical",     rem_summary.get("p1_critical", 0),     "#ef4444"),
            ("P2 High",         rem_summary.get("p2_high",     0),     "#f97316"),
            ("P3 Medium",       rem_summary.get("p3_medium",   0),     "#f59e0b"),
            ("Total Items",     rem_summary.get("total_items", 0),     "#64748b"),
        ]
        for col, (label, val, color) in zip(rem_cols, rem_metrics):
            with col:
                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {color}33;
            border-top:2px solid {color};border-radius:8px;
            padding:0.7rem;text-align:center;">
    <div style="font-family:'Syne',sans-serif;font-weight:800;
                font-size:1.6rem;color:{color};">{val}</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.58rem;
                color:rgba(245,240,235,0.4);margin-top:2px;">
        {label.upper()}
    </div>
</div>
""", height=78)

        # Effort estimate
        effort = rem_summary.get("estimated_total_effort", "")
        wins   = rem_summary.get("quick_wins", [])
        if wins:
            st.markdown("#### ⚡ Quick Wins (Under 30 minutes)")
            wins_html = ""
            for w in wins[:5]:
                wins_html += f"""
<div style="padding:4px 0;border-bottom:1px solid rgba(34,197,94,0.1);
            font-family:'DM Sans',sans-serif;font-size:0.8rem;
            color:rgba(245,240,235,0.75);">
    ✅ {str(w)[:120]}
</div>"""
            components.html(f"""
<div style="background:#120f0a;border:1px solid rgba(34,197,94,0.15);
            border-left:3px solid #22c55e;border-radius:8px;
            padding:0.8rem 1rem;margin-bottom:1rem;">
    {wins_html}
</div>
""", height=max(80, len(wins[:5]) * 35 + 20))

        # Remediation items
        st.markdown("#### 🔧 Remediation Steps")

        if rem_items:
            for item in rem_items[:12]:
                if not isinstance(item, dict):
                    continue

                r_id    = item.get("id",       "")
                r_title = item.get("title",    "Remediation")
                r_pri   = item.get("priority", "P3")
                r_eff   = item.get("effort",   "")
                r_risk  = item.get("risk_if_ignored", "")
                r_pre   = item.get("prerequisites",   [])
                r_steps = item.get("steps",            [])
                r_verif = item.get("verification",     {})
                r_roll  = item.get("rollback",         "")

                r_color = {
                    "P1": "#ef4444",
                    "P2": "#f97316",
                    "P3": "#f59e0b",
                    "P4": "#3b82f6",
                }.get(r_pri, "#64748b")

                # Build steps HTML
                steps_html = ""
                for step in r_steps[:6]:
                    if isinstance(step, dict):
                        s_num    = step.get("step",            "")
                        s_action = step.get("action",          "")
                        s_cmd    = step.get("command",         "")
                        s_exp    = step.get("expected_output", "")
                    else:
                        s_num    = ""
                        s_action = str(step)
                        s_cmd    = ""
                        s_exp    = ""

                    steps_html += f"""
<div style="margin-bottom:8px;">
    <div style="font-family:'DM Sans',sans-serif;font-size:0.8rem;
                color:#f5f0eb;margin-bottom:3px;">
        <span style="color:{r_color};font-weight:700;">{s_num}.</span>
        {s_action}
    </div>
    {f'<div style="background:#050402;border:1px solid rgba(34,197,94,0.2);border-radius:4px;padding:5px 8px;font-family:JetBrains Mono,monospace;font-size:0.75rem;color:#22c55e;margin:3px 0;">$ {s_cmd}</div>' if s_cmd else ''}
    {f'<div style="font-size:0.7rem;color:rgba(245,240,235,0.35);font-family:JetBrains Mono,monospace;">Expected: {s_exp[:80]}</div>' if s_exp else ''}
</div>"""

                # Verification
                verif_html = ""
                if isinstance(r_verif, dict):
                    v_cmd = r_verif.get("command",  "")
                    v_exp = r_verif.get("expected", "")
                    if v_cmd:
                        verif_html = f"""
<div style="background:rgba(8,145,178,0.08);border:1px solid rgba(8,145,178,0.2);
            border-radius:4px;padding:5px 8px;margin-top:6px;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;
                color:#0891b2;margin-bottom:2px;">VERIFY:</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.73rem;
                color:#0891b2;">$ {v_cmd}</div>
    {f'<div style="font-size:0.68rem;color:rgba(245,240,235,0.4);">Expected: {v_exp[:80]}</div>' if v_exp else ''}
</div>"""

                est_height = max(150, len(r_steps[:6]) * 80 + 80)

                with st.expander(
                    f"{r_pri} — {r_id} | {r_title} | ⏱ {r_eff}",
                    expanded=(r_pri == "P1")
                ):
                    components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700&family=DM+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid {r_color}22;
            border-top:2px solid {r_color};border-radius:8px;padding:1rem;">

    <div style="display:flex;gap:1rem;margin-bottom:10px;flex-wrap:wrap;">
        <span style="background:{r_color};color:#fff;font-weight:700;
                     font-size:0.7rem;padding:2px 8px;border-radius:4px;">
            {r_pri}
        </span>
        <span style="font-size:0.78rem;color:rgba(245,240,235,0.5);">
            ⏱ Effort: {r_eff}
        </span>
    </div>

    {f'<div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.15);border-radius:4px;padding:6px 8px;margin-bottom:8px;font-size:0.78rem;color:rgba(245,240,235,0.65);"><strong style=\'color:#ef4444;\'>Risk if ignored:</strong> {r_risk[:150]}</div>' if r_risk else ''}

    {steps_html}
    {verif_html}

    {f'<div style="margin-top:8px;font-size:0.72rem;color:rgba(245,240,235,0.35);font-family:JetBrains Mono,monospace;">Rollback: {r_roll[:100]}</div>' if r_roll else ''}
</div>
""", height=est_height)
        else:
            # Raw output fallback
            rem_raw = remediation.get("raw_output", "")
            if rem_raw:
                st.markdown("#### AI Remediation Analysis")
                st.markdown(rem_raw[:3000])

        # Firewall rules
        if fw_rules:
            st.markdown("#### 🔥 Firewall Rules to Add")
            fw_html = ""
            for rule in fw_rules[:10]:
                fw_html += f"""
<div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;
            color:#22c55e;padding:4px 0;
            border-bottom:1px solid rgba(34,197,94,0.1);">
    $ {rule}
</div>"""
            components.html(f"""
<div style="background:#050402;border:1px solid rgba(34,197,94,0.2);
            border-radius:8px;padding:0.9rem 1rem;">
    {fw_html}
</div>
""", height=max(80, len(fw_rules[:10]) * 30 + 20))

        # Monitoring rules
        if mon_rules:
            st.markdown("#### 👁️ Monitoring Rules to Create")
            for rule in mon_rules[:6]:
                if isinstance(rule, dict):
                    m_rule = rule.get("rule",           "")
                    m_impl = rule.get("implementation", "")
                else:
                    m_rule = str(rule)
                    m_impl = ""

                components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400&display=swap" rel="stylesheet">
<div style="background:#120f0a;border:1px solid rgba(8,145,178,0.2);
            border-left:3px solid #0891b2;border-radius:6px;
            padding:0.6rem 0.8rem;margin-bottom:0.4rem;">
    <div style="font-family:'DM Sans',sans-serif;font-size:0.8rem;
                color:#f5f0eb;margin-bottom:2px;">👁 {m_rule}</div>
    {f'<div style="font-size:0.72rem;color:rgba(245,240,235,0.45);">{m_impl[:100]}</div>' if m_impl else ''}
</div>
""", height=70)

        with st.expander("🔧 Raw Remediation JSON"):
            st.json(remediation)

    # Next step
    st.markdown("---")
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<div style="background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);
            border-radius:8px;padding:1rem 1.2rem;text-align:center;
            font-family:'DM Sans',sans-serif;">
    <div style="color:#22c55e;font-weight:600;font-size:0.9rem;margin-bottom:0.3rem;">
        ✅ Incident Response Plan Complete
    </div>
    <div style="color:rgba(245,240,235,0.6);font-size:0.82rem;">
        Navigate to <strong style="color:#f5f0eb;">
        📋 Security Report</strong> in the sidebar to generate
        your executive summary, technical report, and PDF.
    </div>
</div>
""", height=90)