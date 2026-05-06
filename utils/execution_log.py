import time
import random
from typing import List

# ---------------------------------------------------------------------------
# Log entry builder
# ---------------------------------------------------------------------------

TAG_COLORS = {
    "SYS":     "#64748b",
    "AGENT":   "#f59e0b",
    "TASK":    "#f97316",
    "SCAN":    "#ef4444",
    "ANALYZE": "#0891b2",
    "LLM":     "#8b5cf6",
    "DONE":    "#22c55e",
    "ALERT":   "#ef4444",
    "ERROR":   "#ef4444",
    "DB":      "#0891b2",
    "INTEL":   "#6366f1",
    "REPORT":  "#a855f7",
}

def _tag_html(tag: str, blink: bool = False) -> str:
    color   = TAG_COLORS.get(tag, "#64748b")
    blink_s = "animation:blink 1s infinite;" if blink else ""
    return (
        f'<span style="'
        f'background:{color}22;'
        f'color:{color};'
        f'border:1px solid {color}44;'
        f'font-size:0.65rem;'
        f'font-weight:700;'
        f'padding:1px 6px;'
        f'border-radius:3px;'
        f'letter-spacing:0.08em;'
        f'margin-right:6px;'
        f'{blink_s}'
        f'">{tag}</span>'
    )

def _line_html(tag: str, message: str, blink: bool = False) -> str:
    ts    = time.strftime("%H:%M:%S")
    color = "#ef4444" if tag in ("ERROR", "ALERT") else "rgba(245,240,235,0.75)"
    return (
        f'<div style="'
        f'padding:3px 0;'
        f'font-family:JetBrains Mono,monospace;'
        f'font-size:0.78rem;'
        f'color:{color};'
        f'border-bottom:1px solid rgba(239,68,68,0.05);'
        f'">'
        f'<span style="color:#64748b;margin-right:10px;">{ts}</span>'
        f'{_tag_html(tag, blink)}'
        f'{message}'
        f'</div>'
    )

# ---------------------------------------------------------------------------
# Phase log message libraries
# ---------------------------------------------------------------------------

PHASE_LOGS = {
    "intake": [
        ("SYS",     "AutoSEC pipeline initializing..."),
        ("SYS",     "Loading security analysis modules"),
        ("AGENT",   "TargetParserAgent activated"),
        ("TASK",    "Parsing raw input for indicators of compromise"),
        ("SCAN",    "Extracting IP addresses and CIDR ranges"),
        ("SCAN",    "Identifying domain names and URLs"),
        ("SCAN",    "Scanning for open port references"),
        ("ANALYZE", "Detecting input format: log / scan / text"),
        ("ANALYZE", "Running pattern matching on HTTP methods"),
        ("ANALYZE", "Checking for suspicious user agents"),
        ("ALERT",   "Suspicious patterns detected in input"),
        ("AGENT",   "ContextBuilderAgent activated"),
        ("TASK",    "Building security context profile"),
        ("ANALYZE", "Assessing target type: web / network / endpoint"),
        ("ANALYZE", "Determining compliance scope"),
        ("ANALYZE", "Evaluating attack surface exposure"),
        ("LLM",     "Sending context to LLaMA 3.3 70B for analysis"),
        ("LLM",     "Model processing security indicators..."),
        ("DB",      "Persisting target data to Supabase"),
        ("DONE",    "Target intake complete — context profile ready"),
    ],

    "detection": [
        ("SYS",     "Threat Detection Crew initializing"),
        ("AGENT",   "ThreatClassifierAgent activated"),
        ("ANALYZE", "Loading MITRE ATT&CK framework v14"),
        ("TASK",    "Mapping indicators to ATT&CK tactics"),
        ("SCAN",    "Checking Initial Access vectors"),
        ("SCAN",    "Checking Execution and Persistence tactics"),
        ("SCAN",    "Checking Privilege Escalation patterns"),
        ("SCAN",    "Checking Defense Evasion techniques"),
        ("ALERT",   "Suspicious tactic chain identified"),
        ("LLM",     "LLaMA 3.3 classifying threat severity..."),
        ("AGENT",   "IOCAnalyzerAgent activated"),
        ("TASK",    "Analyzing Indicators of Compromise"),
        ("SCAN",    "Cross-referencing suspicious IPs"),
        ("SCAN",    "Checking malicious domain patterns"),
        ("ANALYZE", "Analyzing anomalous port activity"),
        ("ALERT",   "Malicious IOCs confirmed"),
        ("AGENT",   "AnomalyDetectorAgent activated"),
        ("TASK",    "Running behavioral anomaly detection"),
        ("ANALYZE", "Checking authentication failure patterns"),
        ("ANALYZE", "Detecting data exfiltration signatures"),
        ("ANALYZE", "Scanning for lateral movement indicators"),
        ("LLM",     "Model synthesizing anomaly report..."),
        ("DB",      "Saving threat findings to database"),
        ("DONE",    "Threat detection complete"),
    ],

    "vulnerability": [
        ("SYS",     "Vulnerability Assessment Crew initializing"),
        ("AGENT",   "VulnerabilityMapperAgent activated"),
        ("INTEL",   "Querying NIST NVD CVE database"),
        ("INTEL",   "Fetching CVE data for detected services"),
        ("ANALYZE", "Mapping services to known vulnerabilities"),
        ("ANALYZE", "Calculating CVSS scores"),
        ("ALERT",   "Critical CVEs identified"),
        ("LLM",     "LLaMA 3.3 assessing exploitability..."),
        ("AGENT",   "AttackVectorAnalyzerAgent activated"),
        ("TASK",    "Mapping attack paths via MITRE ATT&CK"),
        ("ANALYZE", "Identifying attack chain entry points"),
        ("ANALYZE", "Calculating likelihood and impact scores"),
        ("SCAN",    "Finding critical chokepoints in attack path"),
        ("AGENT",   "ExposureAssessorAgent activated"),
        ("TASK",    "Assessing overall attack surface"),
        ("ANALYZE", "Scoring public-facing assets"),
        ("ANALYZE", "Checking authentication weaknesses"),
        ("ANALYZE", "Evaluating encryption gaps"),
        ("LLM",     "Model computing exposure score 0-100..."),
        ("DB",      "Saving vulnerability data"),
        ("DONE",    "Vulnerability assessment complete"),
    ],

    "response": [
        ("SYS",     "Incident Response Crew initializing"),
        ("AGENT",   "IncidentClassifierAgent activated"),
        ("TASK",    "Classifying incident type and severity"),
        ("ANALYZE", "Applying NIST IR framework"),
        ("ANALYZE", "Applying SANS IR methodology"),
        ("ANALYZE", "Determining priority: P1/P2/P3/P4"),
        ("ALERT",   "Incident classification confirmed"),
        ("LLM",     "LLaMA 3.3 analyzing incident scope..."),
        ("AGENT",   "ResponsePlaybookAgent activated"),
        ("TASK",    "Generating incident response playbook"),
        ("ANALYZE", "Building Preparation phase steps"),
        ("ANALYZE", "Building Identification phase steps"),
        ("ANALYZE", "Building Containment phase steps"),
        ("ANALYZE", "Building Eradication phase steps"),
        ("ANALYZE", "Building Recovery phase steps"),
        ("ANALYZE", "Building Lessons Learned phase"),
        ("AGENT",   "RemediationAdvisorAgent activated"),
        ("TASK",    "Generating technical remediation steps"),
        ("ANALYZE", "Prioritizing fixes by CVSS and impact"),
        ("LLM",     "Model generating actionable commands..."),
        ("DB",      "Saving incident response to database"),
        ("DONE",    "Incident response playbook complete"),
    ],

    "report": [
        ("SYS",     "Security Report Crew initializing"),
        ("AGENT",   "ExecutiveReportAgent activated"),
        ("TASK",    "Writing executive summary for CISO"),
        ("ANALYZE", "Translating technical findings to business risk"),
        ("ANALYZE", "Calculating overall risk rating"),
        ("LLM",     "LLaMA 3.3 drafting executive summary..."),
        ("AGENT",   "TechnicalReportAgent activated"),
        ("TASK",    "Compiling full technical findings"),
        ("ANALYZE", "Mapping CVE references"),
        ("ANALYZE", "Documenting MITRE ATT&CK mappings"),
        ("ANALYZE", "Building remediation priority matrix"),
        ("LLM",     "Model generating technical report..."),
        ("AGENT",   "ComplianceMapperAgent activated"),
        ("TASK",    "Mapping findings to compliance frameworks"),
        ("ANALYZE", "Checking OWASP Top 10 compliance"),
        ("ANALYZE", "Checking NIST CSF compliance"),
        ("ANALYZE", "Checking PCI-DSS requirements"),
        ("ANALYZE", "Checking HIPAA / GDPR requirements"),
        ("ANALYZE", "Checking ISO 27001 controls"),
        ("LLM",     "Model finalizing compliance assessment..."),
        ("REPORT",  "Generating PDF security report"),
        ("DB",      "Saving final report to database"),
        ("DONE",    "Security report generation complete"),
    ],
}

# ---------------------------------------------------------------------------
# HTML terminal builder
# ---------------------------------------------------------------------------

TERMINAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
@keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }
.autosec-terminal {
    background: #050402;
    border: 1px solid rgba(239,68,68,0.25);
    border-top: 3px solid #ef4444;
    border-radius: 8px;
    padding: 0;
    overflow: hidden;
    font-family: 'JetBrains Mono', monospace;
}
.terminal-titlebar {
    background: #0d0a07;
    padding: 8px 12px;
    display: flex;
    align-items: center;
    gap: 6px;
    border-bottom: 1px solid rgba(239,68,68,0.15);
}
.dot { width:10px; height:10px; border-radius:50%; }
.dot-red    { background:#ef4444; }
.dot-yellow { background:#f59e0b; }
.dot-green  { background:#22c55e; }
.terminal-label {
    color: rgba(245,240,235,0.4);
    font-size: 0.7rem;
    margin-left: 8px;
    letter-spacing: 0.1em;
}
.terminal-body {
    padding: 12px 14px;
    max-height: 380px;
    overflow-y: auto;
    background: #050402;
}
.terminal-body::-webkit-scrollbar { width:4px; }
.terminal-body::-webkit-scrollbar-track { background:#050402; }
.terminal-body::-webkit-scrollbar-thumb { background:#ef444466; border-radius:2px; }
.log-line {
    animation: fadeIn 0.2s ease;
}
.cursor {
    display:inline-block;
    width:8px; height:14px;
    background:#ef4444;
    animation:blink 1s infinite;
    vertical-align:middle;
    margin-left:4px;
}
</style>
"""

def build_terminal_html(
    lines:      List[tuple],
    title:      str  = "AutoSEC // Threat Analysis Engine",
    show_cursor: bool = True,
) -> str:
    """
    Build a complete terminal HTML block.
    lines = list of (tag, message) tuples
    """
    rows = ""
    for tag, msg in lines:
        blink = tag in ("ALERT", "ERROR")
        rows += f'<div class="log-line">{_line_html(tag, msg, blink)}</div>\n'

    cursor_html = '<div style="padding:4px 0;"><span class="cursor"></span></div>' if show_cursor else ""

    return f"""
{TERMINAL_CSS}
<div class="autosec-terminal">
    <div class="terminal-titlebar">
        <div class="dot dot-red"></div>
        <div class="dot dot-yellow"></div>
        <div class="dot dot-green"></div>
        <span class="terminal-label">{title}</span>
    </div>
    <div class="terminal-body" id="terminal-body">
        {rows}
        {cursor_html}
    </div>
</div>
<script>
    var tb = document.getElementById('terminal-body');
    if(tb) tb.scrollTop = tb.scrollHeight;
</script>
"""


def build_phase_log(phase: str, extra_lines: List[tuple] = None) -> str:
    """
    Build terminal HTML for a specific pipeline phase.
    phase: 'intake' | 'detection' | 'vulnerability' | 'response' | 'report'
    """
    base_lines = PHASE_LOGS.get(phase, [("SYS", "Processing...")])
    all_lines  = list(base_lines)
    if extra_lines:
        all_lines.extend(extra_lines)

    phase_titles = {
        "intake":        "AutoSEC // Phase 1: Target Intake",
        "detection":     "AutoSEC // Phase 2: Threat Detection",
        "vulnerability": "AutoSEC // Phase 3: Vulnerability Assessment",
        "response":      "AutoSEC // Phase 4: Incident Response",
        "report":        "AutoSEC // Phase 5: Security Report",
    }
    title = phase_titles.get(phase, "AutoSEC // Analysis Engine")
    return build_terminal_html(all_lines, title=title, show_cursor=False)


def build_live_log(phase: str) -> str:
    """
    Build terminal showing logs up to current point — used with st.empty().
    Returns HTML string for components.html().
    """
    return build_phase_log(phase)


# ---------------------------------------------------------------------------
# Streamlit streaming helper
# ---------------------------------------------------------------------------

def stream_execution_log(
    placeholder,
    phase:      str,
    delay_min:  float = 0.12,
    delay_max:  float = 0.35,
):
    """
    Stream log lines one by one into a Streamlit placeholder.
    Usage:
        placeholder = st.empty()
        stream_execution_log(placeholder, "detection")
    """
    import streamlit.components.v1 as components

    lines      = PHASE_LOGS.get(phase, [("SYS", "Processing...")])
    shown      = []

    phase_titles = {
        "intake":        "AutoSEC // Phase 1: Target Intake",
        "detection":     "AutoSEC // Phase 2: Threat Detection",
        "vulnerability": "AutoSEC // Phase 3: Vulnerability Assessment",
        "response":      "AutoSEC // Phase 4: Incident Response",
        "report":        "AutoSEC // Phase 5: Security Report",
    }
    title = phase_titles.get(phase, "AutoSEC // Analysis Engine")

    for tag, msg in lines:
        shown.append((tag, msg))
        html = build_terminal_html(shown, title=title, show_cursor=True)
        with placeholder.container():
            components.html(html, height=420, scrolling=False)
        time.sleep(random.uniform(delay_min, delay_max))

    # Final state — no cursor
    final_html = build_terminal_html(shown, title=title, show_cursor=False)
    with placeholder.container():
        components.html(final_html, height=420, scrolling=False)


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    html = build_phase_log("detection")
    with open("/tmp/test_terminal.html", "w") as f:
        f.write(html)
    print("Terminal HTML written to /tmp/test_terminal.html")
    print(f"Lines in detection phase: {len(PHASE_LOGS['detection'])}")