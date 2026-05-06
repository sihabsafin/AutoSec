import streamlit as st
import streamlit.components.v1 as components

# ---------------------------------------------------------------------------
# Page config — MUST be first Streamlit call
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AutoSEC — Autonomous Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

from utils.styles import inject_styles, show_disclaimer
inject_styles()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------

DEFAULTS = {
    "raw_input":          "",
    "parsed_target":      {},
    "security_context":   {},
    "target_id":          None,
    "compliance_scope":   ["OWASP Top 10", "NIST CSF", "ISO 27001", "PCI-DSS", "GDPR"],
    "org_name":           "",
    "threat_result":      {},
    "vuln_result":        {},
    "response_result":    {},
    "report_result":      {},
    "targets_analyzed":   0,
    "threats_detected":   0,
    "critical_findings":  0,
    "reports_generated":  0,
    "pipeline_phase":     0,
}

for key, val in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = val

# ---------------------------------------------------------------------------
# Hero section
# ---------------------------------------------------------------------------

components.html("""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }
@keyframes scanline {
    0%   { transform: translateY(-100%); }
    100% { transform: translateY(400px); }
}
.hero-wrap {
    position: relative;
    background: linear-gradient(135deg, #0a0805 0%, #1a0808 50%, #0a0805 100%);
    border: 1px solid rgba(239,68,68,0.2);
    border-radius: 12px;
    padding: 2.5rem 2rem;
    overflow: hidden;
    margin-bottom: 1rem;
}
.hero-wrap::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #ef4444, #f59e0b, transparent);
    animation: pulse 3s infinite;
}
.hero-wrap::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 40px;
    background: linear-gradient(180deg, rgba(239,68,68,0.06), transparent);
    animation: scanline 4s linear infinite;
    pointer-events: none;
}
.hero-badge {
    display: inline-block;
    background: rgba(239,68,68,0.12);
    border: 1px solid rgba(239,68,68,0.3);
    color: #ef4444;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    font-weight: 500;
    padding: 3px 10px;
    border-radius: 4px;
    letter-spacing: 0.12em;
    margin-bottom: 1rem;
}
.hero-title {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 3rem;
    color: #f5f0eb;
    margin: 0.3rem 0;
    line-height: 1.1;
}
.hero-title span { color: #ef4444; }
.hero-tagline {
    font-family: 'DM Sans', sans-serif;
    font-size: 1.1rem;
    color: rgba(245,240,235,0.55);
    font-weight: 300;
    margin-top: 0.5rem;
    letter-spacing: 0.15em;
}
.hero-tagline strong { color: #f59e0b; font-weight: 500; }
.grid-bg {
    position: absolute;
    top: 0; right: 0;
    width: 300px; height: 100%;
    background-image:
        linear-gradient(rgba(239,68,68,0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(239,68,68,0.05) 1px, transparent 1px);
    background-size: 30px 30px;
    mask-image: linear-gradient(to left, rgba(0,0,0,0.4), transparent);
}
</style>

<div class="hero-wrap">
    <div class="grid-bg"></div>
    <div class="hero-badge">▶ AUTOSEC v1.0 // DEFENSIVE SECURITY PLATFORM</div>
    <div class="hero-title">Auto<span>SEC</span></div>
    <div class="hero-tagline">
        <strong>Detect.</strong> &nbsp;Analyze. &nbsp;<strong>Respond.</strong>
        &nbsp;—&nbsp; Autonomous Threat Intelligence
    </div>
</div>
""", height=200)

# ---------------------------------------------------------------------------
# Legal disclaimer
# ---------------------------------------------------------------------------

show_disclaimer()

# ---------------------------------------------------------------------------
# Stats row
# ---------------------------------------------------------------------------

def _get_stats():
    """Get stats from session state + Supabase if connected."""
    base = {
        "targets":  st.session_state["targets_analyzed"],
        "threats":  st.session_state["threats_detected"],
        "critical": st.session_state["critical_findings"],
        "reports":  st.session_state["reports_generated"],
    }
    try:
        from utils.database import get_dashboard_stats, is_connected
        if is_connected():
            db = get_dashboard_stats()
            return {
                "targets":  max(base["targets"],  db.get("targets_analyzed",  0)),
                "threats":  max(base["threats"],  db.get("threats_detected",  0)),
                "critical": max(base["critical"], db.get("critical_findings", 0)),
                "reports":  max(base["reports"],  db.get("reports_generated", 0)),
            }
    except Exception:
        pass
    return base

stats = _get_stats()

st.markdown("### 📊 Platform Statistics")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🎯 Targets Analyzed",  stats["targets"])
with col2:
    st.metric("⚠️ Threats Detected",  stats["threats"])
with col3:
    st.metric("🔴 Critical Findings", stats["critical"])
with col4:
    st.metric("📄 Reports Generated", stats["reports"])

st.markdown("---")

# ---------------------------------------------------------------------------
# Pipeline phase cards
# ---------------------------------------------------------------------------

st.markdown("### 🔄 Analysis Pipeline")

PHASES = [
    {
        "num":   "01",
        "icon":  "🎯",
        "title": "Target Intake",
        "desc":  "Parse logs, IPs, domains, Nmap scans. Build security context profile.",
        "page":  "pages/1_Target_Intake.py",
        "color": "#ef4444",
        "done":  bool(st.session_state["parsed_target"]),
    },
    {
        "num":   "02",
        "icon":  "🔍",
        "title": "Threat Detection",
        "desc":  "MITRE ATT&CK mapping. IOC analysis. Behavioral anomaly detection.",
        "page":  "pages/2_Threat_Detection.py",
        "color": "#f97316",
        "done":  bool(st.session_state["threat_result"]),
    },
    {
        "num":   "03",
        "icon":  "🛡️",
        "title": "Vulnerability Assessment",
        "desc":  "CVE mapping via NIST NVD. Attack vector analysis. Exposure scoring.",
        "page":  "pages/3_Vulnerability_Assessment.py",
        "color": "#f59e0b",
        "done":  bool(st.session_state["vuln_result"]),
    },
    {
        "num":   "04",
        "icon":  "🚨",
        "title": "Incident Response",
        "desc":  "Incident classification. Response playbook. Technical remediation guide.",
        "page":  "pages/4_Incident_Response.py",
        "color": "#22c55e",
        "done":  bool(st.session_state["response_result"]),
    },
    {
        "num":   "05",
        "icon":  "📋",
        "title": "Security Report",
        "desc":  "Executive summary. Technical report. Compliance mapping. PDF export.",
        "page":  "pages/5_Security_Report.py",
        "color": "#0891b2",
        "done":  bool(st.session_state["report_result"]),
    },
]

phase_cols = st.columns(5)

for i, (col, phase) in enumerate(zip(phase_cols, PHASES)):
    with col:
        done_indicator = "✅" if phase["done"] else "⭕"
        border_color   = phase["color"] if phase["done"] else "rgba(239,68,68,0.15)"

        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
.phase-card {{
    background: #120f0a;
    border: 1px solid {border_color};
    border-top: 3px solid {phase['color']};
    border-radius: 8px;
    padding: 1rem 0.8rem;
    height: 160px;
    transition: all 0.2s ease;
    cursor: default;
}}
.phase-num {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: {phase['color']};
    letter-spacing: 0.1em;
    margin-bottom: 0.3rem;
}}
.phase-icon {{
    font-size: 1.5rem;
    margin-bottom: 0.3rem;
}}
.phase-title {{
    font-family: 'Syne', sans-serif;
    font-weight: 700;
    font-size: 0.85rem;
    color: #f5f0eb;
    margin-bottom: 0.4rem;
}}
.phase-desc {{
    font-family: 'DM Sans', sans-serif;
    font-size: 0.7rem;
    color: rgba(245,240,235,0.5);
    line-height: 1.4;
}}
.phase-status {{
    font-size: 0.7rem;
    margin-top: 0.4rem;
}}
</style>
<div class="phase-card">
    <div class="phase-num">PHASE {phase['num']}</div>
    <div class="phase-icon">{phase['icon']}</div>
    <div class="phase-title">{phase['title']}</div>
    <div class="phase-desc">{phase['desc']}</div>
    <div class="phase-status">{done_indicator}</div>
</div>
""", height=175)

st.markdown("---")

# ---------------------------------------------------------------------------
# Navigation guide
# ---------------------------------------------------------------------------

st.markdown("### 🧭 How to Use AutoSEC")

components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
.nav-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.8rem;
}
.nav-card {
    background: #120f0a;
    border: 1px solid rgba(239,68,68,0.12);
    border-left: 3px solid #f59e0b;
    border-radius: 8px;
    padding: 0.8rem 1rem;
}
.nav-step {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #f59e0b;
    letter-spacing: 0.1em;
    margin-bottom: 0.2rem;
}
.nav-title {
    font-family: 'DM Sans', sans-serif;
    font-weight: 600;
    font-size: 0.88rem;
    color: #f5f0eb;
    margin-bottom: 0.2rem;
}
.nav-desc {
    font-family: 'DM Sans', sans-serif;
    font-size: 0.78rem;
    color: rgba(245,240,235,0.55);
    line-height: 1.4;
}
</style>
<div class="nav-grid">
    <div class="nav-card">
        <div class="nav-step">STEP 1</div>
        <div class="nav-title">→ Go to Target Intake</div>
        <div class="nav-desc">
            Paste logs, upload files, or manually enter target details.
            Supports Nmap, Apache/Nginx logs, AWS CloudTrail, firewall logs,
            Windows Event Logs, and free-text incident descriptions.
        </div>
    </div>
    <div class="nav-card">
        <div class="nav-step">STEP 2</div>
        <div class="nav-title">→ Run Threat Detection</div>
        <div class="nav-desc">
            AI agents classify threats using MITRE ATT&CK framework,
            analyze indicators of compromise, and detect behavioral anomalies.
        </div>
    </div>
    <div class="nav-card">
        <div class="nav-step">STEP 3</div>
        <div class="nav-title">→ Vulnerability Assessment</div>
        <div class="nav-desc">
            Map CVEs using NIST NVD free API. Analyze attack vectors
            and kill chains. Calculate your exposure score 0-100.
        </div>
    </div>
    <div class="nav-card">
        <div class="nav-step">STEP 4 → 5</div>
        <div class="nav-title">→ Response + Report</div>
        <div class="nav-desc">
            Generate incident response playbook, technical remediation guide,
            executive summary, compliance mapping, and downloadable PDF report.
        </div>
    </div>
</div>
""", height=220)

st.markdown("---")

# ---------------------------------------------------------------------------
# Test inputs section
# ---------------------------------------------------------------------------

st.markdown("### 🧪 Quick Test Inputs")
st.markdown(
    "Copy any of these into **Target Intake → Paste Text** to demo the system:",
    unsafe_allow_html=False
)

test_tab1, test_tab2, test_tab3 = st.tabs([
    "🌐 Web Attack Logs",
    "🔍 Nmap Scan Output",
    "🚨 Incident Description"
])

with test_tab1:
    st.code("""192.168.1.105 - - [15/Jan/2024:03:22:11 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.105 - - [15/Jan/2024:03:22:14 +0000] "POST /admin/login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.105 - - [15/Jan/2024:03:22:15 +0000] "POST /admin/login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.105 - - [15/Jan/2024:03:22:16 +0000] "POST /admin/login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0"
45.33.32.156 - - [15/Jan/2024:03:25:00 +0000] "GET /wp-admin/../../etc/passwd HTTP/1.1" 404 289 "-" "sqlmap/1.7"
45.33.32.156 - - [15/Jan/2024:03:25:01 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 0 "-" "sqlmap/1.7"
45.33.32.156 - - [15/Jan/2024:03:25:02 +0000] "GET /index.php?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 500 0 "-" "sqlmap/1.7"
10.0.0.45 - admin [15/Jan/2024:03:30:00 +0000] "GET /api/users/export?format=csv HTTP/1.1" 200 458923 "-" "python-requests/2.28"
198.51.100.77 - - [15/Jan/2024:04:15:00 +0000] "GET /shell.php HTTP/1.1" 200 145 "-" "curl/7.68.0"
198.51.100.77 - - [15/Jan/2024:04:15:03 +0000] "POST /shell.php HTTP/1.1" 200 892 "-" "curl/7.68.0"
""", language="text")

with test_tab2:
    st.code("""Nmap scan report for target.example.com (203.0.113.45)
Host is up (0.023s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 2.3.4
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu
23/tcp   open  telnet     Linux telnetd
80/tcp   open  http       Apache httpd 2.2.22
443/tcp  open  https      Apache httpd 2.2.22
3306/tcp open  mysql      MySQL 5.5.61-0+deb8u1
4444/tcp open  krb524?
8080/tcp open  http-proxy
8443/tcp open  https-alt
27017/tcp open mongodb    MongoDB 2.6.10

OS: Linux 3.x|4.x
""", language="text")

with test_tab3:
    st.code("""We noticed unusual activity on our production server at approximately 2 AM last night.
The server is running Ubuntu 20.04 with Apache 2.4, PHP 8.0, and MySQL 8.0.
Our web application is a customer portal handling credit card data (PCI-DSS scope).

Symptoms observed:
- 3 new admin accounts created (admin2, test_user, backup_admin)
- Unusual outbound connections to 185.220.101.45 and 104.21.34.67 on port 4444
- Large file transfer detected: 2.3GB sent to external IP at 03:15 AM
- Apache error logs show multiple PHP deserialization errors
- Found suspicious files: /var/www/html/images/.htaccess, /tmp/.hidden_shell.php
- Database logs show SELECT * FROM customers query run at 03:20 AM (no scheduled job)
- CPU usage spiked to 100% for 45 minutes between 03:00-03:45 AM
- Failed SSH login attempts from 185.220.101.45: 847 attempts in 12 minutes

Our team discovered this at 8 AM when reviewing overnight alerts.
We need to understand what happened and what to do next.
""", language="text")

st.markdown("---")

# ---------------------------------------------------------------------------
# Sidebar — pipeline status + navigation
# ---------------------------------------------------------------------------

with st.sidebar:
    components.html("""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
.sidebar-logo {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.6rem;
    color: #f5f0eb;
    margin-bottom: 2px;
}
.sidebar-logo span { color: #ef4444; }
.sidebar-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    color: rgba(245,240,235,0.35);
    letter-spacing: 0.1em;
    margin-bottom: 1rem;
}
.pipeline-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: rgba(245,240,235,0.4);
    letter-spacing: 0.1em;
    margin-bottom: 0.5rem;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid rgba(239,68,68,0.15);
}
</style>
<div class="sidebar-logo">Auto<span>SEC</span></div>
<div class="sidebar-sub">AUTONOMOUS SECURITY PLATFORM</div>
<div class="pipeline-label">⬡ PIPELINE STATUS</div>
""", height=100)

    phases_sidebar = [
        ("🎯 Target Intake",          bool(st.session_state["parsed_target"])),
        ("🔍 Threat Detection",       bool(st.session_state["threat_result"])),
        ("🛡️ Vulnerability Assess",  bool(st.session_state["vuln_result"])),
        ("🚨 Incident Response",      bool(st.session_state["response_result"])),
        ("📋 Security Report",        bool(st.session_state["report_result"])),
    ]

    for name, done in phases_sidebar:
        icon  = "✅" if done else "⭕"
        color = "#22c55e" if done else "rgba(245,240,235,0.35)"
        st.markdown(
            f'<div style="font-size:0.82rem;color:{color};'
            f'padding:3px 0;font-family:DM Sans,sans-serif;">'
            f'{icon} {name}</div>',
            unsafe_allow_html=True
        )

    st.markdown("---")

    # Risk score in sidebar
    if st.session_state["report_result"]:
        score = st.session_state["report_result"].get("risk_score", 0)
        color = (
            "#ef4444" if score >= 75 else
            "#f97316" if score >= 50 else
            "#f59e0b" if score >= 25 else
            "#22c55e"
        )
        label = (
            "CRITICAL" if score >= 75 else
            "HIGH"     if score >= 50 else
            "MEDIUM"   if score >= 25 else
            "LOW"
        )
        components.html(f"""
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
.risk-widget {{
    background: #120f0a;
    border: 1px solid {color}44;
    border-left: 3px solid {color};
    border-radius: 8px;
    padding: 0.8rem;
    margin-top: 0.5rem;
    text-align: center;
}}
.risk-label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.6rem;
    color: rgba(245,240,235,0.4);
    letter-spacing: 0.12em;
    margin-bottom: 4px;
}}
.risk-score {{
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 2rem;
    color: {color};
    line-height: 1;
}}
.risk-rating {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: {color};
    letter-spacing: 0.1em;
    margin-top: 2px;
}}
</style>
<div class="risk-widget">
    <div class="risk-label">OVERALL RISK SCORE</div>
    <div class="risk-score">{score}</div>
    <div class="risk-rating">/100 — {label}</div>
</div>
""", height=110)

    st.markdown("---")

    # DB status
    try:
        from utils.database import is_connected
        db_ok = is_connected()
    except Exception:
        db_ok = False

    db_color = "#22c55e" if db_ok else "#64748b"
    db_label = "Connected" if db_ok else "Not configured"
    st.markdown(
        f'<div style="font-size:0.75rem;color:{db_color};'
        f'font-family:JetBrains Mono,monospace;">'
        f'◉ Supabase: {db_label}</div>',
        unsafe_allow_html=True
    )

    # Reset button
    st.markdown("---")
    if st.button("🔄 Reset Pipeline", use_container_width=True):
        for key, val in DEFAULTS.items():
            st.session_state[key] = val
        st.rerun()

# ---------------------------------------------------------------------------
# Footer disclaimer
# ---------------------------------------------------------------------------

st.markdown("---")
components.html("""
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
.footer {
    text-align: center;
    padding: 1rem 0;
    font-family: 'DM Sans', sans-serif;
}
.footer-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: rgba(245,240,235,0.25);
    letter-spacing: 0.15em;
    margin-bottom: 0.4rem;
}
.footer-text {
    font-size: 0.75rem;
    color: rgba(245,240,235,0.3);
    line-height: 1.6;
    max-width: 700px;
    margin: 0 auto;
}
.footer-text a {
    color: rgba(239,68,68,0.6);
    text-decoration: none;
}
</style>
<div class="footer">
    <div class="footer-title">AUTOSEC // DEFENSIVE SECURITY PLATFORM // v1.0</div>
    <div class="footer-text">
        Built with CrewAI + LLaMA 3.3 70B + NIST NVD API.<br>
        For authorized security testing only. All findings are AI-generated
        and require review by a qualified security professional before any action is taken.<br>
        AutoSEC does not perform actual network scanning.
    </div>
</div>
""", height=120)