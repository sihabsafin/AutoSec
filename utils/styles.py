GOOGLE_FONTS = """
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
"""

BASE_CSS = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body, .stApp {
    background-color: #0a0805 !important;
    color: #f5f0eb !important;
    font-family: 'DM Sans', sans-serif;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #0d0a07 !important;
    border-right: 1px solid rgba(239,68,68,0.2);
}

/* Hide default Streamlit header */
header[data-testid="stHeader"] { background: transparent !important; }

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #ef4444, #b91c1c) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 6px !important;
    font-family: 'DM Sans', sans-serif !important;
    font-weight: 500 !important;
    padding: 0.5rem 1.5rem !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #f97316, #ef4444) !important;
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(239,68,68,0.4) !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background: #120f0a !important;
    border-bottom: 1px solid rgba(239,68,68,0.2) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    color: rgba(245,240,235,0.5) !important;
    font-family: 'DM Sans', sans-serif !important;
    font-weight: 500 !important;
    border-bottom: 2px solid transparent !important;
    padding: 0.6rem 1.2rem !important;
}
.stTabs [aria-selected="true"] {
    color: #ef4444 !important;
    border-bottom: 2px solid #ef4444 !important;
    background: transparent !important;
}

/* Inputs */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea {
    background: #1a1510 !important;
    border: 1px solid rgba(239,68,68,0.25) !important;
    color: #f5f0eb !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #ef4444 !important;
    box-shadow: 0 0 0 2px rgba(239,68,68,0.15) !important;
}

/* Selectbox */
.stSelectbox > div > div {
    background: #1a1510 !important;
    border: 1px solid rgba(239,68,68,0.25) !important;
    color: #f5f0eb !important;
    border-radius: 6px !important;
}

/* Multiselect */
.stMultiSelect > div > div {
    background: #1a1510 !important;
    border: 1px solid rgba(239,68,68,0.25) !important;
    color: #f5f0eb !important;
    border-radius: 6px !important;
}

/* File uploader */
.stFileUploader > div {
    background: #120f0a !important;
    border: 1px dashed rgba(239,68,68,0.3) !important;
    border-radius: 8px !important;
}

/* Metrics */
[data-testid="stMetric"] {
    background: #120f0a !important;
    border: 1px solid rgba(239,68,68,0.15) !important;
    border-radius: 8px !important;
    padding: 1rem !important;
}
[data-testid="stMetricValue"] {
    color: #ef4444 !important;
    font-family: 'Syne', sans-serif !important;
    font-weight: 700 !important;
}

/* Dataframes */
.stDataFrame {
    border: 1px solid rgba(239,68,68,0.2) !important;
    border-radius: 8px !important;
    overflow: hidden !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0805; }
::-webkit-scrollbar-thumb { background: rgba(239,68,68,0.4); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #ef4444; }
</style>
"""

DISCLAIMER_HTML = """
<div style="
    background: rgba(239,68,68,0.08);
    border-left: 4px solid #ef4444;
    border-radius: 0 8px 8px 0;
    padding: 1rem 1.2rem;
    margin: 1rem 0;
    font-family: 'DM Sans', sans-serif;
">
    <div style="color:#ef4444; font-weight:700; font-size:0.8rem; letter-spacing:0.1em; margin-bottom:0.4rem;">
        ⚠ AUTHORIZED USE ONLY
    </div>
    <div style="color:rgba(245,240,235,0.75); font-size:0.82rem; line-height:1.6;">
        AutoSEC is a <strong style="color:#f5f0eb;">defensive security research tool</strong> for authorized testing only.
        Only use on systems you <strong style="color:#f5f0eb;">own or have explicit written permission</strong> to test.
        Unauthorized scanning is illegal under CFAA, Computer Misuse Act, and similar laws.
        All findings are <strong style="color:#f5f0eb;">AI-generated</strong> and require review by a qualified security professional before any action.
        AutoSEC does <strong style="color:#f5f0eb;">not</strong> perform actual network scanning.
    </div>
</div>
"""

SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#ef4444", "text": "#fff"},
    "HIGH":     {"bg": "#f97316", "text": "#fff"},
    "MEDIUM":   {"bg": "#f59e0b", "text": "#000"},
    "LOW":      {"bg": "#3b82f6", "text": "#fff"},
    "INFO":     {"bg": "#94a3b8", "text": "#000"},
}

MITRE_TACTIC_COLORS = {
    "Initial Access":        "#ef4444",
    "Execution":             "#f97316",
    "Persistence":           "#f59e0b",
    "Privilege Escalation":  "#eab308",
    "Defense Evasion":       "#84cc16",
    "Credential Access":     "#22c55e",
    "Discovery":             "#0891b2",
    "Lateral Movement":      "#6366f1",
    "Collection":            "#8b5cf6",
    "Exfiltration":          "#a855f7",
    "Command and Control":   "#ec4899",
    "Impact":                "#f43f5e",
}

def severity_badge(severity: str) -> str:
    s = severity.upper()
    c = SEVERITY_COLORS.get(s, {"bg": "#64748b", "text": "#fff"})
    return f"""<span style="
        background:{c['bg']};
        color:{c['text']};
        font-family:'DM Sans',sans-serif;
        font-size:0.7rem;
        font-weight:700;
        padding:2px 8px;
        border-radius:4px;
        letter-spacing:0.05em;
    ">{s}</span>"""

def priority_badge(priority: str) -> str:
    colors = {
        "P1": "#ef4444", "P2": "#f97316",
        "P3": "#f59e0b", "P4": "#3b82f6"
    }
    p = priority.upper()
    color = colors.get(p, "#64748b")
    return f"""<span style="
        background:{color};
        color:#fff;
        font-family:'Syne',sans-serif;
        font-size:0.75rem;
        font-weight:700;
        padding:3px 10px;
        border-radius:4px;
        letter-spacing:0.08em;
    ">{p} {'CRITICAL' if p=='P1' else 'HIGH' if p=='P2' else 'MEDIUM' if p=='P3' else 'LOW'}</span>"""

def card_html(title: str, content: str, border_color: str = "#ef4444") -> str:
    return f"""
    <div style="
        background:#120f0a;
        border:1px solid rgba(239,68,68,0.15);
        border-left:3px solid {border_color};
        border-radius:8px;
        padding:1rem 1.2rem;
        margin-bottom:0.8rem;
        font-family:'DM Sans',sans-serif;
    ">
        <div style="color:#f5f0eb;font-weight:600;margin-bottom:0.4rem;font-size:0.95rem;">
            {title}
        </div>
        <div style="color:rgba(245,240,235,0.7);font-size:0.85rem;line-height:1.6;">
            {content}
        </div>
    </div>"""

def section_header(title: str, subtitle: str = "") -> str:
    sub = f'<div style="color:rgba(245,240,235,0.5);font-size:0.85rem;margin-top:0.3rem;">{subtitle}</div>' if subtitle else ""
    return f"""
    <div style="margin-bottom:1.5rem;">
        <h2 style="
            font-family:'Syne',sans-serif;
            font-weight:800;
            font-size:1.4rem;
            color:#f5f0eb;
            margin:0;
        ">{title}</h2>
        {sub}
    </div>"""

def inject_styles():
    import streamlit as st
    st.markdown(GOOGLE_FONTS + BASE_CSS, unsafe_allow_html=True)

def show_disclaimer():
    import streamlit as st
    import streamlit.components.v1 as components
    components.html(DISCLAIMER_HTML, height=110)