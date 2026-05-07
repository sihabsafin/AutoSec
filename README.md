

```markdown
# AutoSEC

Autonomous cybersecurity threat detection and response system built on CrewAI multi-agent orchestration. Feed it a log file, Nmap scan, or incident description — it returns a complete security intelligence package in minutes.

**This is a defensive security tool.** Only use on systems you own or have explicit written permission to test.

---

## What it does

AutoSEC runs a 5-phase pipeline across 13 specialized AI agents:

```
Input (logs / scan / description)
    ↓
Phase 1 — Target Intake        Parse indicators, build security context
    ↓
Phase 2 — Threat Detection     MITRE ATT&CK mapping, IOC analysis, anomaly detection
    ↓
Phase 3 — Vulnerability Assessment   CVE mapping via NIST NVD, attack vectors, exposure score
    ↓
Phase 4 — Incident Response    Priority classification, NIST playbook, remediation with commands
    ↓
Phase 5 — Security Report      Executive summary, technical report, compliance mapping, PDF
```

Input formats supported:
- Apache / Nginx access logs
- Nmap scan output (text)
- Windows Event Logs
- AWS CloudTrail JSON
- Firewall / iptables logs
- Free-text incident descriptions
- IP lists, CIDR ranges, domain names

Output delivered:
- MITRE ATT&CK tactic coverage with technique IDs
- IOC table (suspicious IPs, attack tools, malicious paths)
- CVE findings with CVSS scores pulled live from NIST NVD
- Attack chain reconstruction (step-by-step kill chain)
- Exposure score 0–100
- Incident priority (P1–P4) with regulatory notification assessment
- NIST SP 800-61 response playbook with exact commands
- Executive summary (non-technical, business risk language)
- Compliance gap analysis: OWASP, NIST CSF, PCI-DSS, HIPAA, GDPR, ISO 27001
- Downloadable PDF, JSON export, and text reports

---

## Stack

| Layer | Technology |
|---|---|
| Agent framework | CrewAI 1.x |
| Primary LLM | Groq — LLaMA 3.3 70B (14,400 req/day free) |
| Fallback LLM | Google Gemini 2.0 Flash (1,500 req/day free) |
| Threat intelligence | NIST NVD CVE API (free, no key required) |
| Frontend | Streamlit |
| Database | Supabase PostgreSQL |
| PDF generation | ReportLab |
| Hosting | Streamlit Community Cloud |
| Monthly cost | $0 |

---

## Project structure

```
autosec/
├── app.py                        # Main SOC dashboard
├── config.py                     # LLM setup, secrets handling
├── requirements.txt
├── packages.txt
│
├── agents/
│   ├── agents.py                 # 13 agent definitions (lazy loaded)
│   └── tasks.py                  # All task definitions
│
├── crews/
│   └── crews.py                  # 5 crew orchestrators
│
├── utils/
│   ├── styles.py                 # Dark red/amber SOC theme
│   ├── execution_log.py          # Terminal-style streaming log
│   ├── input_parser.py           # Multi-format log parser
│   ├── threat_intel.py           # NIST NVD CVE lookup
│   ├── pdf_report.py             # ReportLab PDF generator
│   └── database.py               # Supabase helpers
│
├── pages/
│   ├── 1_Target_Intake.py
│   ├── 2_Threat_Detection.py
│   ├── 3_Vulnerability_Assessment.py
│   ├── 4_Incident_Response.py
│   ├── 5_Security_Report.py
│   └── 6_Threat_Dashboard.py
│
└── .streamlit/
    ├── config.toml
    └── secrets.toml              # Not committed — add your keys here
```

---

## The 13 agents

**Phase 1 — Target Intake**
- `TargetParserAgent` — Extracts IPs, domains, ports, user agents, file paths, timestamps from any input format
- `ContextBuilderAgent` — Determines target type, attack surface, data sensitivity, compliance scope, threat actor profile

**Phase 2 — Threat Detection**
- `ThreatClassifierAgent` — Maps indicators to MITRE ATT&CK tactics and techniques with severity ratings
- `IOCAnalyzerAgent` — Identifies suspicious IPs, attack tools, malicious paths, auth anomalies
- `AnomalyDetectorAgent` — Detects behavioral patterns: brute force, exfiltration, lateral movement, webshells

**Phase 3 — Vulnerability Assessment**
- `VulnerabilityMapperAgent` — Maps services to CVEs with CVSS scores and exploitability assessment
- `AttackVectorAnalyzerAgent` — Builds complete attack chains with likelihood and impact scoring
- `ExposureAssessorAgent` — Calculates exposure score across 5 dimensions with quick wins

**Phase 4 — Incident Response**
- `IncidentClassifierAgent` — NIST/SANS classification with regulatory notification assessment
- `ResponsePlaybookAgent` — Full 6-phase playbook with owner, timeline, and specific actions per step
- `RemediationAdvisorAgent` — Exact remediation commands with verification steps and rollback instructions

**Phase 5 — Security Report**
- `ExecutiveReportAgent` — Non-technical business risk summary for CISO/management
- `TechnicalReportAgent` — Full technical findings with CVE references, ATT&CK mappings, commands
- `ComplianceMapperAgent` — Gap analysis across OWASP, NIST CSF, PCI-DSS, HIPAA, GDPR, ISO 27001

---

## Local setup

**Requirements:** Python 3.11, pip

```bash
# 1. Clone
git clone https://github.com/yourusername/autosec.git
cd autosec

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure secrets
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# Edit secrets.toml and add your API keys

# 5. Run
streamlit run app.py
```

Open `http://localhost:8501`

---

## API keys

You need at least one LLM key. Groq is recommended — free tier is generous.

```toml
# .streamlit/secrets.toml

GROQ_API_KEY   = "gsk_..."      # Required — get free at console.groq.com
GEMINI_API_KEY = ""             # Optional fallback — aistudio.google.com
SUPABASE_URL   = ""             # Optional — for persistent storage
SUPABASE_KEY   = ""             # Optional — for persistent storage
```

**Get your Groq key:**
1. Go to [console.groq.com](https://console.groq.com)
2. Create account (free)
3. API Keys → Create API Key
4. Paste into `secrets.toml`

**NIST NVD API** — no key required. The CVE lookup works out of the box with a rate limit of 5 requests per 30 seconds.

---

## Deploy to Streamlit Community Cloud

Streamlit Community Cloud deploys directly from GitHub. Free hosting, no server management.

**Step 1 — Push to GitHub**

```bash
# Create .gitignore first
cat > .gitignore << 'EOF'
.streamlit/secrets.toml
__pycache__/
*.pyc
.env
venv/
.DS_Store
*.pdf
*.log
EOF

git init
git add .
git commit -m "Initial AutoSEC deployment"
git branch -M main
git remote add origin https://github.com/yourusername/autosec.git
git push -u origin main
```

**Step 2 — Deploy on Streamlit Cloud**

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Sign in with GitHub
3. Click **New app**
4. Repository: `yourusername/autosec`
5. Branch: `main`
6. Main file path: `app.py`
7. Click **Deploy**

**Step 3 — Add secrets in Streamlit Cloud**

1. App dashboard → **Settings** → **Secrets**
2. Paste your `secrets.toml` content
3. Save → app restarts automatically

**Step 4 — Set Python version**

1. App dashboard → **Settings** → **General**
2. Python version → select **3.11**
3. Save and reboot

Deployment takes 2–4 minutes. Your app will be live at:
`https://yourusername-autosec-app-xxxx.streamlit.app`

---

## Supabase setup (optional)

AutoSEC works without a database — it uses session state. Supabase enables persistent storage across sessions and historical analytics.

**Step 1 — Create project**
1. Go to [supabase.com](https://supabase.com) → New project
2. Choose a region close to your users
3. Save your database password

**Step 2 — Run schema**

Go to **SQL Editor** in your Supabase project and run:

```sql
create table if not exists scan_targets (
    id              uuid primary key default gen_random_uuid(),
    target_input    text,
    target_type     text,
    parsed_data     jsonb,
    context         jsonb,
    created_at      timestamptz default now()
);

create table if not exists threat_findings (
    id              uuid primary key default gen_random_uuid(),
    target_id       uuid references scan_targets(id),
    phase           text,
    severity        text,
    result_json     jsonb,
    created_at      timestamptz default now()
);

create table if not exists security_reports (
    id              uuid primary key default gen_random_uuid(),
    target_id       uuid references scan_targets(id),
    executive_summary   text,
    technical_report    text,
    compliance_mapping  jsonb,
    risk_score          int,
    created_at      timestamptz default now()
);

create table if not exists incident_responses (
    id              uuid primary key default gen_random_uuid(),
    target_id       uuid references scan_targets(id),
    incident_type   text,
    priority        text,
    playbook        jsonb,
    remediation     jsonb,
    created_at      timestamptz default now()
);
```

**Step 3 — Get credentials**

Settings → API:
- `Project URL` → paste as `SUPABASE_URL`
- `anon public` key → paste as `SUPABASE_KEY`

---

## Test inputs

Three ready-to-use inputs for testing the full pipeline.

**Web attack logs (Apache)**

```
192.168.1.105 - - [15/Jan/2024:03:22:11 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.105 - - [15/Jan/2024:03:22:14 +0000] "POST /admin/login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0"
192.168.1.105 - - [15/Jan/2024:03:22:15 +0000] "POST /admin/login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0"
45.33.32.156 - - [15/Jan/2024:03:25:00 +0000] "GET /wp-admin/../../etc/passwd HTTP/1.1" 404 289 "-" "sqlmap/1.7"
45.33.32.156 - - [15/Jan/2024:03:25:01 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 0 "-" "sqlmap/1.7"
45.33.32.156 - - [15/Jan/2024:03:25:02 +0000] "GET /index.php?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 500 0 "-" "sqlmap/1.7"
10.0.0.45 - admin [15/Jan/2024:03:30:00 +0000] "GET /api/users/export?format=csv HTTP/1.1" 200 458923 "-" "python-requests/2.28"
198.51.100.77 - - [15/Jan/2024:04:15:00 +0000] "GET /shell.php HTTP/1.1" 200 145 "-" "curl/7.68.0"
198.51.100.77 - - [15/Jan/2024:04:15:03 +0000] "POST /shell.php HTTP/1.1" 200 892 "-" "curl/7.68.0"
```

**Nmap scan output**

```
Nmap scan report for target.example.com (203.0.113.45)
Host is up (0.023s latency).

PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        vsftpd 2.3.4
22/tcp    open  ssh        OpenSSH 7.2p2 Ubuntu
23/tcp    open  telnet     Linux telnetd
80/tcp    open  http       Apache httpd 2.2.22
3306/tcp  open  mysql      MySQL 5.5.61-0+deb8u1
4444/tcp  open  krb524?
27017/tcp open  mongodb    MongoDB 2.6.10
```

**Security incident description**

```
Unusual activity detected on production server at 2 AM.
Server: Ubuntu 20.04, Apache 2.4, PHP 8.0, MySQL 8.0 — PCI-DSS scope.

- 3 new admin accounts created: admin2, test_user, backup_admin
- Outbound connections to 185.220.101.45 on port 4444
- 2.3GB transferred to external IP at 03:15 AM
- Suspicious files: /tmp/.hidden_shell.php
- SELECT * FROM customers executed at 03:20 AM (no scheduled job)
- 847 failed SSH attempts from 185.220.101.45 in 12 minutes
```

---

## Architecture decisions

**Why agents run sequentially, not in parallel**

Each phase feeds structured output into the next. Threat classification informs vulnerability prioritization. Vulnerability data shapes the incident response playbook. Parallel execution breaks this dependency chain. Sequential also makes debugging straightforward — you can inspect exactly what each agent produced.

**Why lazy loading is mandatory**

CrewAI agents instantiate the LLM client on creation. On Streamlit Cloud, `st.secrets` is not available at module import time — only at runtime. Any agent created at module level will crash with a missing API key error before the app even starts. All 13 agents use getter functions that run only when called.

**Why components.html() instead of st.markdown()**

Streamlit's `unsafe_allow_html=True` works for simple cases but fails silently for complex HTML inside column loops, animated elements, and custom fonts. `components.html()` renders in an isolated iframe with full CSS support. Every card, chart, and terminal in AutoSEC uses it.

**Why temperature 0.2**

Security analysis requires deterministic, precise output — not creative variation. A CVE ID is either correct or it's not. An attack chain either follows the evidence or it fabricates. Temperature 0.2 keeps the agents grounded in the data they receive.

**Why the input parser runs before the LLM agents**

The regex-based parser in `input_parser.py` runs locally in milliseconds and extracts structured indicators before any LLM call. This gives the agents pre-processed, structured data rather than raw text, which improves accuracy and reduces token usage significantly.

---

## Known limitations

- **No active scanning.** AutoSEC analyzes data you provide. It does not connect to targets, run Nmap, or perform any active reconnaissance. If you want scan data, run the scan yourself and paste the output.

- **AI-generated findings require expert review.** The agents can misidentify benign traffic as malicious, miss context that a human analyst would catch, or produce CVE mappings that don't apply to the exact version in your environment. Treat output as a starting point for investigation, not a definitive verdict.

- **NVD API rate limits.** The free NIST NVD API allows 5 requests per 30 seconds without an API key. Nmap scans with many services will trigger delays. The code handles this with `time.sleep()` between requests, but very large scans may take several minutes for the CVE lookup phase.

- **Groq free tier limits.** LLaMA 3.3 70B on Groq allows 14,400 requests per day. Running the full 5-phase pipeline uses approximately 15–20 API calls. You can run roughly 700–900 full analyses per day on the free tier.

- **Context window.** Long log files are truncated at 8,000 characters for the parser agent and 5,000–6,000 characters for downstream agents. Very large log files should be pre-filtered to the suspicious time window before pasting.

---

## Security and responsible use

AutoSEC is built for:
- Security teams auditing their own infrastructure
- Developers reviewing their application security posture
- Students learning threat analysis and incident response
- Researchers analyzing malware samples and attack patterns

AutoSEC is **not** built for:
- Scanning systems you do not own
- Automating attacks or exploitation
- Evading detection on third-party systems
- Any activity that violates computer fraud laws in your jurisdiction

Relevant laws include the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent legislation in other jurisdictions. Unauthorized scanning and testing carries criminal penalties. The legal disclaimer displayed throughout the application is not decorative.

---

## Dependencies

```
crewai>=1.6.0,<2.0.0
litellm>=1.56.0
streamlit==1.41.0
groq==0.13.0
supabase==2.10.0
PyMuPDF==1.25.1
pandas==2.2.3
plotly==5.24.1
requests==2.32.3
reportlab==4.2.5
tiktoken>=0.8.0
setuptools>=68.0.0
```

No `chromadb`, no `langchain`, no `pydantic` pinning. These caused dependency conflicts in early builds and were eliminated.

---

## Troubleshooting

**App crashes immediately on Streamlit Cloud**

Check that Python version is set to 3.11 in App Settings → General. The default is 3.9 which has compatibility issues with the dependency set.

**"OPENAI_API_KEY is required" error**

An agent or dependency is being instantiated at module level before `st.secrets` is available. All agents in `agents.py` must use getter functions. Check that no agent is created outside a function.

**GROQ_API_KEY not found despite being in secrets**

Confirm the key is in Streamlit Cloud secrets (Settings → Secrets), not just in your local `secrets.toml`. Local files are not deployed.

**NVD API returning empty results**

NIST NVD rate limits anonymous requests. If running multiple searches quickly, add a `time.sleep(6)` between calls. The `threat_intel.py` module handles this automatically for the pipeline — manual CVE searches from the UI do not have retry logic.

**PDF generation fails with font error**

ReportLab uses standard built-in fonts (Helvetica, Courier). The PDF generator does not require system font installation. If you see a font error, check that `reportlab==4.2.5` installed correctly.

**Supabase connection refused**

Verify `SUPABASE_URL` includes `https://` and ends without a trailing slash. Verify `SUPABASE_KEY` is the `anon public` key, not the `service_role` key. AutoSEC skips database operations gracefully if the connection fails — the app continues working with session state only.

---

## License

MIT License. See `LICENSE` for full text.

Built for the security community. Use responsibly.
```



1. Create a GitHub repository
2. Push the code
3. Deploy it on Streamlit via share.streamlit.io
4. Add the Groq API key in Secrets
5. Set Python version to 3.11
