import re
import json
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

IP_PATTERN     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
URL_PATTERN    = re.compile(r'https?://[^\s\'"<>]+')
PORT_PATTERN   = re.compile(r'\b(\d{1,5})/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?')
CVE_PATTERN    = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
TIMESTAMP_PATTERN = re.compile(
    r'\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
)
HTTP_LOG_PATTERN = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+|-)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
)
HTTP_STATUS_PATTERN = re.compile(r'\b([1-5]\d{2})\b')
USER_AGENT_PATTERN  = re.compile(r'"([^"]*(?:Mozilla|curl|python|wget|sqlmap|nikto|nmap|masscan)[^"]*)"',
                                  re.IGNORECASE)

SUSPICIOUS_TOOLS = [
    "sqlmap", "nikto", "nmap", "masscan", "metasploit", "burpsuite",
    "hydra", "john", "hashcat", "aircrack", "wireshark", "ettercap",
    "beef", "empire", "cobalt", "mimikatz", "meterpreter"
]

SUSPICIOUS_PATHS = [
    "/etc/passwd", "/etc/shadow", "../../", "../",
    "/.htaccess", "/.env", "/wp-admin", "/phpmyadmin",
    "/admin", "/shell", "cmd=", "exec=", "system(",
    "base64_decode", "eval(", "union select", "or '1'='1",
    "/proc/", "/dev/", "UNION", "DROP TABLE", "INSERT INTO"
]

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Common backdoor",
    31337: "Elite/backdoor",
    6666: "IRC/botnet",
    6667: "IRC/botnet",
    9001: "Tor",
    9050: "Tor SOCKS",
    23:   "Telnet (unencrypted)",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh",
}

PRIVATE_IP_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)

def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)

def _extract_ips(text: str) -> dict:
    all_ips = [ip for ip in IP_PATTERN.findall(text) if _is_valid_ip(ip)]
    unique  = list(dict.fromkeys(all_ips))
    private = [ip for ip in unique if _is_private_ip(ip)]
    public  = [ip for ip in unique if not _is_private_ip(ip)]
    return {"all": unique, "private": private, "public": public}

def _extract_domains(text: str) -> list:
    raw = DOMAIN_PATTERN.findall(text)
    skip = {
        "localhost", "example.com", "test.com", "internal",
        "lan", "local", "corp"
    }
    seen, result = set(), []
    for d in raw:
        d = d.lower().rstrip(".")
        if d not in seen and d not in skip and len(d) > 4:
            seen.add(d)
            result.append(d)
    return result

def _extract_urls(text: str) -> list:
    return list(dict.fromkeys(URL_PATTERN.findall(text)))

def _is_suspicious_path(path: str) -> bool:
    p = path.lower()
    return any(s.lower() in p for s in SUSPICIOUS_PATHS)

def _is_suspicious_agent(agent: str) -> bool:
    a = agent.lower()
    return any(t.lower() in a for t in SUSPICIOUS_TOOLS)

def _extract_timestamps(text: str) -> list:
    return TIMESTAMP_PATTERN.findall(text)

def _extract_cves(text: str) -> list:
    return list(dict.fromkeys(CVE_PATTERN.findall(text.upper())))


# ---------------------------------------------------------------------------
# Format detectors
# ---------------------------------------------------------------------------

def _detect_input_type(text: str) -> str:
    t = text.lower()
    if "nmap scan report" in t or "host is up" in t:
        return "nmap_scan"
    if re.search(r'\d+/tcp\s+(open|closed)', t):
        return "nmap_scan"
    if re.search(r'\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}', t):
        return "access_log"
    if "eventid" in t or "event id" in t or "windows" in t and "log" in t:
        return "event_log"
    if '"eventversion"' in t or "cloudtrail" in t:
        return "cloudtrail"
    if re.search(r'\bcontainer\b|\bdocker\b|\bk8s\b|\bkubernetes\b', t):
        return "container_log"
    if re.search(r'iptables|firewall|deny|permit|src=|dst=', t):
        return "firewall_log"
    if re.search(r'ip address|subnet|gateway|vlan|interface', t):
        return "network_config"
    return "raw_text"


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------

def _parse_nmap(text: str) -> dict:
    ports = []
    for m in PORT_PATTERN.finditer(text):
        port_num = int(m.group(1))
        entry = {
            "port":    port_num,
            "state":   m.group(2),
            "service": m.group(3),
            "version": (m.group(4) or "").strip(),
            "suspicious": port_num in SUSPICIOUS_PORTS,
            "note":    SUSPICIOUS_PORTS.get(port_num, ""),
        }
        ports.append(entry)

    target_match = re.search(
        r'Nmap scan report for (.+?)(?:\s*\((\d+\.\d+\.\d+\.\d+)\))?$',
        text, re.MULTILINE
    )
    target_host = ""
    target_ip   = ""
    if target_match:
        target_host = target_match.group(1).strip()
        target_ip   = target_match.group(2) or ""

    os_match = re.search(r'OS[:\s]+(.+)', text, re.IGNORECASE)
    os_info  = os_match.group(1).strip() if os_match else ""

    return {
        "target_host": target_host,
        "target_ip":   target_ip,
        "os_detected": os_info,
        "open_ports":  [p for p in ports if p["state"] == "open"],
        "all_ports":   ports,
        "suspicious_ports": [p for p in ports if p["suspicious"]],
    }


def _parse_access_log(text: str) -> dict:
    entries = []
    failed_auth   = 0
    status_counts = {}
    agents        = []
    suspicious_requests = []

    for line in text.strip().splitlines():
        m = HTTP_LOG_PATTERN.match(line.strip())
        if not m:
            continue
        ip, timestamp, method, path, status, size, referer, ua = (
            m.group(1), m.group(2), m.group(3),
            m.group(4), m.group(5), m.group(6),
            m.group(7) or "", m.group(8) or ""
        )
        status_int = int(status)
        status_counts[status_int] = status_counts.get(status_int, 0) + 1

        if status_int in (401, 403):
            failed_auth += 1

        if ua and ua not in agents:
            agents.append(ua)

        is_susp = _is_suspicious_path(path) or _is_suspicious_agent(ua)
        entry = {
            "ip": ip, "timestamp": timestamp,
            "method": method, "path": path,
            "status": status_int, "size": size,
            "user_agent": ua, "suspicious": is_susp,
        }
        entries.append(entry)
        if is_susp:
            suspicious_requests.append(entry)

    http_errors = [
        {"code": code, "count": cnt}
        for code, cnt in sorted(status_counts.items())
        if code >= 400
    ]

    return {
        "total_requests":     len(entries),
        "failed_auth_count":  failed_auth,
        "http_errors":        http_errors,
        "unique_user_agents": list(dict.fromkeys(agents)),
        "suspicious_requests": suspicious_requests[:20],
        "status_distribution": status_counts,
    }


def _parse_cloudtrail(text: str) -> dict:
    try:
        data   = json.loads(text)
        events = data.get("Records", [data]) if isinstance(data, dict) else data
        ips, users, actions = [], [], []
        for ev in events[:100]:
            if isinstance(ev, dict):
                ip = ev.get("sourceIPAddress", "")
                if ip:
                    ips.append(ip)
                user = ev.get("userIdentity", {})
                if isinstance(user, dict):
                    users.append(user.get("userName", user.get("type", "")))
                actions.append(ev.get("eventName", ""))
        return {
            "event_count":   len(events),
            "source_ips":    list(dict.fromkeys(ips)),
            "users_involved":list(dict.fromkeys(filter(None, users))),
            "actions":       list(dict.fromkeys(actions)),
        }
    except Exception:
        return {"parse_error": "Could not parse CloudTrail JSON"}


def _parse_firewall_log(text: str) -> dict:
    denied, allowed = [], []
    for line in text.strip().splitlines():
        l = line.lower()
        ips_found = IP_PATTERN.findall(line)
        ports_found = re.findall(r'(?:dpt|dst_port|dport)=(\d+)', line, re.IGNORECASE)
        entry = {
            "line":  line.strip(),
            "ips":   ips_found,
            "ports": ports_found,
        }
        if any(w in l for w in ("deny", "drop", "reject", "block")):
            denied.append(entry)
        elif any(w in l for w in ("allow", "permit", "accept")):
            allowed.append(entry)

    return {
        "denied_count":  len(denied),
        "allowed_count": len(allowed),
        "denied_entries": denied[:20],
    }


# ---------------------------------------------------------------------------
# Suspicious pattern detection (works across all formats)
# ---------------------------------------------------------------------------

def _detect_suspicious_patterns(text: str) -> list:
    patterns_found = []
    t = text.lower()

    checks = [
        ("SQL Injection",       r"union\s+select|or\s+'1'\s*=\s*'1|drop\s+table|insert\s+into|--\s*$"),
        ("Path Traversal",      r"\.\./|\.\.\\|%2e%2e"),
        ("XSS Attempt",         r"<script|javascript:|onerror=|onload=|alert\("),
        ("Command Injection",   r";\s*(?:ls|cat|id|whoami|wget|curl)\b|&&|\|\|"),
        ("PHP Exploit",         r"php://|base64_decode\s*\(|eval\s*\(|system\s*\("),
        ("Brute Force",         r"(?:failed|invalid|incorrect).{0,30}(?:password|login|auth)"),
        ("Data Exfiltration",   r"\d+(?:\.\d+)?\s*(?:gb|mb)\s+(?:sent|transfer|upload)"),
        ("Backdoor/Webshell",   r"shell\.php|cmd\.php|\.php\?(?:cmd|exec|command)="),
        ("Credential Dump",     r"mimikatz|lsass|sam\s+dump|hashdump|ntds\.dit"),
        ("Lateral Movement",    r"psexec|wmiexec|pass.the.hash|pass.the.ticket"),
        ("C2 Communication",    r"beacon|cobalt.strike|empire\s+agent|meterpreter"),
        ("Recon Activity",      r"nmap|masscan|shodan|censys|dirbuster|gobuster"),
    ]

    for name, pattern in checks:
        if re.search(pattern, t, re.IGNORECASE):
            patterns_found.append(name)

    return patterns_found


def _detect_brute_force(text: str) -> dict:
    failed = re.findall(
        r'(\d+\.\d+\.\d+\.\d+).{0,80}(?:failed|invalid|incorrect|401|unauthorized)',
        text, re.IGNORECASE
    )
    counts = {}
    for ip in failed:
        counts[ip] = counts.get(ip, 0) + 1

    bf_ips = {ip: cnt for ip, cnt in counts.items() if cnt >= 5}
    return {
        "brute_force_detected": len(bf_ips) > 0,
        "offending_ips":        bf_ips,
        "total_failed_attempts": sum(bf_ips.values()),
    }


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def parse_target_input(raw_input: str) -> dict:
    """
    Parse any security-related input and return a structured JSON dict.
    Handles: Nmap, Apache/Nginx logs, CloudTrail, firewall logs, free text.
    """
    if not raw_input or not raw_input.strip():
        return {"error": "Empty input provided"}

    text        = raw_input.strip()
    input_type  = _detect_input_type(text)
    ip_data     = _extract_ips(text)
    domains     = _extract_domains(text)
    urls        = _extract_urls(text)
    timestamps  = _extract_timestamps(text)
    cves        = _extract_cves(text)
    patterns    = _detect_suspicious_patterns(text)
    brute_force = _detect_brute_force(text)

    # Format-specific parsing
    format_data: dict = {}
    open_ports:  list = []
    susp_ips:    list = []

    if input_type == "nmap_scan":
        format_data = _parse_nmap(text)
        open_ports  = format_data.get("open_ports", [])
        susp_ips    = [p["note"] and p["port"]
                       for p in format_data.get("suspicious_ports", [])]
        susp_ips    = [str(p["port"]) for p in format_data.get("suspicious_ports", [])]

    elif input_type == "access_log":
        format_data = _parse_access_log(text)
        susp_reqs   = format_data.get("suspicious_requests", [])
        susp_ips    = list(dict.fromkeys(r["ip"] for r in susp_reqs))

    elif input_type == "cloudtrail":
        format_data = _parse_cloudtrail(text)
        susp_ips    = format_data.get("source_ips", [])

    elif input_type == "firewall_log":
        format_data = _parse_firewall_log(text)
        susp_ips    = list(dict.fromkeys(
            ip for e in format_data.get("denied_entries", [])
            for ip in e.get("ips", [])
        ))

    # Merge brute force IPs into suspicious
    if brute_force["brute_force_detected"]:
        bf_ips = list(brute_force["offending_ips"].keys())
        susp_ips = list(dict.fromkeys(susp_ips + bf_ips))

    # Time range
    time_range = {"start": "", "end": ""}
    if timestamps:
        time_range = {"start": timestamps[0], "end": timestamps[-1]}

    # Targets list (IPs + domains)
    all_targets = list(dict.fromkeys(
        ip_data["public"] + ip_data["private"] + domains
    ))

    result = {
        "input_type":          input_type,
        "targets":             all_targets[:30],
        "public_ips":          ip_data["public"],
        "private_ips":         ip_data["private"],
        "domains":             domains[:20],
        "urls":                urls[:20],
        "open_ports":          open_ports,
        "suspicious_ips":      susp_ips[:20],
        "suspicious_domains":  [d for d in domains if any(
                                    t in d for t in ["evil", "malware", "hack", "shell", "c2"]
                                )],
        "failed_auth_attempts": format_data.get("failed_auth_count", 0),
        "brute_force":         brute_force,
        "http_errors":         format_data.get("http_errors", []),
        "unique_user_agents":  format_data.get("unique_user_agents", [])[:10],
        "suspicious_patterns": patterns,
        "cve_references":      cves,
        "time_range":          time_range,
        "total_events":        format_data.get("total_requests",
                               format_data.get("event_count",
                               text.count("\n") + 1)),
        "format_specific":     format_data,
        "raw_indicators":      patterns,
    }

    return result


# ---------------------------------------------------------------------------
# PDF / file content extractor
# ---------------------------------------------------------------------------

def extract_text_from_file(uploaded_file) -> str:
    """
    Extract text from uploaded Streamlit file object.
    Supports: .txt, .log, .csv, .json, .pdf
    """
    name = uploaded_file.name.lower()

    if name.endswith(".pdf"):
        try:
            import fitz  # PyMuPDF
            data  = uploaded_file.read()
            doc   = fitz.open(stream=data, filetype="pdf")
            pages = [page.get_text() for page in doc]
            return "\n".join(pages)
        except Exception as e:
            return f"[PDF parse error: {e}]"

    elif name.endswith(".json"):
        try:
            data = json.load(uploaded_file)
            return json.dumps(data, indent=2)
        except Exception:
            return uploaded_file.read().decode("utf-8", errors="replace")

    else:
        return uploaded_file.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_log = """
192.168.1.105 - - [15/Jan/2024:03:22:11 +0000] "GET /admin/login.php HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.105 - - [15/Jan/2024:03:22:14 +0000] "POST /admin/login.php HTTP/1.1" 401 567 "-" "Mozilla/5.0"
45.33.32.156 - - [15/Jan/2024:03:25:00 +0000] "GET /wp-admin/../../etc/passwd HTTP/1.1" 404 289 "-" "sqlmap/1.7"
45.33.32.156 - - [15/Jan/2024:03:25:01 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 0 "-" "sqlmap/1.7"
198.51.100.77 - - [15/Jan/2024:04:15:00 +0000] "GET /shell.php HTTP/1.1" 200 145 "-" "curl/7.68.0"
    """
    result = parse_target_input(test_log)
    print(json.dumps(result, indent=2))