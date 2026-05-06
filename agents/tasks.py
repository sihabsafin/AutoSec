from crewai import Task

# ---------------------------------------------------------------------------
# Helper — every task accepts agent as first parameter (mandatory pattern)
# ---------------------------------------------------------------------------

# ===========================================================================
# PHASE 1 — Target Intake Tasks
# ===========================================================================

def task_parse_target(agent, raw_input: str) -> Task:
    return Task(
        description=f"""
You are analyzing the following security input provided by an authorized
security professional for defensive analysis of their own systems.

RAW INPUT:
---
{raw_input[:8000]}
---

Your job is to parse this input and extract ALL security-relevant indicators.

Extract and identify:
1. All IP addresses (classify as public or private/internal)
2. All domain names and URLs
3. All port numbers and associated services
4. All HTTP methods and status codes (if log data)
5. All user agents (flag tools like sqlmap, nikto, curl, masscan)
6. All timestamps and time patterns
7. All file paths (flag suspicious ones like /etc/passwd, shell.php)
8. All usernames mentioned
9. Failed authentication attempts and their source IPs
10. Any CVE references already mentioned
11. Suspicious patterns: SQL injection, path traversal, XSS, brute force

Determine the input format:
- nmap_scan (Nmap output)
- access_log (Apache/Nginx log)
- event_log (Windows Event Log)
- cloudtrail (AWS CloudTrail JSON)
- firewall_log (firewall/iptables log)
- raw_text (incident description or mixed)

IMPORTANT DISCLAIMER: Only analyze the data provided.
Do NOT perform actual network scanning or active reconnaissance.
This is purely defensive analysis of provided data.

Return a comprehensive JSON object with all extracted indicators.
Be thorough — missing an indicator could mean missing a threat.
""",
        expected_output="""
A detailed JSON object containing:
{
  "input_type": "detected format",
  "targets": ["list of all IPs and domains"],
  "public_ips": ["external IPs found"],
  "private_ips": ["internal IPs found"],
  "domains": ["domain names found"],
  "urls": ["full URLs found"],
  "open_ports": [{"port": 22, "service": "SSH", "version": "OpenSSH 7.2"}],
  "suspicious_ips": ["IPs involved in attacks"],
  "failed_auth_attempts": 0,
  "brute_force_detected": true/false,
  "http_errors": [{"code": 401, "count": 5}],
  "unique_user_agents": ["list including any attack tools"],
  "suspicious_patterns": ["SQL Injection", "Path Traversal", etc],
  "suspicious_paths": ["list of suspicious file paths"],
  "cve_references": ["CVE-XXXX-XXXX"],
  "time_range": {"start": "timestamp", "end": "timestamp"},
  "total_events": 0,
  "attack_tools_detected": ["sqlmap", "nikto", etc],
  "key_findings": ["bullet summary of most important findings"]
}
""",
        agent=agent,
    )


def task_build_context(agent, parsed_data: str) -> Task:
    return Task(
        description=f"""
Based on the following parsed security indicators, build a comprehensive
security context profile for this target.

PARSED INDICATORS:
---
{parsed_data[:6000]}
---

Build the security context by determining:

1. TARGET TYPE
   - Web Application (has HTTP logs, web ports 80/443/8080)
   - Network Infrastructure (Nmap scan, multiple services)
   - Endpoint/Server (system logs, specific OS indicators)
   - Cloud Environment (CloudTrail, cloud service indicators)
   - Mixed/Unknown

2. ATTACK SURFACE SUMMARY
   - What is externally exposed?
   - What services are running?
   - What is the overall complexity?

3. DATA SENSITIVITY ASSESSMENT
   - What type of data might this system handle?
   - Credit card data (PCI-DSS scope)?
   - Health data (HIPAA scope)?
   - EU personal data (GDPR scope)?
   - Authentication credentials?
   - Intellectual property?

4. COMPLIANCE CONTEXT
   - Which frameworks are likely relevant?
   - PCI-DSS, HIPAA, GDPR, ISO 27001, NIST CSF, OWASP

5. INDUSTRY VERTICAL (if determinable from context)

6. THREAT ACTOR PROFILE
   - Based on the attack patterns, what type of threat actor?
   - Opportunistic scanner, targeted attacker, insider threat, APT?

7. INITIAL RISK ESTIMATE
   - Preliminary risk rating: Critical / High / Medium / Low
   - Key risk factors

Return a comprehensive JSON context profile.
""",
        expected_output="""
A detailed JSON object containing:
{
  "target_type": "Web Application / Network / Endpoint / Cloud / Mixed",
  "target_description": "brief description of what this system appears to be",
  "attack_surface": {
    "externally_exposed": ["list of exposed services/ports"],
    "internal_services": ["list of internal services"],
    "attack_surface_size": "Small / Medium / Large / Critical"
  },
  "data_sensitivity": {
    "likely_data_types": ["authentication credentials", "user data", etc],
    "sensitivity_level": "Low / Medium / High / Critical",
    "pii_likely": true/false,
    "financial_data_likely": true/false,
    "health_data_likely": true/false
  },
  "compliance_scope": {
    "applicable_frameworks": ["PCI-DSS", "GDPR", "NIST CSF"],
    "primary_framework": "most relevant framework",
    "compliance_risk": "description of compliance exposure"
  },
  "threat_actor_profile": {
    "actor_type": "Opportunistic / Targeted / APT / Insider",
    "sophistication": "Low / Medium / High",
    "likely_motivation": "Financial / Espionage / Disruption / Unknown",
    "evidence": "what in the data supports this assessment"
  },
  "initial_risk_estimate": {
    "rating": "Critical / High / Medium / Low",
    "key_risk_factors": ["list of main risk drivers"],
    "urgency": "Immediate / 24h / 72h / Scheduled"
  },
  "industry_vertical": "Finance / Healthcare / Technology / Government / Unknown",
  "context_summary": "2-3 sentence plain English summary of the overall security situation"
}
""",
        agent=agent,
    )


# ===========================================================================
# PHASE 2 — Threat Detection Tasks
# ===========================================================================

def task_classify_threats(agent, parsed_target: str, context: str) -> Task:
    return Task(
        description=f"""
Classify all threats found in the following security data using the
MITRE ATT&CK framework. This is a defensive analysis of provided data only.

PARSED TARGET DATA:
---
{parsed_target[:5000]}
---

SECURITY CONTEXT:
---
{context[:3000]}
---

Map every threat indicator to MITRE ATT&CK tactics and techniques:

TACTICS TO CHECK (map indicators to each applicable tactic):
1. Initial Access (T1190 Exploit Public App, T1078 Valid Accounts, T1566 Phishing)
2. Execution (T1059 Command Scripting, T1203 Exploitation)
3. Persistence (T1098 Account Manipulation, T1505 Server Software Component)
4. Privilege Escalation (T1068 Exploitation, T1055 Process Injection)
5. Defense Evasion (T1036 Masquerading, T1070 Indicator Removal)
6. Credential Access (T1110 Brute Force, T1003 Credential Dumping)
7. Discovery (T1046 Network Scan, T1082 System Info Discovery)
8. Lateral Movement (T1021 Remote Services, T1550 Use Alternate Auth)
9. Collection (T1005 Local Data, T1074 Data Staged)
10. Exfiltration (T1041 Exfil over C2, T1048 Exfil over Alt Protocol)
11. Command and Control (T1071 App Layer Protocol, T1105 Ingress Tool Transfer)
12. Impact (T1485 Data Destruction, T1486 Data Encrypted for Impact)

For each tactic detected, provide:
- Which specific techniques were used
- The evidence from the data supporting this
- Severity: Critical / High / Medium / Low / Info
- Confidence: High / Medium / Low

Overall threat assessment with severity score.
""",
        expected_output="""
A comprehensive JSON threat classification:
{
  "overall_severity": "Critical / High / Medium / Low",
  "overall_confidence": "High / Medium / Low",
  "threat_summary": "plain English summary of what is happening",
  "mitre_attack_mapping": {
    "Initial Access": {
      "detected": true/false,
      "techniques": [
        {
          "id": "T1190",
          "name": "Exploit Public-Facing Application",
          "evidence": "specific evidence from data",
          "severity": "Critical",
          "confidence": "High"
        }
      ]
    },
    "Execution": {"detected": false, "techniques": []},
    "Persistence": {"detected": true/false, "techniques": []},
    "Privilege Escalation": {"detected": false, "techniques": []},
    "Defense Evasion": {"detected": false, "techniques": []},
    "Credential Access": {"detected": true/false, "techniques": []},
    "Discovery": {"detected": false, "techniques": []},
    "Lateral Movement": {"detected": false, "techniques": []},
    "Collection": {"detected": false, "techniques": []},
    "Exfiltration": {"detected": false, "techniques": []},
    "Command and Control": {"detected": false, "techniques": []},
    "Impact": {"detected": false, "techniques": []}
  },
  "severity_counts": {
    "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
  },
  "top_threats": [
    {
      "title": "threat name",
      "severity": "Critical",
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1190",
      "description": "what this threat means",
      "evidence": "specific data evidence"
    }
  ]
}
""",
        agent=agent,
    )


def task_analyze_iocs(agent, parsed_target: str, context: str) -> Task:
    return Task(
        description=f"""
Analyze all Indicators of Compromise (IOCs) in the following security data.
This is defensive analysis of provided data only.

PARSED TARGET DATA:
---
{parsed_target[:5000]}
---

SECURITY CONTEXT:
---
{context[:2000]}
---

Analyze each category of IOC:

1. SUSPICIOUS IP ADDRESSES
   - Identify IPs involved in attacks (brute force, scanning, exploitation)
   - Note geographic anomalies if determinable
   - Check for known attacker infrastructure patterns (Tor exits, VPS ranges)
   - Classify: Scanner / Attacker / C2 / Unknown

2. MALICIOUS DOMAINS & URLs
   - Suspicious domain patterns (typosquatting, DGA-like names)
   - Malicious paths requested (/etc/passwd, shell.php, wp-config.php)
   - Encoded or obfuscated URLs

3. ANOMALOUS USER AGENTS
   - Attack tools (sqlmap, nikto, masscan, Metasploit, curl used maliciously)
   - Unusual or suspicious UA strings
   - Automated scanner signatures

4. AUTHENTICATION ANOMALIES
   - Brute force patterns (multiple failures from same IP)
   - Credential stuffing patterns (many users, one IP)
   - Successful auth after many failures (successful brute force)

5. SUSPICIOUS FILE PATHS & COMMANDS
   - Webshell access patterns
   - Path traversal attempts
   - System file access attempts
   - Command injection patterns

6. NETWORK ANOMALIES
   - Unusual ports (4444, 1337, 31337, 9001)
   - Large data transfers (potential exfiltration)
   - Unusual outbound connections

For each IOC provide: value, type, confidence, severity, evidence.
""",
        expected_output="""
A comprehensive IOC analysis JSON:
{
  "ioc_summary": {
    "total_iocs": 0,
    "critical_iocs": 0,
    "high_iocs": 0,
    "ioc_types_found": ["IP", "Domain", "User-Agent", "File-Path"]
  },
  "suspicious_ips": [
    {
      "ip": "45.33.32.156",
      "classification": "Active Attacker",
      "activity": "SQL injection attempts, path traversal",
      "request_count": 15,
      "severity": "Critical",
      "confidence": "High",
      "evidence": "specific log entries or data"
    }
  ],
  "malicious_domains": [
    {
      "domain": "domain.example",
      "reason": "why suspicious",
      "severity": "High",
      "evidence": "specific evidence"
    }
  ],
  "suspicious_user_agents": [
    {
      "agent": "sqlmap/1.7",
      "tool": "SQLMap - SQL injection tool",
      "severity": "Critical",
      "source_ip": "45.33.32.156"
    }
  ],
  "auth_anomalies": [
    {
      "type": "Brute Force",
      "source_ip": "IP address",
      "target": "login endpoint or service",
      "attempt_count": 0,
      "success": false,
      "severity": "High"
    }
  ],
  "suspicious_paths": [
    {
      "path": "/etc/passwd",
      "type": "System File Access",
      "severity": "Critical",
      "source_ip": "IP",
      "evidence": "log entry"
    }
  ],
  "network_anomalies": [
    {
      "type": "Suspicious Port",
      "detail": "Port 4444 open - Metasploit default",
      "severity": "Critical"
    }
  ],
  "top_iocs": ["prioritized list of most critical IOCs with brief descriptions"]
}
""",
        agent=agent,
    )


def task_detect_anomalies(agent, threats: str, iocs: str) -> Task:
    return Task(
        description=f"""
Perform deep behavioral anomaly analysis based on the threat classification
and IOC data. Identify patterns that indicate active or past attack activity.

THREAT CLASSIFICATION:
---
{threats[:4000]}
---

IOC ANALYSIS:
---
{iocs[:4000]}
---

Detect and analyze the following behavioral anomaly categories:

1. TEMPORAL ANOMALIES
   - Unusual access times (middle of night, weekends)
   - Activity spikes at specific times
   - Impossible travel (same user, different geographies, short time)

2. AUTHENTICATION ANOMALIES
   - Brute force progression (many fails then success)
   - Credential stuffing patterns
   - Privilege escalation after login
   - Account creation after compromise

3. DATA ACCESS ANOMALIES
   - Unusual data volumes accessed or transferred
   - Access to sensitive files outside normal patterns
   - Bulk data export operations
   - Database dumps

4. NETWORK ANOMALIES
   - Unusual outbound connections (C2 communication)
   - Port scanning from internal hosts
   - Lateral movement between systems
   - DNS anomalies

5. APPLICATION ANOMALIES
   - SQL injection attempts and successes
   - XSS attempts
   - Path traversal sequences
   - PHP/RCE exploitation chains
   - Webshell deployment and usage

6. ATTACK CHAIN INDICATORS
   - Reconnaissance → Exploitation sequences
   - Multi-stage attack progression
   - Persistence mechanism installation
   - Exfiltration following compromise

Synthesize all anomalies into an overall attack narrative if one exists.
""",
        expected_output="""
A comprehensive anomaly detection report:
{
  "anomaly_summary": {
    "total_anomalies": 0,
    "attack_chain_detected": true/false,
    "active_attack": true/false,
    "data_breach_likely": true/false,
    "overall_confidence": "High / Medium / Low"
  },
  "attack_narrative": "plain English story of what happened, step by step",
  "temporal_anomalies": [
    {
      "type": "Off-hours Access",
      "detail": "Activity at 03:15 AM — unusual for business system",
      "severity": "High",
      "evidence": "specific evidence"
    }
  ],
  "authentication_anomalies": [
    {
      "type": "Brute Force Followed by Success",
      "detail": "description",
      "severity": "Critical",
      "evidence": "specific evidence"
    }
  ],
  "data_anomalies": [
    {
      "type": "Large Data Transfer",
      "detail": "2.3GB sent to external IP at 03:15 AM",
      "severity": "Critical",
      "evidence": "specific evidence"
    }
  ],
  "network_anomalies": [],
  "application_anomalies": [
    {
      "type": "SQL Injection Chain",
      "detail": "Progressive SQL injection attempts from same IP",
      "severity": "Critical",
      "evidence": "specific log entries"
    }
  ],
  "attack_chain": [
    {"step": 1, "action": "Reconnaissance", "detail": "Attacker scanned for admin login"},
    {"step": 2, "action": "Initial Access", "detail": "SQL injection attempted"},
    {"step": 3, "action": "Exploitation", "detail": "Webshell deployed to /shell.php"}
  ],
  "top_anomalies": ["ranked list of most critical behavioral anomalies"]
}
""",
        agent=agent,
    )


# ===========================================================================
# PHASE 3 — Vulnerability Assessment Tasks
# ===========================================================================

def task_map_vulnerabilities(agent, parsed_target: str, threat_intel: str) -> Task:
    return Task(
        description=f"""
Map all identified services and software versions to known CVE vulnerabilities.
Apply CVSS scoring and assess exploitability. This is defensive analysis only.

PARSED TARGET DATA (services, versions, ports):
---
{parsed_target[:5000]}
---

THREAT INTELLIGENCE (CVE data from NVD):
---
{threat_intel[:4000]}
---

For each service or software version identified:

1. CVE MAPPING
   - Identify all known CVEs for each service+version combination
   - Use the threat intel data provided (from NIST NVD)
   - Do not fabricate CVE IDs — only reference CVEs in the provided data
     or well-known CVEs you are certain about

2. CVSS SCORING
   - Apply CVSS v3.1 scoring (0.0 to 10.0)
   - Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9

3. EXPLOITABILITY ASSESSMENT
   - Attack Vector: Network / Adjacent / Local / Physical
   - Authentication Required: None / Single / Multiple
   - Complexity: Low / High
   - Public Exploit Available: Yes / No / Unknown
   - Actively Exploited in Wild: Yes / No / Unknown

4. PARTICULARLY DANGEROUS SERVICES TO CHECK:
   - vsftpd 2.3.4 (backdoor CVE-2011-2523)
   - OpenSSH 7.2p2 (username enumeration CVE-2016-6210)
   - Apache 2.2.x (multiple critical CVEs)
   - MySQL 5.5.x (multiple CVEs)
   - MongoDB 2.6 (no auth by default)
   - Telnet (unencrypted, always flagged)
   - FTP on port 21 (unencrypted)
   - Port 4444 open (Metasploit default listener)

Prioritize by: CVSS score × network accessibility × business impact.
""",
        expected_output="""
A comprehensive vulnerability mapping:
{
  "vulnerability_summary": {
    "total_vulnerabilities": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "remotely_exploitable": 0,
    "public_exploits_available": 0
  },
  "vulnerabilities": [
    {
      "service": "vsftpd",
      "version": "2.3.4",
      "port": 21,
      "cve_id": "CVE-2011-2523",
      "cvss_score": 10.0,
      "severity": "Critical",
      "title": "vsftpd 2.3.4 Backdoor",
      "description": "This version contains a backdoor that opens a shell on port 6200",
      "attack_vector": "Network",
      "authentication_required": "None",
      "complexity": "Low",
      "public_exploit": true,
      "actively_exploited": true,
      "remediation": "Immediately upgrade to vsftpd 3.0.5",
      "priority": 1
    }
  ],
  "dangerous_configurations": [
    {
      "issue": "Telnet enabled",
      "port": 23,
      "risk": "All traffic transmitted in cleartext",
      "severity": "High",
      "remediation": "Disable telnet, use SSH instead"
    }
  ],
  "top_vulnerabilities": ["ranked list of most critical vulnerabilities"],
  "patch_priority_order": ["ordered list: fix this first, then this, then this"]
}
""",
        agent=agent,
    )


def task_analyze_attack_vectors(agent, vulnerabilities: str, context: str) -> Task:
    return Task(
        description=f"""
Map potential attack paths using MITRE ATT&CK. Identify complete attack chains
from initial access to final objective. This is defensive threat modeling.

VULNERABILITY DATA:
---
{vulnerabilities[:5000]}
---

SECURITY CONTEXT:
---
{context[:3000]}
---

For each significant vulnerability or combination of vulnerabilities:

1. ATTACK CHAIN MAPPING
   - Initial Access: How does attacker get in? (which vulnerability)
   - Execution: What can they execute after entry?
   - Persistence: How could they maintain access?
   - Privilege Escalation: How could they get admin/root?
   - Lateral Movement: Where could they go from here?
   - Collection: What data could they access?
   - Exfiltration: How could they get data out?
   - Impact: What is the worst case outcome?

2. ATTACK VECTOR SCORING
   - Likelihood: How likely is this attack path? (1-10)
   - Impact: What is the impact if successful? (1-10)
   - Risk Score: Likelihood × Impact
   - Complexity: Simple / Moderate / Complex

3. CRITICAL CHOKEPOINTS
   - Where in the kill chain can defenders most effectively interrupt?
   - What single control would block the most attack paths?
   - Quick wins vs. long-term hardening

4. ATTACK SCENARIOS
   Build 2-3 realistic attack scenarios showing end-to-end attack paths
   based on the actual vulnerabilities found.

Think like a sophisticated attacker planning an operation.
""",
        expected_output="""
A comprehensive attack vector analysis:
{
  "attack_vector_summary": {
    "total_attack_paths": 0,
    "critical_paths": 0,
    "easiest_entry_point": "description",
    "most_dangerous_path": "description",
    "estimated_time_to_compromise": "minutes / hours / days"
  },
  "attack_chains": [
    {
      "id": "AC-001",
      "name": "Unauthenticated RCE via vsftpd Backdoor",
      "likelihood": 9,
      "impact": 10,
      "risk_score": 90,
      "complexity": "Simple",
      "steps": [
        {
          "phase": "Initial Access",
          "technique": "T1190 - Exploit Public-Facing Application",
          "action": "Trigger vsftpd 2.3.4 backdoor on port 21",
          "result": "Shell access on port 6200"
        },
        {
          "phase": "Execution",
          "technique": "T1059 - Command Scripting",
          "action": "Execute system commands via backdoor shell",
          "result": "Full command execution as service user"
        }
      ]
    }
  ],
  "critical_chokepoints": [
    {
      "control": "Patch vsftpd immediately",
      "attack_paths_blocked": 3,
      "implementation_effort": "Low",
      "priority": 1
    }
  ],
  "attack_scenarios": [
    {
      "scenario": "Scenario 1: Opportunistic Attacker",
      "description": "step by step realistic attack narrative",
      "time_to_compromise": "15 minutes",
      "likelihood": "Very High"
    }
  ]
}
""",
        agent=agent,
    )


def task_assess_exposure(agent, vulnerabilities: str, attack_vectors: str) -> Task:
    return Task(
        description=f"""
Assess the overall attack surface exposure and calculate an exposure score 0-100.

VULNERABILITY DATA:
---
{vulnerabilities[:4000]}
---

ATTACK VECTOR ANALYSIS:
---
{attack_vectors[:4000]}
---

Systematically evaluate these exposure dimensions:

1. PUBLIC ATTACK SURFACE (0-25 points)
   - Number of public-facing services
   - Unnecessary services exposed
   - Dangerous protocols (Telnet, FTP, unencrypted services)
   - Score: 0 (minimal) to 25 (maximally exposed)

2. VULNERABILITY EXPOSURE (0-30 points)
   - Number and severity of known CVEs
   - Remotely exploitable vulnerabilities
   - Publicly known exploits available
   - Score: 0 (no known vulns) to 30 (many critical remotely exploitable)

3. AUTHENTICATION WEAKNESS (0-20 points)
   - Default credentials risk
   - No authentication on services (MongoDB, etc.)
   - Brute force exposure
   - Score: 0 (strong auth everywhere) to 20 (no auth on critical services)

4. CONFIGURATION ISSUES (0-15 points)
   - Dangerous default configurations
   - Missing security headers
   - Unnecessary features enabled
   - Score: 0 (well configured) to 15 (severe misconfigurations)

5. ENCRYPTION GAPS (0-10 points)
   - Unencrypted protocols in use
   - Weak SSL/TLS configurations
   - Score: 0 (all encrypted) to 10 (critical data unencrypted)

Total exposure score = sum of all dimensions.
Provide specific deductions for each finding.
""",
        expected_output="""
A comprehensive exposure assessment:
{
  "exposure_score": 75,
  "exposure_rating": "Critical / High / Medium / Low",
  "score_breakdown": {
    "public_attack_surface": {
      "score": 22,
      "max": 25,
      "findings": ["10 services exposed publicly", "Telnet on port 23", "FTP on port 21"]
    },
    "vulnerability_exposure": {
      "score": 28,
      "max": 30,
      "findings": ["Critical CVEs with public exploits", "MongoDB no auth", "Apache 2.2 EOL"]
    },
    "authentication_weakness": {
      "score": 15,
      "max": 20,
      "findings": ["MongoDB unauthenticated", "FTP allows anonymous"]
    },
    "configuration_issues": {
      "score": 6,
      "max": 15,
      "findings": ["Default ports in use", "Debug mode indicators"]
    },
    "encryption_gaps": {
      "score": 8,
      "max": 10,
      "findings": ["Telnet transmits credentials in cleartext", "FTP unencrypted"]
    }
  },
  "public_facing_assets": [
    {
      "asset": "Apache 2.2.22 on port 80",
      "risk": "End of Life software with known critical CVEs",
      "severity": "Critical"
    }
  ],
  "top_exposure_risks": ["ranked list of biggest exposure contributors"],
  "quick_wins": ["actions that immediately reduce exposure score"],
  "exposure_trend": "Increasing / Stable / Decreasing"
}
""",
        agent=agent,
    )


# ===========================================================================
# PHASE 4 — Incident Response Tasks
# ===========================================================================

def task_classify_incident(agent, threat_data: str, vuln_data: str) -> Task:
    return Task(
        description=f"""
Classify this security incident using NIST SP 800-61 and SANS IR frameworks.
Determine incident type, severity, scope, and priority level.

THREAT DETECTION DATA:
---
{threat_data[:5000]}
---

VULNERABILITY DATA:
---
{vuln_data[:3000]}
---

Perform complete incident classification:

1. INCIDENT TYPE DETERMINATION
   Categories (pick the best fit):
   - Active Intrusion: Attacker currently has access
   - Data Breach: Sensitive data accessed or exfiltrated
   - Malware Infection: Malware/backdoor installed
   - Ransomware: Data encrypted for ransom
   - DDoS: Service availability attack
   - Unauthorized Access: Unauthorized login or access
   - Vulnerability Exploitation: CVE actively exploited
   - Insider Threat: Internal actor involved
   - Phishing/Social Engineering: User deception attack
   - Configuration Issue: No attacker but serious risk
   - Security Scan: Reconnaissance/scanning detected
   Multiple types can apply.

2. INCIDENT SCOPE
   - How many systems affected?
   - Is the attacker still active?
   - Is data exfiltration confirmed or suspected?
   - Is the incident contained or spreading?

3. PRIORITY ASSIGNMENT (NIST/SANS)
   P1 CRITICAL: Active attack, data breach, ransomware, critical system compromised
   P2 HIGH: Confirmed exploitation, elevated privileges gained, exfiltration suspected
   P3 MEDIUM: Failed attack detected, vulnerability found, suspicious activity
   P4 LOW: Scanning detected, informational, policy violation

4. REGULATORY NOTIFICATION ASSESSMENT
   - Does this trigger GDPR 72-hour notification?
   - Does this trigger PCI-DSS incident response?
   - Does this trigger HIPAA breach notification?
   - Does this require law enforcement notification?

5. IMMEDIATE ACTIONS REQUIRED
   What must happen in the next 60 minutes?
""",
        expected_output="""
{
  "incident_classification": {
    "primary_type": "Active Intrusion / Data Breach / etc",
    "secondary_types": ["additional incident types"],
    "priority": "P1",
    "priority_label": "CRITICAL",
    "severity": "Critical / High / Medium / Low"
  },
  "incident_scope": {
    "systems_affected": "estimate",
    "attacker_active": true/false,
    "data_exfiltration": "Confirmed / Suspected / Not Detected",
    "containment_status": "Uncontained / Partially Contained / Contained",
    "spread_risk": "High / Medium / Low",
    "incident_phase": "Active / Post-Incident / Discovery"
  },
  "regulatory_obligations": {
    "gdpr_notification_required": true/false,
    "gdpr_deadline": "72 hours from discovery",
    "pci_dss_triggered": true/false,
    "hipaa_triggered": true/false,
    "law_enforcement_recommended": true/false,
    "notification_summary": "what notifications are required and when"
  },
  "immediate_actions_60min": [
    "Action 1: Isolate affected server from network",
    "Action 2: Preserve forensic evidence before any changes",
    "Action 3: Reset all potentially compromised credentials",
    "Action 4: Notify incident response team and management"
  ],
  "incident_summary": "plain English description of what happened and current status",
  "classification_confidence": "High / Medium / Low",
  "classification_rationale": "why this classification was assigned"
}
""",
        agent=agent,
    )


def task_generate_playbook(agent, incident_classification: str, threat_data: str) -> Task:
    return Task(
        description=f"""
Generate a complete, actionable incident response playbook for this specific incident.
Follow NIST SP 800-61 six-phase framework. Be specific and actionable.

INCIDENT CLASSIFICATION:
---
{incident_classification[:4000]}
---

THREAT DATA:
---
{threat_data[:4000]}
---

Generate a complete playbook with ALL six phases.
Each step must be SPECIFIC to this incident — not generic advice.
Include WHO does it, WHEN, and exactly WHAT they do.

PHASE 1 — PREPARATION
- What should have been in place? (document gaps)
- What tools/access does the team need right now?
- Who needs to be notified immediately?
- Communication tree: who calls whom?

PHASE 2 — IDENTIFICATION
- How was this discovered?
- What additional evidence needs to be collected?
- Specific log sources to check right now
- Forensic preservation steps (do these BEFORE any changes)

PHASE 3 — CONTAINMENT
Short-term containment (first 60 minutes):
- Specific network isolation steps
- Account lockdown steps
- Service shutdown decisions (with impact assessment)
Long-term containment:
- Alternative systems/services
- Monitoring enhancements

PHASE 4 — ERADICATION
- Specific malware/backdoor removal steps
- Credential reset procedures
- Patch/fix specific vulnerabilities found
- Clean system verification

PHASE 5 — RECOVERY
- System restoration sequence
- Verification testing before returning to production
- Enhanced monitoring during recovery period
- Staged return to operations

PHASE 6 — LESSONS LEARNED
- Post-incident review agenda
- Specific controls to implement
- Training requirements
- Policy updates needed
- Timeline for follow-up actions
""",
        expected_output="""
{
  "playbook_metadata": {
    "incident_type": "type from classification",
    "priority": "P1/P2/P3/P4",
    "estimated_total_duration": "X hours",
    "team_required": ["SOC Analyst", "Incident Commander", "System Admin", "Legal", "Executive"]
  },
  "phases": {
    "preparation": {
      "duration": "Immediate (0-15 min)",
      "owner": "Incident Commander",
      "steps": [
        {
          "step": 1,
          "action": "Activate incident response team",
          "detail": "specific detail of what to do",
          "owner": "Incident Commander",
          "timeline": "0-5 minutes",
          "tools_needed": ["tool1", "tool2"]
        }
      ]
    },
    "identification": {
      "duration": "15-60 min",
      "owner": "SOC Analyst",
      "steps": []
    },
    "containment": {
      "short_term": {"duration": "0-60 min", "steps": []},
      "long_term": {"duration": "1-24 hours", "steps": []}
    },
    "eradication": {
      "duration": "2-48 hours",
      "steps": []
    },
    "recovery": {
      "duration": "24-72 hours",
      "steps": []
    },
    "lessons_learned": {
      "duration": "1-2 weeks post-incident",
      "steps": []
    }
  },
  "communication_plan": {
    "internal_notifications": ["who to notify and when"],
    "external_notifications": ["regulators, customers, law enforcement if needed"],
    "public_communications": "guidance on public statements"
  },
  "decision_points": [
    {
      "decision": "Should we take the system offline?",
      "criteria": "Take offline IF: active attack confirmed AND business can tolerate downtime",
      "owner": "Incident Commander"
    }
  ]
}
""",
        agent=agent,
    )


def task_generate_remediation(agent, vulnerabilities: str, incident: str) -> Task:
    return Task(
        description=f"""
Generate specific, actionable technical remediation steps ordered by priority.
Include exact commands, configurations, and verification steps.

VULNERABILITY DATA:
---
{vulnerabilities[:4000]}
---

INCIDENT DATA:
---
{incident[:3000]}
---

Generate complete remediation for every finding.

FORMAT FOR EACH REMEDIATION:
- Title: What is being fixed
- Priority: P1 Critical / P2 High / P3 Medium / P4 Low
- Effort: X hours / X days
- Risk if not fixed: what happens if this is ignored
- Prerequisites: what must be done first
- Step-by-step instructions with exact commands
- Verification: how to confirm it worked
- Rollback: how to undo if something breaks

IMPORTANT AREAS TO COVER:

1. CRITICAL PATCHES (P1 — within 24 hours)
   - Specific package update commands for detected vulnerable software
   - Service restart procedures
   - Verification commands

2. DANGEROUS SERVICES (P1 — disable immediately)
   - How to disable Telnet, FTP, MongoDB without auth
   - Firewall rules to add
   - Service alternatives

3. AUTHENTICATION HARDENING (P2 — within 72 hours)
   - Credential reset procedures for compromised accounts
   - SSH hardening (disable root login, key-based auth)
   - Fail2ban or similar installation
   - MFA implementation guidance

4. NETWORK HARDENING (P2 — within 72 hours)
   - Firewall rule additions
   - Port blocking for dangerous ports
   - Network segmentation recommendations

5. MALWARE/BACKDOOR REMOVAL (P1 if present)
   - Webshell detection and removal
   - Backdoor process termination
   - Persistence mechanism removal

6. MONITORING IMPROVEMENTS (P3 — within 1 week)
   - Log monitoring setup
   - Alerting rules to add
   - SIEM/IDS recommendations

Use real Linux/Windows commands where applicable.
""",
        expected_output="""
{
  "remediation_summary": {
    "total_items": 0,
    "p1_critical": 0,
    "p2_high": 0,
    "p3_medium": 0,
    "p4_low": 0,
    "estimated_total_effort": "X person-days",
    "quick_wins": ["things fixable in under 30 minutes"]
  },
  "remediation_items": [
    {
      "id": "REM-001",
      "title": "Upgrade vsftpd to remove backdoor",
      "priority": "P1",
      "effort": "30 minutes",
      "risk_if_ignored": "Remote attacker can gain shell access without authentication",
      "prerequisites": ["Backup current configuration", "Schedule maintenance window"],
      "steps": [
        {
          "step": 1,
          "action": "Check current version",
          "command": "vsftpd --version",
          "expected_output": "vsftpd: version 2.3.4"
        },
        {
          "step": 2,
          "action": "Update vsftpd",
          "command": "sudo apt update && sudo apt upgrade vsftpd -y",
          "expected_output": "Setting up vsftpd (3.0.5) ..."
        },
        {
          "step": 3,
          "action": "Restart service",
          "command": "sudo systemctl restart vsftpd && sudo systemctl status vsftpd",
          "expected_output": "Active: active (running)"
        }
      ],
      "verification": {
        "command": "nmap -sV -p 21 localhost",
        "expected": "Updated version shown, port 6200 closed"
      },
      "rollback": "sudo apt install vsftpd=<previous_version>"
    }
  ],
  "firewall_rules": [
    "sudo ufw deny 23/tcp  # Block Telnet",
    "sudo ufw deny 4444/tcp  # Block Metasploit",
    "sudo ufw deny 6667/tcp  # Block IRC/botnet"
  ],
  "monitoring_rules": [
    {
      "rule": "Alert on port 4444 outbound connections",
      "implementation": "iptables or IDS rule"
    }
  ]
}
""",
        agent=agent,
    )


# ===========================================================================
# PHASE 5 — Security Report Tasks
# ===========================================================================

def task_write_executive_report(
    agent,
    threat_data: str,
    vuln_data: str,
    incident_data: str,
    org_name: str = "the organization",
) -> Task:
    return Task(
        description=f"""
Write a clear, non-technical executive security report for {org_name}.
This report is for CISO and senior management — no technical jargon.

THREAT DETECTION FINDINGS:
---
{threat_data[:3000]}
---

VULNERABILITY FINDINGS:
---
{vuln_data[:3000]}
---

INCIDENT RESPONSE DATA:
---
{incident_data[:2000]}
---

Write a compelling executive report covering:

1. SITUATION OVERVIEW (2-3 sentences)
   What happened? How serious is it? Use plain business language.

2. OVERALL RISK RATING
   Critical / High / Medium / Low — with clear business justification.
   Example: "Your systems are at CRITICAL risk because..."

3. BUSINESS IMPACT (the most important section)
   - Financial risk: potential fines, breach costs, recovery costs
   - Regulatory risk: specific regulations at risk (GDPR, PCI-DSS, HIPAA)
   - Reputational risk: customer trust, public exposure
   - Operational risk: business continuity, service availability

4. TOP 3 FINDINGS (executive-friendly language)
   No CVE numbers — use plain English
   Example: "A known critical flaw in your FTP server allows attackers
   to gain complete control without any password"

5. WHAT WE RECOMMEND
   Three specific recommended actions with business justification.
   Include: what, why it matters, rough cost/effort, timeline.

6. TIMELINE FOR ACTION
   Clear timeline: What must happen TODAY, this WEEK, this MONTH.

7. INVESTMENT REQUIRED
   Rough estimate of security investment needed to remediate.
   Frame as: cost of fix vs. cost of breach.

Write in plain English. Imagine explaining this to a non-technical CEO.
No acronyms without explanation. No CVE IDs. No CVSS scores.
""",
        expected_output="""
A complete executive report as structured text:

EXECUTIVE SECURITY REPORT
==========================

SITUATION OVERVIEW
[2-3 clear sentences about what happened]

OVERALL RISK RATING: [CRITICAL/HIGH/MEDIUM/LOW]
[1-2 sentences explaining why]

BUSINESS IMPACT
[Financial, regulatory, reputational, operational risks in business terms]

TOP 3 FINDINGS
Finding 1: [plain English title]
[Plain English description of the finding and why it matters to the business]

Finding 2: [title]
[description]

Finding 3: [title]
[description]

WHAT WE RECOMMEND
Recommendation 1: [action] — [business justification] — [timeline]
Recommendation 2: [action] — [business justification] — [timeline]
Recommendation 3: [action] — [business justification] — [timeline]

ACTION TIMELINE
Today (within 24 hours): [specific actions]
This Week (within 7 days): [specific actions]
This Month (within 30 days): [specific actions]

INVESTMENT REQUIRED
[Rough cost estimate and ROI framing vs. cost of breach]

DISCLAIMER
[Note that findings are AI-generated and require expert review]
""",
        agent=agent,
    )


def task_write_technical_report(
    agent,
    all_findings: str,
    remediation: str,
) -> Task:
    return Task(
        description=f"""
Write a comprehensive technical security report for the security team.
Include all evidence, CVE references, MITRE ATT&CK mappings, and exact remediation.

ALL SECURITY FINDINGS:
---
{all_findings[:6000]}
---

REMEDIATION DATA:
---
{remediation[:4000]}
---

Write a complete technical report with:

1. TECHNICAL SUMMARY
   - Total findings by severity
   - Key CVEs discovered
   - MITRE ATT&CK tactics detected
   - Overall technical risk assessment

2. DETAILED FINDINGS (one section per major finding)
   For each finding:
   - Title and severity badge
   - CVE ID and CVSS score (if applicable)
   - MITRE ATT&CK tactic and technique ID
   - Technical description
   - Evidence from the provided data
   - Exploitability assessment
   - Specific remediation with commands

3. ATTACK CHAIN ANALYSIS
   - Complete attack path from entry to objective
   - Each step mapped to MITRE ATT&CK

4. REMEDIATION PRIORITY MATRIX
   Table: Finding | Severity | Effort | Impact Reduction | Priority

5. DETECTION RULES
   - Log patterns to alert on
   - Indicators to monitor
   - SIEM rules to create

6. TECHNICAL APPENDIX
   - All IOCs found (IPs, domains, file hashes if available)
   - All CVE references
   - All MITRE ATT&CK technique IDs

Include exact commands. This report goes directly to the security team.
""",
        expected_output="""
A complete technical report as structured text with markdown formatting:

TECHNICAL SECURITY REPORT
==========================

TECHNICAL SUMMARY
Total Findings: X (Critical: X, High: X, Medium: X, Low: X)
CVEs Identified: [list]
MITRE ATT&CK Tactics: [list of detected tactics]
Technical Risk: CRITICAL/HIGH/MEDIUM/LOW

DETAILED FINDINGS
-----------------

[CRITICAL] Finding 1: Title
CVE: CVE-XXXX-XXXX | CVSS: X.X
MITRE: Tactic > Technique (TXXXX)
Description: [technical description]
Evidence: [specific evidence from data]
Exploitability: [remotely exploitable/requires auth/etc]
Remediation:
  $ command 1
  $ command 2
Verification: $ verification command

[HIGH] Finding 2: Title
[continue for all findings...]

ATTACK CHAIN ANALYSIS
Step 1: [MITRE Tactic] — [what happened] — [evidence]
Step 2: [MITRE Tactic] — [what happened] — [evidence]

REMEDIATION PRIORITY MATRIX
| Finding | Severity | Effort | Impact Reduction | Priority |
|---------|----------|--------|-----------------|----------|
| Fix 1   | Critical | 30min  | Critical        | 1        |

DETECTION RULES
Monitor for:
- [specific log pattern to alert on]
- [specific IOC to monitor]

TECHNICAL APPENDIX
Suspicious IPs: [list]
CVE References: [list]
MITRE Techniques: [list]

DISCLAIMER: AI-generated findings require review by a qualified security professional.
""",
        agent=agent,
    )


def task_map_compliance(
    agent,
    all_findings: str,
    compliance_scope: str,
) -> Task:
    return Task(
        description=f"""
Map all security findings to relevant compliance frameworks and identify violations.

ALL SECURITY FINDINGS:
---
{all_findings[:5000]}
---

COMPLIANCE FRAMEWORKS IN SCOPE:
---
{compliance_scope}
---

Map findings to each applicable framework:

1. OWASP TOP 10 (2021)
   A01: Broken Access Control
   A02: Cryptographic Failures
   A03: Injection (SQL, Command, etc.)
   A04: Insecure Design
   A05: Security Misconfiguration
   A06: Vulnerable and Outdated Components
   A07: Identification and Authentication Failures
   A08: Software and Data Integrity Failures
   A09: Security Logging and Monitoring Failures
   A10: Server-Side Request Forgery

2. NIST CYBERSECURITY FRAMEWORK (CSF)
   Identify (ID): Asset management, risk assessment
   Protect (PR): Access control, data security, maintenance
   Detect (DE): Anomalies, monitoring, detection processes
   Respond (RS): Response planning, communications, mitigation
   Recover (RC): Recovery planning, improvements

3. PCI-DSS v4.0 (if financial data in scope)
   Req 1: Network security controls
   Req 2: Secure configurations
   Req 3: Protect cardholder data
   Req 6: Secure systems and software
   Req 10: Log and monitor all access
   Req 11: Test security regularly

4. ISO 27001 (if in scope)
   A.12.6: Technical vulnerability management
   A.9: Access control
   A.10: Cryptography
   A.16: Information security incident management

5. GDPR (if EU personal data in scope)
   Article 25: Data protection by design
   Article 32: Security of processing
   Article 33: Notification of breach
   Article 34: Communication to data subjects

6. HIPAA (if health data in scope)
   164.312 Technical safeguards
   164.308 Administrative safeguards

For each framework, determine:
- Status: Compliant / Partial / Non-Compliant / N/A
- Specific control violations
- What remediation achieves compliance
- Regulatory penalty risk
""",
        expected_output="""
{
  "compliance_summary": {
    "frameworks_assessed": ["OWASP Top 10", "NIST CSF", "PCI-DSS", "ISO 27001", "GDPR"],
    "overall_compliance_status": "Non-Compliant / Partial / Compliant",
    "critical_violations": 0,
    "regulatory_penalty_risk": "High / Medium / Low",
    "estimated_fine_exposure": "description of potential fines"
  },
  "framework_assessments": {
    "OWASP Top 10": {
      "status": "Non-Compliant",
      "violations": [
        {
          "control": "A03: Injection",
          "status": "Non-Compliant",
          "finding": "SQL injection vulnerabilities detected",
          "evidence": "specific evidence",
          "remediation": "parameterized queries, input validation",
          "priority": "P1"
        }
      ],
      "compliant_controls": ["A04", "A08"],
      "compliance_percentage": 60
    },
    "NIST CSF": {
      "status": "Partial",
      "violations": [],
      "compliance_percentage": 45
    },
    "PCI-DSS": {
      "status": "Non-Compliant",
      "violations": [],
      "compliance_percentage": 30
    },
    "ISO 27001": {
      "status": "Partial",
      "violations": [],
      "compliance_percentage": 50
    },
    "GDPR": {
      "status": "Non-Compliant",
      "violations": [],
      "compliance_percentage": 40
    }
  },
  "compliance_roadmap": [
    {
      "action": "Patch all critical vulnerabilities",
      "frameworks_addressed": ["OWASP A06", "PCI-DSS Req 6", "ISO A.12.6"],
      "timeline": "24 hours",
      "compliance_improvement": "Significant improvement across 3 frameworks"
    }
  ],
  "breach_notification_required": {
    "gdpr": true/false,
    "hipaa": true/false,
    "pci_dss": true/false,
    "details": "specific notification requirements and deadlines"
  }
}
""",
        agent=agent,
    )


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Testing task function signatures...")

    import inspect

    task_functions = [
        task_parse_target,
        task_build_context,
        task_classify_threats,
        task_analyze_iocs,
        task_detect_anomalies,
        task_map_vulnerabilities,
        task_analyze_attack_vectors,
        task_assess_exposure,
        task_classify_incident,
        task_generate_playbook,
        task_generate_remediation,
        task_write_executive_report,
        task_write_technical_report,
        task_map_compliance,
    ]

    for fn in task_functions:
        params = list(inspect.signature(fn).parameters.keys())
        assert params[0] == "agent", f"{fn.__name__} must have 'agent' as first param!"
        print(f"  ✓ {fn.__name__}({', '.join(params[:3])}{'...' if len(params)>3 else ''})")

    print(f"\nAll {len(task_functions)} task functions verified.")
    print("First parameter is 'agent' in all tasks — lazy loading pattern confirmed.")