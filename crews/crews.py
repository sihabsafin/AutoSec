import json
from crewai import Crew, Process

# ---------------------------------------------------------------------------
# Safe helpers — used across all crews
# ---------------------------------------------------------------------------

def _safe_json(raw) -> dict:
    """Parse crew task output safely — never crashes."""
    try:
        text = str(raw).strip()
        # Strip markdown code fences
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        return json.loads(text)
    except Exception:
        return {"raw_output": str(raw)[:2000]}


def _out(task) -> str:
    """Extract raw string output from a CrewAI task."""
    try:
        o = task.output
        if hasattr(o, "raw"):
            return str(o.raw)
        return str(o)
    except Exception:
        return "{}"


def _severity_from_findings(findings: dict) -> str:
    """Determine overall severity from aggregated findings."""
    for key in ("overall_severity", "severity", "priority"):
        val = findings.get(key, "")
        if val in ("Critical", "High", "Medium", "Low"):
            return val
    # Check severity counts
    counts = findings.get("severity_counts", {})
    if counts.get("critical", 0) > 0:
        return "Critical"
    if counts.get("high", 0) > 0:
        return "High"
    if counts.get("medium", 0) > 0:
        return "Medium"
    return "Low"


# ===========================================================================
# CREW 1 — Target Intake Crew
# ===========================================================================

def run_intake_crew(raw_input: str) -> dict:
    """
    Phase 1: Parse target input and build security context.
    Returns: {parsed_target, security_context}
    """
    from agents.agents import (
        get_target_parser_agent,
        get_context_builder_agent,
    )
    from agents.tasks import (
        task_parse_target,
        task_build_context,
    )

    # Instantiate agents
    parser_agent  = get_target_parser_agent()
    context_agent = get_context_builder_agent()

    # Build tasks — agent always first param
    t1 = task_parse_target(parser_agent, raw_input)

    # Run first task independently to get parsed data
    Crew(
        agents=[parser_agent],
        tasks=[t1],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    parsed_output = _out(t1)
    parsed_target = _safe_json(parsed_output)

    # Build context task using parsed output
    t2 = task_build_context(context_agent, parsed_output)

    Crew(
        agents=[context_agent],
        tasks=[t2],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    security_context = _safe_json(_out(t2))

    return {
        "parsed_target":   parsed_target,
        "security_context": security_context,
    }


# ===========================================================================
# CREW 2 — Threat Detection Crew
# ===========================================================================

def run_detection_crew(parsed_target: dict, security_context: dict) -> dict:
    """
    Phase 2: Classify threats, analyze IOCs, detect anomalies.
    Returns: {threat_classification, ioc_analysis, anomaly_detection}
    """
    from agents.agents import (
        get_threat_classifier_agent,
        get_ioc_analyzer_agent,
        get_anomaly_detector_agent,
    )
    from agents.tasks import (
        task_classify_threats,
        task_analyze_iocs,
        task_detect_anomalies,
    )

    pt_str  = json.dumps(parsed_target,    ensure_ascii=False)[:5000]
    ctx_str = json.dumps(security_context, ensure_ascii=False)[:3000]

    # Agent 1 — Threat Classifier
    a1 = get_threat_classifier_agent()
    t1 = task_classify_threats(a1, pt_str, ctx_str)

    Crew(
        agents=[a1],
        tasks=[t1],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    threats = _safe_json(_out(t1))

    # Agent 2 — IOC Analyzer
    a2 = get_ioc_analyzer_agent()
    t2 = task_analyze_iocs(a2, pt_str, ctx_str)

    Crew(
        agents=[a2],
        tasks=[t2],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    iocs = _safe_json(_out(t2))

    # Agent 3 — Anomaly Detector (uses output of t1 + t2)
    a3  = get_anomaly_detector_agent()
    t3  = task_detect_anomalies(
        a3,
        json.dumps(threats, ensure_ascii=False)[:4000],
        json.dumps(iocs,    ensure_ascii=False)[:4000],
    )

    Crew(
        agents=[a3],
        tasks=[t3],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    anomalies = _safe_json(_out(t3))

    # Count severity
    severity_counts = threats.get("severity_counts", {
        "critical": 0, "high": 0, "medium": 0, "low": 0
    })
    total_threats = sum(severity_counts.values())

    return {
        "threat_classification": threats,
        "ioc_analysis":          iocs,
        "anomaly_detection":     anomalies,
        "severity_counts":       severity_counts,
        "total_threats":         total_threats,
        "overall_severity":      _severity_from_findings(threats),
    }


# ===========================================================================
# CREW 3 — Vulnerability Assessment Crew
# ===========================================================================

def run_vulnerability_crew(
    parsed_target:   dict,
    security_context: dict,
    threat_intel:    dict = None,
) -> dict:
    """
    Phase 3: Map CVEs, analyze attack vectors, assess exposure.
    Returns: {vulnerability_map, attack_vectors, exposure_assessment}
    """
    from agents.agents import (
        get_vulnerability_mapper_agent,
        get_attack_vector_analyzer_agent,
        get_exposure_assessor_agent,
    )
    from agents.tasks import (
        task_map_vulnerabilities,
        task_analyze_attack_vectors,
        task_assess_exposure,
    )

    pt_str      = json.dumps(parsed_target,    ensure_ascii=False)[:5000]
    ctx_str     = json.dumps(security_context, ensure_ascii=False)[:3000]
    intel_str   = json.dumps(threat_intel or {}, ensure_ascii=False)[:4000]

    # Agent 1 — Vulnerability Mapper
    a1 = get_vulnerability_mapper_agent()
    t1 = task_map_vulnerabilities(a1, pt_str, intel_str)

    Crew(
        agents=[a1],
        tasks=[t1],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    vuln_map = _safe_json(_out(t1))

    # Agent 2 — Attack Vector Analyzer
    a2 = get_attack_vector_analyzer_agent()
    t2 = task_analyze_attack_vectors(
        a2,
        json.dumps(vuln_map, ensure_ascii=False)[:5000],
        ctx_str,
    )

    Crew(
        agents=[a2],
        tasks=[t2],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    attack_vectors = _safe_json(_out(t2))

    # Agent 3 — Exposure Assessor
    a3 = get_exposure_assessor_agent()
    t3 = task_assess_exposure(
        a3,
        json.dumps(vuln_map,       ensure_ascii=False)[:4000],
        json.dumps(attack_vectors, ensure_ascii=False)[:4000],
    )

    Crew(
        agents=[a3],
        tasks=[t3],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    exposure = _safe_json(_out(t3))

    # Extract key metrics
    vuln_summary = vuln_map.get("vulnerability_summary", {})
    exposure_score = exposure.get("exposure_score", 0)

    return {
        "vulnerability_map":    vuln_map,
        "attack_vectors":       attack_vectors,
        "exposure_assessment":  exposure,
        "exposure_score":       exposure_score,
        "total_cves":           vuln_summary.get("total_vulnerabilities", 0),
        "critical_cves":        vuln_summary.get("critical_count", 0),
        "high_cves":            vuln_summary.get("high_count", 0),
    }


# ===========================================================================
# CREW 4 — Incident Response Crew
# ===========================================================================

def run_response_crew(
    threat_result: dict,
    vuln_result:   dict,
) -> dict:
    """
    Phase 4: Classify incident, generate playbook, generate remediation.
    Returns: {incident_classification, playbook, remediation}
    """
    from agents.agents import (
        get_incident_classifier_agent,
        get_response_playbook_agent,
        get_remediation_advisor_agent,
    )
    from agents.tasks import (
        task_classify_incident,
        task_generate_playbook,
        task_generate_remediation,
    )

    threat_str = json.dumps(threat_result, ensure_ascii=False)[:5000]
    vuln_str   = json.dumps(vuln_result,   ensure_ascii=False)[:3000]

    # Agent 1 — Incident Classifier
    a1 = get_incident_classifier_agent()
    t1 = task_classify_incident(a1, threat_str, vuln_str)

    Crew(
        agents=[a1],
        tasks=[t1],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    incident_class = _safe_json(_out(t1))

    # Agent 2 — Playbook Generator
    a2  = get_response_playbook_agent()
    t2  = task_generate_playbook(
        a2,
        json.dumps(incident_class, ensure_ascii=False)[:4000],
        threat_str,
    )

    Crew(
        agents=[a2],
        tasks=[t2],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    playbook = _safe_json(_out(t2))

    # Agent 3 — Remediation Advisor
    a3  = get_remediation_advisor_agent()
    t3  = task_generate_remediation(
        a3,
        vuln_str,
        json.dumps(incident_class, ensure_ascii=False)[:3000],
    )

    Crew(
        agents=[a3],
        tasks=[t3],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    remediation = _safe_json(_out(t3))

    # Extract key metrics
    inc_class   = incident_class.get("incident_classification", {})
    priority    = inc_class.get("priority", "P3")
    inc_type    = inc_class.get("primary_type", "Unknown")
    rem_summary = remediation.get("remediation_summary", {})

    return {
        "incident_classification": incident_class,
        "playbook":                playbook,
        "remediation":             remediation,
        "priority":                priority,
        "incident_type":           inc_type,
        "p1_items":                rem_summary.get("p1_critical", 0),
        "total_remediation_items": rem_summary.get("total_items", 0),
    }


# ===========================================================================
# CREW 5 — Security Report Crew
# ===========================================================================

def run_report_crew(
    threat_result:    dict,
    vuln_result:      dict,
    response_result:  dict,
    security_context: dict,
    org_name:         str  = "the organization",
    compliance_scope: list = None,
) -> dict:
    """
    Phase 5: Write executive report, technical report, compliance mapping.
    Returns: {executive_summary, technical_report, compliance_mapping, risk_score}
    """
    from agents.agents import (
        get_executive_report_agent,
        get_technical_report_agent,
        get_compliance_mapper_agent,
    )
    from agents.tasks import (
        task_write_executive_report,
        task_write_technical_report,
        task_map_compliance,
    )

    # Aggregate all findings for report agents
    all_findings = {
        "threats":   threat_result,
        "vulns":     vuln_result,
        "incident":  response_result,
        "context":   security_context,
    }
    all_str      = json.dumps(all_findings,    ensure_ascii=False)[:6000]
    threat_str   = json.dumps(threat_result,   ensure_ascii=False)[:3000]
    vuln_str     = json.dumps(vuln_result,     ensure_ascii=False)[:3000]
    incident_str = json.dumps(response_result, ensure_ascii=False)[:2000]
    rem_str      = json.dumps(
        response_result.get("remediation", {}), ensure_ascii=False
    )[:3000]

    # Compliance scope string
    scope_list   = compliance_scope or [
        "OWASP Top 10", "NIST CSF", "ISO 27001",
        "PCI-DSS", "HIPAA", "GDPR"
    ]
    scope_str    = ", ".join(scope_list)

    # Agent 1 — Executive Report
    a1  = get_executive_report_agent()
    t1  = task_write_executive_report(
        a1, threat_str, vuln_str, incident_str, org_name
    )

    Crew(
        agents=[a1],
        tasks=[t1],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    exec_summary = _out(t1)

    # Agent 2 — Technical Report
    a2  = get_technical_report_agent()
    t2  = task_write_technical_report(a2, all_str, rem_str)

    Crew(
        agents=[a2],
        tasks=[t2],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    tech_report = _out(t2)

    # Agent 3 — Compliance Mapper
    a3  = get_compliance_mapper_agent()
    t3  = task_map_compliance(a3, all_str, scope_str)

    Crew(
        agents=[a3],
        tasks=[t3],
        process=Process.sequential,
        verbose=True,
    ).kickoff()

    compliance = _safe_json(_out(t3))

    # Calculate overall risk score (0-100)
    risk_score = _calculate_risk_score(
        threat_result, vuln_result, response_result
    )

    return {
        "executive_summary":  exec_summary,
        "technical_report":   tech_report,
        "compliance_mapping": compliance,
        "risk_score":         risk_score,
    }


# ===========================================================================
# Risk Score Calculator
# ===========================================================================

def _calculate_risk_score(
    threat_result:   dict,
    vuln_result:     dict,
    response_result: dict,
) -> int:
    """
    Calculate overall risk score 0-100 from all phase results.
    Weighted: Threats 40% + Vulns 35% + Exposure 25%
    """
    score = 0

    # --- Threat component (0-40) ---
    severity_counts = threat_result.get("severity_counts", {})
    critical_t = severity_counts.get("critical", 0)
    high_t     = severity_counts.get("high",     0)
    medium_t   = severity_counts.get("medium",   0)

    threat_score = min(40, (critical_t * 15) + (high_t * 8) + (medium_t * 3))
    score += threat_score

    # --- Vulnerability component (0-35) ---
    critical_v = vuln_result.get("critical_cves", 0)
    high_v     = vuln_result.get("high_cves",     0)
    total_v    = vuln_result.get("total_cves",    0)

    vuln_score = min(35, (critical_v * 12) + (high_v * 6) + (total_v * 1))
    score += vuln_score

    # --- Exposure component (0-25) ---
    exposure_raw = vuln_result.get("exposure_score", 0)
    # Scale NVD exposure (0-100) to our component (0-25)
    exposure_score = min(25, int(exposure_raw * 0.25))
    score += exposure_score

    # Priority boost
    priority = response_result.get("priority", "P3")
    if priority == "P1":
        score = min(100, score + 10)
    elif priority == "P2":
        score = min(100, score + 5)

    return min(100, max(0, score))


# ===========================================================================
# Full Pipeline Runner (convenience function for testing)
# ===========================================================================

def run_full_pipeline(
    raw_input:        str,
    org_name:         str  = "Unknown Organization",
    compliance_scope: list = None,
) -> dict:
    """
    Run all 5 crews sequentially.
    Returns complete results dict with all phases.
    """
    results = {}

    print("\n" + "="*60)
    print("AUTOSEC PIPELINE STARTING")
    print("="*60)

    # Phase 1
    print("\n[PHASE 1] Target Intake...")
    intake = run_intake_crew(raw_input)
    results["intake"] = intake

    # Phase 2
    print("\n[PHASE 2] Threat Detection...")
    detection = run_detection_crew(
        intake["parsed_target"],
        intake["security_context"],
    )
    results["detection"] = detection

    # Phase 3 — get threat intel first
    print("\n[PHASE 3] Vulnerability Assessment...")
    try:
        from utils.threat_intel import get_threat_intel_summary
        threat_intel = get_threat_intel_summary(intake["parsed_target"])
    except Exception:
        threat_intel = {}

    vulnerability = run_vulnerability_crew(
        intake["parsed_target"],
        intake["security_context"],
        threat_intel,
    )
    results["vulnerability"] = vulnerability

    # Phase 4
    print("\n[PHASE 4] Incident Response...")
    response = run_response_crew(detection, vulnerability)
    results["response"] = response

    # Phase 5
    print("\n[PHASE 5] Security Report...")
    report = run_report_crew(
        detection,
        vulnerability,
        response,
        intake["security_context"],
        org_name=org_name,
        compliance_scope=compliance_scope,
    )
    results["report"] = report

    print("\n" + "="*60)
    print(f"PIPELINE COMPLETE — Risk Score: {report['risk_score']}/100")
    print("="*60)

    return results


# ---------------------------------------------------------------------------
# Quick self-test (no LLM calls)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Testing crew module imports and helpers...")

    # Test _safe_json
    tests = [
        ('{"key": "value"}',          {"key": "value"}),
        ('```json\n{"a":1}\n```',      {"a": 1}),
        ("not valid json at all !!!",  None),
    ]
    for raw, expected in tests:
        result = _safe_json(raw)
        if expected:
            assert result == expected, f"Failed: {raw!r}"
        else:
            assert "raw_output" in result, f"Should fallback: {raw!r}"
        print(f"  ✓ _safe_json OK: {raw[:30]!r}...")

    # Test risk score
    mock_threat = {"severity_counts": {"critical": 2, "high": 3, "medium": 1}}
    mock_vuln   = {"critical_cves": 2, "high_cves": 3, "total_cves": 7, "exposure_score": 75}
    mock_resp   = {"priority": "P1"}
    score = _calculate_risk_score(mock_threat, mock_vuln, mock_resp)
    assert 0 <= score <= 100, f"Score out of range: {score}"
    print(f"  ✓ _calculate_risk_score: {score}/100")

    # Test crew functions exist
    crew_fns = [
        run_intake_crew,
        run_detection_crew,
        run_vulnerability_crew,
        run_response_crew,
        run_report_crew,
        run_full_pipeline,
    ]
    for fn in crew_fns:
        print(f"  ✓ {fn.__name__} — defined OK")

    print(f"\nAll crew helpers verified.")
    print("Run 'run_full_pipeline()' with API keys to test full pipeline.")