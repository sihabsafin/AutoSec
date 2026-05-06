import json
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Supabase SQL schema — run this once in Supabase SQL Editor
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
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
"""

# ---------------------------------------------------------------------------
# Client factory — lazy, gracefully skips if no credentials
# ---------------------------------------------------------------------------

_supabase_client = None


def _get_client():
    """
    Returns Supabase client or None if credentials are missing.
    Never crashes — always safe to call.
    """
    global _supabase_client

    if _supabase_client is not None:
        return _supabase_client

    try:
        from config import SUPABASE_URL, SUPABASE_KEY
        if not SUPABASE_URL or not SUPABASE_KEY:
            return None
        from supabase import create_client
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        return _supabase_client
    except Exception:
        return None


def is_connected() -> bool:
    """Check if Supabase is configured and reachable."""
    return _get_client() is not None


# ---------------------------------------------------------------------------
# Safe JSON helper
# ---------------------------------------------------------------------------

def _to_jsonb(data) -> dict:
    """Convert anything to a JSON-safe dict."""
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return {"raw": data}
    try:
        return json.loads(json.dumps(data, default=str))
    except Exception:
        return {"raw": str(data)}


# ---------------------------------------------------------------------------
# scan_targets table
# ---------------------------------------------------------------------------

def save_scan_target(
    target_input:  str,
    target_type:   str,
    parsed_data:   dict,
    context:       dict,
) -> Optional[str]:
    """
    Insert a new scan target. Returns the UUID or None on failure.
    Gracefully skips if Supabase is not configured.
    """
    client = _get_client()
    if not client:
        return None

    try:
        resp = client.table("scan_targets").insert({
            "target_input": target_input[:5000],
            "target_type":  target_type,
            "parsed_data":  _to_jsonb(parsed_data),
            "context":      _to_jsonb(context),
        }).execute()

        rows = resp.data
        if rows:
            return rows[0].get("id")
    except Exception as e:
        print(f"[DB] save_scan_target error: {e}")

    return None


def get_scan_target(target_id: str) -> Optional[dict]:
    """Fetch a scan target by UUID."""
    client = _get_client()
    if not client or not target_id:
        return None

    try:
        resp = client.table("scan_targets") \
                     .select("*") \
                     .eq("id", target_id) \
                     .single() \
                     .execute()
        return resp.data
    except Exception as e:
        print(f"[DB] get_scan_target error: {e}")
        return None


def list_recent_targets(limit: int = 20) -> list:
    """List most recent scan targets."""
    client = _get_client()
    if not client:
        return []

    try:
        resp = client.table("scan_targets") \
                     .select("id, target_type, target_input, created_at") \
                     .order("created_at", desc=True) \
                     .limit(limit) \
                     .execute()
        return resp.data or []
    except Exception as e:
        print(f"[DB] list_recent_targets error: {e}")
        return []


# ---------------------------------------------------------------------------
# threat_findings table
# ---------------------------------------------------------------------------

def save_threat_findings(
    target_id:   str,
    phase:       str,
    severity:    str,
    result_json: dict,
) -> Optional[str]:
    """Save threat findings for a phase."""
    client = _get_client()
    if not client or not target_id:
        return None

    try:
        resp = client.table("threat_findings").insert({
            "target_id":   target_id,
            "phase":       phase,
            "severity":    severity,
            "result_json": _to_jsonb(result_json),
        }).execute()

        rows = resp.data
        if rows:
            return rows[0].get("id")
    except Exception as e:
        print(f"[DB] save_threat_findings error: {e}")

    return None


def get_threat_findings(target_id: str) -> list:
    """Get all threat findings for a target."""
    client = _get_client()
    if not client or not target_id:
        return []

    try:
        resp = client.table("threat_findings") \
                     .select("*") \
                     .eq("target_id", target_id) \
                     .order("created_at") \
                     .execute()
        return resp.data or []
    except Exception as e:
        print(f"[DB] get_threat_findings error: {e}")
        return []


# ---------------------------------------------------------------------------
# incident_responses table
# ---------------------------------------------------------------------------

def save_incident_response(
    target_id:     str,
    incident_type: str,
    priority:      str,
    playbook:      dict,
    remediation:   dict,
) -> Optional[str]:
    """Save incident response data."""
    client = _get_client()
    if not client or not target_id:
        return None

    try:
        resp = client.table("incident_responses").insert({
            "target_id":     target_id,
            "incident_type": incident_type,
            "priority":      priority,
            "playbook":      _to_jsonb(playbook),
            "remediation":   _to_jsonb(remediation),
        }).execute()

        rows = resp.data
        if rows:
            return rows[0].get("id")
    except Exception as e:
        print(f"[DB] save_incident_response error: {e}")

    return None


def get_incident_response(target_id: str) -> Optional[dict]:
    """Get incident response for a target."""
    client = _get_client()
    if not client or not target_id:
        return None

    try:
        resp = client.table("incident_responses") \
                     .select("*") \
                     .eq("target_id", target_id) \
                     .order("created_at", desc=True) \
                     .limit(1) \
                     .execute()
        rows = resp.data
        return rows[0] if rows else None
    except Exception as e:
        print(f"[DB] get_incident_response error: {e}")
        return None


# ---------------------------------------------------------------------------
# security_reports table
# ---------------------------------------------------------------------------

def save_security_report(
    target_id:         str,
    executive_summary: str,
    technical_report:  str,
    compliance_mapping: dict,
    risk_score:        int,
) -> Optional[str]:
    """Save final security report."""
    client = _get_client()
    if not client or not target_id:
        return None

    try:
        resp = client.table("security_reports").insert({
            "target_id":          target_id,
            "executive_summary":  executive_summary[:10000],
            "technical_report":   technical_report[:10000],
            "compliance_mapping": _to_jsonb(compliance_mapping),
            "risk_score":         risk_score,
        }).execute()

        rows = resp.data
        if rows:
            return rows[0].get("id")
    except Exception as e:
        print(f"[DB] save_security_report error: {e}")

    return None


def get_security_report(target_id: str) -> Optional[dict]:
    """Get security report for a target."""
    client = _get_client()
    if not client or not target_id:
        return None

    try:
        resp = client.table("security_reports") \
                     .select("*") \
                     .eq("target_id", target_id) \
                     .order("created_at", desc=True) \
                     .limit(1) \
                     .execute()
        rows = resp.data
        return rows[0] if rows else None
    except Exception as e:
        print(f"[DB] get_security_report error: {e}")
        return None


# ---------------------------------------------------------------------------
# Dashboard analytics
# ---------------------------------------------------------------------------

def get_dashboard_stats() -> dict:
    """
    Aggregate stats for the SOC dashboard.
    Returns safe defaults if DB not connected.
    """
    client = _get_client()
    if not client:
        return {
            "targets_analyzed":  0,
            "threats_detected":  0,
            "critical_findings": 0,
            "reports_generated": 0,
            "db_connected":      False,
        }

    try:
        targets  = client.table("scan_targets").select("id", count="exact").execute()
        findings = client.table("threat_findings").select("id", count="exact").execute()
        critical = client.table("threat_findings") \
                         .select("id", count="exact") \
                         .eq("severity", "Critical") \
                         .execute()
        reports  = client.table("security_reports").select("id", count="exact").execute()

        return {
            "targets_analyzed":  targets.count  or 0,
            "threats_detected":  findings.count or 0,
            "critical_findings": critical.count or 0,
            "reports_generated": reports.count  or 0,
            "db_connected":      True,
        }
    except Exception as e:
        print(f"[DB] get_dashboard_stats error: {e}")
        return {
            "targets_analyzed":  0,
            "threats_detected":  0,
            "critical_findings": 0,
            "reports_generated": 0,
            "db_connected":      False,
        }


def get_recent_findings_for_dashboard(limit: int = 50) -> list:
    """Get recent findings for the dashboard timeline."""
    client = _get_client()
    if not client:
        return []

    try:
        resp = client.table("threat_findings") \
                     .select("phase, severity, created_at") \
                     .order("created_at", desc=True) \
                     .limit(limit) \
                     .execute()
        return resp.data or []
    except Exception as e:
        print(f"[DB] get_recent_findings error: {e}")
        return []


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Supabase connected: {is_connected()}")
    print(f"Schema SQL preview:\n{SCHEMA_SQL[:200]}...")

    stats = get_dashboard_stats()
    print(f"Dashboard stats: {stats}")