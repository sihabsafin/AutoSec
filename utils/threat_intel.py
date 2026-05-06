import requests
import time
import json
from typing import Optional

# ---------------------------------------------------------------------------
# NIST NVD Free API — no key required
# ---------------------------------------------------------------------------

NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HEADERS = {"User-Agent": "AutoSEC-Research-Tool/1.0"}


def _cvss_to_severity(score) -> str:
    if score is None:
        return "Unknown"
    score = float(score)
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"


def _extract_cvss(metrics: dict) -> Optional[float]:
    """Pull the best available CVSS base score from NVD metrics block."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except Exception:
                pass
    return None


def _parse_cve_entry(vuln: dict) -> dict:
    cve     = vuln.get("cve", {})
    metrics = cve.get("metrics", {})
    score   = _extract_cvss(metrics)

    descs = cve.get("descriptions", [])
    desc  = next((d["value"] for d in descs if d["lang"] == "en"), "No description available.")

    refs  = cve.get("references", [])
    ref_urls = [r.get("url", "") for r in refs[:3]]

    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwes.append(d.get("value", ""))

    return {
        "cve_id":      cve.get("id", ""),
        "description": desc[:400],
        "cvss_score":  score,
        "severity":    _cvss_to_severity(score),
        "published":   cve.get("published", "")[:10],
        "modified":    cve.get("lastModified", "")[:10],
        "references":  ref_urls,
        "cwe":         cwes[:3],
        "exploitable": score is not None and score >= 7.0,
    }


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def search_cves_by_keyword(keyword: str, max_results: int = 5) -> list:
    """
    Search NIST NVD for CVEs matching a keyword.
    Free API — no key needed. Rate limit: 5 req/30s without key.
    """
    if not keyword or not keyword.strip():
        return []

    try:
        resp = requests.get(
            NVD_BASE,
            params={
                "keywordSearch":  keyword.strip(),
                "resultsPerPage": max_results,
            },
            headers=NVD_HEADERS,
            timeout=15,
        )

        if resp.status_code == 200:
            data  = resp.json()
            vulns = data.get("vulnerabilities", [])
            return [_parse_cve_entry(v) for v in vulns]

        elif resp.status_code == 429:
            # Rate limited — wait and retry once
            time.sleep(6)
            resp2 = requests.get(
                NVD_BASE,
                params={"keywordSearch": keyword.strip(), "resultsPerPage": max_results},
                headers=NVD_HEADERS,
                timeout=15,
            )
            if resp2.status_code == 200:
                return [_parse_cve_entry(v) for v in resp2.json().get("vulnerabilities", [])]

    except requests.exceptions.Timeout:
        return [{"error": "NVD API timeout — try again in a moment"}]
    except Exception as e:
        return [{"error": f"NVD lookup failed: {str(e)}"}]

    return []


def get_cve_details(cve_id: str) -> dict:
    """
    Fetch full details for a specific CVE ID.
    Example: get_cve_details("CVE-2021-44228")
    """
    if not cve_id or not cve_id.strip():
        return {}

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    try:
        resp = requests.get(
            NVD_BASE,
            params={"cveId": cve_id},
            headers=NVD_HEADERS,
            timeout=15,
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                return _parse_cve_entry(vulns[0])
    except Exception as e:
        return {"error": f"CVE lookup failed: {str(e)}"}

    return {"error": f"{cve_id} not found in NVD"}


def search_cves_by_service(service: str, version: str = "", max_results: int = 5) -> list:
    """
    Search CVEs for a specific service/software version.
    Example: search_cves_by_service("OpenSSH", "7.2", 5)
    """
    keyword = f"{service} {version}".strip()
    results = search_cves_by_keyword(keyword, max_results)

    # Small delay to respect NVD rate limit
    time.sleep(1)
    return results


def bulk_cve_lookup(services: list, max_per_service: int = 3) -> dict:
    """
    Look up CVEs for multiple services from Nmap scan output.
    services = [{"service": "OpenSSH", "version": "7.2p2"}, ...]
    Returns dict keyed by service name.
    """
    results = {}

    for item in services[:8]:  # Max 8 services to avoid rate limiting
        service = item.get("service", "")
        version = item.get("version", "")
        port    = item.get("port", "")

        if not service or service in ("unknown", "tcpwrapped"):
            continue

        key     = f"{service}:{port}" if port else service
        cves    = search_cves_by_service(service, version, max_per_service)
        results[key] = {
            "service": service,
            "version": version,
            "port":    port,
            "cves":    cves,
            "critical_count": sum(1 for c in cves if c.get("severity") == "Critical"),
            "high_count":     sum(1 for c in cves if c.get("severity") == "High"),
        }

        # Respect NVD rate limit — max 5 req per 30s without API key
        time.sleep(2)

    return results


def get_threat_intel_summary(parsed_target: dict) -> dict:
    """
    Auto-pull CVE intel based on parsed target data.
    Called by VulnerabilityMapperAgent.
    """
    summary = {
        "cve_findings":   [],
        "service_vulns":  {},
        "total_cves":     0,
        "critical_count": 0,
        "high_count":     0,
        "top_cves":       [],
    }

    # Get open ports/services from nmap parse
    open_ports = parsed_target.get("open_ports", [])
    if open_ports:
        services = [
            {
                "service": p.get("service", ""),
                "version": p.get("version", ""),
                "port":    p.get("port", ""),
            }
            for p in open_ports
            if p.get("service") and p.get("service") not in ("unknown", "tcpwrapped")
        ]
        if services:
            summary["service_vulns"] = bulk_cve_lookup(services, max_per_service=3)

    # Also search any CVEs already mentioned in the input
    mentioned_cves = parsed_target.get("cve_references", [])
    for cve_id in mentioned_cves[:5]:
        detail = get_cve_details(cve_id)
        if detail and "error" not in detail:
            summary["cve_findings"].append(detail)
        time.sleep(1)

    # Aggregate counts
    all_cves = summary["cve_findings"].copy()
    for svc_data in summary["service_vulns"].values():
        all_cves.extend(svc_data.get("cves", []))

    summary["total_cves"]     = len(all_cves)
    summary["critical_count"] = sum(1 for c in all_cves if c.get("severity") == "Critical")
    summary["high_count"]     = sum(1 for c in all_cves if c.get("severity") == "High")
    summary["top_cves"]       = sorted(
        [c for c in all_cves if c.get("cvss_score") is not None],
        key=lambda x: x.get("cvss_score", 0),
        reverse=True
    )[:10]

    return summary


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Testing NIST NVD API...")

    print("\n1. Keyword search: 'OpenSSH'")
    results = search_cves_by_keyword("OpenSSH", max_results=2)
    for r in results:
        print(f"  {r.get('cve_id')} | {r.get('severity')} | CVSS: {r.get('cvss_score')}")

    print("\n2. CVE details: CVE-2021-44228 (Log4Shell)")
    detail = get_cve_details("CVE-2021-44228")
    print(f"  {detail.get('cve_id')} | {detail.get('severity')} | {detail.get('description', '')[:80]}...")

    print("\nNVD API test complete.")