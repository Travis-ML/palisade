# palisade/capabilities/vuln_remediation/tools/intel_server.py
"""Exploit-intelligence tools. Read-only; trust tier VERIFIED."""
import json
import urllib.request
from functools import lru_cache

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("palisade-vuln-intel")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"


@lru_cache(maxsize=1)
def _kev() -> dict[str, dict]:
    with urllib.request.urlopen(KEV_URL, timeout=20) as r:
        return {v["cveID"]: v for v in json.load(r)["vulnerabilities"]}


@mcp.tool()
def kev_lookup(cve_id: str) -> dict:
    """CISA KEV entry for a CVE: in_kev, date_added, due_date, known_ransomware_use."""
    e = _kev().get(cve_id.upper())
    if e is None:
        return {"cve_id": cve_id, "in_kev": False}
    return {"cve_id": cve_id, "in_kev": True, "date_added": e["dateAdded"],
            "due_date": e["dueDate"],
            "known_ransomware_use": e.get("knownRansomwareCampaignUse") == "Known"}


@mcp.tool()
def epss_lookup(cve_id: str) -> dict:
    """FIRST EPSS score (30-day exploitation probability, 0 to 1), percentile,
    and as_of date; epss is None when the CVE is unscored."""
    with urllib.request.urlopen(EPSS_URL.format(cve=cve_id.upper()), timeout=20) as r:
        rows = json.load(r).get("data", [])
    return _epss_result(cve_id, rows[0] if rows else None)
