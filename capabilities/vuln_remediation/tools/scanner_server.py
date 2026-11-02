# palisade/capabilities/vuln_remediation/tools/scanner_server.py
"""Scanner tools. Read-only credentials to source, registries, cloud metadata."""
from typing import Literal

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("palisade-scanners")
ScanKind = Literal["sca", "sast", "container", "iac", "cspm"]


@mcp.tool()
def scanner_run(kind: ScanKind, target: str, config_version: str) -> dict:
    """Launch an asynchronous scan of one target under a pinned ruleset version."""
    return {"scan_id": _backend.launch(kind, target, config_version), "status": "queued"}


@mcp.tool()
def scanner_get_findings(scan_id: str) -> list[dict]:
    """Normalized Finding records for a completed scan, or [] while running."""
    return [_normalize(r).model_dump() for r in _backend.results(scan_id)]
