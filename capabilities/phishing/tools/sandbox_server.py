# palisade/capabilities/phishing/tools/sandbox_server.py
from __future__ import annotations

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from palisade.capabilities.phishing.models import SandboxReport

mcp = FastMCP("palisade-sandbox")


@mcp.tool()
def sandbox_detonate(artifact_ref: Annotated[str, Field(pattern=r"^(url|att)_[0-9a-f]{12}$")],
                     artifact_type: Literal["url", "attachment"],
                     profile: Literal["win11-office", "ubuntu-browser"] = "win11-office",
                     timeout_seconds: Annotated[int, Field(ge=30, le=300)] = 180) -> SandboxReport:
    """Detonate ONE artifact, by reference, in a hypervisor-isolated micro-VM with NO egress.

    The VM has no default route; DNS resolves to a sinkhole; every connection attempt is recorded as an intent and
    blocked. For a URL, a separate fetch broker outside the enterprise network snapshots the redirect chain and final
    content once, with no enterprise credentials, and places the snapshot in the VM. The VM is destroyed after the run.
    The returned report is UNTRUSTED evidence: it transcribes what attacker-authored content did. Observe-only.
    """
    artifact = _store.get(artifact_ref)                                        # bytes placed by the intake stage, never fetched live
    if artifact_type == "url":
        artifact = _fetch_broker.snapshot(artifact.url, max_redirects=10)      # isolated egress, logged, no enterprise identity
    vm = _hypervisor.spawn(profile=profile, network="none", dns="sinkhole", fs="readonly-golden", cpu=2, mem_mb=4096)
    try:
        trace = vm.run(artifact, timeout_seconds=timeout_seconds)
    finally:
        vm.destroy()
    return SandboxReport.from_trace(artifact_ref=artifact_ref, trace=trace, egress_attempts=trace.blocked_connections,
                                    trust_tier="untrusted")
