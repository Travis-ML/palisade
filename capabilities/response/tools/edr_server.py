# palisade/capabilities/response/tools/edr_server.py
from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from palisade.capabilities.response.tools.common import ContainmentRegistry, ToolResult, utcnow

mcp = FastMCP("palisade-edr-response")
registry = ContainmentRegistry(kind="edr_isolation", warn_before=timedelta(minutes=30))
HostId = Annotated[str, Field(pattern=r"^host-[0-9]{4}$")]


@mcp.tool()
def edr_isolate_host(host_id: HostId, ttl_minutes: Annotated[int, Field(ge=15, le=1440)], reason: str) -> ToolResult:
    """Network-isolate ONE host by absolute host id for at most ttl_minutes.

    Semi-reversible, single-object, production control. Isolation holds past expiry until a human renews or
    releases; expiry opens that decision and pages. Returns the host's role and owner as preconditions and the
    exact edr_release_host call that reverses it. Servers and domain controllers are refused at the gateway by
    the RoE regardless of this server's behavior.
    """
    host = _edr.get_host(host_id)                       # read-only lookup; raises if unknown
    effect = _edr.isolate(host_id, comment=reason)      # the one privileged call this server can make
    expires = utcnow() + timedelta(minutes=ttl_minutes)
    registry.track(target=host_id, effect_id=effect.id, expires_at=expires)
    return ToolResult(
        status="ok", effect_id=effect.id, expires_at=expires,
        preconditions={"role": host.role, "owner": host.owner, "online": host.online, "last_seen": host.last_seen},
        reversal={"tool_name": "edr_release_host", "arguments": {"host_id": host_id, "reason": f"release of {effect.id}"}},
        summary=f"{host_id} ({host.role}) isolated until {expires.isoformat()}",
    )


@mcp.tool()
def edr_release_host(host_id: HostId, reason: str) -> ToolResult:
    """Release ONE host from isolation. Reversible, single-object. Closes the matching containment record."""
    effect = _edr.release(host_id, comment=reason)
    registry.close(target=host_id)
    return ToolResult(status="ok", effect_id=effect.id, expires_at=None, preconditions={}, summary=f"{host_id} released",
                      reversal={"tool_name": "edr_isolate_host", "arguments": {"host_id": host_id, "ttl_minutes": 240, "reason": "re-isolate"}})
