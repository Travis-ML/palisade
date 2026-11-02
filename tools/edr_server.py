"""
palisade.tools.edr_server
=========================

EDR tools as an MCP server (FastMCP): look up, isolate for a bounded time,
release early. The server enforces the TTL range, protected roles, and
automatic release. None of that is negotiable from the prompt.
"""

from __future__ import annotations

import asyncio
import os
from datetime import timedelta
from typing import Annotated, Literal, Optional, Protocol

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from palisade.core.types import FiveQuestionIntent, utcnow

mcp = FastMCP("palisade-edr")

MIN_TTL_MINUTES = 15
MAX_TTL_MINUTES = 240
PROTECTED_ROLES = {"domain_controller"}   # this tool cannot express isolating these

HostId = Annotated[
    str,
    Field(pattern=r"^host-\d{4,6}$", description="Absolute EDR host identifier, e.g. host-4471"),
]


class HostRecord(BaseModel):
    host_id: str
    hostname: str
    role: Literal["workstation", "server", "domain_controller", "jump_host", "unknown"]
    criticality: Literal["tier0", "tier1", "tier2", "tier3"]
    owner_team: str
    isolation_state: Literal["normal", "isolated"]
    isolated_until: Optional[str] = None
    last_seen: str
    open_alerts: int


class IsolationResult(BaseModel):
    host_id: str
    isolation_state: Literal["isolated"]
    isolated_at: str
    isolated_until: str
    release_scheduled: bool
    preconditions: dict[str, str]


class EdrBackend(Protocol):
    """Vendor adapter (CrowdStrike, Defender, SentinelOne, or the lab fake)."""

    async def get_host(self, host_id: str) -> HostRecord: ...
    async def isolate(self, host_id: str) -> None: ...
    async def release(self, host_id: str) -> None: ...


_backend: EdrBackend
_release_timers: dict[str, asyncio.TimerHandle] = {}


@mcp.tool(
    name="edr_get_host",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                idempotentHint=True, openWorldHint=False),
)
async def edr_get_host(host_id: HostId) -> HostRecord:
    """Return the EDR record for one host: role, criticality, owner team,
    isolation state, open alerts. Read-only. Call this before any containment
    action so the preconditions are in context."""
    return await _backend.get_host(host_id)


@mcp.tool(
    name="edr_isolate_host",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                idempotentHint=True, openWorldHint=False),
)
async def edr_isolate_host(
    host_id: HostId,
    ttl_minutes: Annotated[int, Field(ge=MIN_TTL_MINUTES, le=MAX_TTL_MINUTES,
                                      description="Isolation auto-releases after this many minutes")],
    reason: Annotated[str, Field(min_length=20, max_length=500,
                                 description="One-paragraph reason, cited to evidence")],
    intent: FiveQuestionIntent,
) -> IsolationResult:
    """Network-isolate ONE host for a bounded time. Semi-reversible, single-object,
    production control. The server releases the isolation when ttl_minutes expires;
    there is no indefinite isolation. Domain controllers cannot be isolated with this
    tool. Requires the five-question intent."""
    host = await _backend.get_host(host_id)
    if host.role in PROTECTED_ROLES:
        raise ToolError(f"{host_id} has role {host.role}; this tool cannot isolate protected "
                        f"roles. Escalate to a human with the evidence.")
    if host.isolation_state == "isolated":
        raise ToolError(f"{host_id} is already isolated until {host.isolated_until}.")

    await _backend.isolate(host_id)
    now = utcnow()
    until = now + timedelta(minutes=ttl_minutes)
    _schedule_release(host_id, ttl_minutes * 60)
    return IsolationResult(
        host_id=host_id,
        isolation_state="isolated",
        isolated_at=now.isoformat(),
        isolated_until=until.isoformat(),
        release_scheduled=True,
        preconditions={
            "role": host.role,
            "criticality": host.criticality,
            "owner_team": host.owner_team,
            "open_alerts": str(host.open_alerts),
        },
    )


@mcp.tool(name="edr_release_host",
          annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                      idempotentHint=True, openWorldHint=False))
async def edr_release_host(host_id: HostId,
                           reason: Annotated[str, Field(min_length=10, max_length=500)]) -> HostRecord:
    """Release one host from isolation early. Reversible; it undoes edr_isolate_host."""
    await _backend.release(host_id)
    _cancel_release(host_id)
    return await _backend.get_host(host_id)


def _schedule_release(host_id: str, seconds: int) -> None:
    loop = asyncio.get_running_loop()
    _cancel_release(host_id)
    _release_timers[host_id] = loop.call_later(
        seconds, lambda: asyncio.ensure_future(_backend.release(host_id)))


def _cancel_release(host_id: str) -> None:
    handle = _release_timers.pop(host_id, None)
    if handle is not None:
        handle.cancel()


def serve(backend: EdrBackend) -> None:
    global _backend
    _backend = backend
    mcp.run(transport=os.environ.get("PALISADE_MCP_TRANSPORT", "stdio"))   # or "streamable-http"
