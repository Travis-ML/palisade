# palisade/capabilities/response/tools/common.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ToolResult(BaseModel):
    """What every response tool returns. The reversal is a ready-to-run call, not a description of one."""
    status: Literal["ok", "error"]
    effect_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    preconditions: dict[str, Any] = Field(default_factory=dict)   # facts the approver and the ledger should see
    reversal: Optional[dict[str, Any]] = None                      # {"tool_name": ..., "arguments": {...}}
    summary: str = ""
    error: Optional[str] = None


@dataclass
class Containment:
    target: str
    effect_id: str
    expires_at: datetime
    warned: bool = False


class ContainmentRegistry:
    """Tracks live containments so a TTL becomes a human decision instead of a silent release.

    Hosts and accounts hold past expiry (kind != "fw_indicator"); the registry only reports what is due.
    Warning is idempotent: each containment warns once.
    """

    def __init__(self, kind: str, warn_before: timedelta, emit: Callable[[str, dict[str, Any]], None] | None = None,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.kind, self.warn_before, self._clock = kind, warn_before, clock
        self._emit = emit or (lambda name, detail: None)
        self._live: dict[str, Containment] = {}

    def track(self, target: str, effect_id: str, expires_at: datetime) -> None:
        self._live[target] = Containment(target, effect_id, expires_at)

    def close(self, target: str) -> None:
        self._live.pop(target, None)

    def live(self) -> list[Containment]:
        return list(self._live.values())

    def sweep(self) -> list[Containment]:
        """Emit containment.ttl_expiring once for each containment inside the warning window or past expiry.
        The caller opens the renewal decision and pages; nothing here releases anything."""
        now, due = self._clock(), []
        for c in self._live.values():
            if not c.warned and now >= c.expires_at - self.warn_before:
                c.warned = True
                self._emit("containment.ttl_expiring", {"kind": self.kind, "target": c.target, "effect_id": c.effect_id,
                                                        "expires_at": c.expires_at.isoformat()})
                due.append(c)
        return due
