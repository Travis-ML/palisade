"""palisade/capabilities/knowledge_gardener/checks.py: deterministic staleness checks; the agent reasons only over findings."""
from __future__ import annotations

from datetime import timedelta
from typing import Literal

from pydantic import BaseModel, Field

from palisade.core.types import new_id, utcnow


class StalenessFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("stale"))
    check: str
    path: str                                  # knowledge item affected
    evidence: list[str]                        # tool results, by reference, that justify the finding
    severity: Literal["info", "warn", "high"]
    proposed_change: str                       # one paragraph; the agent expands it into a diff


def check_retired_tools(kb, registry) -> list[StalenessFinding]:
    live = {t.name for t in registry.tools()}
    out: list[StalenessFinding] = []
    for doc in kb.iter("runbooks/"):
        for name in doc.tool_references():
            if name not in live:
                out.append(StalenessFinding(check="retired_tool", path=doc.path, severity="high",
                                            evidence=[f"registry:{registry.version}", f"{doc.path}#L{doc.line_of(name)}"],
                                            proposed_change=f"replace `{name}` with its successor from the registry"))
    return out


def check_roe_expiry(roe_store, within: timedelta = timedelta(days=14)) -> list[StalenessFinding]:
    out: list[StalenessFinding] = []
    for roe in roe_store.all():
        if roe.is_active() and roe.not_after - utcnow() <= within:
            out.append(StalenessFinding(check="roe_expiring", path=f"roe/{roe.engagement_id}.yaml", severity="warn",
                                        evidence=[f"roe:{roe.engagement_id}:not_after={roe.not_after.isoformat()}"],
                                        proposed_change=f"draft renewal for owner {roe.owner}; no change to scope or ceilings"))
    return out


def check_dark_sources(siem, detections, days: int = 14) -> list[StalenessFinding]:
    out: list[StalenessFinding] = []
    for rule in detections.iter_sigma():
        if siem.event_count(rule.logsource, since=timedelta(days=days)) == 0:
            out.append(StalenessFinding(check="dark_logsource", path=rule.path, severity="high",
                                        evidence=[f"siem:{rule.logsource}:0 events in {days}d"],
                                        proposed_change="mark rule as unmonitored; ticket the pipeline owner"))
    return out
