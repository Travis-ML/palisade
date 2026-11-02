# palisade/capabilities/alert_triage/models.py
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable, Literal, Optional

from pydantic import BaseModel, Field

from palisade.core.types import DecisionRecord, Hypothesis, TrustTier


class Alert(BaseModel):
    alert_id: str
    tenant_id: str
    source: str
    detection_family: str
    rule_id: str
    severity: Literal["low", "medium", "high", "critical"]
    observed_at: datetime
    host_id: Optional[str] = None
    user_id: Optional[str] = None
    fields: dict[str, Any] = Field(default_factory=dict)      # everything here is attacker-influenceable
    trust_tier: TrustTier = TrustTier.UNTRUSTED

    def content_hash(self) -> str:
        body = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


def evidence_id_for(result_hash: str) -> str:
    """The same derivation the approval screen uses (Chapter 13), so a replayed run cites the same ids."""
    return f"ev_{result_hash[:8]}"


class Evidence(BaseModel):
    """One governed read, citable by id, pointing at the DecisionRecord that produced it."""
    evidence_id: str
    tool_name: str
    arguments_redacted: dict[str, Any]
    summary: str
    result_hash: str
    trust_tier: TrustTier
    observed_at: datetime
    record_hash: str


class CorrelationSet(BaseModel):
    cluster_key: str
    window_minutes: int
    related_alert_ids: list[str] = Field(default_factory=list)
    distinct_hosts: list[str] = Field(default_factory=list)
    distinct_users: list[str] = Field(default_factory=list)

    @classmethod
    def from_rows(cls, alert: Alert, rows: Iterable[dict[str, Any]], window_minutes: int) -> "CorrelationSet":
        """Rows are the bounded siem_query result the gateway retained: alert_id, host_id, user_id per row."""
        related = [r for r in rows if r.get("alert_id") != alert.alert_id]
        return cls(
            cluster_key=f"{alert.tenant_id}:{alert.host_id or alert.user_id or alert.rule_id}",
            window_minutes=window_minutes,
            related_alert_ids=sorted({str(r["alert_id"]) for r in related if r.get("alert_id")}),
            distinct_hosts=sorted({str(r["host_id"]) for r in related if r.get("host_id")}),
            distinct_users=sorted({str(r["user_id"]) for r in related if r.get("user_id")}),
        )


class ValidationQuery(BaseModel):
    hypothesis_label: Literal["benign", "suspicious", "malicious"]
    tool_name: str                       # run only if it is on the read surface
    arguments: dict[str, Any]
    expectation: str                     # what the result should look like if the hypothesis is true


class HypothesisSet(BaseModel):
    hypotheses: list[Hypothesis] = Field(min_length=2, max_length=5)
    validation_queries: list[ValidationQuery] = Field(default_factory=list, max_length=6)

    def top_two_gap(self) -> float:
        weights = sorted((h.weight for h in self.hypotheses), reverse=True)
        return weights[0] - weights[1]


class VerdictDraft(BaseModel):
    """Structured output of the Verdict step, before verification."""
    chosen: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_weighting: str
    cited_evidence: list[str] = Field(default_factory=list)
    recommended_tool: Optional[str] = None
    recommended_arguments: dict[str, Any] = Field(default_factory=dict)
    recommendation_rationale: str = ""


class QueryTemplates(BaseModel):
    """Named, parameterized SIEM queries from the capability settings. The model never writes query text."""
    host_24h: str
    related_alerts: str


def fanout_plan(alert: Alert, queries: QueryTemplates, max_indicators: int = 5) -> list[tuple[str, dict[str, Any], list[str]]]:
    """The enrichment calls for one alert as (tool, arguments, targets): the host's EDR record and a 24h SIEM
    query, the user's identity record, and a lookup per indicator, at most five. The workflow runs them in parallel."""
    tenant = alert.tenant_id
    plan: list[tuple[str, dict[str, Any], list[str]]] = []
    if alert.host_id:
        plan.append(("edr_get_host", {"host_id": alert.host_id}, [f"tenant:{tenant}:host:{alert.host_id}"]))
        plan.append(("siem_query", {"query": queries.host_24h, "max_rows": 100,
                                    "params": {"host": alert.host_id, "window_h": 24}}, [f"tenant:{tenant}:*"]))
    if alert.user_id:
        plan.append(("idp_get_user", {"user_id": alert.user_id}, [f"tenant:{tenant}:user:{alert.user_id}"]))
    seen: list[str] = []
    for value in alert.fields.get("indicators", []):
        if isinstance(value, str) and value and value not in seen:
            seen.append(value)
    for indicator in seen[:max_indicators]:
        plan.append(("ti_lookup_indicator", {"indicator": indicator}, [f"tenant:{tenant}:indicator:{indicator}"]))
    return plan


def evidence_from_records(records: Iterable[DecisionRecord]) -> list[Evidence]:
    """Rebuild the evidence list from a replayed run: one item per executed read, in ledger order."""
    out: list[Evidence] = []
    for r in records:
        if r.proposed_action is None or r.execution is None or r.execution.status != "ok":
            continue
        out.append(Evidence(
            evidence_id=evidence_id_for(r.execution.result_hash), tool_name=r.proposed_action.tool_name,
            arguments_redacted=r.proposed_action.arguments, summary=r.execution.result_summary,
            result_hash=r.execution.result_hash, trust_tier=TrustTier.UNTRUSTED,
            observed_at=r.execution.executed_at, record_hash=r.record_hash))
    return out
