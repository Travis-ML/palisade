# palisade/policy/engine.py
from __future__ import annotations
from typing import Any, Protocol
import httpx
from pydantic import ValidationError
from palisade.core.types import (AgentIdentity, AutonomyTier, PolicyDecision, ProposedAction,
                                 RulesOfEngagement, RunState)
from palisade.roe import prefer_reversible, scope_labels

class TargetResolver(Protocol):           # canonical group memberships from the asset inventory (Chapter 8)
    def labels(self, target_id: str) -> list[str]: ...

class RecentActions(Protocol):            # reads the ledger for the rate-limit window
    def recent(self, agent_id: str, within_seconds: int) -> list[dict[str, Any]]: ...

class PolicyInputBuilder:
    def __init__(self, resolver: TargetResolver, recent: RecentActions, window_seconds: int = 3600) -> None:
        self._resolver, self._recent, self._window = resolver, recent, window_seconds

    def _labels(self, target: str, roe: RulesOfEngagement | None) -> list[str]:
        labels = list(self._resolver.labels(target))
        if roe is not None:                  # Chapter 11: the RoE entries any identifier of this object matches
            for identifier in (target, *labels):
                labels += [e for e in scope_labels(roe, identifier) if e not in labels]
        return labels

    def build(self, action: ProposedAction, agent: AgentIdentity, effective_tier: AutonomyTier,
              roe: RulesOfEngagement | None, state: RunState, now_epoch: int,
              flagged_context: bool = False) -> dict[str, Any]:
        roe_doc: dict[str, Any] = {"active": False}
        if roe is not None:
            roe_doc = {
                "engagement_id": roe.engagement_id, "plane": roe.plane.value, "active": roe.is_active(),
                "not_before_epoch": int(roe.not_before.timestamp()),
                "not_after_epoch": int(roe.not_after.timestamp()),
                "scope": roe.scope.model_dump(),
                "ceilings": [{"action_class": c.action_class.model_dump(mode="json"),
                              "max_tier": int(c.max_tier), "rate_limit": c.rate_limit} for c in roe.ceilings],
            }
        action_doc: dict[str, Any] = {
            "tool_name": action.tool_name,
            "action_class": action.action_class.model_dump(mode="json"),
            "targets": [{"id": t, "labels": self._labels(t, roe)} for t in action.target_ids],
            "arguments": action.arguments,
        }
        if action.intent is not None:        # omit the key when absent; the policy also treats null as missing
            action_doc["intent"] = action.intent.model_dump()
        sibling = prefer_reversible(action)  # Chapter 11: the reversible counterpart, if the tool has one
        if sibling is not None:
            action_doc["reversible_alternative"] = sibling
        return {
            "action": action_doc,
            "agent": {"agent_id": agent.agent_id, "plane": agent.plane.value, "effective_tier": int(effective_tier)},
            "roe": roe_doc,
            "state": {"engagement_id": state.engagement_id, "now_epoch": now_epoch,
                      "recent_actions": self._recent.recent(agent.agent_id, self._window),
                      "flagged_context": flagged_context},      # Section 14.2.2: did the screen flag this step's context?
        }

class PolicyEngine:
    def __init__(self, base_url: str = "http://opa:8181",
                 path: str = "/v1/data/palisade/authz/decision", timeout_s: float = 1.5) -> None:
        self._url = base_url.rstrip("/") + path
        self._client = httpx.Client(timeout=timeout_s)

    def evaluate(self, input: dict[str, Any]) -> PolicyDecision:
        try:
            resp = self._client.post(self._url, json={"input": input})
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            return self._unavailable(f"{type(exc).__name__}: {exc}", input)   # transport: fail closed

        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            # OPA answered, but nothing is at the policy path (bundle not loaded, wrong package).
            return self._unavailable("no result at policy path", input)

        try:
            return PolicyDecision.model_validate(result)
        except ValidationError as exc:
            return PolicyDecision(
                verdict="deny", rule_id="engine.malformed",
                reasons=[f"decision does not match PolicyDecision: {exc.error_count()} error(s)"],
                required_tier=AutonomyTier.AUTONOMOUS, effective_tier=AutonomyTier.SHADOW,
                evaluated_inputs={"raw": result})

    @staticmethod
    def _unavailable(reason: str, input: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision(
            verdict="deny", rule_id="engine.unavailable",
            reasons=[f"policy engine unreachable or unusable: {reason}"],
            required_tier=AutonomyTier.AUTONOMOUS, effective_tier=AutonomyTier.SHADOW,
            evaluated_inputs={"tool_name": input.get("action", {}).get("tool_name")})
