# tests/test_mode_contract.py
"""Control C-13.1: select_mode (Chapter 13) and the policy (Chapter 14) agree for every tool at every tier."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from palisade.core.types import (ActionCeiling, ActionDomain, AgentIdentity, AutonomyTier, FiveQuestionIntent,
                                 PolicyDecision, ProposedAction, RulesOfEngagement, RunState, ScopeList)
from palisade.hitl.gate import HitlMode, select_mode
from palisade.policy.engine import PolicyEngine, PolicyInputBuilder
from palisade.roe import ceiling_for, sign_roe
from palisade.tools.catalog import TOOL_CATALOG, CatalogEntry

OPA_URL = os.environ.get("PALISADE_OPA_URL", "http://127.0.0.1:8181")
INTENT = FiveQuestionIntent(intent="contract test", necessity="n/a", harm="none", data="n/a", alternatives="n/a")
NOT_THE_TIER = ("tool.", "taxonomy.", "plane.", "roe.", "engine.", "intent.")


class _Stub:
    """Resolver and ledger stand-in: every target is in scope and nothing has happened recently."""

    def labels(self, target_id: str) -> list[str]:
        return ["tenant:t"]

    def recent(self, agent_id: str, within_seconds: int) -> list[dict[str, Any]]:
        return []


@pytest.fixture(scope="module")
def engine() -> PolicyEngine:
    try:
        httpx.get(OPA_URL + "/health", timeout=1.0).raise_for_status()
    except httpx.HTTPError:
        pytest.skip(f"no OPA server at {OPA_URL}; start it as in Lab 14, step 3")
    return PolicyEngine(OPA_URL)


def _decide(engine: PolicyEngine, entry: CatalogEntry, tier: AutonomyTier) -> PolicyDecision:
    now = datetime.now(timezone.utc)
    plane, ac = entry.plane, entry.action_class
    roe = sign_roe(
        RulesOfEngagement(
            engagement_id="eng_contract", name="contract", plane=plane, owner="owner", approvers=["owner"],
            stop_authorities=["owner"], scope=ScopeList(in_scope=["tenant:t"]),
            ceilings=[ActionCeiling(action_class=ac, max_tier=ceiling_for(ac, plane).max_tier)],
            not_before=now - timedelta(hours=1), not_after=now + timedelta(hours=1)),
        Ed25519PrivateKey.generate(), "contract-key")
    agent = AgentIdentity(agent_id="agent", display_name="agent", owner="owner", plane=plane,
                          recertify_by=now + timedelta(days=30))
    state = RunState(agent_id="agent", plane=plane, engagement_id="eng_contract", goal="contract test")
    action = ProposedAction(tool_name=entry.tool_name, arguments={}, action_class=ac, target_ids=["t1"], intent=INTENT)
    doc = PolicyInputBuilder(_Stub(), _Stub()).build(action, agent, tier, roe, state, int(time.time()))
    return engine.evaluate(doc)


def _family(mode: HitlMode) -> str:
    return "no_human" if mode in (HitlMode.ON_THE_LOOP, HitlMode.OVER_THE_LOOP) else mode.value


def _draft_under_review(entry: CatalogEntry, tier: AutonomyTier) -> bool:
    """An internal_change draft at tiers 2 and 3: the policy allows it, a human reviews it."""
    return (entry.action_class.domain is ActionDomain.INTERNAL_CHANGE
            and ceiling_for(entry.action_class, entry.plane).gate == "sample_review"
            and tier in (AutonomyTier.DRAFT, AutonomyTier.ACT_WITH_APPROVAL))


@pytest.mark.parametrize("tool_name", sorted(TOOL_CATALOG))
@pytest.mark.parametrize("tier", list(AutonomyTier), ids=lambda t: f"tier{int(t)}")
def test_select_mode_agrees_with_policy(engine: PolicyEngine, tool_name: str, tier: AutonomyTier) -> None:
    entry = TOOL_CATALOG[tool_name]
    decision = _decide(engine, entry, tier)

    off_tier = [r for r in decision.reasons if r.startswith(NOT_THE_TIER)]
    assert not off_tier, f"{tool_name} was refused for a reason other than its tier: {off_tier}"

    wanted = {"deny": "not_permitted", "escalate": "in_the_loop", "allow": "no_human"}[decision.verdict]
    if wanted == "no_human" and _draft_under_review(entry, tier):
        wanted = "in_the_loop"
    got = _family(select_mode(entry.action_class, tier))
    assert got == wanted, (f"{tool_name} ({entry.action_class.key()}) at tier {int(tier)}: select_mode says {got}, "
                           f"policy says {decision.verdict} by {decision.rule_id}")
