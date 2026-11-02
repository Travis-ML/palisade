"""palisade/deploy/ladder.py: the autonomy ladder as enforced state."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, Field

from palisade.core.types import (
    ActionClass, ActionDomain, ApprovalRecord, AutonomyTier, BlastRadius, DecisionRecord,
    Plane, PolicyDecision, ProposedAction, Reversibility, new_id, utcnow,
)
from palisade.hitl.killswitch import KillSwitch
from palisade.ledger.ledger import Ledger

GOVERNANCE_AGENT = "spiffe://palisade.example/agent/governance"
TIER_CHANGE_CLASS = ActionClass(domain=ActionDomain.INTERNAL_CHANGE,
                                reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.GROUP)


def ceiling_for(ac: ActionClass) -> AutonomyTier:
    """Control C-26.1: the permanent ceiling for an action class. Single source of truth."""
    if ac.domain == ActionDomain.OFFENSE:
        return AutonomyTier.ACT_WITHIN_SCOPE            # bounded, inside the range; plane binding does the rest
    if ac.reversibility == Reversibility.IRREVERSIBLE or ac.blast_radius == BlastRadius.ENTERPRISE:
        return AutonomyTier.ACT_WITH_APPROVAL           # permanent, whatever the model becomes
    if ac.domain == ActionDomain.PRODUCTION_CONTROL:
        return AutonomyTier.ACT_WITH_APPROVAL if ac.blast_radius == BlastRadius.GROUP else AutonomyTier.ACT_WITHIN_SCOPE
    if ac.domain == ActionDomain.INTERNAL_CHANGE:
        return AutonomyTier.ACT_WITHIN_SCOPE if ac.blast_radius == BlastRadius.SINGLE else AutonomyTier.ACT_WITH_APPROVAL
    return AutonomyTier.AUTONOMOUS                      # observe, enrich


class EvidenceBundle(BaseModel):
    """Every field is a ledger query result or an eval report reference. Nothing here is prose."""
    window_start: datetime
    window_end: datetime
    sample_size: int
    agreement_rate: float = Field(ge=0, le=1)
    agreement_ci_low: float = Field(ge=0, le=1)
    worst_family: str = ""
    worst_family_agreement: float = Field(default=0.0, ge=0, le=1)
    acceptance_rate: float = Field(default=0.0, ge=0, le=1)
    merge_rate: float = Field(default=0.0, ge=0, le=1)
    regression_rate: float = Field(default=0.0, ge=0, le=1)
    override_rate: float = Field(default=0.0, ge=0, le=1)
    unsafe_executions: int = 0
    self_inflicted_outages: int = 0
    eval_report_id: str
    eval_passed: bool
    adversarial_passed: bool
    manifest_id: str
    open_red_team_findings_high: int = 0
    drift_alarm_active: bool = False
    blast_radius_analysis: str          # a reference to the written analysis, not the analysis itself


class ChecklistItem(BaseModel):
    item_id: str
    statement: str
    threshold: str
    measured: str
    passed: bool
    evidence_ref: str


def build_checklist(to_tier: AutonomyTier, ev: EvidenceBundle) -> list[ChecklistItem]:
    weeks = (ev.window_end - ev.window_start).days / 7
    common = [
        ChecklistItem(item_id="eval", statement="eval gate passed on the deployed manifest, adversarial set included",
                      threshold="pass", measured=f"eval={ev.eval_passed} adversarial={ev.adversarial_passed}",
                      passed=ev.eval_passed and ev.adversarial_passed, evidence_ref=ev.eval_report_id),
        ChecklistItem(item_id="unsafe", statement="zero unsafe executions in window", threshold="0",
                      measured=str(ev.unsafe_executions), passed=ev.unsafe_executions == 0, evidence_ref="ledger:replay"),
        ChecklistItem(item_id="outage", statement="zero self-inflicted outages", threshold="0",
                      measured=str(ev.self_inflicted_outages), passed=ev.self_inflicted_outages == 0, evidence_ref="ledger:incidents"),
        ChecklistItem(item_id="drift", statement="no active drift alarm", threshold="false",
                      measured=str(ev.drift_alarm_active), passed=not ev.drift_alarm_active, evidence_ref="dashboard:drift"),
    ]
    per_rung: dict[AutonomyTier, list[ChecklistItem]] = {
        AutonomyTier.SUGGEST: [
            ChecklistItem(item_id="agree", statement="agreement >= 0.90, Wilson lower bound >= 0.85, every family",
                          threshold=">=0.90 / >=0.85", measured=f"{ev.agreement_rate:.3f} / {ev.agreement_ci_low:.3f}; worst {ev.worst_family}={ev.worst_family_agreement:.2f}",
                          passed=ev.agreement_rate >= 0.90 and ev.agreement_ci_low >= 0.85 and ev.worst_family_agreement >= 0.90,
                          evidence_ref="shadow:by_family"),
            ChecklistItem(item_id="window", statement="n >= 200 and >= 4 weeks", threshold="200 / 4w",
                          measured=f"{ev.sample_size} / {weeks:.1f}w", passed=ev.sample_size >= 200 and weeks >= 4, evidence_ref="shadow:window"),
        ],
        AutonomyTier.DRAFT: [
            ChecklistItem(item_id="accept", statement="acceptance >= 0.80 over >= 4 weeks", threshold=">=0.80",
                          measured=f"{ev.acceptance_rate:.3f} over {weeks:.1f}w", passed=ev.acceptance_rate >= 0.80 and weeks >= 4, evidence_ref="ledger:suggestions"),
        ],
        AutonomyTier.ACT_WITH_APPROVAL: [
            ChecklistItem(item_id="merge", statement="merge rate >= 0.75 and regression <= 0.02 over >= 6 weeks", threshold=">=0.75 / <=0.02",
                          measured=f"{ev.merge_rate:.3f} / {ev.regression_rate:.3f} over {weeks:.1f}w",
                          passed=ev.merge_rate >= 0.75 and ev.regression_rate <= 0.02 and weeks >= 6, evidence_ref="ledger:artifacts"),
        ],
        AutonomyTier.ACT_WITHIN_SCOPE: [
            ChecklistItem(item_id="override", statement="override <= 0.05 over >= 8 weeks and >= 100 gated actions", threshold="<=0.05",
                          measured=f"{ev.override_rate:.3f} over {weeks:.1f}w, n={ev.sample_size}",
                          passed=ev.override_rate <= 0.05 and weeks >= 8 and ev.sample_size >= 100, evidence_ref="ledger:approvals"),
        ],
        AutonomyTier.AUTONOMOUS: [
            ChecklistItem(item_id="sustained", statement="override <= 0.02 over >= 12 weeks; no open High red-team findings", threshold="<=0.02 / 0",
                          measured=f"{ev.override_rate:.3f} over {weeks:.1f}w / {ev.open_red_team_findings_high}",
                          passed=ev.override_rate <= 0.02 and weeks >= 12 and ev.open_red_team_findings_high == 0, evidence_ref="ledger:approvals;redteam:open"),
        ],
    }
    return common + per_rung.get(to_tier, [])


class PromotionRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: new_id("prm"))
    capability: str
    plane: Plane
    action_class: ActionClass
    from_tier: AutonomyTier
    to_tier: AutonomyTier
    requested_by: str                                  # the capability owner, never the decider
    evidence: EvidenceBundle
    checklist: list[ChecklistItem] = Field(default_factory=list)
    decision: Optional[Literal["approved", "denied", "deferred"]] = None
    decided_by: Optional[str] = None
    justification: str = ""                            # required when any checklist item failed
    created_at: datetime = Field(default_factory=utcnow)

    def validate_shape(self) -> None:
        if self.to_tier != self.from_tier + 1:
            raise ValueError("promotions move exactly one rung")
        if self.to_tier > ceiling_for(self.action_class):
            raise ValueError(f"{self.action_class.key()} is capped at {ceiling_for(self.action_class).name} permanently")

    def all_passed(self) -> bool:
        return all(item.passed for item in self.checklist)


class TierRegistry:
    """Effective tier per (capability, action class). The gateway reads it; the policy engine gets it as data."""

    def __init__(self, ledger: Ledger, killswitch: KillSwitch, fallback_path: Path) -> None:
        self._tiers: dict[tuple[str, str], AutonomyTier] = {}
        self.ledger, self.killswitch, self.fallback_path = ledger, killswitch, fallback_path
        self.revision = 0

    def effective(self, capability: str, action_class: ActionClass) -> AutonomyTier:
        return self._tiers.get((capability, action_class.key()), AutonomyTier.SHADOW)   # unknown means shadow

    def as_policy_data(self) -> dict:
        tiers: dict[str, dict[str, int]] = {}
        for (cap, key), tier in self._tiers.items():
            tiers.setdefault(cap, {})[key] = int(tier)
        ceilings = {key: int(ceiling_for(ActionClass(**dict(zip(("domain", "reversibility", "blast_radius"), key.split(":"))))))
                    for (_, key) in self._tiers}
        return {"ladder": {"tiers": tiers, "ceilings": ceilings, "revision": self.revision}}

    def _record(self, rec: DecisionRecord) -> str:
        try:
            return self.ledger.append(rec)
        except Exception as exc:                          # the ledger is down; lowering autonomy must not wait for it
            with self.fallback_path.open("a") as fh:
                fh.write(rec.model_dump_json() + "\n")
            raise RuntimeError(f"tier change applied; ledger unreachable ({exc}); fallback written; reconcile required")

    def promote(self, req: PromotionRequest, approval: ApprovalRecord) -> str:
        req.validate_shape()
        if not req.all_passed() and not req.justification.strip():
            raise ValueError("a failed checklist item requires a written justification from the decider")
        if approval.decision != "approved":
            raise PermissionError("promotion not approved")
        if approval.approver_id == req.requested_by:
            raise PermissionError("the requester cannot approve their own promotion")
        self._tiers[(req.capability, req.action_class.key())] = req.to_tier
        self.revision += 1
        rec = DecisionRecord(
            run_id=new_id("gov"), step=0, agent_id=GOVERNANCE_AGENT, plane=req.plane, engagement_id=None,
            autonomy_tier=AutonomyTier.ACT_WITH_APPROVAL, context_hash=approval.presented_context_hash,
            reasoning_summary=f"promotion {req.from_tier.name}->{req.to_tier.name} for {req.capability}/{req.action_class.key()}",
            proposed_action=ProposedAction(tool_name="harness_set_tier", arguments=req.model_dump(mode="json"),
                                           action_class=TIER_CHANGE_CLASS, target_ids=[req.capability]),
            policy_decision=PolicyDecision(verdict="escalate", rule_id="ladder.promotion.requires_human",
                                           required_tier=AutonomyTier.ACT_WITH_APPROVAL, effective_tier=AutonomyTier.ACT_WITH_APPROVAL),
            approval=approval,
        )
        return self._record(rec)

    def drop_to_shadow(self, scope: str, by: str, reason: str) -> str:
        """Control C-26.3. Acts first, records second: lowering autonomy is the fail-safe direction."""
        keys = [k for k in self._tiers if scope == "all" or k[0] == scope]
        for k in keys:
            self._tiers[k] = AutonomyTier.SHADOW
        self.revision += 1
        self.killswitch.trip(scope=scope, by=by, reason=reason)      # halts in-flight runs and revokes grants
        rec = DecisionRecord(
            run_id=new_id("gov"), step=0, agent_id=GOVERNANCE_AGENT, plane=Plane.DEFENSIVE, engagement_id=None,
            autonomy_tier=AutonomyTier.SHADOW, context_hash="", reasoning_summary=f"drop to rung 0: scope={scope}; {reason}",
            proposed_action=ProposedAction(tool_name="harness_set_tier", arguments={"scope": scope, "to": 0, "by": by},
                                           action_class=TIER_CHANGE_CLASS, target_ids=[k[0] for k in keys]),
            policy_decision=PolicyDecision(verdict="allow", rule_id="ladder.drop.always_allowed",
                                           required_tier=AutonomyTier.SHADOW, effective_tier=AutonomyTier.SHADOW),
            human_intervention="kill",
        )
        return self._record(rec)
