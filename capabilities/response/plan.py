# palisade/capabilities/response/plan.py
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, ValidationError

from palisade.core.types import ActionClass, FiveQuestionIntent, ProposedAction, Reversibility
from palisade.capabilities.response.library import LIBRARY, reversible_sibling, is_host_tool


class PlanStep(BaseModel):
    step_id: str
    tool_name: str
    arguments: dict[str, Any]
    depends_on: list[str] = Field(default_factory=list)
    rationale: str
    intent: Optional[FiveQuestionIntent] = None      # required by the validator for irreversible or escalated steps
    # filled by the validator, never by the agent:
    action_class: Optional[ActionClass] = None
    target_ids: list[str] = Field(default_factory=list)
    staged: bool = False
    requires_approval: bool = False
    reversal: Optional[dict[str, Any]] = None


class ResponsePlan(BaseModel):
    plan_id: str
    verdict_id: str
    objective: str
    steps: list[PlanStep] = Field(min_length=1, max_length=12)
    abort_conditions: list[str] = Field(default_factory=list)
    revision: int = 0


def in_dependency_order(steps: list[PlanStep]) -> list[PlanStep]:
    """Each step after everything it depends on; ties keep the plan's order. An unknown dependency or a
    cycle is a malformed plan and raises ValueError, which the validator turns into a rejection."""
    ids = {s.step_id for s in steps}
    unknown = sorted({d for s in steps for d in s.depends_on} - ids)
    if unknown:
        raise ValueError(f"unknown dependency {unknown}")
    ordered: list[PlanStep] = []
    placed: set[str] = set()
    remaining = list(steps)
    while remaining:
        ready = next((s for s in remaining if all(d in placed for d in s.depends_on)), None)
        if ready is None:
            raise ValueError("dependency cycle")
        remaining.remove(ready)
        placed.add(ready.step_id)
        ordered.append(ready)
    return ordered


class PlanRejected(Exception):
    """Carries the list of reasons; the caller records them and returns them to the planner for revision."""


class PlanValidator:
    """Stages 1 through 8 of Section 21.4. The plan does not exist for the executor until this returns it."""

    def __init__(self, gateway, planner_identity, resolver, settings) -> None:
        self.gateway, self.planner, self.resolver, self.settings = gateway, planner_identity, resolver, settings

    def validate(self, raw: dict[str, Any], state) -> ResponsePlan:
        try:
            plan = ResponsePlan.model_validate(raw)                                   # 1. schema
        except ValidationError as e:
            raise PlanRejected([f"plan.schema:{e.error_count()} errors"])
        try:
            in_dependency_order(plan.steps)                                           # 1b. dependencies resolve, no cycle
        except ValueError as e:
            raise PlanRejected([f"plan.dependencies:{e}"])
        reasons: list[str] = []
        by_id = {s.step_id: s for s in plan.steps}
        for s in plan.steps:
            spec = LIBRARY.get(s.tool_name)
            if spec is None:                                                           # 2. vocabulary
                reasons.append(f"plan.tool_out_of_vocabulary:{s.step_id}:{s.tool_name}")
                continue
            try:
                spec.arguments.model_validate(s.arguments)                             # 3. arguments
            except ValidationError as e:
                reasons.append(f"plan.arguments:{s.step_id}:{e.errors()[0]['msg']}")
                continue
            if s.action_class is not None and s.action_class != spec.action_class:     # 4. classification
                reasons.append(f"plan.class_mismatch:{s.step_id}")
            s.action_class = spec.action_class
            s.target_ids = self.resolver.targets(s.tool_name, s.arguments)             # expands groups for VIP matching
            s.reversal = spec.reversal(s.arguments)
            if spec.action_class.reversibility == Reversibility.IRREVERSIBLE:
                if s.intent is None:
                    reasons.append(f"plan.intent_required:{s.step_id}")
                sibling = reversible_sibling(s.tool_name)                              # 5. reversibility preference
                if sibling and not any(t.tool_name == sibling and set(t.target_ids) & set(s.target_ids) for t in plan.steps) \
                        and (s.intent is None or len(s.intent.necessity) < 40):
                    reasons.append(f"plan.reversible_alternative_not_considered:{s.step_id}")
                if is_host_tool(s.tool_name) and not any(by_id[d].tool_name in self.settings.evidence_tools for d in s.depends_on):
                    reasons.append(f"plan.evidence_preservation_required:{s.step_id}")   # 6. evidence before irreversible host action
            s.staged = len(s.target_ids) > 1 or spec.action_class.blast_radius.value != "single"   # 8. staging
        if reasons:
            raise PlanRejected(reasons)
        for s in plan.steps:                                                           # 7. policy dry run
            action = ProposedAction(tool_name=s.tool_name, arguments=s.arguments, action_class=s.action_class,
                                    target_ids=s.target_ids, intent=s.intent, rationale=s.rationale)
            decision = self.gateway.authorize(action, self.planner, state)             # recorded by the caller
            if decision.verdict == "deny":
                reasons.append(f"plan.denied:{s.step_id}:{decision.rule_id}:{'; '.join(decision.reasons)}")
            s.requires_approval = decision.verdict == "escalate"
        if reasons:
            raise PlanRejected(reasons)
        return plan
