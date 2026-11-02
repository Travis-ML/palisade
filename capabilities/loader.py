"""palisade/capabilities/loader.py: the canonical capability manifest and the loader that admits it to the control plane."""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Literal, Optional, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from palisade.core.types import (ActionCeiling, ActionClass, ActionDomain, AutonomyTier, BlastRadius,
                                 Plane, Reversibility, RunBudget)
from palisade.deploy.ladder import ceiling_for

Gate = Literal["none", "on_the_loop", "approval", "pr_review", "five_question", "dual_authorization"]
GATE_RANK = {"none": 0, "on_the_loop": 1, "approval": 2, "pr_review": 2, "five_question": 3, "dual_authorization": 4}
SPIFFE = re.compile(r"^spiffe://palisade\.example/agent/[a-z0-9_-]+$")


class Owner(BaseModel):
    human: str
    team: str = "unassigned"      # the loader warns; the RACI (Appendix C) says a team must be named before rung 3
    escalation: str = ""

    @model_validator(mode="before")
    @classmethod
    def _accept_bare_human(cls, v):
        # Part IV excerpts write `owner: soc-lead@palisade.example`; the full file names team and escalation.
        return {"human": v, "escalation": v} if isinstance(v, str) else v


class IdentitySpec(BaseModel):
    agent_id: str
    recertify_days: int = 90


class ToolRef(BaseModel):
    name: str
    server: str
    version: str
    description_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    action_class: ActionClass


class SkillRef(BaseModel):
    name: str
    path: str
    version: int


class GateRule(BaseModel):
    action_class: ActionClass
    gate: Gate


class EvalSpec(BaseModel):
    suite: str
    min_precision: float = Field(ge=0, le=1)
    max_false_negative_rate: float = Field(ge=0, le=1)
    max_over_broad_rate: float = Field(ge=0, le=1)
    adversarial_required: bool = True


class MetricSpec(BaseModel):
    name: str
    query: str
    target: str
    cadence: Literal["daily", "weekly", "monthly"]


class KnowledgeSpec(BaseModel):
    collections: list[str]


class RoESpec(BaseModel):
    required: bool
    engagement_types: list[str]


class Containment(BaseModel):
    """Required for every offensive-plane capability (Chapter 24)."""
    range_id: str
    egress: Literal["none"] = "none"
    artifact_provenance_required: bool = True
    dual_authorization: bool = True
    full_content_capture: bool = True


class CapabilityManifest(BaseModel):
    # Capability-specific sections (a response capability's `staging` and `breakers`, a phishing
    # capability's `dedup` and `notify`) are kept and handed to the capability's own code; the
    # control plane validates only the sections it owns.
    model_config = ConfigDict(extra="allow")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{2,40}$")
    version: str
    plane: Plane
    description: str
    owner: Owner
    identity: IdentitySpec
    tools: list[ToolRef]
    skills: list[SkillRef] = Field(default_factory=list)
    ceilings: list[ActionCeiling]
    required_gates: list[GateRule]
    evals: EvalSpec
    metrics: list[MetricSpec]
    budget: RunBudget = Field(default_factory=RunBudget)
    daily_budget_usd: float = Field(gt=0)
    knowledge: KnowledgeSpec
    roe: RoESpec
    containment: Optional[Containment] = None

    @model_validator(mode="after")
    def _enforce_control_plane_rules(self) -> "CapabilityManifest":
        if not SPIFFE.match(self.identity.agent_id):
            raise ValueError("identity.agent_id must be a palisade.example SPIFFE id")
        if not self.owner.human.strip():
            raise ValueError("every capability has a named human owner")
        ceilings = {c.action_class.key(): c for c in self.ceilings}
        gates = {g.action_class.key(): g.gate for g in self.required_gates}
        for c in self.ceilings:
            if c.max_tier > ceiling_for(c.action_class):
                raise ValueError(f"ceiling {c.max_tier.name} for {c.action_class.key()} exceeds taxonomy ceiling "
                                 f"{ceiling_for(c.action_class).name} (Control A4)")
        for t in self.tools:
            key = t.action_class.key()
            if key not in ceilings or key not in gates:
                raise ValueError(f"tool {t.name}: action class {key} needs a ceiling and a required gate")
            ac, gate = t.action_class, gates[key]
            if ac.domain in (ActionDomain.PRODUCTION_CONTROL, ActionDomain.OFFENSE) and GATE_RANK[gate] < 1:
                raise ValueError(f"tool {t.name}: production control and offense require at least on_the_loop at ceiling")
            if (ac.reversibility == Reversibility.IRREVERSIBLE or ac.blast_radius != BlastRadius.SINGLE) \
                    and ac.domain != ActionDomain.OBSERVE and GATE_RANK[gate] < 2:
                raise ValueError(f"tool {t.name}: irreversible or multi-object actions require approval or stronger (A7)")
            if ac.domain == ActionDomain.OFFENSE and self.plane != Plane.OFFENSIVE:
                raise ValueError(f"tool {t.name}: offense tools are offensive-plane only (A18)")
            if ac.domain == ActionDomain.PRODUCTION_CONTROL and self.plane == Plane.OFFENSIVE:
                raise ValueError(f"tool {t.name}: no production-reaching tool on the offensive plane (A18)")
        if self.plane == Plane.OFFENSIVE:
            if self.containment is None:
                raise ValueError("offensive-plane capabilities must declare containment (A18, A20)")
            if not self.roe.required:
                raise ValueError("offensive-plane capabilities require an active RoE (A3)")
        if any(c.max_tier > AutonomyTier.SHADOW for c in self.ceilings) and not self.evals.suite:
            raise ValueError("a capability that may leave shadow needs an eval suite (A15)")
        return self


class ControlPlane(Protocol):
    """The seams the loader registers against. Each is built in an earlier chapter; none changes here."""
    def register_tools(self, capability: str, tools: list[ToolRef]) -> None: ...        # gateway (Ch 7): pins, hashes
    def seed_tiers(self, capability: str, classes: list[ActionClass]) -> None: ...        # tier registry (Ch 26): all SHADOW
    def push_policy_data(self, doc: dict) -> None: ...                                      # OPA data (Ch 14)
    def register_eval_suite(self, capability: str, spec: EvalSpec) -> None: ...            # eval runner (Ch 15)
    def register_budget(self, scope_id: str, limit_usd: float, window: timedelta) -> None: ...  # governor (Ch 27)
    def register_metrics(self, capability: str, metrics: list[MetricSpec]) -> None: ...   # dashboards (Ch 27)


def _normalize(doc: dict) -> dict:
    """Accept the compact spellings the Part IV packages use, so that authors can write the short
    form and the loader still validates the long form: a top-level `capability:` block;
    `scope_ceiling:` (list or single mapping) for `ceilings:`; `class:` for `action_class:`;
    `domain:reversibility:blast_radius` strings, with `*` expanding over the taxonomy; tier names
    (`ACT_WITH_APPROVAL`) for tier numbers; `agent_id:` or `identities:` for `identity:`;
    `engagement_ids:` and `requires_roe:` for the `roe:` block; and a bare list of gate names in
    `required_gates:`, which applies that gate to every declared ceiling class."""
    doc = {**doc.pop("capability", {}), **doc}
    if "scope_ceiling" in doc:
        sc = doc.pop("scope_ceiling")
        doc["ceilings"] = sc if isinstance(sc, list) else [sc]

    def expand(ac) -> list[dict]:
        if isinstance(ac, dict):
            return [ac]
        d, r, b = ac.split(":")
        domains = [x.value for x in ActionDomain] if d == "*" else [d]
        revs = [x.value for x in Reversibility] if r == "*" else [r]
        blasts = [x.value for x in BlastRadius] if b == "*" else [b]
        return [{"domain": dd, "reversibility": rr, "blast_radius": bb}
                for dd in domains for rr in revs for bb in blasts]

    def tier(v):
        return AutonomyTier[v].value if isinstance(v, str) else v

    for section in ("tools", "ceilings", "required_gates"):
        expanded = []
        for item in doc.get(section, []):
            if isinstance(item, str):                      # `required_gates: [pr_review]`
                expanded.extend({"action_class": c["action_class"], "gate": item} for c in doc.get("ceilings", []))
                continue
            if "class" in item:
                item["action_class"] = item.pop("class")
            if "max_tier" in item:
                item["max_tier"] = tier(item["max_tier"])
            for ac in expand(item.get("action_class", {})):
                expanded.append({**item, "action_class": ac})
        if section in doc:
            doc[section] = expanded

    if "identity" not in doc:
        agent = doc.pop("agent_id", None) or next(iter((doc.get("identities") or {}).values()), None)
        if agent:
            doc["identity"] = {"agent_id": agent}
    if "roe" not in doc:
        doc["roe"] = {"required": doc.pop("requires_roe", True),
                      "engagement_types": doc.pop("engagement_ids", ["standing_defensive"])}
    return doc


def load_capability(path: Path) -> CapabilityManifest:
    return CapabilityManifest.model_validate(_normalize(yaml.safe_load(path.read_text())))


def register(m: CapabilityManifest, cp: ControlPlane) -> None:
    cp.register_tools(m.name, m.tools)
    cp.seed_tiers(m.name, [c.action_class for c in m.ceilings])
    cp.push_policy_data({"capabilities": {m.name: {
        "plane": m.plane.value,
        "ceilings": {c.action_class.key(): int(c.max_tier) for c in m.ceilings},
        "rate_limits": {c.action_class.key(): c.rate_limit for c in m.ceilings if c.rate_limit},
        "gates": {g.action_class.key(): g.gate for g in m.required_gates},
        "roe_required": m.roe.required,
    }}})
    cp.register_eval_suite(m.name, m.evals)
    cp.register_budget(f"capability:{m.name}", m.daily_budget_usd, timedelta(days=1))
    cp.register_metrics(m.name, m.metrics)
