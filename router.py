from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional, Protocol

import yaml
from pydantic import BaseModel, Field

from palisade.core.types import (
    ActionClass, ActionDomain, BlastRadius, Plane, ProposedAction, Reversibility,
)

if TYPE_CHECKING:
    from palisade.roe import RoEStore  # Chapter 11


Sensitivity = Literal["public", "internal", "confidential", "regulated"]
_SENSITIVITY_RANK: dict[str, int] = {"public": 0, "internal": 1, "confidential": 2, "regulated": 3}


class TaskDescriptor(BaseModel):
    """Everything the router needs to choose a model. Nothing about the content."""

    task_type: str                      # e.g. "triage.verdict", "malware.analysis"
    plane: Plane
    agent_id: str
    sensitivity: Sensitivity = "internal"
    residency: Optional[str] = None     # "us", "eu", "vpc" ...
    engagement_id: Optional[str] = None
    latency_budget_ms: Optional[int] = None


class ModelUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class ModelTurn(BaseModel):
    """One model response, normalized so the loop never sees a provider SDK."""

    text: str
    proposed_actions: list[ProposedAction]
    call_ids: dict[str, str]            # action_id -> provider tool-call id
    assistant_message: dict[str, Any]   # the message to append to the transcript
    usage: ModelUsage
    stop_reason: str
    raw: Optional[dict[str, Any]] = None  # full request+response; offensive plane only


# A classifier maps (tool_name, arguments) to (ActionClass, target_ids).
# Chapter 7's ToolSpec registry supplies the real one.
Classifier = Callable[[str, dict[str, Any]], tuple[ActionClass, list[str]]]


def strictest_class() -> ActionClass:
    """What an adapter assigns to an unknown or malformed tool call so that
    default-deny policy, not the adapter, disposes of it."""
    return ActionClass(
        domain=ActionDomain.PRODUCTION_CONTROL,
        reversibility=Reversibility.IRREVERSIBLE,
        blast_radius=BlastRadius.ENTERPRISE,
    )


class ModelClient(Protocol):
    model_id: str
    model_version: str

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **params: Any
    ) -> ModelTurn: ...


Restrictiveness = Literal["filtered", "less_restricted", "open_weight"]


class WeightFile(BaseModel):
    path: str
    sha256: str
    bytes: int


class WeightProvenance(BaseModel):
    """provenance.yaml next to the weights. Written when the artifact is
    obtained, signed by the person who verified it, checked before every load."""

    model_name: str
    source: str                         # e.g. "hf://<org>/<repo>"
    revision: str                       # the upstream commit the files came from
    format: Literal["safetensors", "gguf"]
    precision: str                      # "bf16", "fp16", "int4-awq", "q4_k_m"
    quantized_by: Optional[str] = None  # "upstream", "self:<toolchain@version>", or a third party
    files: list[WeightFile]
    obtained_at: datetime
    verified_by: str                    # a named human
    signature: Optional[str] = None
    signer_key_id: Optional[str] = None


class ModelSpec(BaseModel):
    model_id: str
    version: str
    provider: Literal["anthropic", "openai_compat"]
    locus: Literal["managed_api", "self_hosted", "on_prem"]
    plane: Plane
    restrictiveness: Restrictiveness = "filtered"
    capability_tier: Literal["frontier", "standard", "small", "specialized"] = "standard"
    residency: list[str] = Field(default_factory=list)
    max_sensitivity: Sensitivity = "confidential"
    endpoint: Optional[str] = None
    allowed_task_types: list[str] = Field(default_factory=list)  # required when not "filtered"
    weights_provenance: Optional[str] = None                     # path to provenance.yaml
    capture_full_content: bool = False


class RuleMatch(BaseModel):
    task_types: list[str] = Field(default_factory=lambda: ["*"])
    planes: list[Plane] = Field(default_factory=lambda: [Plane.DEFENSIVE, Plane.OFFENSIVE])
    min_sensitivity: Sensitivity = "public"
    max_sensitivity: Sensitivity = "regulated"
    requires_active_roe: bool = False


class RoutingRule(BaseModel):
    rule_id: str
    description: str = ""
    match: RuleMatch = Field(default_factory=RuleMatch)
    effect: Literal["route", "deny"] = "route"
    model: Optional[str] = None         # key into RoutingPolicy.models when effect == "route"
    params: dict[str, Any] = Field(default_factory=dict)

    def matches(self, task: TaskDescriptor) -> bool:
        m = self.match
        if task.plane not in m.planes:
            return False
        if "*" not in m.task_types and task.task_type not in m.task_types:
            return False
        rank = _SENSITIVITY_RANK[task.sensitivity]
        return _SENSITIVITY_RANK[m.min_sensitivity] <= rank <= _SENSITIVITY_RANK[m.max_sensitivity]


class RoutingPolicy(BaseModel):
    version: str
    models: dict[str, ModelSpec]
    rules: list[RoutingRule]

    @classmethod
    def from_yaml(cls, path: str | Path, settings: dict[str, str] | None = None) -> "RoutingPolicy":
        text = Path(path).read_text(encoding="utf-8")
        for key, value in (settings or {}).items():
            text = text.replace("{" + key + "}", value)   # "{settings.models.frontier}" -> real id
        return cls.model_validate(yaml.safe_load(text))


class RoutingDenied(Exception):
    def __init__(self, rule_id: str, reasons: list[str]) -> None:
        super().__init__(f"{rule_id}: {'; '.join(reasons)}")
        self.rule_id = rule_id
        self.reasons = reasons


@dataclass
class RoutingDecision:
    model_id: str
    model_version: str
    rule_id: str
    client: ModelClient
    params: dict[str, Any] = field(default_factory=dict)


class ModelRouter:
    """select() is called on every model call. It is cheap, and it is the
    control point, so it is never cached across steps."""

    def __init__(
        self,
        policy: RoutingPolicy,
        clients: dict[str, ModelClient],
        bound_plane: Plane,
        roe_store: Optional["RoEStore"] = None,
        verified_weights: Optional[set[str]] = None,
    ) -> None:
        self.policy = policy
        self.clients = clients
        self.bound_plane = bound_plane
        self.roe_store = roe_store
        self.verified_weights = verified_weights or set()

    def select(self, task: TaskDescriptor) -> RoutingDecision:
        for rule in self.policy.rules:          # first match wins; order is policy
            if not rule.matches(task):
                continue
            if rule.effect == "deny":
                raise RoutingDenied(rule.rule_id, [rule.description or "explicit deny"])
            if rule.model is None or rule.model not in self.policy.models:
                raise RoutingDenied(rule.rule_id, ["rule names no configured model"])
            spec = self.policy.models[rule.model]
            reasons = self._ineligible(rule, spec, task, rule.model)
            if reasons:
                raise RoutingDenied(f"{rule.rule_id}.ineligible", reasons)
            if rule.model not in self.clients:
                raise RoutingDenied(rule.rule_id, [f"no client bound for {rule.model} in this process"])
            return RoutingDecision(
                model_id=spec.model_id, model_version=spec.version, rule_id=rule.rule_id,
                client=self.clients[rule.model], params=dict(rule.params),
            )
        raise RoutingDenied("router.default.deny", ["no routing rule matched"])

    def _ineligible(self, rule: RoutingRule, spec: ModelSpec, task: TaskDescriptor, key: str) -> list[str]:
        """The compensating controls, re-checked on every call regardless of
        what the rule author wrote. A rule can be wrong; these cannot be waived."""
        reasons: list[str] = []
        if spec.plane != task.plane or spec.plane != self.bound_plane:
            reasons.append(f"plane mismatch: model={spec.plane.value} task={task.plane.value} process={self.bound_plane.value}")
        if _SENSITIVITY_RANK[task.sensitivity] > _SENSITIVITY_RANK[spec.max_sensitivity]:
            reasons.append(f"sensitivity {task.sensitivity} exceeds model ceiling {spec.max_sensitivity}")
        if task.residency and spec.residency and task.residency not in spec.residency:
            reasons.append(f"residency {task.residency} not served by model ({spec.residency})")
        if task.sensitivity == "regulated" and spec.locus == "managed_api":
            reasons.append("regulated data may not leave the VPC")
        if spec.restrictiveness != "filtered":
            if spec.plane != Plane.OFFENSIVE:
                reasons.append("less-restricted or open-weight models exist only on the offensive plane")
            if task.task_type not in spec.allowed_task_types:
                reasons.append(f"task {task.task_type} not on the model's allowlist")
            if not rule.match.requires_active_roe:
                reasons.append("rule routing to a less-restricted model must require an active RoE")
        if rule.match.requires_active_roe:
            active = self.roe_store.active(task.engagement_id) if (self.roe_store and task.engagement_id) else None
            if active is None:
                reasons.append(f"no active signed RoE for engagement {task.engagement_id}")
        if spec.restrictiveness == "open_weight" and key not in self.verified_weights:
            reasons.append("open weights not verified in this process")
        return reasons


PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".pkl", ".ckpt"}


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def verify_weights(provenance: WeightProvenance, root: Path) -> list[str]:
    """Return a list of problems. Empty means the artifact on disk is the
    artifact a named human verified. Anything else and the model is not loaded."""
    problems: list[str] = []
    if provenance.signature is None:
        problems.append("provenance file is unsigned")
    listed = {f.path for f in provenance.files}
    on_disk = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    for extra in sorted(on_disk - listed - {"provenance.yaml"}):
        problems.append(f"unlisted file present: {extra}")
    for f in provenance.files:
        p = root / f.path
        if p.suffix in PICKLE_SUFFIXES:
            problems.append(f"{f.path}: pickle-based format refused; require safetensors or gguf")
            continue
        if not p.is_file():
            problems.append(f"{f.path}: missing")
            continue
        if p.stat().st_size != f.bytes:
            problems.append(f"{f.path}: size {p.stat().st_size} != {f.bytes}")
        digest = sha256_file(p)
        if digest != f.sha256:
            problems.append(f"{f.path}: sha256 {digest[:12]}... != pinned {f.sha256[:12]}...")
    return problems
