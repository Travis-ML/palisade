"""
palisade.context.skills
=======================

Skill manifests: signed YAML carrying a procedure plus the contract around it
(tools allowed, per-class ceilings, required gates, knowledge, evals).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal, Optional, Protocol

import yaml
from pydantic import BaseModel, Field

from palisade.core.types import ActionCeiling, ActionClass, AutonomyTier, Plane, RulesOfEngagement, TrustTier
from palisade.context.retriever import KnowledgeItem, Provenance, SignatureVerifier


class RequiredGate(BaseModel):
    action_class: ActionClass
    gate: Literal["five_question", "dual_approval"]
    approvers: list[str] = Field(default_factory=list)      # "role:ir_oncall", "user:u.ramirez"


class SkillManifest(BaseModel):
    name: str
    version: str
    owner: str
    plane: Plane
    description: str
    applies_to: dict[str, list[str]] = Field(default_factory=dict)
    inputs: dict[str, Any] = Field(default_factory=dict)     # JSON Schema
    tools_allowed: list[str]
    ceilings: list[ActionCeiling]
    required_gates: list[RequiredGate] = Field(default_factory=list)
    knowledge: list[str] = Field(default_factory=list)
    evals: Optional[str] = None
    procedure: str
    signature: Optional[str] = None
    signer_key_id: Optional[str] = None

    def canonical(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature", "signer_key_id"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def to_knowledge_item(self) -> KnowledgeItem:
        """The procedure enters context as enterprise-tier knowledge, citable by id and version."""
        return KnowledgeItem(
            item_id=f"skills/{self.name}", version=self.version, kind="runbook",
            content=self.procedure, trust_tier=TrustTier.ENTERPRISE,
            provenance=Provenance(source=f"git://skills/{self.name}.yaml", author=self.owner,
                                  signature=self.signature, signer_key_id=self.signer_key_id),
        ).seal()


class ToolRegistryView(Protocol):
    def get(self, name: str): ...


class SkillError(Exception):
    pass


class SkillLoader:
    def __init__(self, verifier: SignatureVerifier, registry: ToolRegistryView) -> None:
        self._verifier, self._registry = verifier, registry

    def load(self, path: Path) -> SkillManifest:
        manifest = SkillManifest(**yaml.safe_load(path.read_text(encoding="utf-8")))
        if not (manifest.signature and manifest.signer_key_id and
                self._verifier.verify(manifest.signer_key_id, manifest.canonical(), manifest.signature)):
            raise SkillError(f"{manifest.name}: unsigned or bad signature")
        for tool in manifest.tools_allowed:
            spec = self._registry.get(tool)
            if spec is None or spec.plane != manifest.plane:
                raise SkillError(f"{manifest.name}: tool {tool} not in registry on plane {manifest.plane.value}")
        return manifest


def effective_ceilings(skill: SkillManifest, roe: RulesOfEngagement,
                       granted: dict[str, AutonomyTier]) -> list[ActionCeiling]:
    """min(skill, RoE, earned rung) per action class. A skill can lower, never raise."""
    roe_by_key = {c.action_class.key(): c for c in roe.ceilings}
    out: list[ActionCeiling] = []
    for sc in skill.ceilings:
        key = sc.action_class.key()
        rc = roe_by_key.get(key)
        if rc is None:
            continue                                      # not in the RoE: not permitted at all
        tier = min(int(sc.max_tier), int(rc.max_tier), int(granted.get(key, AutonomyTier.SHADOW)))
        rate = sc.rate_limit or rc.rate_limit
        out.append(ActionCeiling(action_class=sc.action_class, max_tier=AutonomyTier(tier), rate_limit=rate))
    return out
