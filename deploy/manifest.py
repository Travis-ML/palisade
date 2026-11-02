"""palisade/deploy/manifest.py: versioned everything."""
from __future__ import annotations

import hashlib
from datetime import datetime

from pydantic import BaseModel, Field

from palisade.core.types import new_id, utcnow


class DeploymentManifest(BaseModel):
    manifest_id: str = Field(default_factory=lambda: new_id("mft"))
    capability: str
    model_id: str
    model_version: str
    routing_policy_rev: str
    prompt_hash: str
    tool_pins: dict[str, str]           # tool name -> "version@sha256(description)"
    policy_bundle_rev: str
    knowledge_commit: str
    skills_version: str
    eval_report_id: str
    created_at: datetime = Field(default_factory=utcnow)

    def digest(self) -> str:
        body = self.model_dump_json(exclude={"manifest_id", "created_at"})
        return hashlib.sha256(body.encode()).hexdigest()
