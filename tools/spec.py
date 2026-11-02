"""
palisade.tools.spec
===================

What the registry knows about one tool. The Gateway authorizes against this
record, never against what a live server claims about itself.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from pydantic import BaseModel, Field

from palisade.core.types import ActionClass, AutonomyTier, Plane


class ToolSpec(BaseModel):
    name: str                          # "edr_isolate_host"
    server: str                        # "palisade-edr"
    server_version: str                # pinned, "1.4.2"
    description: str
    input_schema: dict[str, Any]
    plane: Plane
    action_class: ActionClass          # fixed at registration; the agent cannot relabel
    required_tier: AutonomyTier        # the rung this class demands for autonomous execution
    requires_intent: bool = False      # five-question fields are required parameters
    permissions: list[str] = Field(default_factory=list)   # what the broker may grant
    resource_template: str = ""        # "edr:host:{host_id}", formatted from validated arguments
    timeout_seconds: int = 30
    max_result_bytes: int = 64_000
    description_hash: str = ""         # sha256 of canonical(), set at signing
    signature: Optional[str] = None    # Ed25519 over canonical(), base64
    signer_key_id: Optional[str] = None

    def canonical(self) -> bytes:
        """Exactly the fields a reviewer approved."""
        payload = {
            "name": self.name,
            "server": self.server,
            "server_version": self.server_version,
            "description": self.description,
            "input_schema": self.input_schema,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()
