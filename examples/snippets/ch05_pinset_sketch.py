import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field


class PinSet(BaseModel):
    operating_prompt_hash: str
    tool_versions: dict[str, str]        # tool_name -> version from the registry (Chapter 7)
    model_id: str
    model_version: str
    routing_policy_version: str
    sampling: dict[str, Any] = Field(default_factory=lambda: {"temperature": 0.0})

    def digest(self) -> str:
        body = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()
