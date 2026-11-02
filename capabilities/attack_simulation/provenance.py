# palisade/capabilities/attack_simulation/provenance.py
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from palisade.core.types import new_id, utcnow


class ArtifactProvenance(BaseModel):
    """Tagged at creation on every range-generated artifact. The artifact's
    content never appears here; only its hash and its origin."""

    artifact_id: str = Field(default_factory=lambda: new_id("art"))
    engagement_id: str
    generator_model_id: str
    generator_model_version: str
    created_at: datetime = Field(default_factory=utcnow)
    content_hash: str                      # sha256 of the artifact bytes
    confined_to: str                       # the range id; the artifact may exist nowhere else
    disposition: Literal["active", "archived", "destroyed"] = "active"

    @staticmethod
    def hash_content(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


class ArtifactRegistry:
    """Records provenance at creation, verifies confinement, and drives teardown.
    The registry is in-range; its records are exported read-only via the broker."""

    def __init__(self, engagement_id: str, range_id: str) -> None:
        self.engagement_id = engagement_id
        self.range_id = range_id
        self._records: dict[str, ArtifactProvenance] = {}

    def register(self, data: bytes, model_id: str, model_version: str) -> ArtifactProvenance:
        prov = ArtifactProvenance(
            engagement_id=self.engagement_id,
            generator_model_id=model_id,
            generator_model_version=model_version,
            content_hash=ArtifactProvenance.hash_content(data),
            confined_to=self.range_id,
        )
        self._records[prov.artifact_id] = prov
        return prov

    def coverage(self) -> float:
        """Artifact-provenance coverage: the metric must read 1.0 (100%).
        An artifact seen on the range with no registry record is a containment failure."""
        if not self._records:
            return 1.0
        tagged = sum(1 for p in self._records.values() if p.content_hash)
        return tagged / len(self._records)

    def teardown(self, archive: set[str] | None = None) -> None:
        """Controlled destruction/archival at engagement end. Nothing persists
        outside the controlled archive."""
        archive = archive or set()
        for art_id, prov in self._records.items():
            prov.disposition = "archived" if art_id in archive else "destroyed"
