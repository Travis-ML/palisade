# palisade/hitl/feedback.py (Sections 13.5.2 to 13.5.4 build this file in order)
from __future__ import annotations      # ReviewLabel is defined later in the file and used in annotations above it

import random
from collections import defaultdict
from typing import Optional
from palisade.core.types import DecisionRecord

def stratum(record: DecisionRecord) -> str:
    if record.proposed_action is None:
        return "no_action"
    return record.proposed_action.action_class.key()

def sample_week(records: list[DecisionRecord], fraction: float = 0.15,
                min_per_stratum: int = 5, seed: Optional[int] = None) -> list[DecisionRecord]:
    rng = random.Random(seed)
    by_stratum: dict[str, list[DecisionRecord]] = defaultdict(list)
    for r in records:
        by_stratum[stratum(r)].append(r)
    picked: list[DecisionRecord] = []
    for key, group in sorted(by_stratum.items()):
        n = max(min_per_stratum, round(len(group) * fraction))
        picked.extend(rng.sample(group, min(n, len(group))))
    return picked


def agreement_rate(labels: list[ReviewLabel]) -> float:
    return sum(1 for l in labels if l.label == "agree") / len(labels) if labels else 0.0

def override_rate(records: list[DecisionRecord]) -> float:
    executed = [r for r in records if r.execution is not None and r.execution.status == "ok"]
    if not executed:
        return 0.0
    overridden = sum(
        1 for r in executed
        if r.human_intervention == "override"
        or (r.approval is not None and r.approval.decision == "modified")
    )
    return overridden / len(executed)


import json
from datetime import datetime
from typing import Literal
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field
from palisade.core.types import utcnow

class ReviewLabel(BaseModel):
    record_id: str
    reviewer_id: str
    label: Literal["agree", "disagree_benign", "disagree_harmful"]
    correct_verdict: Optional[str] = None
    notes: str = ""
    labeled_at: datetime = Field(default_factory=utcnow)
    signature: str = ""          # hex Ed25519 over canonical_body()
    signer_key_id: str = ""

    def canonical_body(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature", "signer_key_id"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

class SignedFeedbackChannel:
    def __init__(self, reviewer_keys: dict[str, tuple[str, bytes]]) -> None:
        self._keys = reviewer_keys        # key_id -> (reviewer_id, raw 32-byte public key)
        self.accepted: list[ReviewLabel] = []
        self.rejected: list[tuple[ReviewLabel, str]] = []

    def submit(self, label: ReviewLabel) -> bool:
        entry = self._keys.get(label.signer_key_id)
        if entry is None:
            return self._reject(label, "unknown signer key")
        reviewer_id, raw_key = entry
        if reviewer_id != label.reviewer_id:
            return self._reject(label, "key does not belong to claimed reviewer")
        try:
            Ed25519PublicKey.from_public_bytes(raw_key).verify(
                bytes.fromhex(label.signature), label.canonical_body())
        except (InvalidSignature, ValueError):
            return self._reject(label, "bad signature")
        self.accepted.append(label)
        return True

    def _reject(self, label: ReviewLabel, why: str) -> bool:
        self.rejected.append((label, why))
        return False
