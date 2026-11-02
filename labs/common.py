# palisade/labs/common.py (the helpers shared by the labs)
from __future__ import annotations

import hashlib
import math
from typing import Any

from palisade.memory import LocalKms


def lab_kms() -> LocalKms:
    """A process-local key service. Keys live in memory and are gone when the process exits: right for a
    lab, and the reason ciphertext written in one lab process cannot be read by the next (Chapter 9)."""
    return LocalKms()


class HashEmbedder:
    """Deterministic embedding from token hashes. Strings that share tokens land near each other, which is
    enough to exercise retrieval code; it carries no meaning, so never use it to judge retrieval quality."""

    def __init__(self, dims: int = 64) -> None:
        self.dims = dims

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.dims
            for token in text.lower().split():
                h = int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:4], "big")
                vec[h % self.dims] += 1.0 if (h >> 16) & 1 else -1.0
            norm = math.sqrt(sum(x * x for x in vec)) or 1.0
            out.append([x / norm for x in vec])
        return out


class AcceptAllVerifier:
    """A signature verifier that accepts everything. It makes Chapter 8's ingestion path runnable without a
    signing service. A harness that ships this verifier has no ingestion control at all."""

    def verify(self, key_id: str, payload: bytes, signature_b64: str) -> bool:
        return True


class MemorySink:
    """Collects emitted events so a lab can assert on what happened."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def emit(self, kind: str, **fields: Any) -> None:
        self.events.append((kind, fields))


# palisade/labs/common.py (continued)
from typing import Protocol

from palisade.core.types import AgentIdentity, Plane


class LabEnvironment(Protocol):
    plane: Plane                    # the plane this lab process is bound to (Chapter 4)
    agent_id: str                   # the SPIFFE id the lab runs as (Chapter 12)
    operating_prompt: str           # the capability's operating prompt (Chapter 5)
    routing_policy_path: str        # routing YAML (Chapter 6)
    settings_map: dict[str, str]    # placeholder substitutions for that YAML (Chapter 6)
    clients: dict[str, Any]         # provider name -> ModelClient: scripted fakes, or the real adapters (Chapter 6)
    key_registry: Any               # KeyRegistry holding the governance public key (Chapter 11)
    identity_registry: Any          # IdentityRegistry with the lab's agent identities (Chapter 12)
    broker_key: bytes               # credential broker signing key (Chapter 12)
    broker_key_id: str
    tool_registry: Any              # the Chapter 7 tool registry, loaded from the lab's manifests
    tiers: Any                      # TierRegistry: what autonomy tier each agent holds (Chapter 7)
    resolver: Any                   # TargetResolver: target id -> canonical labels (Chapters 8 and 14)
    transport: Any                  # ToolTransport: in-process fakes, or MCP over HTTP (Chapter 7)
    presenter: Any                  # GlassBoxPresenter (Chapter 13)
    scorer: Any                     # IntentScorer (Chapter 13)
    escalation: Any                 # EscalationRouter (Chapter 13)
    channel: Any                    # ApproverChannel: a canned approver in a lab, a signed channel in production
    reversal_paths: dict[str, str]  # tool -> the tool that undoes it (Chapters 13 and 21)
    runs: Any                       # the run registry the kill switch walks (Chapter 13)
    trip_state: Any                 # TripState: kill-switch state held outside the agent's process (Chapter 13)

    @classmethod
    def from_compose(cls) -> "LabEnvironment": ...
