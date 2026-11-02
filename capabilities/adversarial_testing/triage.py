# palisade/capabilities/adversarial_testing/triage.py
from __future__ import annotations

from pydantic import BaseModel, Field

from palisade.core.types import new_id, utcnow


class ProbeHit(BaseModel):
    """One scored attempt from garak / PyRIT / promptfoo, normalized."""

    hit_id: str = Field(default_factory=lambda: new_id("hit"))
    suite: str                       # "garak" | "pyrit" | "promptfoo"
    probe_category: str              # the tool's category, e.g. "prompt_injection"
    matrix_row: str                  # which ATLAS/ASI row this maps to
    target_surface: str
    score: float                     # the suite's own detector/scorer score, 0..1
    reproduced: int                  # attempts that reproduced, out of attempts_run
    attempts_run: int
    evidence_ref: str                # pointer into the accounting substrate; NOT the probe text


class Finding(BaseModel):
    """A deduplicated, prioritized weakness. The engagement's unit of output."""

    finding_id: str = Field(default_factory=lambda: new_id("find"))
    engagement_id: str
    matrix_row: str
    title: str                       # abstract description of the weakness class
    target_surface: str
    severity: str                    # "low" | "medium" | "high" | "critical"
    reproducibility: float           # reproduced / attempts across the cluster
    hit_refs: list[str] = Field(default_factory=list)
    rationale: str                   # why this severity, citing surface and reproducibility
    created_at: str = Field(default_factory=lambda: utcnow().isoformat())


def deduplicate(hits: list[ProbeHit]) -> dict[str, list[ProbeHit]]:
    """Cluster hits by (matrix_row, target_surface). Many probe variations,
    one underlying weakness. Clustering is what turns 400 hits into 12 findings."""
    clusters: dict[str, list[ProbeHit]] = {}
    for h in hits:
        key = f"{h.matrix_row}::{h.target_surface}"
        clusters.setdefault(key, []).append(h)
    return clusters


def score_severity(cluster: list[ProbeHit]) -> tuple[str, float]:
    """Severity is blast radius on the target times reproducibility, bounded by
    whether the target's own guardrails ever caught it. Deterministic so two
    runs of the same hits yield the same backlog."""
    reproduced = sum(h.reproduced for h in cluster)
    attempts = sum(h.attempts_run for h in cluster) or 1
    repro = reproduced / attempts
    high_impact_rows = {"AML.T0024", "AML.T0057", "AML.T0051", "AML.T0010"}
    row = cluster[0].matrix_row.split("/")[0].strip()
    base = "high" if row in high_impact_rows else "medium"
    if repro >= 0.8 and base == "high":
        return "critical", repro
    if repro < 0.1:
        return "low", repro
    return base, repro
