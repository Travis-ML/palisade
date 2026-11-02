"""palisade/deploy/shadow.py: dual-run comparison that produces promotion evidence."""
from __future__ import annotations

import math
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from palisade.core.types import GlassBoxVerdict, utcnow


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95 percent Wilson score interval for a proportion. n == 0 returns (0, 0)."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, center - half), min(1.0, center + half)


class ShadowObservation(BaseModel):
    alert_id: str
    capability: str
    detection_family: str
    run_id: str
    agent_verdict: str
    agent_confidence: float
    human_verdict: Optional[str] = None
    human_id: Optional[str] = None
    observed_at: datetime = Field(default_factory=utcnow)


class AgreementStats(BaseModel):
    n: int
    agree: int
    rate: float
    ci_low: float
    ci_high: float


class ShadowSink:
    def __init__(self) -> None:
        self.obs: dict[str, ShadowObservation] = {}

    def capture(self, alert_id: str, capability: str, family: str, verdict: GlassBoxVerdict) -> None:
        self.obs[alert_id] = ShadowObservation(alert_id=alert_id, capability=capability, detection_family=family,
                                               run_id=verdict.run_id, agent_verdict=verdict.chosen,
                                               agent_confidence=verdict.confidence)

    def human(self, alert_id: str, verdict: str, by: str) -> None:
        if alert_id in self.obs:
            self.obs[alert_id].human_verdict, self.obs[alert_id].human_id = verdict, by


class ShadowComparer:
    def __init__(self, sink: ShadowSink) -> None:
        self.sink = sink

    def agreement(self, capability: str, family: Optional[str] = None,
                  since: Optional[datetime] = None) -> AgreementStats:
        rows = [o for o in self.sink.obs.values() if o.capability == capability and o.human_verdict is not None
                and (family is None or o.detection_family == family) and (since is None or o.observed_at >= since)]
        n = len(rows)
        k = sum(1 for o in rows if o.agent_verdict == o.human_verdict)
        lo, hi = wilson(k, n)
        return AgreementStats(n=n, agree=k, rate=(k / n if n else 0.0), ci_low=lo, ci_high=hi)

    def by_family(self, capability: str) -> dict[str, AgreementStats]:
        fams = {o.detection_family for o in self.sink.obs.values() if o.capability == capability}
        return {f: self.agreement(capability, f) for f in sorted(fams)}
