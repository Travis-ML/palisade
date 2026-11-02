"""palisade/finops/roi.py: baseline to payback, with the ladder's ramp built in."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class Baseline(BaseModel):
    """Signed before deployment. Every field comes from the 30-day capture."""
    alerts_per_day: float
    analyst_minutes_per_alert: float
    loaded_hourly_usd: float
    ingestion_gb_per_day: float
    usd_per_gb: float


class Phase(BaseModel):
    months: int
    deflection: float = Field(ge=0, le=1)         # alerts closed with no analyst time
    minutes_per_reviewed_alert: float             # with a glass box in front of the analyst
    ingestion_reduction: float = Field(default=0.0, ge=0, le=1)


class HarnessCost(BaseModel):
    one_time_usd: float
    monthly_usd: float


def monthly_benefit(b: Baseline, p: Phase) -> float:
    base_labor = b.alerts_per_day * b.analyst_minutes_per_alert / 60 * b.loaded_hourly_usd * 30
    new_labor = b.alerts_per_day * (1 - p.deflection) * p.minutes_per_reviewed_alert / 60 * b.loaded_hourly_usd * 30
    ingestion = b.ingestion_gb_per_day * b.usd_per_gb * 30 * p.ingestion_reduction
    return (base_labor - new_labor) + ingestion


def payback_month(b: Baseline, phases: list[Phase], c: HarnessCost, horizon: int = 36) -> Optional[int]:
    schedule = [p for p in phases for _ in range(p.months)]
    schedule += [phases[-1]] * max(0, horizon - len(schedule))
    cumulative = -c.one_time_usd
    for m, p in enumerate(schedule[:horizon], start=1):
        cumulative += monthly_benefit(b, p) - c.monthly_usd
        if cumulative >= 0:
            return m
    return None


if __name__ == "__main__":
    # Illustrative numbers. Replace every one of them with your signed baseline.
    base = Baseline(alerts_per_day=1500, analyst_minutes_per_alert=8, loaded_hourly_usd=75,
                    ingestion_gb_per_day=400, usd_per_gb=1.20)
    arc = [
        Phase(months=4, deflection=0.0, minutes_per_reviewed_alert=8.0),                           # baseline + shadow: nothing saved
        Phase(months=2, deflection=0.15, minutes_per_reviewed_alert=6.5),                          # suggest/draft
        Phase(months=3, deflection=0.40, minutes_per_reviewed_alert=5.5, ingestion_reduction=0.15),  # rung 3 to 4
        Phase(months=27, deflection=0.60, minutes_per_reviewed_alert=5.0, ingestion_reduction=0.15), # rung 5 with sample review
    ]
    cost = HarnessCost(one_time_usd=250_000, monthly_usd=80_000)
    print("payback month:", payback_month(base, arc, cost))
    print("steady-state monthly benefit:", round(monthly_benefit(base, arc[-1])))
