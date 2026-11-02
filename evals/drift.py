# palisade/evals/drift.py
from __future__ import annotations
import math
from typing import Literal, Optional
from pydantic import BaseModel

class WeeklyPoint(BaseModel):
    week: str          # ISO week, e.g. "2026-W40"
    reviewed: int
    agreed: int
    executed: int
    overridden: int

    @property
    def agreement(self) -> float:
        return self.agreed / self.reviewed if self.reviewed else 0.0

    @property
    def override(self) -> float:
        return self.overridden / self.executed if self.executed else 0.0

class ChartPoint(BaseModel):
    week: str
    value: float
    center: float
    lcl: float
    ucl: float
    signal: Optional[Literal["below_lcl", "above_ucl"]] = None

class PChart:
    def __init__(self, baseline_rate: float, sigma: float = 3.0,
                 direction: Literal["lower_is_bad", "higher_is_bad"] = "lower_is_bad") -> None:
        self._p, self._k, self._direction = baseline_rate, sigma, direction

    def judge(self, week: str, successes: int, n: int) -> ChartPoint:
        value = successes / n if n else 0.0
        se = math.sqrt(self._p * (1 - self._p) / n) if n else 0.0
        lcl, ucl = max(0.0, self._p - self._k * se), min(1.0, self._p + self._k * se)
        signal = None
        if value < lcl and self._direction == "lower_is_bad":
            signal = "below_lcl"
        if value > ucl and self._direction == "higher_is_bad":
            signal = "above_ucl"
        return ChartPoint(week=week, value=value, center=self._p, lcl=lcl, ucl=ucl, signal=signal)

class CUSUM:
    def __init__(self, target: float, k: float, h: float,
                 direction: Literal["decrease", "increase"] = "decrease") -> None:
        self._target, self._k, self._h, self._dir = target, k, h, direction
        self.sum = 0.0

    def update(self, week: str, value: float) -> bool:
        dev = (self._target - value) if self._dir == "decrease" else (value - self._target)
        self.sum = max(0.0, self.sum + dev - self._k)
        return self.sum > self._h

class DriftMonitor:
    def __init__(self, baseline: list[WeeklyPoint]) -> None:
        agree = sum(p.agreed for p in baseline) / max(1, sum(p.reviewed for p in baseline))
        override = sum(p.overridden for p in baseline) / max(1, sum(p.executed for p in baseline))
        self.agree_chart = PChart(agree, direction="lower_is_bad")
        self.override_chart = PChart(override, direction="higher_is_bad")
        self.agree_cusum = CUSUM(target=agree, k=0.01, h=0.05, direction="decrease")
        self.override_cusum = CUSUM(target=override, k=0.005, h=0.025, direction="increase")

    def observe(self, p: WeeklyPoint) -> list[str]:
        alarms: list[str] = []
        a = self.agree_chart.judge(p.week, p.agreed, p.reviewed)
        o = self.override_chart.judge(p.week, p.overridden, p.executed)
        if a.signal:
            alarms.append(f"{p.week}: agreement {a.value:.3f} fell below LCL {a.lcl:.3f}")
        if o.signal:
            alarms.append(f"{p.week}: override {o.value:.3f} rose above UCL {o.ucl:.3f}")
        if self.agree_cusum.update(p.week, p.agreement):
            alarms.append(f"{p.week}: CUSUM detects sustained decline in agreement (S={self.agree_cusum.sum:.3f})")
        if self.override_cusum.update(p.week, p.override):
            alarms.append(f"{p.week}: CUSUM detects sustained rise in overrides (S={self.override_cusum.sum:.3f})")
        return alarms
