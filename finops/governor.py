"""palisade/finops/governor.py: hierarchical cost budgets and token governance above RunBudget."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from palisade.core.types import ProposedAction, RunBudget, RunState, utcnow


class PriceTable(BaseModel):
    per_million_input: dict[str, float]            # model_id -> USD per million input tokens
    per_million_output: dict[str, float]
    tool_unit_usd: dict[str, float] = Field(default_factory=dict)   # tool_name -> USD per unit

    def model_cost(self, model_id: str, in_tok: int, out_tok: int) -> float:
        return in_tok / 1e6 * self.per_million_input[model_id] + out_tok / 1e6 * self.per_million_output[model_id]

    def tool_cost(self, tool_name: str, units: float = 1.0) -> float:
        return self.tool_unit_usd.get(tool_name, 0.0) * units


class BudgetScope(BaseModel):
    scope_id: str                 # "capability:phishing", "tenant:tenant-acme", "engagement:eng_2026q4_soc_triage", "global"
    limit_usd: float
    window: timedelta
    hard: bool = True             # hard halts; soft alerts


class BudgetExceeded(Exception):
    def __init__(self, scope_id: str, spent: float, limit: float) -> None:
        super().__init__(f"budget.{scope_id}: spent {spent:.2f} of {limit:.2f}")
        self.scope_id = scope_id


class CostGovernor:
    def __init__(self, prices: PriceTable, scopes: list[BudgetScope], velocity_limit_usd_per_min: float) -> None:
        self.prices = prices
        self.scopes = {s.scope_id: s for s in scopes}
        self.velocity_limit = velocity_limit_usd_per_min
        self._spend: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
        self.tripped: set[str] = set()

    def _window_spend(self, scope_id: str, window: timedelta) -> float:
        cutoff = utcnow() - window
        return sum(usd for ts, usd in self._spend[scope_id] if ts >= cutoff)

    def _check(self, state: RunState, budget: RunBudget, scope_ids: list[str], estimate: float) -> None:
        if state.cost_usd + estimate > budget.max_cost_usd:
            raise BudgetExceeded("run", state.cost_usd + estimate, budget.max_cost_usd)
        for sid in scope_ids:
            if sid in self.tripped:
                raise BudgetExceeded(f"{sid}.velocity_breaker", 0.0, self.velocity_limit)
            scope = self.scopes.get(sid)
            if scope is None:
                continue
            spent = self._window_spend(sid, scope.window)
            if scope.hard and spent + estimate > scope.limit_usd:
                raise BudgetExceeded(sid, spent + estimate, scope.limit_usd)

    def check_model_call(self, state: RunState, budget: RunBudget, scope_ids: list[str],
                         model_id: str, est_in: int, est_out: int) -> float:
        est = self.prices.model_cost(model_id, est_in, est_out)
        self._check(state, budget, scope_ids, est)
        return est

    def check_tool_call(self, state: RunState, budget: RunBudget, scope_ids: list[str],
                        action: ProposedAction, units: float = 1.0) -> float:
        est = self.prices.tool_cost(action.tool_name, units)
        if est > 0:
            self._check(state, budget, scope_ids, est)
        return est

    def settle(self, state: RunState, scope_ids: list[str], actual_usd: float) -> None:
        now = utcnow()
        state.cost_usd += actual_usd
        for sid in scope_ids:
            self._spend[sid].append((now, actual_usd))
            if self._window_spend(sid, timedelta(minutes=1)) > self.velocity_limit:
                self.tripped.add(sid)          # Control A8: a breaker, not a budget; cleared by a human
