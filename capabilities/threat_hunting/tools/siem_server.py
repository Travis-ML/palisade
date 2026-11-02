# palisade/capabilities/threat_hunting/tools/siem_server.py
"""SIEM query tools with server-enforced cost budgets. Read-only."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

mcp = FastMCP("palisade-siem")
Dialect = Literal["spl", "kql"]


def _hash(rows: list[dict[str, Any]]) -> str:
    """The identity of a result: the same rows in any key order hash to the same value."""
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class QueryCostBudget(BaseModel):
    """Loaded from the capability manifest and the active RoE at startup."""
    max_cost_per_query: float = 5.0        # abstract cost units, calibrated per backend
    max_cost_per_run: float = 40.0
    max_cost_per_hunt: float = 150.0       # a hunt may span several runs
    max_lookback_days: int = 30
    require_scope: bool = True             # index/table must be named; no wildcards


class CostEstimate(BaseModel):
    cost: float
    lookback_days: int
    scoped: bool
    reasons: list[str] = Field(default_factory=list)


_WILDCARD = re.compile(r"(index\s*=\s*\*|\bunion\s+\*|search\s+\*|\bsearch\s+index=\*)", re.I)
_LOOKBACK_SPL = re.compile(r"earliest\s*=\s*-(\d+)([dhm])", re.I)
_LOOKBACK_KQL = re.compile(r"ago\((\d+)([dhm])\)", re.I)


def _lookback_days(dialect: Dialect, query: str) -> int:
    m = (_LOOKBACK_SPL if dialect == "spl" else _LOOKBACK_KQL).search(query)
    if not m:
        return 10_000                      # unbounded: priced as "all time"
    n, unit = int(m.group(1)), m.group(2).lower()
    return n if unit == "d" else max(1, n // (24 if unit == "h" else 1440))


def estimate(dialect: Dialect, query: str, budget: QueryCostBudget) -> CostEstimate:
    days = _lookback_days(dialect, query)
    scoped = not _WILDCARD.search(query)
    reasons: list[str] = []
    cost = 0.15 * min(days, 365)           # base: proportional to window
    if not scoped:
        cost *= 8; reasons.append("unscoped index/table wildcard")
    if days > budget.max_lookback_days:
        reasons.append(f"lookback {days}d exceeds {budget.max_lookback_days}d")
    if dialect == "kql" and "| take" not in query and "| summarize" not in query:
        cost *= 1.5; reasons.append("no aggregation or row limit")
    return CostEstimate(cost=round(cost, 2), lookback_days=days, scoped=scoped, reasons=reasons)


@mcp.tool()
def siem_estimate_cost(dialect: Dialect, query: str) -> dict:
    """Pre-flight cost estimate for a query. Free. Call before siem_query."""
    return estimate(dialect, query, _budget).model_dump()


@mcp.tool()
def siem_query(dialect: Dialect, query: str, run_id: str, hunt_id: str, max_rows: int = 500) -> dict:
    """Execute a read-only SIEM query under the cost budget. Denies, with reasons,
    any query over the per-query cap, outside the lookback window, unscoped when
    scope is required, or that would exhaust the run or hunt budget. Returns rows
    (UNTRUSTED), a result hash, and the actual cost charged."""
    est = estimate(dialect, query, _budget)
    spent_run, spent_hunt = _ledger_costs(run_id, hunt_id)
    if est.cost > _budget.max_cost_per_query or est.lookback_days > _budget.max_lookback_days \
            or (_budget.require_scope and not est.scoped) \
            or spent_run + est.cost > _budget.max_cost_per_run \
            or spent_hunt + est.cost > _budget.max_cost_per_hunt:
        raise PermissionError(f"query denied by cost budget: {est.reasons or ['budget exhausted']}")
    rows, actual = _backend[dialect].run(query, max_rows=max_rows, timeout_s=120)
    return {"rows": rows, "row_count": len(rows), "result_hash": _hash(rows),
            "cost_estimated": est.cost, "cost_actual": actual}
