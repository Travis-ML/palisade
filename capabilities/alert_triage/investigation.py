# palisade/capabilities/alert_triage/investigation.py
from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Literal

from pydantic import BaseModel, Field

from palisade.core.types import AgentIdentity, Plane, RulesOfEngagement, RunBudget, RunState, ScopeList, utcnow
from palisade.capabilities.alert_triage.models import Alert, CorrelationSet, Evidence, evidence_from_records

WORKER_TOOLS: dict[str, list[str]] = {"edr": ["edr_get_host", "siem_query"], "idp": ["idp_get_user", "siem_query"]}  # plus cloud, email
WORKER_BUDGET = RunBudget(max_steps=12, max_wall_seconds=90, max_tokens=40_000, max_cost_usd=0.25, max_tool_calls=12)


class WorkerSpec(BaseModel):
    worker_id: str                  # spiffe://palisade.example/agent/triage/worker/<n>
    source: Literal["siem", "edr", "idp", "email", "cloud"]
    scope: ScopeList                # strictly narrower than the lead's
    budget: RunBudget = WORKER_BUDGET
    question: str


class InvestigationLead:
    """Wired with the TriageWorkflow, the Ledger, the lead's RoE, a GovernedLoop factory, and max_workers."""

    LEAD_ID = "spiffe://palisade.example/agent/triage"

    def plan_workers(self, alert: Alert, corr: CorrelationSet, lead_run: RunState) -> list[WorkerSpec]:
        """One edr worker per distinct host and one idp worker per distinct user, up to max_workers. Each scope is
        a single tenant-prefixed entity plus the lead's denies; each question cites lead_run.run_id and ends with
        'Report facts with query citations; do not conclude.'"""
        ...

    def _narrower(self, spec: WorkerSpec) -> bool:
        """Every worker target must match a lead in_scope pattern; the lead's denies must carry over."""
        def covered(target: str) -> bool:
            return any(p == target or (p.endswith("*") and target.startswith(p[:-1])) for p in self.roe.scope.in_scope)
        return all(covered(t) for t in spec.scope.in_scope) and set(self.roe.scope.out_of_scope) <= set(spec.scope.out_of_scope)

    async def _run_worker(self, spec: WorkerSpec) -> list[Evidence]:
        if not self._narrower(spec):
            raise PermissionError(f"worker scope is not a subset of lead scope: {spec.worker_id}")
        identity = AgentIdentity(agent_id=spec.worker_id, display_name=f"triage worker ({spec.source})", owner=self.roe.owner,
                                 plane=Plane.DEFENSIVE, recertify_by=utcnow() + timedelta(hours=1), delegated_from=self.LEAD_ID)
        narrowed = self.roe.model_copy(update={"scope": spec.scope})       # the policy engine re-verifies the subset
        loop = self.loop_factory(agent=identity, roe=narrowed, tools=WORKER_TOOLS[spec.source])
        state: RunState = await asyncio.to_thread(loop.run, spec.question, spec.budget)
        return evidence_from_records(self.ledger.replay(state.run_id))    # provenance comes from the ledger, not memory

    async def run(self, alert, raw_hash, evidence, corr, hyps, lead_run: RunState):
        batches = await asyncio.gather(*(self._run_worker(s) for s in self.plan_workers(alert, corr, lead_run)))
        merged = list(evidence) + [e for b in batches for e in b]
        spotlit = self.workflow.spotlight.wrap(alert.model_dump(mode="json"), source="alert", run_id=lead_run.run_id)
        hyps2 = await self.workflow._hypothesize(lead_run, spotlit, merged, corr, None)
        merged.extend(await self.workflow._validate(lead_run, hyps2, raw_hash, self.workflow.settings.budget))
        return await self.workflow._verdict(lead_run, alert, raw_hash, spotlit, merged, hyps2)
