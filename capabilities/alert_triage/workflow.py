# palisade/capabilities/alert_triage/workflow.py
from __future__ import annotations

import asyncio
import re
from typing import Any

from palisade.core.types import (
    ActionClass, ActionDomain, BlastRadius, DecisionRecord, GlassBoxVerdict, ModelCallRecord,
    Plane, ProposedAction, QueryLogEntry, Reversibility, RunBudget, RunState,
)
from palisade.capabilities.alert_triage.models import (Alert, CorrelationSet, Evidence, HypothesisSet, VerdictDraft,
                                                       fanout_plan)
from palisade.capabilities.alert_triage.governed import GovernedReader, ToolDenied

OBSERVE_SINGLE = ActionClass(domain=ActionDomain.OBSERVE, reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.SINGLE)
OBSERVE_GROUP = ActionClass(domain=ActionDomain.OBSERVE, reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.GROUP)
ENRICH_SINGLE = ActionClass(domain=ActionDomain.ENRICH, reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.SINGLE)
READ_TOOLS = {"siem_query": OBSERVE_GROUP, "edr_get_host": OBSERVE_SINGLE, "idp_get_user": OBSERVE_SINGLE,
              "mail_get_message": OBSERVE_SINGLE, "cloud_get_activity": OBSERVE_SINGLE, "ti_lookup_indicator": ENRICH_SINGLE}
IDENTITY_FAMILIES = re.compile(r"^identity\.")


class TriageWorkflow:
    """Wired with a GovernedReader, the ModelRouter, ContextAssembler, spotlight (Chapter 14), Retriever,
    MemoryStore, Ledger, an InvestigationLead, and the capability settings."""

    AGENT_ID = "spiffe://palisade.example/agent/triage"

    async def run(self, alert: Alert, budget: RunBudget) -> GlassBoxVerdict:
        state = RunState(agent_id=self.AGENT_ID, plane=Plane.DEFENSIVE,
                         engagement_id=self.reader.roe.engagement_id, goal=f"triage:{alert.alert_id}")
        raw_hash = alert.content_hash()
        # 1. Ingest: every field becomes spotlighted untrusted data; a positive injection screen is evidence.
        spotlit = self.spotlight.wrap(alert.model_dump(mode="json"), source="alert", run_id=state.run_id)
        injection = self.spotlight.screen(alert.fields)
        self.reader.gateway.note_context(state.run_id, flagged=injection.flagged)   # a flagged alert escalates every change
        # 2. Enrich, in parallel.  3. Correlate.
        evidence = await self._enrich(state, alert, raw_hash)
        corr, corr_ev = await self._correlate(state, alert, raw_hash)
        evidence.append(corr_ev)
        # 4. Hypothesize, then the complexity test.
        hyps = await self._hypothesize(state, spotlit, evidence, corr, injection)
        if self._needs_investigation(alert, corr, hyps):
            return await self.investigation.run(alert, raw_hash, evidence, corr, hyps, state)
        # 5. Validate, bounded.  6. Verdict, verified.
        evidence.extend(await self._validate(state, hyps, raw_hash, budget))
        return await self._verdict(state, alert, raw_hash, spotlit, evidence, hyps)

    async def _enrich(self, state: RunState, alert: Alert, ctx_hash: str) -> list[Evidence]:
        """Fan out: edr_get_host and a 24h siem_query per host, idp_get_user per user, ti_lookup_indicator per
        indicator (at most five). Each call is a governed step; a denial is already in the ledger when it raises."""
        async def one(tool: str, args: dict[str, Any], targets: list[str]):
            try:
                return await self.reader.call(state, tool, args, READ_TOOLS[tool], targets,
                                              rationale=f"enrich {alert.detection_family}", context_hash=ctx_hash)
            except ToolDenied:
                return None
        results = await asyncio.gather(*(one(*c) for c in fanout_plan(alert, self.settings.queries)))
        return [r for r in results if r is not None]

    async def _correlate(self, state: RunState, alert: Alert, ctx_hash: str) -> tuple[CorrelationSet, Evidence]:
        """One group-scoped siem_query for alerts on the same host, user, or indicator in the window;
        the bounded rows the gateway retained become the CorrelationSet."""
        window = self.settings.correlation_window_minutes
        ev = await self.reader.call(state, "siem_query",
                                    {"query": self.settings.queries.related_alerts, "max_rows": 100,
                                     "params": {"host": alert.host_id, "user": alert.user_id, "window_m": window}},
                                    OBSERVE_GROUP, [f"tenant:{alert.tenant_id}:*"], rationale="correlate", context_hash=ctx_hash)
        return CorrelationSet.from_rows(alert, self.reader.gateway.last_result_rows(ev.result_hash), window), ev

    async def _hypothesize(self, state, spotlit, evidence, corr, injection) -> HypothesisSet:
        runbook = self.retriever.retrieve(query=f"runbook {spotlit['family']}", trust_tiers=["enterprise"])
        ctx = self.assembler.assemble(state, retrieved=[spotlit, *evidence, corr, injection, *runbook])
        routing = self.router.select(self.settings.tasks.hypothesize)
        turn = routing.client.complete(ctx.messages, tools=[_structured_tool("submit_hypotheses", HypothesisSet)])
        self._record_model_call(state, ctx, routing, turn, "hypothesize")
        return HypothesisSet.model_validate(turn.proposed_actions[0].arguments)

    def _needs_investigation(self, alert: Alert, corr: CorrelationSet, hyps: HypothesisSet) -> bool:
        return (len(corr.distinct_hosts) > 2 or len(corr.distinct_users) > 2 or len(corr.related_alert_ids) >= 5
                or hyps.top_two_gap() < 0.15
                or any(re.match(p, alert.detection_family) for p in self.settings.escalation.investigation_families))

    async def _validate(self, state: RunState, hyps: HypothesisSet, ctx_hash: str, budget: RunBudget) -> list[Evidence]:
        out: list[Evidence] = []
        for vq in hyps.validation_queries[:6]:
            if vq.tool_name not in READ_TOOLS:                # out-of-vocabulary: recorded, never authorized
                self._note(state, ctx_hash, f"verifier rejected: validation.tool_out_of_vocabulary:{vq.tool_name}")
            elif state.tool_calls < budget.max_tool_calls:
                try:
                    out.append(await self.reader.call(state, vq.tool_name, vq.arguments, READ_TOOLS[vq.tool_name],
                                                      targets_from(vq.arguments), rationale=vq.expectation, context_hash=ctx_hash))
                except ToolDenied:
                    pass
        return out

    async def _verdict(self, state, alert, raw_hash, spotlit, evidence, hyps) -> GlassBoxVerdict:
        known = {e.evidence_id for e in evidence}
        draft, failure = None, None
        for attempt in range(2):                              # one re-prompt with the specific failure
            ctx = self.assembler.assemble(state, retrieved=[spotlit, *evidence, hyps, failure])
            routing = self.router.select(self.settings.tasks.verdict)
            turn = routing.client.complete(ctx.messages, tools=[_structured_tool("submit_verdict", VerdictDraft)])
            self._record_model_call(state, ctx, routing, turn, f"verdict:{attempt}")
            draft = VerdictDraft.model_validate(turn.proposed_actions[0].arguments)
            failure = self._verify(draft, hyps, evidence, known, alert)
            if failure is None:
                break
            self._note(state, ctx.hash, f"verifier rejected: {failure}")
        if failure is not None:                               # second failure: downgrade and route to a human
            draft = draft.model_copy(update={"chosen": "suspicious", "confidence": min(draft.confidence, 0.5),
                                             "evidence_weighting": f"{draft.evidence_weighting} [verifier: {failure}; routed to human]"})
        recommended = None
        if draft.recommended_tool in self.settings.response_classes:   # Chapter 21's library; a proposal, never executed here
            recommended = ProposedAction(tool_name=draft.recommended_tool, arguments=draft.recommended_arguments,
                                         action_class=self.settings.response_classes[draft.recommended_tool],
                                         target_ids=targets_from(draft.recommended_arguments), rationale=draft.recommendation_rationale)
        verdict = GlassBoxVerdict(
            run_id=state.run_id, raw_input=alert.model_dump(mode="json"), raw_input_hash=raw_hash,
            query_log=[QueryLogEntry(at=e.observed_at, tool_name=e.tool_name, arguments_redacted=e.arguments_redacted,
                                     result_hash=e.result_hash) for e in evidence],
            hypotheses=hyps.hypotheses, chosen=draft.chosen, confidence=draft.confidence,
            evidence_weighting=draft.evidence_weighting, recommended_action=recommended)
        self._note(state, raw_hash, f"verdict {verdict.verdict_id} {verdict.chosen} conf={verdict.confidence:.2f}: "
                                    f"{verdict.evidence_weighting[:1200]}", proposed=recommended)
        self.memory.write(tenant=alert.tenant_id, key=f"verdict:{verdict.verdict_id}", value=verdict.model_dump(mode="json"),
                          written_by=self.AGENT_ID, evidence=[state.last_record_hash])
        return verdict

    def _verify(self, draft, hyps, evidence, known, alert) -> str | None:
        unresolved = [c for c in draft.cited_evidence if c not in known]
        if unresolved:
            return f"citation.unresolved:{','.join(unresolved)}"
        if any(c not in known for h in hyps.hypotheses for c in h.supporting_evidence + h.contradicting_evidence):
            return "citation.unresolved_in_hypothesis"
        chosen_w = max((h.weight for h in hyps.hypotheses if h.label == draft.chosen), default=0.0)
        if draft.confidence > chosen_w + self.settings.confidence_margin:
            return f"confidence.exceeds_weight:{draft.confidence:.2f}>{chosen_w:.2f}"
        if draft.chosen == "benign" and IDENTITY_FAMILIES.match(alert.detection_family):
            by_id = {e.evidence_id: e for e in evidence}
            if all(by_id[c].tool_name == "chatops_ask_user" for c in draft.cited_evidence):
                return "corroboration.required"
        return None

    def _record_model_call(self, state, ctx, routing, turn, phase: str) -> None:
        """One DecisionRecord per inference, appended before the next model call."""
        self._append(state, ctx.hash, f"{phase}: {turn.text[:1500]}", retrieved=ctx.retrieved,
                     model_call=ModelCallRecord(model_id=routing.model_id, model_version=routing.model_version,
                                                routing_rule=routing.rule_id, input_tokens=turn.usage.input_tokens,
                                                output_tokens=turn.usage.output_tokens, cost_usd=turn.usage.cost_usd))

    def _note(self, state, ctx_hash: str, summary: str, proposed: ProposedAction | None = None) -> None:
        self._append(state, ctx_hash, summary, proposed_action=proposed)   # verifier rejections, closing verdict note

    def _append(self, state, ctx_hash: str, summary: str, **fields) -> None:
        state.step += 1
        state.last_record_hash = self.ledger.append(DecisionRecord(
            run_id=state.run_id, step=state.step, agent_id=self.AGENT_ID, plane=Plane.DEFENSIVE,
            engagement_id=self.reader.roe.engagement_id, autonomy_tier=self.reader.tier,
            context_hash=ctx_hash, reasoning_summary=summary, **fields))


def _structured_tool(name: str, model: type) -> dict[str, Any]:
    """A pseudo-tool for schema-constrained output. Intercepted by the workflow; never dispatched."""
    return {"name": name, "description": f"Submit a {model.__name__}.", "input_schema": model.model_json_schema()}


def targets_from(arguments: dict[str, Any]) -> list[str]:
    return [str(arguments[k]) for k in ("host_id", "user_id", "message_id", "indicator", "resource_id") if k in arguments]
