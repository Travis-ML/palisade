# palisade/capabilities/alert_triage/governed.py
from __future__ import annotations

import asyncio
from datetime import timedelta

from palisade.core.types import (ActionClass, AgentIdentity, AutonomyTier, DecisionRecord, Plane, ProposedAction,
                                 RulesOfEngagement, RunState, TrustTier, utcnow)
from palisade.capabilities.alert_triage.models import Evidence, evidence_id_for


class ToolDenied(Exception):
    """Raised when a governed read is denied or fails. The denial is already in the ledger."""


class GovernedReader:
    """Pattern P-5.1 applied to observe and enrich tools. One DecisionRecord per call.
    Constructed with gateway, broker, ledger, gate, the AgentIdentity, the RoE, and the effective AutonomyTier;
    holds an asyncio.Lock because appends are serial even when executions are not."""

    async def call(self, state: RunState, tool_name: str, arguments: dict, action_class: ActionClass,
                   target_ids: list[str], rationale: str, context_hash: str) -> Evidence:
        action = ProposedAction(tool_name=tool_name, arguments=arguments, action_class=action_class,
                                target_ids=target_ids, rationale=rationale)
        decision = self.gateway.authorize(action, self.agent, state)   # policy + RoE + tier + rate limits
        approval = self.gate.request(action, glass_box=None, decision=decision) if decision.verdict == "escalate" else None
        execution = None
        if decision.verdict == "allow" or (approval is not None and approval.decision == "approved"):
            self.broker.issue(self.agent, action, resource=target_ids[0] if target_ids else tool_name,
                              permissions=["read"], ttl=timedelta(minutes=2))
            execution = await asyncio.to_thread(self.gateway.execute, action, decision, approval)  # gateway resolves the grant by action_id
        async with self._chain_lock:
            state.step += 1
            state.tool_calls += 1
            record = DecisionRecord(run_id=state.run_id, step=state.step, agent_id=self.agent.agent_id, plane=Plane.DEFENSIVE,
                                    engagement_id=self.roe.engagement_id, autonomy_tier=self.tier, context_hash=context_hash,
                                    proposed_action=action, policy_decision=decision, approval=approval, execution=execution)
            state.last_record_hash = self.ledger.append(record)   # the ledger seals against its chain head
        if execution is None or execution.status != "ok":
            raise ToolDenied(f"{tool_name}: {decision.rule_id}")
        return Evidence(evidence_id=evidence_id_for(execution.result_hash), tool_name=tool_name, arguments_redacted=action.arguments,
                        summary=execution.result_summary, result_hash=execution.result_hash,
                        trust_tier=TrustTier.UNTRUSTED, observed_at=utcnow(), record_hash=state.last_record_hash)
