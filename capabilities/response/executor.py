# palisade/capabilities/response/executor.py
from __future__ import annotations

import time
from collections import deque
from datetime import timedelta

from palisade.core.types import (ActionClass, DecisionRecord, ExecutionRecord, Plane, ProposedAction, RunState, utcnow)
from palisade.capabilities.response.plan import PlanStep, ResponsePlan, in_dependency_order


class CircuitBreaker:
    """Closed, open, half-open (Section 21.3.4 primer). allow() is False while open and before cooldown elapses;
    record(ok=False) appends a failure to a sliding window and opens the breaker at the threshold."""

    def __init__(self, failure_threshold: int, window_seconds: int, cooldown_seconds: int) -> None:
        self.threshold, self.window, self.cooldown = failure_threshold, window_seconds, cooldown_seconds
        self.failures: deque[float] = deque()
        self.opened_at: float | None = None

    def allow(self) -> bool:
        if self.opened_at is not None and time.monotonic() - self.opened_at < self.cooldown:
            return False
        self.opened_at = None                          # half-open: the next call is the trial
        return True

    def record(self, ok: bool) -> None:
        if ok:
            return
        now = time.monotonic()
        self.failures.append(now)
        while self.failures and now - self.failures[0] > self.window:
            self.failures.popleft()
        if len(self.failures) >= self.threshold:
            self.opened_at = now


class GovernanceUnavailable(Exception):
    pass


class StagedExecutor:
    """Executes a validated ResponsePlan step by step: re-authorize, gate, credential, execute, record, observe.
    Wired with gateway, policy engine, broker, ledger, approval gate, kill switch, an anomaly-signal source, the
    planner and executor identities, the RoE, and settings; holds one CircuitBreaker per tool and per system."""

    def _preflight(self) -> None:
        for dep, probe in ((self.policy, "policy"), (self.ledger, "ledger"), (self.broker, "broker"), (self.killswitch, "killswitch")):
            if not dep.healthy():
                raise GovernanceUnavailable(probe)
        if self.killswitch.tripped(scope="eng_2026q4_soc_response"):
            raise GovernanceUnavailable("killswitch.tripped")

    def run(self, plan: ResponsePlan, state: RunState, glass_box) -> RunState:
        completed: list[PlanStep] = []
        try:
            for step in in_dependency_order(plan.steps):
                self._preflight()                                                       # fail safe, every step
                targets = step.target_ids if step.staged else [None]
                for batch in _canary_then_batches(targets, self.settings.staging):
                    for target in batch:
                        self._execute_one(step, target, state, glass_box)
                        completed.append(step)
                    if step.staged and self._observe(step, batch):                   # auto-halt on anomaly
                        raise RuntimeError(f"anomaly after batch on {step.step_id}")
            return state
        except (GovernanceUnavailable, RuntimeError) as e:
            return self._halt(state, completed, reason=str(e))

    def _execute_one(self, step: PlanStep, target: str | None, state: RunState, glass_box) -> None:
        args = dict(step.arguments) if target is None else {**step.arguments, **self.settings.target_arg(step.tool_name, target)}
        action = ProposedAction(tool_name=step.tool_name, arguments=args, action_class=step.action_class,
                                target_ids=[target] if target else step.target_ids, intent=step.intent, rationale=step.rationale)
        breakers = (self.tool_breakers[step.tool_name], self.system_breakers[self.settings.system_of(step.tool_name)])
        if not all(b.allow() for b in breakers):
            raise RuntimeError(f"breaker.open:{step.tool_name}")
        decision = self.gateway.authorize(action, self.planner, state)                # re-evaluated at execution time
        approval = self.gate.request(action, glass_box=glass_box, decision=decision) if decision.verdict == "escalate" else None
        execution = None
        permitted = decision.verdict == "allow" or (approval is not None and approval.decision == "approved")
        if permitted:
            self.broker.issue(self.executor, action, resource=action.target_ids[0], permissions=[step.tool_name],
                              ttl=timedelta(minutes=5))                                 # executor identity, never the planner
            execution = self.gateway.execute(action, decision, approval=approval)
            for b in breakers:
                b.record(execution.status == "ok")
        state.step += 1
        state.last_record_hash = self.ledger.append(DecisionRecord(
            run_id=state.run_id, step=state.step, agent_id=self.executor.agent_id if permitted else self.planner.agent_id,
            plane=Plane.DEFENSIVE, engagement_id=self.roe.engagement_id, autonomy_tier=decision.effective_tier,
            context_hash=glass_box.raw_input_hash, proposed_action=action, policy_decision=decision,
            approval=approval, execution=execution))
        if not permitted or execution.status != "ok":
            raise RuntimeError(f"step.not_completed:{step.step_id}:{decision.rule_id if not permitted else execution.error}")

    def _observe(self, step: PlanStep, batch: list[str]) -> bool:
        time.sleep(self.settings.staging.observe_seconds)
        anomalies = self.signals.check(targets=batch, tool_name=step.tool_name)          # tool_error, health_probe, new_alert_on_target, ...
        self.run_anomalies += len(anomalies)
        return bool(anomalies) or self.run_anomalies >= self.settings.breakers.per_run.anomaly_threshold

    def _halt(self, state: RunState, completed: list[PlanStep], reason: str) -> RunState:
        """Revoke first, reverse second, record third, page last. A page is useless if the agent is still acting."""
        state.halted, state.halt_reason = True, reason
        self.broker.revoke_all(self.executor.agent_id)
        for step in reversed([s for s in completed if s.reversal and self.settings.rollback_on_halt]):
            self._execute_one(step.model_copy(update={"tool_name": step.reversal["tool_name"], "arguments": step.reversal["arguments"],
                                                     "staged": False, "intent": None}), None, state, glass_box=self._last_glass_box)
        state.step += 1
        state.last_record_hash = self.ledger.append(DecisionRecord(
            run_id=state.run_id, step=state.step, agent_id=self.planner.agent_id, plane=Plane.DEFENSIVE,
            engagement_id=self.roe.engagement_id, autonomy_tier=self.settings.tier, context_hash="",
            reasoning_summary=f"halted: {reason}; reversals executed for {len(completed)} completed steps",
            human_intervention="kill" if "killswitch" in reason else None))
        self.signals.page(oncall=self.roe.approvers, run_id=state.run_id, reason=reason)
        return state


def _canary_then_batches(targets: list, staging) -> list[list]:
    if targets == [None] or len(targets) <= 1:
        return [targets]
    canary, rest = targets[: staging.canary_size], targets[staging.canary_size:]
    return [canary] + [rest[i: i + staging.batch_size] for i in range(0, len(rest), staging.batch_size)]
