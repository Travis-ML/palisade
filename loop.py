from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional, Protocol, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from palisade.core.types import (
    ActionCeiling, ActionClass, ActionDomain, AgentIdentity, ApprovalRecord, AutonomyTier,
    BlastRadius, DecisionRecord, ExecutionRecord, ModelCallRecord, PolicyDecision,
    ProposedAction, RetrievedItem, Reversibility, RulesOfEngagement, RunBudget, RunState,
    ScopeList, TrustTier, new_id, utcnow,
)
from palisade.router import ModelRouter, ModelTurn, RoutingDenied, TaskDescriptor

if TYPE_CHECKING:  # built in later chapters; the loop depends only on their call shapes
    from palisade.gateway import Gateway                   # Chapter 7
    from palisade.hitl.gate import ApprovalGate            # Chapter 13
    from palisade.hitl.killswitch import KillSwitch        # Chapter 13
    from palisade.identity.broker import CredentialBroker  # Chapter 12
    from palisade.ledger.ledger import Ledger              # Chapter 10


class GovernanceUnavailable(RuntimeError):
    """The ledger, policy engine, broker, or kill switch could not be reached.
    The only correct response is to stop (Control A13)."""


class ContextItem(Protocol):
    """What the assembler needs from a retrieved object. Chapter 8's
    KnowledgeItem satisfies this."""
    item_id: str
    version: str
    content: str
    trust_tier: TrustTier
    source: str


def is_flagged(item: ContextItem) -> bool:
    """Chapter 14's screen attaches a ScreeningResult to the items it flagged; an item never screened has none."""
    screening = getattr(item, "screening", None)
    return bool(screening is not None and screening.flagged)


class AssembledContext(BaseModel):
    system: str
    messages: list[dict[str, Any]]
    retrieved: list[RetrievedItem] = Field(default_factory=list)
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "system": self.system,
            "messages": self.messages,
            "retrieved": [r.model_dump(mode="json") for r in self.retrieved],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ContextAssembler:
    """Owns the run transcript and renders the exact context the model sees."""

    def __init__(self, operating_prompt: str) -> None:
        self.operating_prompt = operating_prompt
        self._transcript: list[dict[str, Any]] = []

    def append(self, message: dict[str, Any]) -> None:
        self._transcript.append(message)

    def assemble(self, state: RunState, retrieved: Sequence[ContextItem]) -> AssembledContext:
        if isinstance(retrieved, (str, bytes)):
            raise TypeError("retrieved must be a sequence of tagged items, not a raw string")
        header = (
            f"run_id={state.run_id} step={state.step} plane={state.plane.value} "
            f"engagement={state.engagement_id or 'none'}\nGoal: {state.goal}"
        )
        blocks = [header]
        records: list[RetrievedItem] = []
        for item in retrieved:
            if not (hasattr(item, "content") and hasattr(item, "source")
                    and isinstance(getattr(item, "trust_tier", None), TrustTier)):
                raise TypeError(f"untagged context item of type {type(item).__name__}: "
                                "every item needs content, source, and a TrustTier (Control C-14.1)")
            digest = hashlib.sha256(item.content.encode("utf-8")).hexdigest()
            records.append(RetrievedItem(
                item_id=item.item_id, version=item.version, content_hash=digest,
                trust_tier=item.trust_tier, source=item.source,
            ))
            blocks.append(
                f"<retrieved id={item.item_id} trust={item.trust_tier.value}>\n"
                f"{item.content}\n</retrieved>"
            )
        ctx = AssembledContext(
            system=self.operating_prompt + "\n\n" + "\n\n".join(blocks),
            messages=list(self._transcript),
            retrieved=records,
        )
        ctx.hash = ctx.compute_hash()
        return ctx


def check_budget(state: RunState, budget: RunBudget, tool_counts: dict[str, int]) -> Optional[str]:
    """Return the budget rule that is exhausted, or None. Checked before every step."""
    elapsed = (utcnow() - state.started_at).total_seconds()
    if state.step >= budget.max_steps:
        return "budget.max_steps"
    if elapsed >= budget.max_wall_seconds:
        return "budget.max_wall_seconds"
    if state.tokens_used >= budget.max_tokens:
        return "budget.max_tokens"
    if state.cost_usd >= budget.max_cost_usd:
        return "budget.max_cost_usd"
    if state.tool_calls >= budget.max_tool_calls:
        return "budget.max_tool_calls"
    for tool, limit in budget.per_tool_limits.items():
        if tool_counts.get(tool, 0) >= limit:
            return f"budget.per_tool.{tool}"
    return None


class CircuitBreaker:
    """Trips on tool error rate, consecutive tool errors, or worker failures
    (Control A8, OWASP ASI08). Unlike the distributed-systems version, this
    breaker has no half-open state: a human resets it."""

    def __init__(
        self,
        window: int = 10,
        max_error_rate: float = 0.5,
        max_consecutive_errors: int = 3,
        max_worker_failures: int = 2,
    ) -> None:
        self._outcomes: deque[bool] = deque(maxlen=window)
        self._consecutive = 0
        self._worker_failures = 0
        self.max_error_rate = max_error_rate
        self.max_consecutive_errors = max_consecutive_errors
        self.max_worker_failures = max_worker_failures
        self.tripped_reason: Optional[str] = None

    def record_tool(self, ok: bool) -> None:
        self._outcomes.append(ok)
        self._consecutive = 0 if ok else self._consecutive + 1
        if self._consecutive >= self.max_consecutive_errors:
            self.tripped_reason = "breaker.consecutive_errors"
        elif len(self._outcomes) == self._outcomes.maxlen:
            error_rate = 1.0 - sum(self._outcomes) / len(self._outcomes)
            if error_rate >= self.max_error_rate:
                self.tripped_reason = "breaker.error_rate"

    def record_worker(self, ok: bool) -> None:
        if not ok:
            self._worker_failures += 1
            if self._worker_failures >= self.max_worker_failures:
                self.tripped_reason = "breaker.worker_failures"

    @property
    def open(self) -> bool:
        return self.tripped_reason is not None


_BLAST_RANK = {BlastRadius.SINGLE: 0, BlastRadius.GROUP: 1, BlastRadius.ENTERPRISE: 2}


def action_fingerprint(action: ProposedAction) -> str:
    body = {"tool": action.tool_name, "args": action.arguments}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class AnomalyDetector:
    """Halts the run on pathological proposal patterns. Observes every
    proposal, allowed or not, because the pattern is in what the model
    wants, not in what it was permitted."""

    def __init__(self, repeat_threshold: int = 3, oscillation_cycles: int = 2,
                 escalation_threshold: int = 3, window: int = 12) -> None:
        self.repeat_threshold = repeat_threshold
        self.oscillation_cycles = oscillation_cycles
        self.escalation_threshold = escalation_threshold
        self._fingerprints: deque[str] = deque(maxlen=window)
        self._over_tier: deque[bool] = deque(maxlen=window)
        self._blast: deque[int] = deque(maxlen=window)

    def observe(self, action: ProposedAction, decision: PolicyDecision) -> Optional[str]:
        self._fingerprints.append(action_fingerprint(action))
        self._over_tier.append(decision.required_tier > decision.effective_tier)
        self._blast.append(_BLAST_RANK[action.action_class.blast_radius])
        return self._repeated() or self._oscillating() or self._escalating()

    def _repeated(self) -> Optional[str]:
        recent = list(self._fingerprints)[-self.repeat_threshold:]
        if len(recent) == self.repeat_threshold and len(set(recent)) == 1:
            return "anomaly.repeated_action"
        return None

    def _oscillating(self) -> Optional[str]:
        n = 2 * self.oscillation_cycles
        recent = list(self._fingerprints)[-n:]
        if len(recent) == n and len(set(recent)) == 2 and recent[::2] == [recent[0]] * (n // 2) \
                and recent[1::2] == [recent[1]] * (n // 2):
            return "anomaly.oscillation"
        return None

    def _escalating(self) -> Optional[str]:
        k = self.escalation_threshold
        over, blast = list(self._over_tier)[-k:], list(self._blast)[-k:]
        if len(over) == k and all(over) and blast == sorted(blast) and blast[-1] > blast[0]:
            return "anomaly.scope_escalation"
        return None


Retrieve = Callable[[RunState], Sequence[ContextItem]]


class GovernedLoop:
    def __init__(
        self,
        agent: AgentIdentity,
        task: TaskDescriptor,
        tier: AutonomyTier,
        router: ModelRouter,
        assembler: ContextAssembler,
        gateway: "Gateway",
        approval_gate: "ApprovalGate",
        broker: "CredentialBroker",
        ledger: "Ledger",
        kill_switch: "KillSwitch",
        tools: list[dict[str, Any]],
        retrieve: Optional[Retrieve] = None,
        breaker: Optional[CircuitBreaker] = None,
        anomalies: Optional[AnomalyDetector] = None,
        grant_ttl: timedelta = timedelta(minutes=5),
        run_id: Optional[str] = None,   # a lead pre-assigns its workers' run ids
    ) -> None:
        self.agent, self.task, self.tier = agent, task, tier
        self.run_id = run_id
        self.router, self.assembler, self.gateway = router, assembler, gateway
        self.approval_gate, self.broker, self.ledger = approval_gate, broker, ledger
        self.kill_switch, self.tools, self.retrieve = kill_switch, tools, retrieve
        self.breaker = breaker or CircuitBreaker()
        self.anomalies = anomalies or AnomalyDetector()
        self.grant_ttl = grant_ttl
        self._tool_counts: dict[str, int] = {}

    # -- entry point ----------------------------------------------------------

    def run(self, goal: str, budget: RunBudget) -> RunState:
        state = RunState(agent_id=self.agent.agent_id, plane=self.agent.plane,
                         engagement_id=self.task.engagement_id, goal=goal)
        if self.run_id:
            state.run_id = self.run_id
        self.assembler.append({"role": "user", "content": goal})
        try:
            while not state.halted:
                self._step(state, budget)
        except GovernanceUnavailable as exc:
            state.halted, state.halt_reason = True, f"fail_safe.{exc}"
        return state


    def _step(self, state: RunState, budget: RunBudget) -> None:
        tripped = self._ask_kill_switch(state)
        if tripped:
            return self._halt(state, None, f"killed.{tripped}", intervention="kill")
        exhausted = check_budget(state, budget, self._tool_counts)
        if exhausted:
            return self._halt(state, None, exhausted)
        if self.breaker.open:
            return self._halt(state, None, self.breaker.tripped_reason or "breaker.open")

        # 1. assemble context and hash it
        retrieved = self.retrieve(state) if self.retrieve else []
        ctx = self.assembler.assemble(state, retrieved)
        self.gateway.note_context(state.run_id, flagged=any(is_flagged(i) for i in retrieved))   # Section 14.2.2

        # 2. model call, recorded (routing is Chapter 6; here we only consume it)
        try:
            route = self.router.select(self.task)
        except RoutingDenied as exc:
            return self._halt(state, ctx, f"routing.{exc.rule_id}")
        started = time.monotonic()
        turn: ModelTurn = route.client.complete(ctx.messages, self.tools, system=ctx.system, **route.params)
        call = ModelCallRecord(
            model_id=route.model_id, model_version=route.model_version, routing_rule=route.rule_id,
            parameters=route.params, input_tokens=turn.usage.input_tokens,
            output_tokens=turn.usage.output_tokens, latency_ms=int((time.monotonic() - started) * 1000),
            cost_usd=turn.usage.cost_usd, full_content_captured=turn.raw is not None,
        )
        state.tokens_used += call.input_tokens + call.output_tokens
        state.cost_usd += call.cost_usd
        self.assembler.append(turn.assistant_message)

        if not turn.proposed_actions:  # a message or a stop is still a governed step
            self._record(state, ctx, call, summary=turn.text[:500])
            reason = "goal.complete" if turn.stop_reason == "end_turn" else f"model.{turn.stop_reason}"
            return self._halt(state, None, reason)

        results: list[dict[str, Any]] = []
        for action in turn.proposed_actions:
            observation = self._govern(state, ctx, call, turn, action)
            results.append({"type": "tool_result", "tool_use_id": turn.call_ids[action.action_id],
                            "content": observation})
            if state.halted:
                break
        # 5. observe: results enter the transcript only after their records are in the ledger
        self.assembler.append({"role": "user", "content": results})


    def _govern(self, state: RunState, ctx: AssembledContext, call: ModelCallRecord,
                turn: ModelTurn, action: ProposedAction) -> str:
        # 3. pre-action governance check: the single most important control point
        decision = self.gateway.authorize(action, self.agent, state)
        if decision.rule_id == "engine.unavailable":
            self._record(state, ctx, call, action=action, decision=decision, summary="policy engine unreachable")
            self._halt(state, None, "fail_safe.policy_engine")
            return "halted"
        anomaly = self.anomalies.observe(action, decision)
        if anomaly:
            self._record(state, ctx, call, action=action, decision=decision, summary=anomaly)
            self._halt(state, None, anomaly)
            return "halted"

        approval: Optional[ApprovalRecord] = None
        execution: Optional[ExecutionRecord] = None
        if decision.verdict == "escalate":
            glass_box = self._glass_box(state, ctx, turn, action, decision)
            approval = self.approval_gate.request(action, glass_box, decision)      # Chapter 13
            if approval.decision == "modified" and approval.modified_arguments is not None:
                action = action.model_copy(update={"arguments": approval.modified_arguments})

        permitted = decision.verdict == "allow" or (
            approval is not None and approval.decision in ("approved", "modified"))
        if permitted:
            # 4. scoped credential bound to this action, then execution through the gateway
            self.broker.issue(self.agent, action, resource=self._resource(action),
                              permissions=[action.tool_name], ttl=self.grant_ttl)   # Chapter 12
            execution = self.gateway.execute(action, decision, approval)             # Chapter 7
            state.tool_calls += 1
            self._tool_counts[action.tool_name] = self._tool_counts.get(action.tool_name, 0) + 1
            self.breaker.record_tool(execution.status == "ok")
            observation = execution.result_summary if execution.status == "ok" \
                else f"tool error ({execution.status}): {execution.error}"
        elif approval is not None:
            observation = f"denied by approver: {approval.justification}"
        else:
            observation = f"denied by policy {decision.rule_id}: {'; '.join(decision.reasons)}"

        # the ledger write happens before the observation can influence the next model call
        self._record(state, ctx, call, action=action, decision=decision, approval=approval,
                     execution=execution, summary=turn.text[:500])
        return observation


    def _record(self, state: RunState, ctx: Optional[AssembledContext], call: Optional[ModelCallRecord],
                *, action: Optional[ProposedAction] = None, decision: Optional[PolicyDecision] = None,
                approval: Optional[ApprovalRecord] = None, execution: Optional[ExecutionRecord] = None,
                summary: str = "", intervention: Optional[str] = None) -> None:
        state.step += 1
        record = DecisionRecord(
            run_id=state.run_id, step=state.step, agent_id=state.agent_id, plane=state.plane,
            engagement_id=state.engagement_id,
            autonomy_tier=decision.effective_tier if decision else self.tier,
            context_hash=ctx.hash if ctx else "", retrieved=ctx.retrieved if ctx else [],
            model_call=call, reasoning_summary=summary, proposed_action=action,
            policy_decision=decision, approval=approval, execution=execution,
            human_intervention=intervention,
        )
        try:
            state.last_record_hash = self.ledger.append(record)                 # Chapter 10
        except Exception as exc:
            raise GovernanceUnavailable(f"ledger: {exc}") from exc

    def _halt(self, state: RunState, ctx: Optional[AssembledContext], reason: str,
              intervention: Optional[str] = None) -> None:
        state.halted, state.halt_reason = True, reason
        self._record(state, ctx, None, summary=f"halt: {reason}", intervention=intervention)

    def _ask_kill_switch(self, state: RunState) -> Optional[str]:
        try:
            return self.kill_switch.is_tripped("global", state.agent_id, state.run_id)  # Chapter 13
        except Exception as exc:
            raise GovernanceUnavailable(f"kill_switch: {exc}") from exc

    @staticmethod
    def _resource(action: ProposedAction) -> str:
        return f"{action.tool_name}:{','.join(action.target_ids) or '*'}"

    @staticmethod
    def _glass_box(state: RunState, ctx: AssembledContext, turn: ModelTurn,
                   action: ProposedAction, decision: PolicyDecision) -> dict[str, Any]:
        return {"run_id": state.run_id, "goal": state.goal, "context_hash": ctx.hash,
                "reasoning": turn.text, "action": action.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json")}


    def delegate(self, state: RunState, ctx: AssembledContext, grant: "WorkerGrant",
                 parent_roe: RulesOfEngagement, parent_budget: RunBudget,
                 build_worker: Callable[["WorkerGrant"], "GovernedLoop"]) -> Optional[RunState]:
        """Delegation is a governed step. The grant is pre-checked locally, then
        authorized by the gateway (the policy engine repeats the subset check),
        then recorded. Only then does a worker exist."""
        problems = narrowing_violations(parent_roe.scope, parent_roe.ceilings, parent_budget, grant)
        action = delegation_action(grant)
        decision = self.gateway.authorize(action, self.agent, state)
        if problems or decision.verdict != "allow":
            self._record(state, ctx, None, action=action, decision=decision,
                         summary=f"delegation refused: {problems or decision.rule_id}")
            return None
        spawned = ExecutionRecord(duration_ms=0, status="ok",
                                  result_summary=f"spawned {grant.worker_agent_id} run {grant.worker_run_id}")
        self._record(state, ctx, None, action=action, decision=decision, execution=spawned,
                     summary=grant.subgoal)                    # this record is the edge in the tree
        worker = build_worker(grant)
        result = worker.run(grant.subgoal, grant.budget)
        self.breaker.record_worker(result.halt_reason == "goal.complete")
        return result


class WorkerGrant(BaseModel):
    """What a lead hands a worker. Every field is a subset of the lead's own."""

    grant_id: str = Field(default_factory=lambda: new_id("dlg"))
    parent_run_id: str
    parent_agent_id: str
    worker_agent_id: str
    worker_run_id: str = Field(default_factory=lambda: new_id("run"))
    subgoal: str
    scope: ScopeList
    ceilings: list[ActionCeiling]
    budget: RunBudget
    not_after: datetime


def narrowing_violations(parent_scope: ScopeList, parent_ceilings: list[ActionCeiling],
                         parent_budget: RunBudget, grant: WorkerGrant) -> list[str]:
    """Fast local pre-check. The policy engine performs the same check on the
    grant (Chapter 14); this exists so a bad grant fails before it is written."""
    problems: list[str] = []
    if not set(grant.scope.in_scope) <= set(parent_scope.in_scope):
        problems.append("scope.in_scope.widened")
    if not set(parent_scope.out_of_scope) <= set(grant.scope.out_of_scope):
        problems.append("scope.out_of_scope.dropped")
    parent_max = {c.action_class.key(): c.max_tier for c in parent_ceilings}
    for ceiling in grant.ceilings:
        key = ceiling.action_class.key()
        if key not in parent_max:
            problems.append(f"ceiling.{key}.not_held_by_parent")
        elif ceiling.max_tier > parent_max[key]:
            problems.append(f"ceiling.{key}.raised")
    for name in ("max_steps", "max_wall_seconds", "max_tokens", "max_cost_usd", "max_tool_calls"):
        if getattr(grant.budget, name) > getattr(parent_budget, name):
            problems.append(f"budget.{name}.exceeds_parent")
    return problems


def worker_identity(lead: AgentIdentity, n: int) -> AgentIdentity:
    return AgentIdentity(
        agent_id=f"{lead.agent_id}/worker/{n}", display_name=f"{lead.display_name} worker {n}",
        owner=lead.owner, plane=lead.plane, recertify_by=lead.recertify_by,
        delegated_from=lead.agent_id,
    )


DELEGATE_CLASS = ActionClass(domain=ActionDomain.INTERNAL_CHANGE,
                             reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.SINGLE)


def delegation_action(grant: WorkerGrant) -> ProposedAction:
    """Delegation is itself a governed step: the lead proposes it, the
    gateway authorizes it, and the ledger records it. The record is the edge
    in the provenance tree."""
    return ProposedAction(
        tool_name="delegate_worker",
        arguments=grant.model_dump(mode="json"),
        action_class=DELEGATE_CLASS,
        target_ids=[grant.worker_agent_id],
        rationale=grant.subgoal,
    )


class AgentMessage(BaseModel):
    message_id: str = Field(default_factory=lambda: new_id("msg"))
    sender: str
    recipient: str
    run_id: str
    parent_run_id: Optional[str] = None
    kind: Literal["task", "result", "approval_request", "approval_response"]
    payload: dict[str, Any]
    sent_at: datetime = Field(default_factory=utcnow)
    signature: Optional[str] = None

    def canonical_body(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_message(message: AgentMessage, key: Ed25519PrivateKey) -> AgentMessage:
    message.signature = key.sign(message.canonical_body()).hex()
    return message


class MessageVerifier:
    """Verifies sender identity, signature, freshness, and single use.
    An unverifiable message is dropped, never 'handled leniently'."""

    def __init__(self, keys: dict[str, Ed25519PublicKey], max_age: timedelta = timedelta(minutes=2)) -> None:
        self.keys = keys
        self.max_age = max_age
        self._seen: set[str] = set()

    def verify(self, message: AgentMessage, expected_recipient: str) -> list[str]:
        problems: list[str] = []
        if message.recipient != expected_recipient:
            problems.append("recipient.mismatch")
        if message.message_id in self._seen:
            problems.append("replayed")
        if utcnow() - message.sent_at > self.max_age:
            problems.append("stale")
        key = self.keys.get(message.sender)
        if key is None or message.signature is None:
            problems.append("sender.unknown_or_unsigned")
        else:
            try:
                key.verify(bytes.fromhex(message.signature), message.canonical_body())
            except (InvalidSignature, ValueError):
                problems.append("signature.invalid")
        if not problems:
            self._seen.add(message.message_id)
        return problems


class LeadApprovalRelay:
    """The worker's ApprovalGate. It holds no approval authority: it signs an
    approval_request up to the lead, and the lead's own ApprovalGate reaches
    the human. The worker accepts only a signed, verified approval_response."""

    def __init__(self, worker_id: str, lead_id: str, worker_key: Ed25519PrivateKey,
                 verifier: MessageVerifier, deliver, run_id: str, parent_run_id: str) -> None:
        self.worker_id, self.lead_id, self.key = worker_id, lead_id, worker_key
        self.verifier, self.deliver = verifier, deliver
        self.run_id, self.parent_run_id = run_id, parent_run_id

    def request(self, action: ProposedAction, glass_box: dict[str, Any],
                decision: PolicyDecision) -> ApprovalRecord:
        request = sign_message(AgentMessage(
            sender=self.worker_id, recipient=self.lead_id, run_id=self.run_id,
            parent_run_id=self.parent_run_id, kind="approval_request",
            payload={"action": action.model_dump(mode="json"), "glass_box": glass_box,
                     "decision": decision.model_dump(mode="json")},
        ), self.key)
        response: AgentMessage = self.deliver(request)
        problems = self.verifier.verify(response, expected_recipient=self.worker_id)
        if problems or response.kind != "approval_response":
            raise GovernanceUnavailable(f"approval response rejected: {problems or response.kind}")
        return ApprovalRecord.model_validate(response.payload)
