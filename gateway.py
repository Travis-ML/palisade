"""
palisade.gateway
================

The policy enforcement point between every agent and every tool server.
Nothing reaches a server except through `authorize` followed by `execute`,
bound to the same action and the same decision. Chapter 11 supplies RoEStore
Chapter 12 CredentialBroker, Chapter 14 PolicyEngine and the policy input builder.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Literal, Optional, Protocol

import jsonschema   # a dependency of the MCP SDK
from pydantic import BaseModel, Field

from palisade.core.types import (
    ActionCeiling, ActionClass, AgentIdentity, ApprovalRecord, AutonomyTier,
    ExecutionRecord, Plane, PolicyDecision, ProposedAction, RulesOfEngagement,
    RunState, ScopedCredential, new_id, utcnow,
)
from palisade.policy.engine import PolicyInputBuilder, TargetResolver
from palisade.tools.registry import IntegrityError, ToolRegistry
from palisade.tools.spec import ToolSpec


# --- collaborators owned by later chapters, declared as protocols -----------

class PolicyEngine(Protocol):
    def evaluate(self, input: dict[str, Any]) -> PolicyDecision: ...


class RoEStore(Protocol):
    def active(self, engagement_id: Optional[str]) -> Optional[RulesOfEngagement]: ...


class CredentialBroker(Protocol):
    def issue(self, agent: AgentIdentity, action: ProposedAction, resource: str,
              permissions: list[str], ttl: timedelta) -> ScopedCredential: ...
    def revoke(self, grant_id: str) -> None: ...


class TierRegistry(Protocol):
    """The earned rung per agent and action class (Chapter 26)."""
    def granted(self, agent_id: str, action_class: ActionClass) -> AutonomyTier: ...


class ToolResult(BaseModel):
    content: list[dict[str, Any]] = Field(default_factory=list)
    structured: Optional[dict[str, Any]] = None
    is_error: bool = False


class ToolTransport(Protocol):
    async def list_tools(self, server: str) -> list[Any]: ...
    async def call(self, server: str, tool_name: str, arguments: dict[str, Any],
                   credential: ScopedCredential) -> ToolResult: ...


class GatewayEvent(BaseModel):
    at: datetime = Field(default_factory=utcnow)
    kind: str                      # session.opened, session.refused, authorize.*, execute.*
    agent_id: str = ""
    run_id: str = ""
    action_id: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)


class EventSink(Protocol):
    def emit(self, event: GatewayEvent) -> None: ...


class Session(BaseModel):
    session_id: str = Field(default_factory=lambda: new_id("sess"))
    agent: AgentIdentity
    verified_servers: list[str]


class _Pending(BaseModel):
    agent: AgentIdentity
    state: RunState
    spec: ToolSpec
    decision: PolicyDecision
    roe: Optional[RulesOfEngagement]


# --- response sanitization ---------------------------------------------------

_SECRET_SHAPES = [
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}"),
    re.compile(r"\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),   # JWT shape
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
_INSTRUCTION_SHAPES = [
    re.compile(r"(?i)\b(ignore|disregard)\b.{0,40}\b(instruction|prompt|rule)"),
    re.compile(r"(?i)<\s*/?\s*(system|instructions?|important|assistant)\b"),
]


class ResponseSanitizer:
    """Bound, redact, hash, and flag a tool result before it can become context."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes

    def sanitize(self, result: ToolResult) -> tuple[str, str, list[str]]:
        text = json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        flags: set[str] = set()
        for shape in _SECRET_SHAPES:
            text, n = shape.subn("[REDACTED]", text)
            if n:
                flags.add("secret_shape_redacted")
        if any(p.search(text) for p in _INSTRUCTION_SHAPES):
            flags.add("instruction_like_content")
        if len(text.encode("utf-8")) > self.max_bytes:
            text = text.encode("utf-8")[: self.max_bytes].decode("utf-8", "ignore") + " ...[TRUNCATED]"
            flags.add("truncated")
        return text, hashlib.sha256(text.encode("utf-8")).hexdigest(), sorted(flags)


# --- the Gateway -------------------------------------------------------------

class Gateway:
    def __init__(
        self,
        registry: ToolRegistry,
        policy: PolicyEngine,
        roe_store: RoEStore,
        broker: CredentialBroker,
        tiers: TierRegistry,
        resolver: TargetResolver,
        transport: ToolTransport,
        sink: EventSink,
        identities: dict[str, AgentIdentity],
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._roe = roe_store
        self._broker = broker
        self._tiers = tiers
        self._inputs = PolicyInputBuilder(resolver, recent=self)   # the document the Rego policy reads (Chapter 14)
        self._transport = transport
        self._sink = sink
        self._identities = identities          # provisioned NHIs (Chapter 12)
        self._sessions: dict[str, Session] = {}
        self._pending: dict[str, _Pending] = {}
        self._recent: dict[str, deque[dict[str, Any]]] = {}
        self._flagged: dict[str, bool] = {}     # run_id -> did the injection screen flag this step's context (Chapter 14)

    # ---- 1. authenticate: open a verified session ---------------------------

    async def open_session(self, presented_id: str, servers: list[str]) -> Session:
        """`presented_id` is the SPIFFE ID from the agent's mTLS client certificate,
        extracted by the TLS terminator. The gateway trusts the chain, not the string."""
        agent = self._identities.get(presented_id)
        if agent is None:
            self._emit("session.refused", agent_id=presented_id,
                       detail={"reason": "unknown identity"})
            raise PermissionError(f"unknown agent identity {presented_id}")
        verified: list[str] = []
        for server in servers:
            live = await self._transport.list_tools(server)
            try:
                self._registry.verify_live(server, live)
            except IntegrityError as exc:
                self._emit("session.refused", agent_id=agent.agent_id,
                           detail={"server": server, "reason": str(exc)})
                raise
            verified.append(server)
        session = Session(agent=agent, verified_servers=verified)
        self._sessions[agent.agent_id] = session
        self._emit("session.opened", agent_id=agent.agent_id,
                   detail={"session_id": session.session_id, "servers": verified})
        return session

    # ---- 2. authorize: one proposed action -------------------------------

    def authorize(self, action: ProposedAction, agent: AgentIdentity,
                  state: RunState) -> PolicyDecision:
        spec = self._registry.get(action.tool_name)
        session = self._sessions.get(agent.agent_id)
        roe = self._roe.active(state.engagement_id)
        effective = self._effective_tier(agent, spec, roe)

        if spec is None:
            return self._deny(action, agent, state, "gateway.unknown_tool",
                              f"{action.tool_name} is not in the registry",
                              AutonomyTier.AUTONOMOUS, effective)
        if session is None or spec.server not in session.verified_servers:
            return self._deny(action, agent, state, "gateway.no_verified_session",
                              f"no verified session to {spec.server}", spec.required_tier, effective)
        if not (spec.plane == agent.plane == state.plane):
            return self._deny(action, agent, state, "gateway.plane_mismatch",
                              f"tool plane {spec.plane.value}, agent plane {agent.plane.value}",
                              spec.required_tier, effective)
        if action.action_class != spec.action_class:
            return self._deny(action, agent, state, "gateway.class_mismatch",
                              "proposed action_class differs from registered class",
                              spec.required_tier, effective)
        try:
            jsonschema.validate(action.arguments, spec.input_schema)
        except jsonschema.ValidationError as exc:
            return self._deny(action, agent, state, "gateway.invalid_arguments",
                              exc.message[:200], spec.required_tier, effective)
        if spec.requires_intent and action.intent is None:
            return self._deny(action, agent, state, "gateway.intent_required",
                              "five-question intent missing", spec.required_tier, effective)

        # No active RoE, no tool call: the RoE is where ceilings are granted, reads included.
        if roe is None:
            return self._deny(action, agent, state, "roe.inactive",
                              "no active signed Rules of Engagement", spec.required_tier, effective)

        # Rate limits are the policy's job. It counts this agent's recent executions (reported by recent()
        # below) against the RoE ceiling's rate_limit and escalates, never denies, when the window is full:
        # a second isolation inside ten minutes is exactly when a human should look.

        # The policy engine decides. Any failure to decide is a deny (Control A13).
        policy_input = self._inputs.build(action, agent, effective, roe, state, int(time.time()),
                                          flagged_context=self._flagged.get(state.run_id, False))
        try:
            decision = self._policy.evaluate(policy_input)
        except Exception as exc:   # transport, timeout, malformed response
            decision = PolicyDecision(
                verdict="deny", rule_id="engine.unavailable",
                reasons=[f"policy engine unreachable: {type(exc).__name__}"],
                required_tier=spec.required_tier, effective_tier=effective)
        return self._finish(action, agent, state, spec, roe, decision)

    # ---- 3. execute: only what was authorized, as it was authorized ---------

    async def execute(self, action: ProposedAction, decision: PolicyDecision,
                      approval: Optional[ApprovalRecord] = None) -> ExecutionRecord:
        t0 = time.monotonic()
        pending = self._pending.pop(action.action_id, None)
        if (pending is None
                or pending.decision.rule_id != decision.rule_id
                or pending.decision.evaluated_at != decision.evaluated_at):
            return self._halted(action, "execute without matching authorization", t0)
        if decision.verdict == "deny":
            return self._halted(action, f"denied by {decision.rule_id}", t0)
        if decision.verdict == "escalate":
            if approval is None or approval.decision == "denied":
                return self._halted(action, "escalated action lacks approval", t0)
            if approval.decision == "modified" and approval.modified_arguments is not None:
                try:
                    jsonschema.validate(approval.modified_arguments, pending.spec.input_schema)
                except jsonschema.ValidationError as exc:
                    return self._halted(action, f"modified arguments invalid: {exc.message}", t0)
                action = action.model_copy(update={"arguments": approval.modified_arguments})

        spec, agent, state = pending.spec, pending.agent, pending.state
        resource = (spec.resource_template.format(**action.arguments)
                    if spec.resource_template else f"tool:{spec.name}")
        try:
            cred = self._broker.issue(agent, action, resource, spec.permissions,
                                      timedelta(seconds=spec.timeout_seconds + 30))
        except Exception as exc:
            return self._halted(action, f"credential broker unavailable: {type(exc).__name__}", t0)

        status: str = "ok"
        error: Optional[str] = None
        try:
            result = await asyncio.wait_for(
                self._transport.call(spec.server, spec.name, action.arguments, cred),
                timeout=spec.timeout_seconds)
            if result.is_error:
                status, error = "error", "tool reported isError"
        except asyncio.TimeoutError:
            status, error, result = "timeout", "tool call exceeded timeout", ToolResult(is_error=True)
        except Exception as exc:
            status, error, result = "error", f"{type(exc).__name__}", ToolResult(is_error=True)
        finally:
            self._broker.revoke(cred.grant_id)          # single use, always

        summary, result_hash, flags = ResponseSanitizer(spec.max_result_bytes).sanitize(result)
        self._recent.setdefault(agent.agent_id, deque(maxlen=200)).append(
            {"tool_name": spec.name, "class_key": spec.action_class.key(), "at_epoch": int(time.time())})
        record = ExecutionRecord(
            duration_ms=int((time.monotonic() - t0) * 1000),
            status=status,  # type: ignore[arg-type]
            credential_grant_id=cred.grant_id,
            result_summary=summary,
            result_hash=result_hash,
            error=error,
        )
        self._emit(f"execute.{status}", agent_id=agent.agent_id, run_id=state.run_id,
                   action_id=action.action_id,
                   detail={"tool": spec.name, "server_version": spec.server_version,
                           "grant_id": cred.grant_id, "result_hash": result_hash,
                           "flags": flags, "approval_id": approval.approval_id if approval else None})
        return record

    # ---- helpers -------------------------------------------------------------

    def _effective_tier(self, agent: AgentIdentity, spec: Optional[ToolSpec],
                        roe: Optional[RulesOfEngagement]) -> AutonomyTier:
        if spec is None:
            return AutonomyTier.SHADOW
        granted = self._tiers.granted(agent.agent_id, spec.action_class)
        ceiling = self._ceiling_for(roe, spec.action_class)
        roe_max = ceiling.max_tier if ceiling else AutonomyTier.SUGGEST
        return AutonomyTier(min(int(granted), int(roe_max)))

    @staticmethod
    def _ceiling_for(roe: Optional[RulesOfEngagement], action_class: ActionClass):
        if roe is None:
            return None
        for c in roe.ceilings:
            if c.action_class == action_class:
                return c
        return None

    def note_context(self, run_id: str, flagged: bool) -> None:
        """Called by whatever assembled the step's context, before the model call. The policy reads the flag
        and escalates any state-changing action while it is set (Section 14.2.2)."""
        self._flagged[run_id] = flagged

    def recent(self, agent_id: str, within_seconds: int) -> list[dict[str, Any]]:
        """The RecentActions source for the policy's rate rule: what this agent executed lately."""
        cutoff = time.time() - within_seconds
        return [r for r in self._recent.get(agent_id, []) if r["at_epoch"] >= cutoff]

    def _finish(self, action, agent, state, spec, roe, decision) -> PolicyDecision:
        if decision.verdict != "deny":
            self._pending[action.action_id] = _Pending(
                agent=agent, state=state, spec=spec, decision=decision, roe=roe)
        self._emit(f"authorize.{decision.verdict}", agent_id=agent.agent_id,
                   run_id=state.run_id, action_id=action.action_id,
                   detail={"tool": action.tool_name, "rule_id": decision.rule_id,
                           "required_tier": int(decision.required_tier),
                           "effective_tier": int(decision.effective_tier),
                           "engagement_id": roe.engagement_id if roe else None})
        return decision

    def _deny(self, action, agent, state, rule_id, reason, required, effective) -> PolicyDecision:
        decision = PolicyDecision(verdict="deny", rule_id=rule_id, reasons=[reason],
                                  required_tier=required, effective_tier=effective)
        return self._finish(action, agent, state, None, None, decision)

    def _halted(self, action: ProposedAction, reason: str, t0: float) -> ExecutionRecord:
        self._emit("execute.halted", action_id=action.action_id,
                   detail={"tool": action.tool_name, "reason": reason})
        return ExecutionRecord(duration_ms=int((time.monotonic() - t0) * 1000),
                               status="halted", error=reason)

    def _emit(self, kind: str, **fields: Any) -> None:
        self._sink.emit(GatewayEvent(kind=kind, **fields))
