"""
palisade.core.types
===================

Shared vocabulary for the Palisade reference harness used throughout
*Engineering an Agentic AI Security Harness* (Travis Lelle).

Every chapter's code imports these types rather than redefining them. The
goal is that a reader can take any snippet in the book, drop it next to this
file, and have the names line up.

The types encode the book's central idea: an agent *proposes* an action, the
harness classifies it (domain x reversibility x blast radius), a policy
engine *disposes* of it against an active Rules of Engagement, a human gates
what the autonomy tier does not cover, and every step is written to an
append-only ledger before anything touches the world.

Pedagogical note: validation and error handling are intentionally thin here.
Production code would be stricter in several places called out in the text.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# The action taxonomy (Chapter 11). Classify before you control.
# ---------------------------------------------------------------------------


class ActionDomain(str, Enum):
    """What kind of thing the action does to the world."""

    OBSERVE = "observe"                      # read telemetry, query, list
    ENRICH = "enrich"                        # look up, correlate, analyze
    INTERNAL_CHANGE = "internal_change"      # ticket, draft rule, PR, comment
    PRODUCTION_CONTROL = "production_control"  # isolate, block, reset, revoke
    OFFENSE = "offense"                      # range-only emulation and probing


class Reversibility(str, Enum):
    REVERSIBLE = "reversible"            # a query, an enrichment, a draft
    SEMI_REVERSIBLE = "semi_reversible"  # a ticket, a quarantine that can be released
    IRREVERSIBLE = "irreversible"        # a reset credential, a sent email, a reimaged host


class BlastRadius(str, Enum):
    SINGLE = "single"          # one object: one token, one host, one mailbox
    GROUP = "group"            # an OU, a subnet, a team
    ENTERPRISE = "enterprise"  # a domain controller, a global block rule


class ActionClass(BaseModel):
    """The product of the three axes sets the gate and the autonomy ceiling."""

    domain: ActionDomain
    reversibility: Reversibility
    blast_radius: BlastRadius

    def key(self) -> str:
        return f"{self.domain.value}:{self.reversibility.value}:{self.blast_radius.value}"


# ---------------------------------------------------------------------------
# Autonomy ladder (Chapter 26) and planes (Chapter 6)
# ---------------------------------------------------------------------------


class AutonomyTier(IntEnum):
    SHADOW = 0              # produces verdicts and plans, takes no actions
    SUGGEST = 1             # surfaces recommendations in the human's workflow
    DRAFT = 2               # produces reviewable artifacts (PRs, tickets, plans)
    ACT_WITH_APPROVAL = 3   # executes only after a human passes the gate
    ACT_WITHIN_SCOPE = 4    # executes reversible, bounded, pre-approved classes
    AUTONOMOUS = 5          # operates within scope with sample review


class Plane(str, Enum):
    DEFENSIVE = "defensive"  # filtered models, production-reaching tools under gates
    OFFENSIVE = "offensive"  # contained, air-gapped, range-only tools


class TrustTier(str, Enum):
    """Where a piece of context came from, and therefore how it may be used."""

    ENTERPRISE = "enterprise"  # organization-authored: runbooks, RoE, standards
    VERIFIED = "verified"      # signed third-party: provenance-checked intel
    UNTRUSTED = "untrusted"    # attacker-influenceable: alerts, emails, files, web, tool descriptions


# ---------------------------------------------------------------------------
# What the agent asks for, and what the harness decides
# ---------------------------------------------------------------------------


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FiveQuestionIntent(BaseModel):
    """Required before any irreversible or high-blast-radius action (Chapter 13)."""

    intent: str = Field(description="What outcome is this action trying to achieve?")
    necessity: str = Field(description="Is there a reversible alternative? Why not use it?")
    harm: str = Field(description="What breaks if the verdict is wrong?")
    data: str = Field(description="What evidence supports the verdict? Cite it.")
    alternatives: str = Field(description="What was considered and rejected?")


class ProposedAction(BaseModel):
    """A tool call the agent *wants* to make. Nothing here has happened yet."""

    action_id: str = Field(default_factory=lambda: new_id("act"))
    tool_name: str
    arguments: dict[str, Any]
    action_class: ActionClass
    target_ids: list[str] = Field(default_factory=list)
    intent: Optional[FiveQuestionIntent] = None
    rationale: str = ""  # the agent's one-paragraph reason, captured for the ledger


class PolicyDecision(BaseModel):
    """Output of the policy engine for one proposed action (Chapter 14)."""

    verdict: Literal["allow", "deny", "escalate"]
    rule_id: str                 # the policy rule that fired, e.g. "roe.scope.in_scope"
    reasons: list[str] = Field(default_factory=list)
    required_tier: AutonomyTier  # the tier this action class demands
    effective_tier: AutonomyTier  # the tier the agent currently holds for this class
    evaluated_inputs: dict[str, Any] = Field(default_factory=dict)
    evaluated_at: datetime = Field(default_factory=utcnow)


class ApprovalRecord(BaseModel):
    """What a human decided, who they were, and what they saw (Chapter 13)."""

    approval_id: str = Field(default_factory=lambda: new_id("apr"))
    approver_id: str
    decision: Literal["approved", "denied", "modified"]
    justification: str
    presented_context_hash: str  # hash of the glass box the approver was shown
    decided_at: datetime = Field(default_factory=utcnow)
    modified_arguments: Optional[dict[str, Any]] = None


class ExecutionRecord(BaseModel):
    """What the tool layer actually did."""

    executed_at: datetime = Field(default_factory=utcnow)
    duration_ms: int
    status: Literal["ok", "error", "timeout", "halted"]
    credential_grant_id: Optional[str] = None  # from the identity broker (Chapter 12)
    result_summary: str = ""                   # redacted, bounded summary
    result_hash: str = ""                      # hash of the full (redacted) result
    error: Optional[str] = None


class ModelCallRecord(BaseModel):
    """Accounting for one inference call (Chapter 6, Chapter 10)."""

    model_id: str
    model_version: str
    routing_rule: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    cost_usd: float = 0.0
    full_content_captured: bool = False  # True on the offensive plane


class RetrievedItem(BaseModel):
    item_id: str
    version: str
    content_hash: str
    trust_tier: TrustTier
    source: str


# ---------------------------------------------------------------------------
# The decision record: one governed step, fully accounted for (Chapter 10)
# ---------------------------------------------------------------------------


class DecisionRecord(BaseModel):
    """
    One row in the append-only ledger. Every pass through the governed loop
    produces exactly one of these, whether or not an action was executed.
    Denied actions are recorded with the same fidelity as executed ones.
    """

    record_id: str = Field(default_factory=lambda: new_id("rec"))
    run_id: str
    step: int
    timestamp: datetime = Field(default_factory=utcnow)
    agent_id: str                  # the agent's non-human identity (Chapter 12)
    plane: Plane
    engagement_id: Optional[str]   # the active RoE this step ran under (Chapter 11)
    autonomy_tier: AutonomyTier

    context_hash: str              # hash of the exact assembled context
    retrieved: list[RetrievedItem] = Field(default_factory=list)
    model_call: Optional[ModelCallRecord] = None
    reasoning_summary: str = ""

    proposed_action: Optional[ProposedAction] = None
    policy_decision: Optional[PolicyDecision] = None
    approval: Optional[ApprovalRecord] = None
    execution: Optional[ExecutionRecord] = None

    human_intervention: Optional[str] = None  # "pause", "override", "kill", or None

    prev_hash: str = ""            # hash chain: tamper evidence (Chapter 10)
    record_hash: str = ""

    def compute_hash(self) -> str:
        payload = self.model_dump(mode="json", exclude={"record_hash"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def seal(self, prev_hash: str) -> "DecisionRecord":
        self.prev_hash = prev_hash
        self.record_hash = self.compute_hash()
        return self


# ---------------------------------------------------------------------------
# Rules of Engagement: the signed, time-boxed authorization (Chapter 11)
# ---------------------------------------------------------------------------


class ScopeList(BaseModel):
    in_scope: list[str] = Field(default_factory=list)       # asset groups, CIDRs, tenants, repos
    out_of_scope: list[str] = Field(default_factory=list)   # explicit denies win over allows


class ActionCeiling(BaseModel):
    """Per action class: the highest tier the RoE permits."""

    action_class: ActionClass
    max_tier: AutonomyTier
    rate_limit: Optional[str] = None  # e.g. "1/10m" : one action per ten minutes


class RulesOfEngagement(BaseModel):
    engagement_id: str
    name: str
    plane: Plane
    owner: str                        # named human authority
    approvers: list[str]              # who may pass the gate for escalated actions
    stop_authorities: list[str]       # who may halt the engagement
    scope: ScopeList
    ceilings: list[ActionCeiling]
    data_handling: dict[str, str] = Field(default_factory=dict)
    not_before: datetime
    not_after: datetime
    stop_conditions: list[str] = Field(default_factory=list)
    signature: Optional[str] = None   # detached signature over the canonical body
    signer_key_id: Optional[str] = None

    def canonical_body(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature", "signer_key_id"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def is_active(self, at: Optional[datetime] = None) -> bool:
        now = at or utcnow()
        return self.not_before <= now <= self.not_after and self.signature is not None


# ---------------------------------------------------------------------------
# Identity and credentials (Chapter 12)
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """A governed non-human identity. The agent authenticates as itself."""

    agent_id: str                 # e.g. "spiffe://palisade.example/agent/triage"
    display_name: str
    owner: str                    # named human owner, always
    plane: Plane
    created_at: datetime = Field(default_factory=utcnow)
    recertify_by: datetime
    delegated_from: Optional[str] = None  # parent agent or user, for sub-agents


class ScopedCredential(BaseModel):
    """Short-lived, narrow, single-purpose. Never a standing secret."""

    grant_id: str = Field(default_factory=lambda: new_id("grant"))
    agent_id: str
    action_id: str                # bound to one proposed action
    resource: str                 # e.g. "edr:host:host-4471"
    permissions: list[str]        # e.g. ["isolate"]
    issued_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    single_use: bool = True
    token: str = Field(repr=False)  # never logged; the ledger stores grant_id only


# ---------------------------------------------------------------------------
# Budgets and run state (Chapter 5)
# ---------------------------------------------------------------------------


class RunBudget(BaseModel):
    max_steps: int = 50
    max_wall_seconds: int = 900
    max_tokens: int = 400_000
    max_cost_usd: float = 10.0
    max_tool_calls: int = 100
    per_tool_limits: dict[str, int] = Field(default_factory=dict)


class RunState(BaseModel):
    run_id: str = Field(default_factory=lambda: new_id("run"))
    agent_id: str
    plane: Plane
    engagement_id: Optional[str]
    goal: str
    step: int = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0
    started_at: datetime = Field(default_factory=utcnow)
    halted: bool = False
    halt_reason: Optional[str] = None
    last_record_hash: str = ""


# ---------------------------------------------------------------------------
# The glass-box verdict (Chapter 10): the auditable unit for decision workflows
# ---------------------------------------------------------------------------


class Hypothesis(BaseModel):
    label: Literal["benign", "suspicious", "malicious"]
    statement: str
    weight: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)


class QueryLogEntry(BaseModel):
    at: datetime
    tool_name: str
    arguments_redacted: dict[str, Any]
    result_hash: str


class GlassBoxVerdict(BaseModel):
    verdict_id: str = Field(default_factory=lambda: new_id("vrd"))
    run_id: str
    raw_input: dict[str, Any]                 # the original alert / email / finding
    raw_input_hash: str
    query_log: list[QueryLogEntry]
    hypotheses: list[Hypothesis]
    chosen: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_weighting: str                   # why this verdict over the alternatives
    recommended_action: Optional[ProposedAction] = None
    reviewer_stamp: Optional[ApprovalRecord] = None


__all__ = [name for name in globals() if not name.startswith("_")]
