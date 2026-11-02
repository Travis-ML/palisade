"""
palisade.roe
============

Rules of Engagement as machine-enforced scope: signing and verification
(Ed25519), the RoEStore, scope matching, the taxonomy-to-ceiling mapping,
per-action-class rate limits, and canary rollout with auto-halt.

The policy engine (Chapter 14) makes the formal allow/deny/escalate
decision. This module supplies the verified RoE and the deterministic
helpers that decision depends on. Nothing here trusts its inputs: an RoE
that fails signature or time checks is not an RoE.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Literal, Optional, Sequence

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from palisade.core.types import (
    ActionCeiling,
    ActionClass,
    ActionDomain,
    AutonomyTier,
    BlastRadius,
    Plane,
    ProposedAction,
    Reversibility,
    RulesOfEngagement,
    utcnow,
)


# ---------------------------------------------------------------------------
# Taxonomy to gate and ceiling (Control A4)
# ---------------------------------------------------------------------------

Gate = Literal["none", "sample_review", "approval", "five_question", "range_only", "forbidden"]


@dataclass(frozen=True)
class CeilingRule:
    max_tier: AutonomyTier
    gate: Gate
    permanent_cap: bool = False  # True: the model getting better changes nothing


def ceiling_for(ac: ActionClass, plane: Plane = Plane.DEFENSIVE) -> CeilingRule:
    """
    The product of the three axes sets the gate and the maximum tier. This
    is the default matrix; an RoE may lower a ceiling, never raise one.
    """
    d, r, b = ac.domain, ac.reversibility, ac.blast_radius

    if d == ActionDomain.OFFENSE:
        if plane != Plane.OFFENSIVE:
            return CeilingRule(AutonomyTier.SHADOW, "forbidden", True)
        return CeilingRule(AutonomyTier.ACT_WITHIN_SCOPE, "range_only")

    if d in (ActionDomain.OBSERVE, ActionDomain.ENRICH):
        if b == BlastRadius.ENTERPRISE:
            return CeilingRule(AutonomyTier.ACT_WITHIN_SCOPE, "sample_review")
        return CeilingRule(AutonomyTier.AUTONOMOUS, "sample_review")

    if d == ActionDomain.INTERNAL_CHANGE:
        if r == Reversibility.IRREVERSIBLE:
            return CeilingRule(AutonomyTier.ACT_WITH_APPROVAL, "approval")
        if b == BlastRadius.ENTERPRISE:
            return CeilingRule(AutonomyTier.ACT_WITH_APPROVAL, "approval")
        return CeilingRule(AutonomyTier.ACT_WITHIN_SCOPE, "sample_review")

    # PRODUCTION_CONTROL
    if r == Reversibility.IRREVERSIBLE:
        if b == BlastRadius.SINGLE:
            # one revoked session, one reset credential: the five questions are
            # always required; tier 4 is reachable only with a long override record
            return CeilingRule(AutonomyTier.ACT_WITHIN_SCOPE, "five_question")
        return CeilingRule(AutonomyTier.ACT_WITH_APPROVAL, "five_question", True)
    if r == Reversibility.SEMI_REVERSIBLE:
        if b == BlastRadius.SINGLE:
            return CeilingRule(AutonomyTier.ACT_WITHIN_SCOPE, "sample_review")
        if b == BlastRadius.GROUP:
            return CeilingRule(AutonomyTier.ACT_WITH_APPROVAL, "approval")
        return CeilingRule(AutonomyTier.ACT_WITH_APPROVAL, "five_question", True)
    # reversible production control (a soft block with TTL, a watch-list add)
    if b == BlastRadius.ENTERPRISE:
        return CeilingRule(AutonomyTier.ACT_WITH_APPROVAL, "approval")
    return CeilingRule(AutonomyTier.ACT_WITHIN_SCOPE, "sample_review")


def effective_ceiling(ac: ActionClass, roe: RulesOfEngagement) -> AutonomyTier:
    """min(default matrix, RoE ceiling). Absent from the RoE means SHADOW."""
    default = ceiling_for(ac, roe.plane).max_tier
    for c in roe.ceilings:
        if c.action_class.key() == ac.key():
            return min(default, c.max_tier)
    return AutonomyTier.SHADOW


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------


def sign_roe(roe: RulesOfEngagement, key: Ed25519PrivateKey, key_id: str) -> RulesOfEngagement:
    """
    Detached Ed25519 signature over canonical_body(). The body excludes the
    signature fields, so signing is idempotent and verification recomputes
    exactly what was signed. Mutating any other field invalidates it.
    """
    sig = key.sign(roe.canonical_body())
    roe.signature = base64.b64encode(sig).decode()
    roe.signer_key_id = key_id
    return roe


def verify_roe(roe: RulesOfEngagement, public_key: Ed25519PublicKey) -> bool:
    if not roe.signature:
        return False
    try:
        public_key.verify(base64.b64decode(roe.signature), roe.canonical_body())
        return True
    except (InvalidSignature, ValueError):
        return False


class KeyRegistry:
    """
    Maps signer_key_id to a public key. In production this is a read-only
    view of the governance function's key directory, fetched over mTLS and
    cached briefly. Rotation is adding a new id, not replacing bytes.
    """

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        self._keys[key_id] = public_key

    def add_pem(self, key_id: str, pem: bytes) -> None:
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("RoE signer keys must be Ed25519")
        self._keys[key_id] = key

    def get(self, key_id: Optional[str]) -> Optional[Ed25519PublicKey]:
        return self._keys.get(key_id or "")


def load_roe_yaml(path: Path) -> RulesOfEngagement:
    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return RulesOfEngagement.model_validate(doc)


# ---------------------------------------------------------------------------
# The store: the only thing the gateway asks for an RoE
# ---------------------------------------------------------------------------


@dataclass
class RoECheck:
    engagement_id: str
    outcome: Literal["active", "missing", "unsigned", "bad_signature", "unknown_key", "not_yet", "expired", "wrong_plane"]
    at: datetime


class RoEStore:
    """
    active(engagement_id) returns the RulesOfEngagement only if it exists,
    its signer is known, its signature verifies, and now is inside the
    window. Every other outcome is None, and every lookup is reported to the
    observer so the ledger can record the check (the Account callout in
    Section 11.4). None is not an error state; it is the normal answer when
    nobody has authorized anything, and the loop must treat it as such.
    """

    def __init__(self, keys: KeyRegistry, observer: Optional[Callable[[RoECheck], None]] = None,
                 plane: Optional[Plane] = None) -> None:
        self._keys = keys
        self._roes: dict[str, RulesOfEngagement] = {}
        self._observe = observer or (lambda c: None)
        self._plane = plane  # the plane this store serves; cross-plane RoEs are refused

    def load(self, roe: RulesOfEngagement) -> None:
        # Loading does not validate. active() does, on every call, because
        # keys get revoked and clocks move.
        self._roes[roe.engagement_id] = roe

    def load_dir(self, directory: Path) -> int:
        n = 0
        for p in sorted(directory.glob("*.yaml")):
            self.load(load_roe_yaml(p))
            n += 1
        return n

    def active(self, engagement_id: str, at: Optional[datetime] = None) -> RulesOfEngagement | None:
        now = at or utcnow()
        roe = self._roes.get(engagement_id)
        outcome: str
        if roe is None:
            outcome = "missing"
        elif self._plane is not None and roe.plane != self._plane:
            outcome = "wrong_plane"
        elif not roe.signature:
            outcome = "unsigned"
        elif (pk := self._keys.get(roe.signer_key_id)) is None:
            outcome = "unknown_key"
        elif not verify_roe(roe, pk):
            outcome = "bad_signature"
        elif now < roe.not_before:
            outcome = "not_yet"
        elif now > roe.not_after:
            outcome = "expired"
        else:
            outcome = "active"
        self._observe(RoECheck(engagement_id=engagement_id, outcome=outcome, at=now))  # type: ignore[arg-type]
        return roe if outcome == "active" else None


# ---------------------------------------------------------------------------
# Scope matching: explicit deny wins, unmatched is out
# ---------------------------------------------------------------------------

_KIND_RE = re.compile(r"^(?P<kind>[a-z_]+):(?P<value>.+)$")


def _parse(entry: str) -> tuple[str, str]:
    m = _KIND_RE.match(entry.strip())
    if not m:
        raise ValueError(f"scope entry must be kind:value, got {entry!r}")
    return m.group("kind"), m.group("value")


def _match_one(target: str, entry: str) -> bool:
    """
    Both sides are kind:value. Kinds must agree. CIDR entries contain IP
    targets; everything else is a case-insensitive glob (fnmatch).
    A hostname is never matched against a CIDR here: resolution to canonical
    identifiers (host id, IP, asset group) happens before matching, in the
    asset inventory (Chapter 8), and the resolved ids are what the gateway
    passes in as target_ids.
    """
    tk, tv = _parse(target)
    ek, ev = _parse(entry)
    if tk != ek:
        return False
    if ek == "cidr":
        try:
            return ipaddress.ip_address(tv) in ipaddress.ip_network(ev, strict=False)
        except ValueError:
            return False
    return fnmatch.fnmatchcase(tv.lower(), ev.lower())


@dataclass
class ScopeVerdict:
    in_scope: bool
    reason: str
    matched_entry: Optional[str] = None


class ScopeMatcher:
    def __init__(self, roe: RulesOfEngagement) -> None:
        self._in = list(roe.scope.in_scope)
        self._out = list(roe.scope.out_of_scope)

    def check_target(self, target: str) -> ScopeVerdict:
        for e in self._out:
            if _match_one(target, e):
                return ScopeVerdict(False, "explicit_deny", e)
        for e in self._in:
            if _match_one(target, e):
                return ScopeVerdict(True, "in_scope", e)
        return ScopeVerdict(False, "unmatched_default_deny")

    def check_object(self, identifiers: Sequence[str]) -> ScopeVerdict:
        """One object known by several identifiers: explicit deny on any of them wins, then any in-scope match admits."""
        verdicts = [self.check_target(i) for i in identifiers]
        denied = next((v for v in verdicts if v.reason == "explicit_deny"), None)
        if denied is not None:
            return denied
        admitted = next((v for v in verdicts if v.in_scope), None)
        return admitted or ScopeVerdict(False, "unmatched_default_deny")

    def check_action(self, action: ProposedAction) -> ScopeVerdict:
        """Every target must be in scope. One out-of-scope target fails the action."""
        if not action.target_ids:
            return ScopeVerdict(False, "no_targets_declared")
        for t in action.target_ids:
            v = self.check_target(t)
            if not v.in_scope:
                return v
        return ScopeVerdict(True, "all_targets_in_scope")


def scope_labels(roe: RulesOfEngagement, target: str) -> list[str]:
    """
    The RoE scope entries this target matches, verbatim. The Rego policy
    (Chapter 14) compares labels by equality and never parses a pattern, so
    the glob and CIDR semantics live here, once: the gateway attaches these
    entries to each resolved target, and "cidr:10.20.0.0/16" becomes a label
    of "cidr:10.20.4.17". A bare id with no kind prefix matches nothing here;
    the resolver's own labels cover it.
    """
    matched: list[str] = []
    for entry in (*roe.scope.out_of_scope, *roe.scope.in_scope):
        try:
            if _match_one(target, entry):
                matched.append(entry)
        except ValueError:
            continue
    return matched


# ---------------------------------------------------------------------------
# Rate and scale limits: a token bucket per action class per engagement
# ---------------------------------------------------------------------------

_RATE_RE = re.compile(r"^(?P<n>\d+)/(?P<q>\d+)(?P<u>[smhd])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_rate(spec: str) -> tuple[int, float]:
    """'1/10m' -> (capacity 1, refill one token every 600s)."""
    m = _RATE_RE.match(spec.strip())
    if not m:
        raise ValueError(f"bad rate spec {spec!r}; expected like '3/1h'")
    n, q, u = int(m.group("n")), int(m.group("q")), m.group("u")
    window = q * _UNIT[u]
    return n, window / n


@dataclass
class _Bucket:
    capacity: int
    refill_every: float
    tokens: float
    updated: float


class RateLimiter:
    """
    Exceeding the limit does not deny; it forces human review. "Isolate at
    most one host autonomously per ten minutes; a second within the window
    goes to a human." The bucket is keyed by (engagement, action class), so
    a runaway agent is capped per engagement regardless of how many runs or
    sub-agents it fans out into.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._clock = clock

    def _bucket(self, key: tuple[str, str], spec: str) -> _Bucket:
        if key not in self._buckets:
            cap, every = parse_rate(spec)
            self._buckets[key] = _Bucket(cap, every, float(cap), self._clock())
        return self._buckets[key]

    def take(self, engagement_id: str, ceiling: ActionCeiling) -> Literal["allow", "escalate"]:
        if not ceiling.rate_limit:
            return "allow"
        b = self._bucket((engagement_id, ceiling.action_class.key()), ceiling.rate_limit)
        now = self._clock()
        b.tokens = min(b.capacity, b.tokens + (now - b.updated) / b.refill_every)
        b.updated = now
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return "allow"
        return "escalate"


# ---------------------------------------------------------------------------
# Reversibility-first: prefer the variant that can be undone
# ---------------------------------------------------------------------------

REVERSIBLE_ALTERNATIVES: dict[str, str] = {
    # irreversible or harsher tool -> reversible-preferred sibling
    "mail_purge_campaign": "mail_quarantine_message",
    "idp_disable_account": "idp_revoke_sessions",
    "idp_reset_credential": "idp_revoke_sessions",
}


def prefer_reversible(action: ProposedAction) -> Optional[str]:
    """
    Returns the reversible sibling's tool name when one exists and the
    proposed action is not already the reversible one. The policy engine
    uses this to escalate with a suggestion, not to silently rewrite the
    call: the agent must re-propose, and the ledger shows both.
    """
    if action.action_class.reversibility != Reversibility.REVERSIBLE:
        return REVERSIBLE_ALTERNATIVES.get(action.tool_name)
    return None


# ---------------------------------------------------------------------------
# Staged rollout with auto-halt
# ---------------------------------------------------------------------------


@dataclass
class WaveResult:
    wave: int
    targets: list[str]
    ok: list[str]
    failed: list[str]
    halted: bool = False
    halt_reason: Optional[str] = None


class CanaryRollout:
    """
    Any action touching more than one object runs in waves. After each wave
    an anomaly predicate inspects the results and the world; if it returns a
    reason, the rollout halts and the remaining targets are never touched.
    The caller writes one ledger record per wave (build thread, 11.7).
    """

    def __init__(self, waves: Sequence[int] = (1, 5, 25), max_failure_ratio: float = 0.0) -> None:
        self._waves = list(waves)
        self._max_fail = max_failure_ratio

    def plan(self, targets: Sequence[str]) -> list[list[str]]:
        out: list[list[str]] = []
        i = 0
        for size in self._waves:
            if i >= len(targets):
                break
            out.append(list(targets[i:i + size]))
            i += size
        if i < len(targets):
            out.append(list(targets[i:]))
        return out

    def run(self, targets: Sequence[str],
            execute: Callable[[str], bool],
            anomaly: Callable[[WaveResult], Optional[str]],
            on_wave: Optional[Callable[[WaveResult], None]] = None) -> list[WaveResult]:
        results: list[WaveResult] = []
        for n, wave in enumerate(self.plan(targets), start=1):
            ok, failed = [], []
            for t in wave:
                (ok if execute(t) else failed).append(t)
            res = WaveResult(wave=n, targets=wave, ok=ok, failed=failed)
            if wave and len(failed) / len(wave) > self._max_fail:
                res.halted, res.halt_reason = True, f"failure ratio {len(failed)}/{len(wave)}"
            else:
                reason = anomaly(res)
                if reason:
                    res.halted, res.halt_reason = True, reason
            results.append(res)
            if on_wave:
                on_wave(res)
            if res.halted:
                break
        return results
