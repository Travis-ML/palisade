"""
palisade.identity.broker
========================

Governed non-human identity for Palisade: the identity registry (lifecycle
and IGA hooks), explicit delegation grants, and the CredentialBroker that
issues ScopedCredentials bound to one action, single-use, minutes-long.

The broker never trusts its caller. It re-checks that the action was
authorized, that the identity is live and recertified, that the plane
matches, and that the resource belongs to the action's declared targets.
Then it mints a token the tool server can verify offline and redeem once.

Pedagogical: tokens are EdDSA-signed compact JWTs minted locally. In
production the mint step calls your secrets platform (dynamic secrets, a
cloud STS with a session policy, or an OAuth token exchange) and the token
that comes back is what the tool server receives. The shape of the grant,
the single-use rule, and the revocation path are what this chapter is about.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Literal, Optional, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from palisade.core.types import (
    ActionDomain,
    AgentIdentity,
    ApprovalRecord,
    Plane,
    PolicyDecision,
    ProposedAction,
    ScopedCredential,
    new_id,
    utcnow,
)

# ---------------------------------------------------------------------------
# Trust domains: one per plane, no federation between them
# ---------------------------------------------------------------------------

TRUST_DOMAIN: dict[Plane, str] = {
    Plane.DEFENSIVE: "spiffe://palisade.example/",
    Plane.OFFENSIVE: "spiffe://range.palisade.example/",
}

_SPIFFE_RE = re.compile(r"^spiffe://[a-z0-9.-]+/agent/[A-Za-z0-9._-]+(/worker/[A-Za-z0-9._-]+)*$")


def plane_of(agent_id: str) -> Optional[Plane]:
    for plane, prefix in TRUST_DOMAIN.items():
        if agent_id.startswith(prefix):
            return plane
    return None


def validate_spiffe_id(agent_id: str) -> None:
    if not _SPIFFE_RE.match(agent_id):
        raise ValueError(f"not a Palisade agent SPIFFE ID: {agent_id}")
    if plane_of(agent_id) is None:
        raise ValueError(f"unknown trust domain in {agent_id}")


# ---------------------------------------------------------------------------
# Identity lifecycle and IGA hooks
# ---------------------------------------------------------------------------


class IdentityError(RuntimeError):
    pass


class IgaConnector(Protocol):
    """
    The minimum Palisade needs from the identity governance system. A real
    connector speaks SCIM or the IGA vendor's API; a test one is a dict.
    """

    def upsert(self, identity: AgentIdentity) -> None: ...
    def owner_is_active(self, owner: str) -> bool: ...
    def disable(self, agent_id: str, reason: str) -> None: ...


class IdentityStatus(BaseModel):
    agent_id: str
    state: Literal["active", "disabled"] = "active"
    disabled_reason: Optional[str] = None
    last_seen: Optional[datetime] = None
    recert_history: list[tuple[datetime, str]] = Field(default_factory=list)


@dataclass
class OrphanFinding:
    agent_id: str
    reason: str


class IdentityRegistry:
    """
    Provision, recertify, deprovision. Every agent has a named human owner,
    a plane, and a recertification deadline. The reconcile() job runs daily:
    it disables identities whose owner has left, whose recertification is
    overdue, or which have been idle past the dormancy window. Orphaned
    agent identities are how standing access survives the humans who
    created it; this job is the control that kills them.
    """

    RECERT_INTERVAL = timedelta(days=90)   # stricter than the human default
    DORMANCY = timedelta(days=30)

    def __init__(self, iga: IgaConnector, clock: Callable[[], datetime] = utcnow) -> None:
        self._iga = iga
        self._now = clock
        self._ids: dict[str, AgentIdentity] = {}
        self._status: dict[str, IdentityStatus] = {}

    def provision(self, agent_id: str, display_name: str, owner: str, plane: Plane,
                  delegated_from: Optional[str] = None) -> AgentIdentity:
        validate_spiffe_id(agent_id)
        if plane_of(agent_id) != plane:
            raise IdentityError(f"{agent_id} is not in the {plane.value} trust domain")
        if not owner or not self._iga.owner_is_active(owner):
            raise IdentityError(f"owner {owner!r} is not an active principal; refusing to provision")
        if delegated_from and not agent_id.startswith(delegated_from.rstrip("/") + "/worker/"):
            raise IdentityError("a sub-agent's SPIFFE ID must sit under its lead's path")
        ident = AgentIdentity(
            agent_id=agent_id, display_name=display_name, owner=owner, plane=plane,
            recertify_by=self._now() + self.RECERT_INTERVAL, delegated_from=delegated_from,
        )
        self._ids[agent_id] = ident
        self._status[agent_id] = IdentityStatus(agent_id=agent_id)
        self._iga.upsert(ident)
        return ident

    def get(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._ids.get(agent_id)

    def status(self, agent_id: str) -> Optional[IdentityStatus]:
        return self._status.get(agent_id)

    def touch(self, agent_id: str) -> None:
        if agent_id in self._status:
            self._status[agent_id].last_seen = self._now()

    def recertify(self, agent_id: str, by: str) -> AgentIdentity:
        ident = self._ids[agent_id]
        if by != ident.owner:
            raise IdentityError("only the named owner recertifies; delegation of recert is not allowed")
        ident.recertify_by = self._now() + self.RECERT_INTERVAL
        self._status[agent_id].recert_history.append((self._now(), by))
        self._iga.upsert(ident)
        return ident

    def deprovision(self, agent_id: str, reason: str) -> None:
        st = self._status.get(agent_id)
        if st is None:
            return
        st.state, st.disabled_reason = "disabled", reason
        self._iga.disable(agent_id, reason)

    def is_live(self, agent_id: str, at: Optional[datetime] = None) -> tuple[bool, str]:
        now = at or self._now()
        ident, st = self._ids.get(agent_id), self._status.get(agent_id)
        if ident is None or st is None:
            return False, "unknown identity"
        if st.state != "active":
            return False, f"disabled: {st.disabled_reason}"
        if now > ident.recertify_by:
            return False, "recertification overdue"
        return True, "live"

    def orphans(self) -> list[OrphanFinding]:
        now = self._now()
        out: list[OrphanFinding] = []
        for aid, ident in self._ids.items():
            st = self._status[aid]
            if st.state != "active":
                continue
            if not self._iga.owner_is_active(ident.owner):
                out.append(OrphanFinding(aid, f"owner {ident.owner} no longer active"))
            elif now > ident.recertify_by:
                out.append(OrphanFinding(aid, "recertification overdue"))
            elif st.last_seen and now - st.last_seen > self.DORMANCY:
                out.append(OrphanFinding(aid, f"dormant since {st.last_seen.date()}"))
        return out

    def reconcile(self) -> list[OrphanFinding]:
        found = self.orphans()
        for f in found:
            self.deprovision(f.agent_id, f.reason)
        return found


# ---------------------------------------------------------------------------
# Delegation as a first-class, logged grant
# ---------------------------------------------------------------------------


class DelegationGrant(BaseModel):
    """
    'Agent A acts on behalf of principal P, for these targets, until T.'
    Modeled on the RFC 8693 actor chain: the agent is the actor, the
    principal is the subject, and the grant is what the broker checks. It
    is narrower than or equal to the principal's own rights, never wider.
    """

    grant_id: str = Field(default_factory=lambda: new_id("grant"))
    actor: str                     # agent SPIFFE ID
    on_behalf_of: str              # user id, or the lead agent's SPIFFE ID
    scope_targets: list[str]       # kind:value entries, same grammar as the RoE
    permitted_domains: list[ActionDomain]
    issued_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    issued_by: str                 # the gateway or lead that created it
    parent_grant_id: Optional[str] = None  # sub-delegation chains back to the root

    def covers(self, action: ProposedAction, at: Optional[datetime] = None) -> tuple[bool, str]:
        now = at or utcnow()
        if now > self.expires_at:
            return False, "delegation expired"
        if action.action_class.domain not in self.permitted_domains:
            return False, f"domain {action.action_class.domain.value} not delegated"
        for t in action.target_ids:
            if t not in self.scope_targets and not any(
                _glob(t, s) for s in self.scope_targets
            ):
                return False, f"target {t} outside delegated scope"
        return True, "covered"


def _glob(target: str, pattern: str) -> bool:
    import fnmatch
    return fnmatch.fnmatchcase(target.lower(), pattern.lower())


def narrow(parent: DelegationGrant, actor: str, targets: list[str],
           domains: list[ActionDomain], ttl: timedelta, issued_by: str,
           now: Optional[datetime] = None) -> DelegationGrant:
    """Sub-delegation can only shrink. Anything not inside the parent is refused."""
    now = now or utcnow()
    for t in targets:
        if not any(_glob(t, s) for s in parent.scope_targets):
            raise IdentityError(f"cannot delegate {t}: not within parent grant")
    for d in domains:
        if d not in parent.permitted_domains:
            raise IdentityError(f"cannot delegate domain {d.value}: not within parent grant")
    expires = min(parent.expires_at, now + ttl)
    return DelegationGrant(actor=actor, on_behalf_of=parent.on_behalf_of, scope_targets=targets,
                           permitted_domains=domains, expires_at=expires, issued_by=issued_by,
                           parent_grant_id=parent.grant_id)


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


class BrokerError(RuntimeError):
    """The loop treats this as governance unavailable or refused: halt the step."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class GrantEvent:
    """What the broker reports to the ledger. The token is never in here."""
    grant_id: str
    agent_id: str
    action_id: str
    resource: str
    permissions: list[str]
    event: Literal["issued", "redeemed", "refused", "revoked", "expired_unused"]
    detail: str
    at: datetime = field(default_factory=utcnow)


class CredentialBroker:
    """
    issue(agent, action, resource, permissions, ttl) -> ScopedCredential
    revoke_all(agent_id) -> int

    Invariants enforced here, not by convention:
      1. No grant without an authorizing decision (allow, or escalate plus an
         approved ApprovalRecord). The broker checks this itself.
      2. The identity is live: registered, not disabled, recertified, in the
         trust domain of the plane it claims.
      3. The resource is one of the action's declared targets.
      4. TTL is capped (default 10 minutes). Single-use by default.
      5. revoke_all() invalidates every live grant for an agent and blocks
         new issuance until a human lifts the block. The kill switch calls it.
    """

    MAX_TTL = timedelta(minutes=10)

    def __init__(self, registry: IdentityRegistry, signing_key: Ed25519PrivateKey, key_id: str,
                 observer: Optional[Callable[[GrantEvent], None]] = None,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self._registry = registry
        self._key = signing_key
        self._key_id = key_id
        self._observe = observer or (lambda e: None)
        self._now = clock
        self._live: dict[str, ScopedCredential] = {}     # grant_id -> credential
        self._redeemed: set[str] = set()
        self._blocked_agents: dict[str, str] = {}        # agent_id -> reason

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    # -- issuance -------------------------------------------------------------

    def _refuse(self, agent_id: str, action: ProposedAction, resource: str,
                permissions: list[str], why: str) -> BrokerError:
        self._observe(GrantEvent("", agent_id, action.action_id, resource, permissions, "refused", why))
        return BrokerError(why)

    def issue(self, agent: AgentIdentity, action: ProposedAction, resource: str,
              permissions: list[str], ttl: timedelta, *,
              decision: Optional[PolicyDecision] = None,
              approval: Optional[ApprovalRecord] = None,
              delegation: Optional[DelegationGrant] = None) -> ScopedCredential:
        aid = agent.agent_id

        # 1. authorization: the broker re-checks, it does not take the caller's word
        if decision is None:
            raise self._refuse(aid, action, resource, permissions, "no policy decision presented")
        if decision.verdict == "deny":
            raise self._refuse(aid, action, resource, permissions, f"denied by {decision.rule_id}")
        if decision.verdict == "escalate":
            if approval is None or approval.decision not in ("approved", "modified"):
                raise self._refuse(aid, action, resource, permissions, "escalated action lacks an approval")
        # 2. identity
        live, why = self._registry.is_live(aid, self._now())
        if not live:
            raise self._refuse(aid, action, resource, permissions, f"identity not live: {why}")
        if aid in self._blocked_agents:
            raise self._refuse(aid, action, resource, permissions, f"agent blocked: {self._blocked_agents[aid]}")
        if plane_of(aid) != agent.plane:
            raise self._refuse(aid, action, resource, permissions, "plane does not match trust domain")
        # 3. resource binding
        if resource not in action.target_ids:
            raise self._refuse(aid, action, resource, permissions, f"resource {resource} is not a declared target")
        # 3b. delegation, when acting on behalf of someone
        if delegation is not None:
            ok, why = delegation.covers(action, self._now())
            if not ok or delegation.actor != aid:
                raise self._refuse(aid, action, resource, permissions, f"delegation does not cover: {why}")
        # 4. TTL cap
        ttl = min(ttl, self.MAX_TTL)
        if ttl <= timedelta(0):
            raise self._refuse(aid, action, resource, permissions, "non-positive ttl")

        now = self._now()
        grant_id = new_id("grant")
        payload = {
            "iss": "palisade-broker", "kid": self._key_id, "jti": grant_id,
            "sub": aid, "aud": resource, "act_id": action.action_id,
            "perms": sorted(permissions), "iat": int(now.timestamp()),
            "exp": int((now + ttl).timestamp()), "single_use": True,
            "dlg": delegation.grant_id if delegation else None,
        }
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self._key_id}
        signing_input = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}." \
                        f"{_b64(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())}"
        token = f"{signing_input}.{_b64(self._key.sign(signing_input.encode()))}"

        cred = ScopedCredential(
            grant_id=grant_id, agent_id=aid, action_id=action.action_id, resource=resource,
            permissions=sorted(permissions), issued_at=now, expires_at=now + ttl,
            single_use=True, token=token,
        )
        self._live[grant_id] = cred
        self._registry.touch(aid)
        self._observe(GrantEvent(grant_id, aid, action.action_id, resource, cred.permissions,
                                 "issued", f"ttl={int(ttl.total_seconds())}s"))
        return cred

    # -- redemption (called by the tool server or the gateway's executor) ------

    def redeem(self, token: str, resource: str, permission: str) -> ScopedCredential:
        try:
            h, p, s = token.split(".")
            self._key.public_key().verify(_unb64(s), f"{h}.{p}".encode())
            payload = json.loads(_unb64(p))
        except (ValueError, InvalidSignature) as exc:
            raise BrokerError(f"token invalid: {exc}") from exc
        grant_id = payload["jti"]
        cred = self._live.get(grant_id)
        if cred is None:
            raise BrokerError("grant unknown or revoked")
        now = self._now()
        if now > cred.expires_at:
            self._live.pop(grant_id, None)
            self._observe(GrantEvent(grant_id, cred.agent_id, cred.action_id, cred.resource,
                                     cred.permissions, "expired_unused", "redeem after expiry"))
            raise BrokerError("grant expired")
        if grant_id in self._redeemed:
            raise BrokerError("grant already redeemed (single use)")
        if payload["aud"] != resource or permission not in payload["perms"]:
            raise BrokerError("token not valid for this resource or permission")
        self._redeemed.add(grant_id)
        self._live.pop(grant_id, None)
        self._observe(GrantEvent(grant_id, cred.agent_id, cred.action_id, resource,
                                 [permission], "redeemed", "ok"))
        return cred

    # -- revocation -------------------------------------------------------------

    def revoke_all(self, agent_id: str, reason: str = "kill switch") -> int:
        """
        Invalidate every live grant for the agent and refuse new ones until
        unblock() is called by a human. Returns the number revoked. Also
        revokes grants held by the agent's sub-agents (path prefix match),
        because a lead that has been stopped must not keep acting through
        its workers.
        """
        n = 0
        for gid, cred in list(self._live.items()):
            if cred.agent_id == agent_id or cred.agent_id.startswith(agent_id.rstrip("/") + "/worker/"):
                self._live.pop(gid)
                n += 1
                self._observe(GrantEvent(gid, cred.agent_id, cred.action_id, cred.resource,
                                         cred.permissions, "revoked", reason))
        self._blocked_agents[agent_id] = reason
        return n

    def unblock(self, agent_id: str, by: str) -> None:
        self._blocked_agents.pop(agent_id, None)
        self._observe(GrantEvent("", agent_id, "", "", [], "revoked", f"block lifted by {by}"))

    def live_grants(self, agent_id: Optional[str] = None) -> list[ScopedCredential]:
        return [c for c in self._live.values() if agent_id is None or c.agent_id == agent_id]
