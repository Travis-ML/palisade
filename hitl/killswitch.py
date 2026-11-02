# palisade/hitl/killswitch.py
import logging
from typing import Optional, Protocol
from pydantic import BaseModel, Field
from palisade.core.types import DecisionRecord, Plane, RunState, new_id, utcnow

log = logging.getLogger("palisade.hitl.killswitch")

class RunController(Protocol):
    def active_runs(self) -> list[RunState]: ...
    def halt(self, run_id: str, reason: str) -> None: ...
    def tenant_of(self, run_id: str) -> str | None: ...
    def capability_of(self, run_id: str) -> str | None: ...

class CredentialRevoker(Protocol):          # palisade.identity.broker.CredentialBroker satisfies this
    def revoke_all(self, agent_id: str) -> int: ...

class LedgerWriter(Protocol):               # palisade.ledger.ledger.Ledger satisfies this
    def append(self, record: DecisionRecord) -> str: ...

class TripState(Protocol):                  # outside the agent's process; gateways read it every step
    def set_tripped(self, scope: str, by: str, reason: str) -> None: ...
    def tripped_scopes(self) -> list[str]: ...

class KillRecord(BaseModel):
    kill_id: str = Field(default_factory=lambda: new_id("kill"))
    scope: str
    by: str
    reason: str
    runs_halted: list[str]
    agents_revoked: dict[str, int]
    ledger_hashes: list[str]
    tripped_at: str

def run_in_scope(run: RunState, scope: str, ctl: RunController) -> bool:
    kind, _, value = scope.partition(":")
    match kind:
        case "global":      return True
        case "plane":       return run.plane is Plane(value)
        case "engagement":  return run.engagement_id == value
        case "tenant":      return ctl.tenant_of(run.run_id) == value
        case "capability":  return ctl.capability_of(run.run_id) == value
        case "run":         return run.run_id == value
        case "agent":       # a worker's id is prefixed by its lead's: killing a lead kills its tree
            return run.agent_id == value or run.agent_id.startswith(value + "/")
    raise ValueError(f"unknown kill scope: {scope}")

class KillSwitch:
    def __init__(self, runs: RunController, broker: CredentialRevoker,
                 ledger: LedgerWriter, trip_state: TripState) -> None:
        self._runs, self._broker, self._ledger, self._trip = runs, broker, ledger, trip_state

    def is_tripped(self, *candidates: str) -> Optional[str]:
        """Called by the loop (Chapter 5) and the gateway on every governed step with the
        identifiers that describe the current run: "global", the agent id, the run id, and
        optionally the engagement or tenant. Returns the first tripped scope that covers any
        of them, or None. A transport failure raises, and the caller treats that as
        governance unavailable (Control A13): it halts rather than assuming "not tripped"."""
        for scope in self._trip.tripped_scopes():
            kind, _, value = scope.partition(":")
            if kind == "global":
                return scope
            for c in candidates:
                if c == value or (kind == "agent" and c.startswith(value + "/")):
                    return scope
        return None

    def trip(self, scope: str, by: str, reason: str) -> KillRecord:
        now = utcnow()
        self._trip.set_tripped(scope, by, reason)                 # 1. fence every gateway
        affected = [r for r in self._runs.active_runs() if run_in_scope(r, scope, self._runs)]

        revoked: dict[str, int] = {}                                # 2. revoke first
        for agent_id in sorted({r.agent_id for r in affected}):
            try:
                revoked[agent_id] = self._broker.revoke_all(agent_id)
            except Exception as exc:
                log.critical("revoke_all failed for %s during kill %s: %s", agent_id, scope, exc)
                revoked[agent_id] = -1

        halted: list[str] = []                                      # 3. then halt the loops
        for r in affected:
            self._runs.halt(r.run_id, f"kill:{scope}:{by}")
            halted.append(r.run_id)

        hashes: list[str] = []                                      # 4. account for it
        for r in affected:
            rec = DecisionRecord(
                run_id=r.run_id, step=r.step + 1, agent_id=r.agent_id, plane=r.plane,
                engagement_id=r.engagement_id, autonomy_tier=0, context_hash="",
                reasoning_summary=f"kill switch tripped by {by}: {reason}",
                human_intervention="kill",
            ).seal(prev_hash=r.last_record_hash)
            try:
                hashes.append(self._ledger.append(rec))
            except Exception as exc:
                log.critical("ledger append failed during kill %s: %s", scope, exc)

        return KillRecord(scope=scope, by=by, reason=reason, runs_halted=halted,
                          agents_revoked=revoked, ledger_hashes=hashes, tripped_at=now.isoformat())
