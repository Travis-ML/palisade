# palisade/capabilities/attack_simulation/authorization.py
from __future__ import annotations

from palisade.core.types import RulesOfEngagement
from palisade.roe import RoEStore          # Chapter 11: verifies signature + window


class AuthorizationError(Exception):
    """Raised to halt the scenario engine. There is no ungoverned fallback."""


def require_active_roe(engagement_id: str) -> RulesOfEngagement:
    """The engine's first call. RoEStore.active() returns None if the RoE is
    expired or its signature does not verify. None is a hard stop."""
    roe = RoEStore().active(engagement_id)
    if roe is None:
        raise AuthorizationError("no active, in-window, signed RoE: engine refuses to run")
    if roe.plane.value != "offensive":
        raise AuthorizationError("RoE is not scoped to the offensive plane")
    return roe


def require_dual_authorization(roe: RulesOfEngagement, cosignatures: list[str]) -> None:
    """High-impact scenarios need two distinct named authorities. The primary RoE
    signature is one; a detached co-signature from a second authority is the other."""
    distinct = {s for s in cosignatures if s}
    named = set(roe.approvers) | {roe.owner}
    authorities = {s for s in distinct if s in named}
    if len(authorities) < 2:
        raise AuthorizationError("high-impact scenario requires two named authorities")
