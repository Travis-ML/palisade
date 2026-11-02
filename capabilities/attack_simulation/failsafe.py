# palisade/capabilities/attack_simulation/failsafe.py
from palisade.capabilities.attack_simulation.authorization import (
    AuthorizationError, require_active_roe,
)


def preflight(engine) -> None:
    """Called before every emulation step. Any failure halts; nothing degrades.
    This is Control A13 at its strictest: governance uncertain => offense stops."""
    if not engine.substrate.writable():
        engine.halt("accounting substrate unavailable")
        return
    require_active_roe(engine.engagement_id)         # raises AuthorizationError if not active
    if not engine.killswitch.reachable():
        engine.halt("kill switch unreachable")
        return
    if not engine.containment.intact() or engine.registry.coverage() < 1.0:
        engine.halt("containment boundary not verified")
        return
