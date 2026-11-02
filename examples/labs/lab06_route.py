from palisade.core.types import Plane
from palisade.router import ModelRouter, RoutingDenied, RoutingPolicy, TaskDescriptor

policy = RoutingPolicy.from_yaml("labs/routing.yaml", {
    "settings.models.frontier": "frontier-snapshot-2026-09", "settings.models.frontier_version": "2026-09",
    "settings.models.fast": "fast-snapshot-2026-09", "settings.models.fast_version": "2026-09",
})

class Dummy:
    def __init__(self, key): self.model_id, self.model_version = key, "x"
    def complete(self, *a, **k): raise NotImplementedError

class RoE:                                  # stands in for RoEStore (Chapter 11)
    def active(self, eid): return object() if eid == "eng_2026q4_range_07" else None

def clients_for(plane):
    return {k: Dummy(k) for k, s in policy.models.items() if s.plane == plane}

defensive = ModelRouter(policy, clients_for(Plane.DEFENSIVE), Plane.DEFENSIVE, RoE())
offensive = ModelRouter(policy, clients_for(Plane.OFFENSIVE), Plane.OFFENSIVE, RoE(), verified_weights={"range_analyst"})
