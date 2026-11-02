"""palisade/capabilities/register_all.py: admit every capability package; touch nothing else."""
from pathlib import Path

from palisade.capabilities.loader import load_capability, register
from palisade.core.types import ActionClass


class PalisadeControlPlane:
    """Adapter over the components earlier chapters built. Thin on purpose: the seams already exist."""

    def __init__(self, gateway, tiers, policy, evals, governor, dashboards) -> None:
        self.gateway, self.tiers, self.policy = gateway, tiers, policy
        self.evals, self.governor, self.dashboards = evals, governor, dashboards

    def register_tools(self, capability, tools):
        for t in tools:
            self.gateway.register_tool(capability, t.name, t.server, t.version, t.description_sha256, t.action_class)

    def seed_tiers(self, capability: str, classes: list[ActionClass]):
        self.tiers.seed(capability, classes)                    # SHADOW for new keys; existing tiers untouched

    def push_policy_data(self, doc):
        self.policy.push_data(doc)                              # OPA /v1/data merge

    def register_eval_suite(self, capability, spec):
        self.evals.register(capability, spec.suite, spec.model_dump())

    def register_budget(self, scope_id, limit_usd, window):
        self.governor.add_scope(scope_id, limit_usd, window)

    def register_metrics(self, capability, metrics):
        self.dashboards.register(capability, [m.model_dump() for m in metrics])


def admit_all(root: Path, cp: PalisadeControlPlane) -> list[str]:
    admitted = []
    for manifest_path in sorted(root.glob("*/capability.yaml")):
        m = load_capability(manifest_path)                     # refuses anything the control plane cannot govern
        register(m, cp)
        admitted.append(f"{m.name}@{m.version} ({m.plane.value})")
    return admitted
