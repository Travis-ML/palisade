# palisade/policy/build_data.py
"""Generate the OPA data document (tools and taxonomy) from the tool catalog and Chapter 11's matrix."""
from __future__ import annotations

import json
import sys

from palisade.core.types import ActionClass, ActionDomain, AutonomyTier, Plane
from palisade.roe import ceiling_for
from palisade.tools.catalog import TOOL_CATALOG, CatalogEntry


def taxonomy_row(ac: ActionClass) -> dict[str, object]:
    """The tier at which a class may run without a human, and whether a human is always required."""
    plane = Plane.OFFENSIVE if ac.domain is ActionDomain.OFFENSE else Plane.DEFENSIVE
    rule = ceiling_for(ac, plane)
    if ac.domain in (ActionDomain.OBSERVE, ActionDomain.ENRICH):
        return {"required_tier": 0, "approval_always": False}
    if rule.gate == "five_question":     # the five questions and a human, every time
        return {"required_tier": int(AutonomyTier.ACT_WITH_APPROVAL), "approval_always": True}
    if rule.gate == "approval":          # a human every time: no reachable tier satisfies the class alone
        return {"required_tier": int(AutonomyTier.AUTONOMOUS), "approval_always": False}
    if ac.domain is ActionDomain.INTERNAL_CHANGE:   # a draft; its review is the gate
        return {"required_tier": int(AutonomyTier.DRAFT), "approval_always": False}
    return {"required_tier": int(rule.max_tier), "approval_always": False}


def build(catalog: dict[str, CatalogEntry] = TOOL_CATALOG) -> dict[str, object]:
    taxonomy = {e.action_class.key(): taxonomy_row(e.action_class) for e in catalog.values()}
    tools = {name: {"plane": e.plane.value,
                    "requires_targets": e.action_class.domain not in (ActionDomain.OBSERVE, ActionDomain.ENRICH)}
             for name, e in catalog.items()}
    return {"palisade": {"taxonomy": dict(sorted(taxonomy.items())), "tools": dict(sorted(tools.items()))}}


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=2)
    sys.stdout.write("\n")
