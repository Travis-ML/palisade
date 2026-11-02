# palisade/capabilities/attack_simulation/tools/range_server.py
from mcp.server.fastmcp import FastMCP

from palisade.core.types import (
    ActionClass, ActionDomain, BlastRadius, Reversibility, ProposedAction,
)
from palisade.gateway import Gateway
from palisade.capabilities.attack_simulation.authorization import require_active_roe
from palisade.capabilities.attack_simulation.failsafe import preflight

mcp = FastMCP("palisade-attack-simulation")


@mcp.tool()
def range_emulate_step(
    engagement_id: str,
    scenario_id: str,
    phase_index: int,
    technique_id: str,        # an ATT&CK technique id, e.g. "T1566" (the taxonomy, not the how)
    objective: str,           # what this step measures, in defensive terms
) -> dict:
    """Emulate one scenario step inside the authorized range and return its
    defensive measurement. The step is expressed as a technique id and an
    objective. Implementation of the technique is internal to the range and is
    NOT an argument of this tool. Refuses without an active RoE or intact
    containment."""
    engine = _range_engine(engagement_id)
    preflight(engine)                              # Control C-24.5: halts on any uncertainty
    roe = require_active_roe(engagement_id)        # Control C-24.3: no RoE, no run

    if technique_id not in roe_permitted_techniques(roe):
        return {"status": "denied", "reason": "technique_class_out_of_scope"}

    action = ProposedAction(
        tool_name="range_emulate_step",
        arguments={
            "scenario_id": scenario_id,
            "phase_index": phase_index,
            "technique_id": technique_id,          # taxonomy id only
            "objective": objective,
        },
        action_class=ActionClass(
            domain=ActionDomain.OFFENSE,
            reversibility=Reversibility.REVERSIBLE,   # a step against synthetic range assets
            blast_radius=BlastRadius.SINGLE,          # one range, contained
        ),
        target_ids=[f"range:{engine.range_id}"],
        rationale=f"Scenario {scenario_id} phase {phase_index}: {objective}.",
    )
    decision = Gateway().authorize(action, agent=engine.identity, state=engine.state)
    if decision.verdict != "allow":
        return {"status": "denied", "reason": decision.rule_id}

    measurement = engine.emulate(scenario_id, phase_index, technique_id, objective)
    # measurement is a defensive result: did the mirrored blue stack detect and respond.
    return {
        "status": "ok",
        "detected": measurement.detected,
        "responded": measurement.responded,
        "time_to_detect_ms": measurement.ttd_ms,
        "coverage_delta": measurement.coverage_delta,
    }
