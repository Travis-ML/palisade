# palisade/capabilities/adversarial_testing/tools/probe_server.py
from mcp.server.fastmcp import FastMCP

from palisade.core.types import (
    ActionClass, ActionDomain, BlastRadius, Reversibility, ProposedAction,
)
from palisade.roe import RoEStore          # Chapter 11
from palisade.gateway import Gateway       # Chapter 7

mcp = FastMCP("palisade-adversarial-testing")

# Registered suites. The agent may select among these; it cannot invent one.
REGISTERED_SUITES = {"garak", "pyrit", "promptfoo"}


@mcp.tool()
def probe_suite_run(engagement_id: str, suite: str, config_ref: str) -> dict:
    """Launch a registered probe suite against the engagement's authorized target.

    The suite and config are registered, version-controlled artifacts. The target
    endpoint is resolved from the signed RoE, never from the caller. Refuses
    without an active, in-window RoE.
    """
    if suite not in REGISTERED_SUITES:
        return {"status": "denied", "reason": "unregistered_suite"}

    roe = RoEStore().active(engagement_id)          # None if expired or signature invalid
    if roe is None:
        return {"status": "denied", "reason": "roe.inactive"}      # Control C-23.3

    target = _resolve_target_from_roe(roe)          # the ONE in-scope isolated instance
    config = _load_registered_config(config_ref)    # version-controlled; endpoint checked
    if config.endpoint != target.endpoint:
        return {"status": "denied", "reason": "endpoint_not_authorized"}   # Control C-23.2

    action = ProposedAction(
        tool_name="probe_suite_run",
        arguments={"suite": suite, "config_ref": config_ref, "target": target.id},
        action_class=ActionClass(
            domain=ActionDomain.OFFENSE,
            reversibility=Reversibility.REVERSIBLE,   # a probe against a synthetic target
            blast_radius=BlastRadius.SINGLE,          # one isolated instance
        ),
        target_ids=[target.id],
        rationale=f"Probe suite {suite} against {target.id} under {engagement_id}.",
    )
    # The gateway applies the pre-action governance check (policy engine + RoE + tier
    # + rate limit) and records the DecisionRecord before the suite runs.
    decision = Gateway().authorize(action, agent=_tester_identity(), state=_run_state())
    if decision.verdict != "allow":
        return {"status": "denied", "reason": decision.rule_id}

    result = _invoke_suite(suite, config, target)    # scripted; output to the substrate
    return {"status": "ok", "hits": result.hit_count, "report_ref": result.ref}
