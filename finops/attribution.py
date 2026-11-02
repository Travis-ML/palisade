"""palisade/finops/attribution.py: one cost event per priced thing, joined to the ledger."""
from palisade.core.types import DecisionRecord, new_id


def cost_events_for(rec: DecisionRecord, capability: str, tenant_id: str | None,
                    tool_units: float | None, tool_unit_name: str | None, tool_cost_usd: float) -> list[dict]:
    base = {"ts": rec.timestamp.isoformat(), "run_id": rec.run_id, "step": rec.step, "record_hash": rec.record_hash,
            "capability": capability, "plane": rec.plane.value, "agent_id": rec.agent_id,
            "tenant_id": tenant_id, "engagement_id": rec.engagement_id}
    events: list[dict] = []
    if rec.model_call is not None:
        mc = rec.model_call
        events.append({**base, "event_id": new_id("cost"), "kind": "model", "model_id": mc.model_id,
                       "model_version": mc.model_version, "routing_rule": mc.routing_rule,
                       "input_tokens": mc.input_tokens, "output_tokens": mc.output_tokens, "cost_usd": mc.cost_usd})
    if rec.proposed_action is not None and rec.execution is not None and tool_cost_usd > 0:
        events.append({**base, "event_id": new_id("cost"), "kind": "tool", "tool_name": rec.proposed_action.tool_name,
                       "units": tool_units, "unit": tool_unit_name, "cost_usd": tool_cost_usd})
    return events
