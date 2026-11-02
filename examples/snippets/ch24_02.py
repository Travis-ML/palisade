# Recording one generation call on the attack-simulation plane.
from palisade.core.types import ModelCallRecord, DecisionRecord, Plane

model_call = ModelCallRecord(
    model_id=decision.model_id,
    model_version=decision.model_version,
    routing_rule=decision.rule_id,          # an offensive-plane, in-range routing rule
    parameters={"temperature": 1.0},
    input_tokens=turn.usage.input_tokens,
    output_tokens=turn.usage.output_tokens,
    full_content_captured=True,             # ALWAYS True here; the record is the safety net
)
# The full prompt and completion text are written to the isolated substrate alongside
# this record. The generated artifact itself is registered for provenance (§24.1.3),
# not pasted into the record.

record = DecisionRecord(
    run_id=state.run_id,
    step=state.step,
    agent_id=state.agent_id,                 # a range-only identity (Chapter 12)
    plane=Plane.OFFENSIVE,
    engagement_id=state.engagement_id,       # never None on this plane
    autonomy_tier=state.tier,
    context_hash=assembled.hash,
    model_call=model_call,
    proposed_action=proposed,                # a range_emulate_step call (Section 24.8)
    policy_decision=decision,
)
