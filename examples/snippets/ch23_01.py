# How an offensive-plane model call is recorded. full_content_captured is the plane's rule.
from palisade.core.types import ModelCallRecord

record = ModelCallRecord(
    model_id=decision.model_id,
    model_version=decision.model_version,
    routing_rule=decision.rule_id,          # must be an offensive-plane rule
    parameters={"temperature": 1.0},
    input_tokens=turn.usage.input_tokens,
    output_tokens=turn.usage.output_tokens,
    full_content_captured=True,             # ALWAYS True on the offensive plane
)
# The full prompt and completion text are written to the isolated substrate alongside
# this record; on the defensive plane only the context hash would be retained.
