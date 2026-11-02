"""
palisade.ledger.otel
====================

OpenTelemetry helpers that emit spans following the GenAI semantic
conventions (gen_ai.*) plus Palisade's own namespace (palisade.*).

As of October 2026 every gen_ai.* attribute is in Development status and
the conventions live in the semantic-conventions-genai repository. Pin the
version you emit under (SEMCONV_PIN below) and record it on every span so
a future migration can be done by query rather than by archaeology.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, Optional

from opentelemetry import trace
from opentelemetry.trace import Span, SpanKind, Status, StatusCode

from palisade.core.types import DecisionRecord, ModelCallRecord, ProposedAction

# Replace with the tag you adopted. Changing this is a deliberate migration.
SEMCONV_PIN = "gen_ai:development:2026-06"
SCHEMA_URL = "https://opentelemetry.io/schemas/1.37.0"

_tracer = trace.get_tracer("palisade", "0.1.0", schema_url=SCHEMA_URL)


def _common(span: Span, run_id: str, agent_id: str, plane: str,
            engagement_id: Optional[str]) -> None:
    span.set_attribute("gen_ai.conversation.id", run_id)
    span.set_attribute("gen_ai.agent.id", agent_id)
    span.set_attribute("palisade.run_id", run_id)
    span.set_attribute("palisade.plane", plane)
    span.set_attribute("palisade.engagement_id", engagement_id or "")
    span.set_attribute("palisade.semconv", SEMCONV_PIN)


@contextmanager
def agent_span(agent_name: str, agent_id: str, run_id: str, plane: str,
               engagement_id: Optional[str]) -> Iterator[Span]:
    """One span per run: `invoke_agent {agent_name}`. Children: steps."""
    with _tracer.start_as_current_span(f"invoke_agent {agent_name}",
                                       kind=SpanKind.INTERNAL) as span:
        span.set_attribute("gen_ai.operation.name", "invoke_agent")
        span.set_attribute("gen_ai.agent.name", agent_name)
        _common(span, run_id, agent_id, plane, engagement_id)
        yield span


@contextmanager
def model_span(provider: str, request_model: str, run_id: str, agent_id: str,
               plane: str, engagement_id: Optional[str],
               params: Optional[dict[str, Any]] = None) -> Iterator[Span]:
    """
    `chat {model}`: the inference call. No prompt or completion content is
    attached here. Content capture (gen_ai.input.messages and
    gen_ai.output.messages) is opt-in in the conventions, and in Palisade the
    full text goes to the ledger's content store, keyed by context_hash,
    never into the trace pipeline.
    """
    with _tracer.start_as_current_span(f"chat {request_model}",
                                       kind=SpanKind.CLIENT) as span:
        span.set_attribute("gen_ai.operation.name", "chat")
        span.set_attribute("gen_ai.provider.name", provider)
        span.set_attribute("gen_ai.request.model", request_model)
        for key in ("temperature", "max_tokens", "top_p"):
            if params and key in params:
                span.set_attribute(f"gen_ai.request.{key}", params[key])
        _common(span, run_id, agent_id, plane, engagement_id)
        try:
            yield span
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.set_attribute("error.type", type(exc).__name__)
            raise


def record_model_result(span: Span, call: ModelCallRecord,
                        finish_reasons: Optional[list[str]] = None) -> None:
    """Attach the response side of a model call once you have it."""
    span.set_attribute("gen_ai.response.model", call.model_version or call.model_id)
    span.set_attribute("gen_ai.usage.input_tokens", call.input_tokens)
    span.set_attribute("gen_ai.usage.output_tokens", call.output_tokens)
    if finish_reasons:
        span.set_attribute("gen_ai.response.finish_reasons", finish_reasons)
    span.set_attribute("palisade.routing_rule", call.routing_rule)
    span.set_attribute("palisade.cost_usd", call.cost_usd)
    span.set_attribute("palisade.latency_ms", call.latency_ms)


@contextmanager
def tool_span(action: ProposedAction, run_id: str, agent_id: str, plane: str,
              engagement_id: Optional[str]) -> Iterator[Span]:
    """`execute_tool {tool_name}`: one span per executed (not proposed) call."""
    with _tracer.start_as_current_span(f"execute_tool {action.tool_name}",
                                       kind=SpanKind.INTERNAL) as span:
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        span.set_attribute("gen_ai.tool.name", action.tool_name)
        span.set_attribute("gen_ai.tool.call.id", action.action_id)
        span.set_attribute("gen_ai.tool.type", "function")
        span.set_attribute("palisade.action.class", action.action_class.key())
        span.set_attribute("palisade.action.target_ids", action.target_ids)
        _common(span, run_id, agent_id, plane, engagement_id)
        try:
            yield span
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            span.set_attribute("error.type", type(exc).__name__)
            raise


class OtelSink:
    """
    A RecordSink (see ledger.py) that emits one `palisade.step` span per
    sealed record. The span carries record_id and record_hash so a trace
    viewer can jump to the authoritative ledger row. The link runs one way:
    traces point at the ledger; the ledger never depends on the trace store.
    """

    def emit(self, record: DecisionRecord) -> None:
        start_ns = int(record.timestamp.timestamp() * 1e9)
        span = _tracer.start_span("palisade.step", start_time=start_ns, kind=SpanKind.INTERNAL)
        try:
            _common(span, record.run_id, record.agent_id, record.plane.value, record.engagement_id)
            span.set_attribute("palisade.record_id", record.record_id)
            span.set_attribute("palisade.record_hash", record.record_hash)
            span.set_attribute("palisade.step", record.step)
            span.set_attribute("palisade.context_hash", record.context_hash)
            span.set_attribute("palisade.autonomy_tier", int(record.autonomy_tier))
            if record.proposed_action:
                span.set_attribute("gen_ai.tool.name", record.proposed_action.tool_name)
                span.set_attribute("palisade.action.class", record.proposed_action.action_class.key())
            if record.policy_decision:
                span.set_attribute("palisade.policy.verdict", record.policy_decision.verdict)
                span.set_attribute("palisade.policy.rule_id", record.policy_decision.rule_id)
            if record.execution:
                span.set_attribute("palisade.execution.status", record.execution.status)
            if record.model_call:
                span.set_attribute("gen_ai.request.model", record.model_call.model_id)
                span.set_attribute("gen_ai.usage.input_tokens", record.model_call.input_tokens)
                span.set_attribute("gen_ai.usage.output_tokens", record.model_call.output_tokens)
            if record.human_intervention:
                span.set_attribute("palisade.human_intervention", record.human_intervention)
        finally:
            span.end()
