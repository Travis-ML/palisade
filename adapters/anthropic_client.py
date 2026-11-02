"""
palisade/adapters/anthropic_client.py (part 1 of 2; Chapter 6 adds AnthropicMessagesClient)

Converts Messages API content blocks to and from Palisade's vocabulary. The classification
of a tool into an ActionClass comes from a catalog the harness owns (Chapter 3 builds it);
it is never taken from the model and never inferred from the tool's description.
"""
from __future__ import annotations

import json
from typing import Any

from palisade.core.types import ActionClass, ProposedAction


class UnknownToolError(Exception):
    """The model named a tool that is not in the harness's catalog. This is a denial, not a bug."""


def proposed_actions_from_blocks(blocks: list[Any], catalog: dict[str, ActionClass],
                                 rationale: str = "") -> list[ProposedAction]:
    actions: list[ProposedAction] = []
    for block in blocks:
        if getattr(block, "type", None) != "tool_use":
            continue
        if block.name not in catalog:
            raise UnknownToolError(block.name)
        arguments = dict(block.input)
        actions.append(ProposedAction(
            action_id=block.id,                        # reuse the provider id so results can be matched
            tool_name=block.name,
            arguments=arguments,
            action_class=catalog[block.name],
            target_ids=_targets_from_arguments(arguments),
            rationale=rationale,
        ))
    return actions


def text_from_blocks(blocks: list[Any]) -> str:
    return "".join(getattr(b, "text", "") for b in blocks if getattr(b, "type", None) == "text")


def tool_result_block(action: ProposedAction, content: Any, is_error: bool = False) -> dict:
    body = content if isinstance(content, str) else json.dumps(content)
    block = {"type": "tool_result", "tool_use_id": action.action_id, "content": body}
    if is_error:
        block["is_error"] = True
    return block


_TARGET_KEYS = ("host_id", "account_id", "user_id", "message_id", "indicator", "tenant_id", "repo")


def _targets_from_arguments(arguments: dict[str, Any]) -> list[str]:
    return [str(arguments[k]) for k in _TARGET_KEYS if k in arguments]


# palisade/adapters/anthropic_client.py (part 2 of 2: append to the file Chapter 2 started;
# the converters, ProposedAction, Any, and the future import are already at the top of it)
from typing import Optional

from anthropic import Anthropic

from palisade.router import Classifier, ModelTurn, ModelUsage, strictest_class


class AnthropicMessagesClient:
    def __init__(
        self,
        model_id: str,
        model_version: str,
        classifier: Classifier,
        price_per_mtok: tuple[float, float] = (0.0, 0.0),   # (input, output); from your contract
        api_key: Optional[str] = None,
        default_max_tokens: int = 4096,
    ) -> None:
        self.model_id = model_id
        self.model_version = model_version
        self._classify = classifier
        self._price_in, self._price_out = price_per_mtok
        self._client = Anthropic(api_key=api_key)   # falls back to ANTHROPIC_API_KEY
        self._default_max_tokens = default_max_tokens

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **params: Any) -> ModelTurn:
        system = params.pop("system", "")
        max_tokens = params.pop("max_tokens", self._default_max_tokens)
        response = self._client.messages.create(
            model=self.model_id, max_tokens=max_tokens, system=system,
            tools=tools, messages=messages,
            tool_choice={"type": "auto", "disable_parallel_tool_use": True},
            **params,
        )
        text_parts: list[str] = []
        actions: list[ProposedAction] = []
        call_ids: dict[str, str] = {}
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                arguments = dict(block.input) if isinstance(block.input, dict) else {"_raw": block.input}
                try:
                    action_class, targets = self._classify(block.name, arguments)
                except KeyError:                       # unknown tool: let default-deny dispose of it
                    action_class, targets = strictest_class(), []
                action = ProposedAction(tool_name=block.name, arguments=arguments,
                                        action_class=action_class, target_ids=targets,
                                        rationale="\n".join(text_parts)[-2000:])
                actions.append(action)
                call_ids[action.action_id] = block.id
        usage = ModelUsage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cost_usd=(response.usage.input_tokens * self._price_in
                      + response.usage.output_tokens * self._price_out) / 1_000_000,
        )
        return ModelTurn(
            text="\n".join(text_parts),
            proposed_actions=actions,
            call_ids=call_ids,
            assistant_message={"role": "assistant",
                               "content": [b.model_dump(exclude_none=True) for b in response.content]},
            usage=usage,
            stop_reason=response.stop_reason or "end_turn",
        )
