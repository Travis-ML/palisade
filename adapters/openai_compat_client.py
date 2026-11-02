"""palisade.adapters.openai_compat_client"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from palisade.core.types import ProposedAction
from palisade.router import Classifier, ModelTurn, ModelUsage, strictest_class


def to_openai_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {
        "name": tool["name"], "description": tool.get("description", ""),
        "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
    }}


def to_openai_messages(message: dict[str, Any]) -> list[dict[str, Any]]:
    """One Palisade message may become several chat-completions messages."""
    role, content = message["role"], message["content"]
    if isinstance(content, str):
        return [{"role": role, "content": content}]
    if role == "assistant":
        text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
        calls = [{"id": b["id"], "type": "function",
                  "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                 for b in content if b.get("type") == "tool_use"]
        out: dict[str, Any] = {"role": "assistant", "content": text or None}
        if calls:
            out["tool_calls"] = calls
        return [out]
    out_msgs: list[dict[str, Any]] = []
    for block in content:                       # user turn: tool results and text
        if block.get("type") == "tool_result":
            out_msgs.append({"role": "tool", "tool_call_id": block["tool_use_id"],
                             "content": block["content"] if isinstance(block["content"], str)
                             else json.dumps(block["content"])})
        elif block.get("type") == "text":
            out_msgs.append({"role": "user", "content": block["text"]})
    return out_msgs


class OpenAICompatClient:
    def __init__(
        self,
        base_url: str,
        model_id: str,
        model_version: str,
        classifier: Classifier,
        api_key: Optional[str] = None,
        capture_full_content: bool = False,
        timeout_s: float = 120.0,
    ) -> None:
        self.model_id = model_id
        self.model_version = model_version
        self._classify = classifier
        self._capture = capture_full_content
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = httpx.Client(base_url=base_url, headers=headers, timeout=timeout_s)

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], **params: Any) -> ModelTurn:
        system = params.pop("system", "")
        body: dict[str, Any] = {
            "model": self.model_id,
            "messages": [{"role": "system", "content": system}]
                        + [m for msg in messages for m in to_openai_messages(msg)],
            "tools": [to_openai_tool(t) for t in tools],
            "tool_choice": "auto",
            **params,
        }
        response = self._http.post("/v1/chat/completions", json=body)
        response.raise_for_status()
        data = response.json()
        message = data["choices"][0]["message"]

        text = message.get("content") or ""
        blocks: list[dict[str, Any]] = [{"type": "text", "text": text}] if text else []
        actions: list[ProposedAction] = []
        call_ids: dict[str, str] = {}
        for call in message.get("tool_calls") or []:
            name = call["function"]["name"]
            try:
                arguments = json.loads(call["function"]["arguments"] or "{}")
                action_class, targets = self._classify(name, arguments)
            except (json.JSONDecodeError, KeyError):   # malformed or unknown: default-deny disposes of it
                arguments = {"_malformed": call["function"]["arguments"]}
                action_class, targets = strictest_class(), []
            action = ProposedAction(tool_name=name, arguments=arguments, action_class=action_class,
                                    target_ids=targets, rationale=text[-2000:])
            actions.append(action)
            call_ids[action.action_id] = call["id"]
            blocks.append({"type": "tool_use", "id": call["id"], "name": name, "input": arguments})

        usage = data.get("usage", {})
        return ModelTurn(
            text=text,
            proposed_actions=actions,
            call_ids=call_ids,
            assistant_message={"role": "assistant", "content": blocks},
            usage=ModelUsage(input_tokens=usage.get("prompt_tokens", 0),
                             output_tokens=usage.get("completion_tokens", 0), cost_usd=0.0),
            stop_reason="tool_use" if actions else (data["choices"][0].get("finish_reason") or "end_turn"),
            raw={"request": body, "response": data} if self._capture else None,
        )
