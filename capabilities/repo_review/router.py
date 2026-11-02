# palisade/capabilities/repo_review/router.py
from __future__ import annotations

import re
from pathlib import PurePosixPath

from pydantic import BaseModel

AGENT_MARKERS = re.compile(
    r"(from mcp\.|import mcp|FastMCP|anthropic\.|openai\.|langchain|\btools?=\[|tool_use|function_call)"
)
SECRET_PATHS = re.compile(r"(\.env|\.pem$|\.key$|secrets?\.(ya?ml|json)$|config/.*prod)")


class RouteDecision(BaseModel):
    path: str
    skills: list[str]      # review skills to run, in order
    rule_id: str           # which routing rule fired, for the ledger


def route(path: str, content_head: str) -> RouteDecision:
    """Deterministic routing by extension, path, and content markers.
    Every file gets the secrets skill; AI/agent files get both their
    language skill and review_ai_agent_code."""
    p = PurePosixPath(path)
    skills = ["review_secrets"]
    rule = "default.secrets_only"
    if p.suffix == ".py":
        skills.append("review_python_web"); rule = "lang.python"
    elif p.suffix == ".go":
        skills.append("review_go_service"); rule = "lang.go"
    elif p.suffix in {".tf", ".yaml", ".yml"} and ("resource " in content_head or "apiVersion" in content_head):
        skills.append("review_iac"); rule = "component.iac"
    if AGENT_MARKERS.search(content_head):
        skills.append("review_ai_agent_code"); rule += "+ai_agent"
    if SECRET_PATHS.search(path):
        rule += "+secret_path"
    return RouteDecision(path=path, skills=skills, rule_id=rule)
