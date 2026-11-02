"""
palisade.tools.registry
=======================

The curated registry. Only what is registered here is callable. Registration
screens the description, checks the hash, and verifies the signature. Session
open compares what a live server advertises against what was approved.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel

from palisade.tools.spec import ToolSpec


class DescriptionFinding(BaseModel):
    code: str
    detail: str


class IntegrityError(Exception):
    """A tool does not match what was approved. Fail closed."""


# Deliberately broad: a finding means "a human looks at this", not "malicious".
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("imperative_to_model",
     re.compile(r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|system)\b"
                r".{0,40}\b(instruction|rule|prompt)", re.I | re.S)),
    ("concealment",
     re.compile(r"\b(do not|don't|never)\b.{0,30}\b(tell|mention|reveal|disclose|report)\b"
                r".{0,30}\b(user|operator|human|analyst|anyone)", re.I | re.S)),
    ("side_channel_read",
     re.compile(r"\b(read|open|include|attach|send)\b.{0,40}"
                r"(~/\.|/etc/|\.ssh|\.env|credentials|\.aws|\.kube|secrets?)", re.I | re.S)),
    ("pseudo_markup",
     re.compile(r"<\s*/?\s*(important|system|instructions?|hidden|assistant)\b", re.I)),
    ("cross_tool_steering",
     re.compile(r"\b(before|after|whenever)\b.{0,30}\b(calling|using|invoking)\b"
                r".{0,40}\b(also|then|make sure to)\b.{0,40}\b(call|use|invoke)\b", re.I | re.S)),
]
_OPAQUE_BLOB = re.compile(r"[A-Za-z0-9+/=]{120,}")


def screen_description(text: str) -> list[DescriptionFinding]:
    findings: list[DescriptionFinding] = []
    if any(unicodedata.category(ch) == "Cf" for ch in text):
        findings.append(DescriptionFinding(code="invisible_chars", detail="zero-width or format characters"))
    if _OPAQUE_BLOB.search(text):
        findings.append(DescriptionFinding(code="opaque_blob", detail="long base64-like run"))
    if len(text) > 2000:
        findings.append(DescriptionFinding(code="oversized", detail=f"{len(text)} chars"))
    for code, pattern in _PATTERNS:
        if m := pattern.search(text):
            findings.append(DescriptionFinding(code=code, detail=m.group(0)[:120]))
    return findings


class ToolRegistry:
    def __init__(self, trusted_signers: dict[str, Ed25519PublicKey]) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._signers = trusted_signers

    # ---- review time ------------------------------------------------------

    @staticmethod
    def sign(spec: ToolSpec, key: Ed25519PrivateKey, key_id: str) -> ToolSpec:
        """Run by the reviewer's tooling after a human has read the description."""
        spec.description_hash = spec.compute_hash()
        spec.signature = base64.b64encode(key.sign(spec.canonical())).decode("ascii")
        spec.signer_key_id = key_id
        return spec

    def register(self, spec: ToolSpec, *, require_signature: bool = True) -> ToolSpec:
        findings = screen_description(spec.description)
        if findings:
            raise IntegrityError(f"{spec.name}: description failed screening: "
                                 f"{[f.code for f in findings]}")
        if spec.compute_hash() != spec.description_hash:
            raise IntegrityError(f"{spec.name}: description_hash does not match content")
        if require_signature:
            self._verify_signature(spec)
        self._specs[spec.name] = spec
        return spec

    def _verify_signature(self, spec: ToolSpec) -> None:
        if not spec.signature or spec.signer_key_id not in self._signers:
            raise IntegrityError(f"{spec.name}: missing signature or unknown signer")
        try:
            self._signers[spec.signer_key_id].verify(
                base64.b64decode(spec.signature), spec.canonical())
        except InvalidSignature as exc:
            raise IntegrityError(f"{spec.name}: bad signature") from exc

    # ---- run time ---------------------------------------------------------

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._specs.get(name)

    def for_server(self, server: str) -> list[ToolSpec]:
        return [s for s in self._specs.values() if s.server == server]

    def verify_live(self, server: str, live_tools: Iterable[Any]) -> None:
        """
        Compare what a server advertises this session against what was approved.
        `live_tools` are mcp.types.Tool objects from tools/list.
        """
        approved = {s.name: s for s in self.for_server(server)}
        seen: set[str] = set()
        for tool in live_tools:
            seen.add(tool.name)
            spec = approved.get(tool.name)
            if spec is None:
                raise IntegrityError(f"{server}: unapproved tool advertised: {tool.name}")
            live = spec.model_copy(update={
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
            })
            if live.compute_hash() != spec.description_hash:
                raise IntegrityError(
                    f"{server}: {tool.name} changed since approval "
                    f"(approved {spec.description_hash[:12]}, live {live.compute_hash()[:12]})")
        missing = [name for name in approved if name not in seen]
        if missing:
            raise IntegrityError(f"{server}: approved tools not advertised: {missing}")
