# palisade/capabilities/phishing/models.py
from __future__ import annotations

import hashlib
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

from palisade.core.types import TrustTier


class MessageHeaders(BaseModel):
    """Parsed by code, never by the model."""
    from_address: str
    reply_to: str | None = None
    return_path: str | None = None
    subject: str = ""
    spf: Literal["pass", "fail", "softfail", "neutral", "none", "error"] = "none"
    dkim: Literal["pass", "fail", "none", "error"] = "none"
    dmarc: Literal["pass", "fail", "none", "error"] = "none"
    received_chain: list[str] = Field(default_factory=list)


class UrlRef(BaseModel):
    ref: str                  # "url_" + 12 hex characters; the only handle the agent and the sandbox use
    host: str
    path_sha256: str          # the path is hashed; the live URL never enters the context


class AttachmentRef(BaseModel):
    ref: str                  # "att_" + 12 hex characters
    sha256: str
    declared_type: str
    size: int


class ParsedMessage(BaseModel):
    message_id: str
    headers: MessageHeaders
    body_text: str            # attacker-authored; enters context only inside a spotlighted block
    urls: list[UrlRef] = Field(default_factory=list)
    attachments: list[AttachmentRef] = Field(default_factory=list)

    def url_ref(self, url: str) -> str:
        """Stable reference for a URL found in the body. The sandbox accepts only this form."""
        return "url_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


class SandboxTrace(Protocol):
    """What the isolated VM hands back; the hypervisor adapter implements it."""
    blocked_connections: list[str]       # host:port of every attempted connection; none were allowed
    observations: list[str]              # process, file, and registry events, already bounded
    signal: Literal["benign", "suspicious", "malicious", "inconclusive"]


class SandboxReport(BaseModel):
    """A transcription of what attacker-authored content did. Evidence, never instruction."""
    artifact_ref: str
    egress_attempts: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list, max_length=50)
    verdict_signal: Literal["benign", "suspicious", "malicious", "inconclusive"] = "inconclusive"
    trust_tier: TrustTier = TrustTier.UNTRUSTED

    @classmethod
    def from_trace(cls, artifact_ref: str, trace: SandboxTrace, egress_attempts: list[str],
                   trust_tier: str = "untrusted") -> "SandboxReport":
        return cls(artifact_ref=artifact_ref, egress_attempts=list(egress_attempts),
                   observations=list(trace.observations)[:50], verdict_signal=trace.signal,
                   trust_tier=TrustTier(trust_tier))


class CampaignScope(BaseModel):
    """The facts scoping established. Each map is user -> the evidence ids that support the claim."""
    fingerprint: dict[str, Any]
    recipient: dict[str, list[str]] = Field(default_factory=dict)       # received the message
    clicked: dict[str, list[str]] = Field(default_factory=dict)         # proxy hit on a campaign URL host
    authenticated: dict[str, list[str]] = Field(default_factory=dict)   # sign-in from an unfamiliar place after the click
    reset: dict[str, list[str]] = Field(default_factory=dict)           # credential already reset
