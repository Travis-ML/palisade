"""
palisade.ledger.ledger
======================

The accounting substrate: an append-only, hash-chained ledger of
DecisionRecords, with redaction at write, signed checkpoints, and export
hooks for OpenTelemetry and the SIEM.

Pedagogical: a JSONL file stands in for WORM object storage. Production
notes are called out inline.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from palisade.core.types import DecisionRecord, utcnow

GENESIS_HASH = ""  # the first record's prev_hash


# ---------------------------------------------------------------------------
# Errors. The loop treats any of these as "governance unavailable" (A13).
# ---------------------------------------------------------------------------


class LedgerError(RuntimeError):
    """Raised when a write cannot be completed. The caller must halt."""


@dataclass
class RedactionRule:
    name: str
    pattern: re.Pattern[str]
    mode: str  # "redact" (drop the value) or "tokenize" (deterministic token)


DEFAULT_RULES: list[RedactionRule] = [
    # Credentials: never stored, not even tokenized.
    RedactionRule("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "redact"),
    RedactionRule("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "redact"),
    RedactionRule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "redact"),
    RedactionRule("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "redact"),
    RedactionRule("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), "redact"),
    RedactionRule("kv_secret", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|client[_-]?secret)\s*[:=]\s*\S+"), "redact"),
    # PII: tokenized so correlation survives and re-identification is possible
    # through the controlled path only.
    RedactionRule("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "tokenize"),
    RedactionRule("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "tokenize"),
    RedactionRule("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "redact"),
]

# Values that look like secrets but are structural: hashes, ids, tool names.
DEFAULT_ALLOWLIST: list[re.Pattern[str]] = [
    re.compile(r"^[0-9a-f]{64}$"),                 # sha256 hex (context_hash, result_hash)
    re.compile(r"^(rec|run|act|apr|grant|vrd)_[0-9a-f]{12}$"),  # Palisade ids
    re.compile(r"^host-\d+$"),                      # asset ids
    re.compile(r"^spiffe://[A-Za-z0-9./_-]+$"),     # agent identities
    re.compile(r"^eng_[A-Za-z0-9_]+$"),             # engagement ids
    re.compile(r"^(10\.0\.0\.1|127\.0\.0\.1)$"),    # known infrastructure addresses
]


class Redactor:
    """
    Walks a DecisionRecord and rewrites every string field.

    "redact" replaces the match with a fixed marker. "tokenize" replaces it
    with a deterministic token derived from an HMAC key the ledger service
    holds. The same input yields the same token within one tenant, so
    analysts can still join records on a tokenized IP or address. The
    token-to-value map lives in a separate vault (not shown) and is readable
    only through the re-identification path your legal and privacy teams
    sign off on.
    """

    def __init__(
        self,
        token_key: bytes,
        rules: Optional[list[RedactionRule]] = None,
        allowlist: Optional[list[re.Pattern[str]]] = None,
        on_tokenize: Optional[Callable[[str, str, str], None]] = None,
    ) -> None:
        self._key = token_key
        self.rules = rules or DEFAULT_RULES
        self.allowlist = allowlist or DEFAULT_ALLOWLIST
        self._on_tokenize = on_tokenize  # (rule_name, token, original) -> vault
        self.stats: dict[str, int] = {}

    def token_for(self, rule_name: str, value: str) -> str:
        digest = hmac.new(self._key, f"{rule_name}:{value}".encode(), hashlib.sha256).digest()
        return f"tok_{rule_name}_{base64.b32encode(digest[:10]).decode().lower().rstrip('=')}"

    def redact_text(self, text: str) -> str:
        if any(p.match(text) for p in self.allowlist):
            return text
        for rule in self.rules:
            def _sub(m: re.Match[str], rule: RedactionRule = rule) -> str:
                self.stats[rule.name] = self.stats.get(rule.name, 0) + 1
                if rule.mode == "redact":
                    return f"[REDACTED:{rule.name}]"
                tok = self.token_for(rule.name, m.group(0))
                if self._on_tokenize:
                    self._on_tokenize(rule.name, tok, m.group(0))
                return tok
            text = rule.pattern.sub(_sub, text)
        return text

    def _walk(self, node: Any) -> Any:
        if isinstance(node, str):
            return self.redact_text(node)
        if isinstance(node, list):
            return [self._walk(x) for x in node]
        if isinstance(node, dict):
            return {k: self._walk(v) for k, v in node.items()}
        return node

    def redact_record(self, record: DecisionRecord) -> DecisionRecord:
        payload = record.model_dump(mode="json")
        cleaned = self._walk(payload)
        return DecisionRecord.model_validate(cleaned)


class LedgerStore(Protocol):
    def append_line(self, line: str) -> None: ...
    def iter_lines(self) -> Iterator[str]: ...


class InMemoryLedgerStore:
    """Tests and labs only. Not to be confused with palisade.memory.MemoryStore (Chapter 9)."""

    def __init__(self) -> None:
        self._lines: list[str] = []

    def append_line(self, line: str) -> None:
        self._lines.append(line)

    def iter_lines(self) -> Iterator[str]:
        return iter(list(self._lines))


class JsonlStore:
    """
    One JSON document per line, file opened in append mode on every write.
    This is tamper-evident (because of the chain) but not tamper-proof: a
    root user can rewrite the file. Production replaces this with an object
    store bucket under Object Lock in compliance mode, or an equivalent WORM
    target, written by an identity that holds PutObject and nothing else.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append_line(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    def iter_lines(self) -> Iterator[str]:
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if line:
                    yield line


# ---------------------------------------------------------------------------
# Export hooks
# ---------------------------------------------------------------------------


class RecordSink(Protocol):
    """Anything that wants a copy of every sealed record: OTel, SIEM, metrics."""

    def emit(self, record: DecisionRecord) -> None: ...


# ---------------------------------------------------------------------------
# Signed checkpoints: anchor the chain head outside the ledger's own storage
# ---------------------------------------------------------------------------


@dataclass
class Checkpoint:
    head_hash: str
    count: int
    at: datetime
    signer_key_id: str
    signature: str  # base64 Ed25519 over canonical body

    def body(self) -> bytes:
        return json.dumps(
            {"head_hash": self.head_hash, "count": self.count, "at": self.at.isoformat()},
            sort_keys=True, separators=(",", ":"),
        ).encode()

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        try:
            public_key.verify(base64.b64decode(self.signature), self.body())
            return True
        except InvalidSignature:
            return False


class Ledger:
    """
    Append-only. There is no update, no delete, and no method that takes a
    record_hash and changes anything. The only writes are append() and
    checkpoint(). Reading is replay() and iteration.
    """

    def __init__(
        self,
        store: LedgerStore,
        redactor: Redactor,
        sinks: Optional[list[RecordSink]] = None,
    ) -> None:
        self._store = store
        self._redactor = redactor
        self._sinks = sinks or []
        self._head = GENESIS_HASH
        self._count = 0
        # Recover the head from existing storage so restarts continue the chain.
        for rec in self._iter_records():
            self._head = rec.record_hash
            self._count += 1

    @classmethod
    def open(
        cls,
        path: str | Path,
        token_key: Optional[bytes] = None,
        sinks: Optional[list[RecordSink]] = None,
    ) -> "Ledger":
        """
        Convenience constructor used by the labs and the capability runners:
        a JsonlStore at `path` and a Redactor with the default rule set. The
        tokenization key comes from PALISADE_LEDGER_TOKEN_KEY when not given.
        Production wires an object-lock store and a KMS-held key instead.
        """
        key = token_key or os.environ.get("PALISADE_LEDGER_TOKEN_KEY", "").encode("utf-8")
        if not key:
            raise LedgerError("no tokenization key: set PALISADE_LEDGER_TOKEN_KEY or pass token_key")
        return cls(JsonlStore(Path(path) / "ledger.jsonl"), Redactor(token_key=key), sinks)

    # -- reads ---------------------------------------------------------------

    def _iter_records(self) -> Iterator[DecisionRecord]:
        for line in self._store.iter_lines():
            yield DecisionRecord.model_validate_json(line)

    def __iter__(self) -> Iterator[DecisionRecord]:
        return self._iter_records()

    @property
    def head(self) -> str:
        return self._head

    @property
    def count(self) -> int:
        return self._count

    def replay(self, run_id: str) -> list[DecisionRecord]:
        """Every record for one run, in step order. Empty list if unknown."""
        records = [r for r in self._iter_records() if r.run_id == run_id]
        records.sort(key=lambda r: r.step)
        return records

    def verify_chain(self) -> bool:
        """
        Recompute every hash and check every link. Returns False (and sets
        .last_break) on the first inconsistency rather than raising, so a
        verifier job can report rather than crash.
        """
        prev = GENESIS_HASH
        self.last_break: Optional[tuple[int, str]] = None
        for idx, rec in enumerate(self._iter_records()):
            if rec.prev_hash != prev:
                self.last_break = (idx, f"prev_hash mismatch at {rec.record_id}")
                return False
            if rec.compute_hash() != rec.record_hash:
                self.last_break = (idx, f"content hash mismatch at {rec.record_id}")
                return False
            prev = rec.record_hash
        return True

    # -- writes --------------------------------------------------------------

    def append(self, record: DecisionRecord) -> str:
        """
        Redact, seal onto the chain, persist, fan out. Returns record_hash.
        Any failure raises LedgerError; the governed loop halts on it.
        """
        try:
            clean = self._redactor.redact_record(record)
            clean.seal(self._head)
            self._store.append_line(clean.model_dump_json())
        except Exception as exc:  # pedagogical: production distinguishes causes
            raise LedgerError(f"ledger append failed: {exc}") from exc
        self._head = clean.record_hash
        self._count += 1
        for sink in self._sinks:
            try:
                sink.emit(clean)
            except Exception:
                # Export is best-effort; the durable write already happened.
                # Production alerts on sink failures; it does not block the loop.
                pass
        return clean.record_hash

    def checkpoint(self, signer: Ed25519PrivateKey, signer_key_id: str) -> Checkpoint:
        """
        Sign the current head. Publish the result somewhere the ledger writer
        cannot touch (a different account, a transparency log, a printed
        sheet in a safe if you must). An attacker who rewrites the chain must
        now also forge this signature or explain why the anchor disagrees.
        """
        cp = Checkpoint(
            head_hash=self._head, count=self._count, at=utcnow(),
            signer_key_id=signer_key_id, signature="",
        )
        cp.signature = base64.b64encode(signer.sign(cp.body())).decode()
        return cp


def flatten_record(record: DecisionRecord) -> dict[str, Any]:
    """
    A flat, SIEM-friendly projection. Field names are stable because the
    detections in Section 10.9 depend on them.
    """
    pa = record.proposed_action
    pd = record.policy_decision
    ex = record.execution
    ap = record.approval
    return {
        "@timestamp": record.timestamp.isoformat(),
        "event.module": "palisade",
        "event.dataset": "palisade.ledger",
        "palisade.record_id": record.record_id,
        "palisade.run_id": record.run_id,
        "palisade.step": record.step,
        "palisade.hour_utc": record.timestamp.hour,
        "palisade.weekday": record.timestamp.isoweekday(),
        "palisade.agent_id": record.agent_id,
        "palisade.plane": record.plane.value,
        "palisade.engagement_id": record.engagement_id,
        "palisade.autonomy_tier": int(record.autonomy_tier),
        "palisade.context_hash": record.context_hash,
        "palisade.action.tool_name": pa.tool_name if pa else None,
        "palisade.action.domain": pa.action_class.domain.value if pa else None,
        "palisade.action.reversibility": pa.action_class.reversibility.value if pa else None,
        "palisade.action.blast_radius": pa.action_class.blast_radius.value if pa else None,
        "palisade.action.target_ids": pa.target_ids if pa else [],
        "palisade.tenants": [t.split(":", 1)[1] for t in (pa.target_ids if pa else []) if t.startswith("tenant:")],
        "palisade.action.arguments": pa.arguments if pa else {},
        "palisade.policy.verdict": pd.verdict if pd else None,
        "palisade.policy.rule_id": pd.rule_id if pd else None,
        "palisade.approval.approver_id": ap.approver_id if ap else None,
        "palisade.approval.decision": ap.decision if ap else None,
        "palisade.execution.status": ex.status if ex else None,
        "palisade.execution.duration_ms": ex.duration_ms if ex else None,
        "palisade.human_intervention": record.human_intervention,
        "palisade.model.id": record.model_call.model_id if record.model_call else None,
        "palisade.model.cost_usd": record.model_call.cost_usd if record.model_call else None,
        "palisade.record_hash": record.record_hash,
        "palisade.prev_hash": record.prev_hash,
    }


class SiemForwarder:
    """
    Emits flattened events to a transport. The transport is a callable so
    the same class fronts an HTTP Event Collector, a syslog socket, or a
    test list. Production batches, retries, and alerts on backlog.
    """

    def __init__(self, transport: Callable[[dict[str, Any]], None]) -> None:
        self._send = transport

    def emit(self, record: DecisionRecord) -> None:
        self._send(flatten_record(record))
