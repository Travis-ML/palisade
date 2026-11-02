"""
palisade.context.retriever
==========================

KnowledgeItem with provenance and trust tier; hybrid retrieval (BM25 + dense,
reciprocal rank fusion, optional reranker); integrity verification on read;
spotlighting; citation checking; the ingest gate. Pedagogical: in-memory
indexes, no persistence, thin error handling.
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import math
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Literal, Optional, Protocol

from pydantic import BaseModel, Field

from palisade.core.types import RetrievedItem, TrustTier, utcnow
from palisade.tools.registry import screen_description   # same screen as Chapter 7

Kind = Literal["runbook", "detection", "asset", "identity", "investigation",
               "intel", "roe", "standard", "alert", "observation"]


class Provenance(BaseModel):
    source: str                               # "git://knowledge@a1b2c3/runbooks/idp/x.md", "feed://vendor-x", "alert://siem/evt_91f2"
    author: str = ""
    ingested_at: datetime = Field(default_factory=utcnow)
    ingested_by: str = ""                     # the ingest identity, a SPIFFE id
    signature: Optional[str] = None
    signer_key_id: Optional[str] = None
    checks_passed: list[str] = Field(default_factory=list)


class KnowledgeItem(BaseModel):
    item_id: str
    version: str
    kind: Kind
    content: str
    content_hash: str = ""
    trust_tier: TrustTier = TrustTier.UNTRUSTED       # default is untrusted; promotion is earned at ingest
    provenance: Provenance
    tags: list[str] = Field(default_factory=list)
    valid_until: Optional[datetime] = None

    @property
    def source(self) -> str:                 # satisfies the ContextAssembler's ContextItem protocol (Chapter 5)
        return self.provenance.source

    def compute_hash(self) -> str:
        payload = f"{self.item_id}@{self.version}\n{self.content}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def seal(self) -> "KnowledgeItem":
        self.content_hash = self.compute_hash()
        return self

    def to_retrieved(self) -> RetrievedItem:
        return RetrievedItem(item_id=self.item_id, version=self.version,
                             content_hash=self.content_hash, trust_tier=self.trust_tier,
                             source=self.source)


class IntegrityError(Exception):
    pass


# --- lexical index: BM25 with an identifier-preserving tokenizer -------------

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*[A-Za-z0-9]|[A-Za-z0-9]")


def tokenize(text: str) -> list[str]:
    """Keeps host-4471, 10.42.7.19, T1003.001, and hashes whole."""
    return [t.lower() for t in _TOKEN.findall(text)]


class BM25Index:
    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self._tf: dict[str, Counter[str]] = {}
        self._len: dict[str, int] = {}
        self._df: Counter[str] = Counter()

    def add(self, item_id: str, text: str) -> None:
        tokens = tokenize(text)
        self._tf[item_id] = Counter(tokens)
        self._len[item_id] = len(tokens)
        for term in set(tokens):
            self._df[term] += 1

    def search(self, query: str, k: int) -> list[tuple[str, float]]:
        n = len(self._tf)
        if n == 0:
            return []
        avg = sum(self._len.values()) / n
        scores: dict[str, float] = defaultdict(float)
        for term in set(tokenize(query)):
            df = self._df.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
            for item_id, tf in self._tf.items():
                f = tf.get(term, 0)
                if f == 0:
                    continue
                norm = f + self.k1 * (1 - self.b + self.b * self._len[item_id] / avg)
                scores[item_id] += idf * (f * (self.k1 + 1)) / norm
        return sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:k]


# --- dense index behind a protocol; any embedding model plugs in ------------

class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class Reranker(Protocol):
    def rerank(self, query: str, candidates: list[KnowledgeItem]) -> list[KnowledgeItem]: ...


class DenseIndex:
    def __init__(self, embedder: Embedder) -> None:
        self._embedder = embedder
        self._vectors: dict[str, list[float]] = {}

    def add(self, item_id: str, text: str) -> None:
        self._vectors[item_id] = self._embedder.embed([text])[0]

    def search(self, query: str, k: int) -> list[tuple[str, float]]:
        q = self._embedder.embed([query])[0]
        qn = math.sqrt(sum(x * x for x in q)) or 1.0
        scored = []
        for item_id, v in self._vectors.items():
            vn = math.sqrt(sum(x * x for x in v)) or 1.0
            scored.append((item_id, sum(a * b for a, b in zip(q, v)) / (qn * vn)))
        return sorted(scored, key=lambda kv: kv[1], reverse=True)[:k]


def reciprocal_rank_fusion(*ranked: list[tuple[str, float]], c: int = 60) -> list[str]:
    fused: dict[str, float] = defaultdict(float)
    for lst in ranked:
        for rank, (item_id, _) in enumerate(lst, start=1):
            fused[item_id] += 1.0 / (c + rank)
    return [item_id for item_id, _ in sorted(fused.items(), key=lambda kv: kv[1], reverse=True)]


# --- the store and the retriever --------------------------------------------

class EventSink(Protocol):
    def emit(self, kind: str, **fields: Any) -> None: ...


class KnowledgeStore:
    """Sealed items by id. Production: a document database plus object storage."""

    def __init__(self) -> None:
        self._items: dict[str, KnowledgeItem] = {}
        self.quarantined: dict[str, KnowledgeItem] = {}

    def put(self, item: KnowledgeItem) -> None:
        if not item.content_hash:
            raise IntegrityError(f"{item.item_id}: unsealed item")
        self._items[item.item_id] = item

    def get(self, item_id: str) -> Optional[KnowledgeItem]:
        return self._items.get(item_id)

    def latest_version_of(self, item_id: str) -> Optional[KnowledgeItem]:
        return self._items.get(item_id)

    def quarantine(self, item: KnowledgeItem) -> None:
        self._items.pop(item.item_id, None)
        self.quarantined[item.item_id] = item


class Retriever:
    def __init__(self, store: KnowledgeStore, lexical: BM25Index, dense: Optional[DenseIndex],
                 sink: EventSink, reranker: Optional[Reranker] = None, candidates: int = 50) -> None:
        self._store, self._lex, self._dense = store, lexical, dense
        self._sink, self._reranker, self._candidates = sink, reranker, candidates

    def index(self, item: KnowledgeItem) -> None:
        self._store.put(item)
        self._lex.add(item.item_id, item.content)
        if self._dense is not None:
            self._dense.add(item.item_id, item.content)

    def retrieve(self, query: str, trust_tiers: set[TrustTier], k: int = 8,
                 kinds: Optional[set[str]] = None) -> list[KnowledgeItem]:
        lists = [self._lex.search(query, self._candidates)]
        if self._dense is not None:
            lists.append(self._dense.search(query, self._candidates))
        now = utcnow()
        out: list[KnowledgeItem] = []
        for item_id in reciprocal_rank_fusion(*lists):
            item = self._store.get(item_id)
            if item is None:
                continue
            if item.trust_tier not in trust_tiers:          # structural tier filter
                continue
            if kinds and item.kind not in kinds:
                continue
            if item.valid_until and item.valid_until < now:
                continue
            if item.compute_hash() != item.content_hash:      # integrity on read (C-8.3)
                self._store.quarantine(item)
                self._sink.emit("knowledge.integrity_failure", item_id=item.item_id,
                                version=item.version, expected=item.content_hash[:12])
                continue
            out.append(item)
        if self._reranker is not None:
            out = self._reranker.rerank(query, out)
        return out[:k]


# --- spotlighting ---------------------------------------------------------------

class Spotlighter:
    """Wrap untrusted content so the model can tell what it is and cannot be told otherwise."""

    def __init__(self, process_secret: bytes) -> None:
        self._secret = process_secret

    def boundary(self, run_id: str) -> str:
        return hmac.new(self._secret, run_id.encode("utf-8"), "sha256").hexdigest()[:16]

    def wrap(self, content: str, *, source: str, item_id: str, run_id: str) -> str:
        b = self.boundary(run_id)
        body = "".join(ch for ch in content if unicodedata.category(ch) != "Cf")   # strip invisible chars
        body = re.sub(r"</?\s*untrusted\b[^>]*>", "[delimiter-like text removed]", body, flags=re.I)
        body = body.replace(b, "[boundary-like text removed]")
        return (f'<untrusted source="{source}" id="{item_id}" boundary="{b}">\n'
                f"{body}\n"
                f'</untrusted boundary="{b}">')

    @staticmethod
    def datamark(content: str, marker: str = "ˆ") -> str:
        """Interleave a marker between words so the text cannot read as instruction."""
        return marker.join(content.split())


class ContextBlock(BaseModel):
    channel: Literal["instruction", "enterprise", "verified", "untrusted"]
    text: str
    source: str
    item_ref: Optional[str] = None          # "item_id@version" or "result:<hash>"


def render_blocks(blocks: list[ContextBlock], spot: Spotlighter, run_id: str) -> str:
    """The ContextAssembler (Chapter 5) calls this; channels render differently and in order."""
    order = {"instruction": 0, "enterprise": 1, "verified": 2, "untrusted": 3}
    parts: list[str] = []
    for blk in sorted(blocks, key=lambda b: order[b.channel]):
        if blk.channel == "instruction":
            parts.append(blk.text)
        elif blk.channel in ("enterprise", "verified"):
            parts.append(f'<knowledge trust="{blk.channel}" ref="{blk.item_ref}">\n{blk.text}\n</knowledge>')
        else:
            parts.append(spot.wrap(blk.text, source=blk.source, item_id=blk.item_ref or "", run_id=run_id))
    return "\n\n".join(parts)


# --- citation enforcement ------------------------------------------------------

_CITE = re.compile(r"\[cite:([A-Za-z0-9_./-]+)@([A-Za-z0-9_.-]+)\]")
_RESULT = re.compile(r"\[result:([0-9a-f]{8,64})\]")


class CitationChecker:
    def check(self, text: str, retrieved: list[RetrievedItem], result_hashes: set[str]) -> list[str]:
        known = {(r.item_id, r.version) for r in retrieved}
        problems: list[str] = []
        cites = _CITE.findall(text)
        results = _RESULT.findall(text)
        for item_id, version in cites:
            if (item_id, version) not in known:
                problems.append(f"citation.unresolved: {item_id}@{version}")
        for prefix in results:
            if not any(h.startswith(prefix) for h in result_hashes):
                problems.append(f"citation.unresolved: result:{prefix}")
        if not cites and not results:
            problems.append("citation.missing: no evidence cited")
        return problems


# --- the ingest gate ---------------------------------------------------------------

class SignatureVerifier(Protocol):
    def verify(self, key_id: str, payload: bytes, signature_b64: str) -> bool: ...


class Ingestor:
    """Source allowlist caps the claimable tier; enterprise/verified need signatures;
    anomalous writes are quarantined for a human."""

    def __init__(self, store: KnowledgeStore, retriever: Retriever, verifier: SignatureVerifier,
                 source_tiers: dict[str, TrustTier], sink: EventSink) -> None:
        self._store, self._retriever, self._verifier = store, retriever, verifier
        self._source_tiers, self._sink = source_tiers, sink

    def ingest(self, item: KnowledgeItem) -> Literal["accepted", "quarantined"]:
        checks: list[str] = []
        cap = self._claimable_tier(item.provenance.source)
        if _rank(item.trust_tier) > _rank(cap):
            return self._quarantine(item, f"source may claim at most {cap.value}")
        checks.append("source_allowlist")
        if item.trust_tier in (TrustTier.ENTERPRISE, TrustTier.VERIFIED):
            p = item.provenance
            if not (p.signature and p.signer_key_id and
                    self._verifier.verify(p.signer_key_id, item.compute_hash().encode(), p.signature)):
                return self._quarantine(item, "missing or invalid signature")
            checks.append("signature")
        previous = self._store.latest_version_of(item.item_id)
        if previous is not None and item.kind in ("runbook", "standard", "roe"):
            ratio = difflib.SequenceMatcher(None, previous.content, item.content).ratio()
            if ratio < 0.5:
                return self._quarantine(item, f"large rewrite (similarity {ratio:.2f})")
        if item.kind in ("runbook", "standard", "asset", "identity") and screen_description(item.content):
            return self._quarantine(item, "instruction-like content in a non-instruction document")
        checks.append("anomaly")
        item.provenance.checks_passed = checks
        item.seal()
        self._retriever.index(item)
        self._sink.emit("knowledge.accepted", item_id=item.item_id, version=item.version,
                        tier=item.trust_tier.value, checks=checks)
        return "accepted"

    def _claimable_tier(self, source: str) -> TrustTier:
        for prefix, tier in self._source_tiers.items():
            if source.startswith(prefix):
                return tier
        return TrustTier.UNTRUSTED

    def _quarantine(self, item: KnowledgeItem, reason: str) -> Literal["quarantined"]:
        self._store.quarantine(item)
        self._sink.emit("knowledge.quarantined", item_id=item.item_id, version=item.version, reason=reason)
        return "quarantined"


def _rank(tier: TrustTier) -> int:
    return {TrustTier.UNTRUSTED: 0, TrustTier.VERIFIED: 1, TrustTier.ENTERPRISE: 2}[tier]
