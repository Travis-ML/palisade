"""
palisade.memory
===============

MemoryStore: persistence across runs with writer attribution, mandatory
evidence, a trust-tier floor, per-key hash chaining, AEAD integrity verified
on read, per-tenant envelope encryption, append-only versioning with rollback,
and the read log that drives re-adjudication.

Pedagogical: in-memory rows and a local KMS. Production notes inline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from datetime import datetime
from typing import Any, Iterable, Literal, Optional, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, Field

from palisade.core.types import RetrievedItem, TrustTier, new_id, utcnow
from palisade.tools.registry import screen_description


class MemoryIntegrityError(Exception):
    pass


class MemoryPolicyError(Exception):
    pass


# --- the versioned record ----------------------------------------------------------

class MemoryVersion(BaseModel):
    tenant: str
    key: str                              # namespaced: "host/host-4471/last_investigation"
    version: int
    value: Any                            # decrypted on read; never persisted in clear
    written_by: str                       # SPIFFE id of an agent, or a human identity
    evidence: list[str]                   # "rec_...", "result:<hash>", "cite:<item>@<v>", "memory://..."
    trust_tier: TrustTier
    written_at: datetime
    reason: str = ""
    prev_hash: str = ""
    version_hash: str = ""
    status: Literal["active", "superseded", "rolled_back", "quarantined"] = "active"

    def compute_hash(self) -> str:
        payload = self.model_dump(mode="json", exclude={"version_hash", "status"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def ref(self) -> str:
        return f"memory://{self.tenant}/{self.key}@{self.version}"

    def to_retrieved(self) -> RetrievedItem:
        return RetrievedItem(item_id=f"{self.tenant}/{self.key}", version=str(self.version),
                             content_hash=self.version_hash, trust_tier=self.trust_tier, source=self.ref())


class EncryptedRow(BaseModel):
    """What is persisted. The value is ciphertext; the header is plaintext metadata
    bound to the ciphertext through the AEAD associated data."""
    tenant: str
    key: str
    version: int
    kek_id: str
    wrapped_dek_b64: str
    nonce_b64: str
    ciphertext_b64: str
    header: dict[str, Any]       # written_by, evidence, trust_tier, written_at, reason, prev_hash, version_hash
    status: str = "active"


# --- key management ----------------------------------------------------------------

class Kms(Protocol):
    def generate_data_key(self, tenant: str) -> tuple[bytes, bytes, str]:
        """Returns (plaintext_dek, wrapped_dek, kek_id)."""
        ...

    def unwrap(self, tenant: str, wrapped_dek: bytes, kek_id: str) -> bytes: ...
    def destroy_tenant_keys(self, tenant: str) -> None: ...


class LocalKms:
    """Lab only. One KEK per tenant, held in process memory.

    Production: a cloud KMS (AWS KMS, Cloud KMS, Key Vault) or an HSM, one KEK per
    tenant, with a key policy allowing Decrypt only to the memory service's identity,
    automatic rotation, and audit logging of every unwrap."""

    def __init__(self) -> None:
        self._keks: dict[str, bytes] = {}

    def generate_data_key(self, tenant: str) -> tuple[bytes, bytes, str]:
        kek = self._keks.setdefault(tenant, AESGCM.generate_key(bit_length=256))
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        wrapped = nonce + AESGCM(kek).encrypt(nonce, dek, tenant.encode("utf-8"))
        return dek, wrapped, f"kek:{tenant}:v1"

    def unwrap(self, tenant: str, wrapped_dek: bytes, kek_id: str) -> bytes:
        kek = self._keks[tenant]                    # KeyError once shredded
        return AESGCM(kek).decrypt(wrapped_dek[:12], wrapped_dek[12:], tenant.encode("utf-8"))

    def destroy_tenant_keys(self, tenant: str) -> None:
        self._keks.pop(tenant, None)


# --- write policy ------------------------------------------------------------------

_SECRET = re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
_TIER_RANK = {TrustTier.UNTRUSTED: 0, TrustTier.VERIFIED: 1, TrustTier.ENTERPRISE: 2}


class MemoryWritePolicy:
    NAMESPACES = ("host/", "user/", "indicator/", "baseline/", "feedback/", "case/", "verdict/")
    MAX_VALUE_BYTES = 8_000

    def check(self, key: str, value: Any, written_by: str, evidence: list[str],
              evidence_tiers: Optional[list[TrustTier]]) -> TrustTier:
        if not key.startswith(self.NAMESPACES):
            raise MemoryPolicyError(f"key outside allowed namespaces: {key}")
        if not evidence:
            raise MemoryPolicyError("every memory write cites evidence")
        serialized = json.dumps(value, sort_keys=True)
        if len(serialized.encode("utf-8")) > self.MAX_VALUE_BYTES:
            raise MemoryPolicyError("memory holds conclusions, not transcripts")
        if _SECRET.search(serialized):
            raise MemoryPolicyError("secret-shaped content refused")
        if screen_description(serialized):
            raise MemoryPolicyError("instruction-like content refused")
        # Trust-tier floor (P-9.2): never more trusted than the least trusted evidence.
        if evidence_tiers:
            return min(evidence_tiers, key=_TIER_RANK.__getitem__)
        return TrustTier.UNTRUSTED if written_by.startswith("spiffe://") else TrustTier.ENTERPRISE


# --- the store ---------------------------------------------------------------------

class EventSink(Protocol):
    def emit(self, kind: str, **fields: Any) -> None: ...


class ReadLogEntry(BaseModel):
    tenant: str
    key: str
    version: int
    run_id: str
    at: datetime = Field(default_factory=utcnow)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _aad(tenant: str, key: str, version: int, version_hash: str) -> bytes:
    return json.dumps({"tenant": tenant, "key": key, "version": version, "version_hash": version_hash},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


class MemoryStore:
    def __init__(self, kms: Kms, writers: set[str], sink: EventSink,
                 policy: Optional[MemoryWritePolicy] = None) -> None:
        self._kms, self._writers, self._sink = kms, writers, sink
        self._policy = policy or MemoryWritePolicy()
        self._rows: dict[tuple[str, str], list[EncryptedRow]] = {}
        self._reads: list[ReadLogEntry] = []

    # ---- write -------------------------------------------------------------------

    def write(self, tenant: str, key: str, value: Any, written_by: str, evidence: list[str], *,
              evidence_tiers: Optional[list[TrustTier]] = None, reason: str = "") -> MemoryVersion:
        if written_by not in self._writers:
            raise MemoryPolicyError(f"{written_by} is not an allowed memory writer")
        tier = self._policy.check(key, value, written_by, evidence, evidence_tiers)
        history = self._rows.setdefault((tenant, key), [])
        prev_hash = history[-1].header["version_hash"] if history else ""
        mv = MemoryVersion(tenant=tenant, key=key, version=len(history) + 1, value=value,
                           written_by=written_by, evidence=list(evidence), trust_tier=tier,
                           written_at=utcnow(), reason=reason, prev_hash=prev_hash)
        mv.version_hash = mv.compute_hash()

        dek, wrapped, kek_id = self._kms.generate_data_key(tenant)
        nonce = os.urandom(12)
        plaintext = json.dumps(value, sort_keys=True).encode("utf-8")
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, _aad(tenant, key, mv.version, mv.version_hash))

        for row in history:
            if row.status == "active":
                row.status = "superseded"
        history.append(EncryptedRow(
            tenant=tenant, key=key, version=mv.version, kek_id=kek_id,
            wrapped_dek_b64=_b64e(wrapped), nonce_b64=_b64e(nonce), ciphertext_b64=_b64e(ciphertext),
            header=mv.model_dump(mode="json", exclude={"tenant", "key", "version", "value", "status"}),
        ))
        self._sink.emit("memory.write", ref=mv.ref(), written_by=written_by, tier=tier.value,
                        evidence=list(evidence), version_hash=mv.version_hash, reason=reason)
        return mv

    # ---- read: decrypt, verify, log ------------------------------------------------

    def read(self, tenant: str, key: str, *, run_id: str) -> Optional[MemoryVersion]:
        history = self._rows.get((tenant, key), [])
        active = [r for r in history if r.status == "active"]
        if not active:
            return None                                  # quarantined-latest reads as nothing
        mv = self._open(active[-1], history)
        self._reads.append(ReadLogEntry(tenant=tenant, key=key, version=mv.version, run_id=run_id))
        return mv

    def history(self, tenant: str, key: str) -> list[MemoryVersion]:
        history = self._rows.get((tenant, key), [])
        return [self._open(row, history) for row in history]

    def _open(self, row: EncryptedRow, history: list[EncryptedRow]) -> MemoryVersion:
        ref = f"memory://{row.tenant}/{row.key}@{row.version}"
        try:
            dek = self._kms.unwrap(row.tenant, _b64d(row.wrapped_dek_b64), row.kek_id)
        except Exception as exc:
            raise MemoryIntegrityError(f"{ref}: key unavailable (wrong tenant or shredded)") from exc
        try:
            plaintext = AESGCM(dek).decrypt(_b64d(row.nonce_b64), _b64d(row.ciphertext_b64),
                                            _aad(row.tenant, row.key, row.version, row.header["version_hash"]))
        except InvalidTag as exc:
            self._sink.emit("memory.integrity_failure", ref=ref, reason="aead_tag")
            raise MemoryIntegrityError(f"{ref}: ciphertext or bound metadata altered") from exc
        mv = MemoryVersion(tenant=row.tenant, key=row.key, version=row.version,
                           value=json.loads(plaintext), status=row.status, **row.header)
        if mv.compute_hash() != row.header["version_hash"]:
            self._sink.emit("memory.integrity_failure", ref=ref, reason="version_hash")
            raise MemoryIntegrityError(f"{ref}: version hash mismatch")
        if row.version > 1 and mv.prev_hash != history[row.version - 2].header["version_hash"]:
            self._sink.emit("memory.integrity_failure", ref=ref, reason="chain")
            raise MemoryIntegrityError(f"{ref}: hash chain broken")
        return mv

    # ---- rollback, quarantine, dependents, shred -----------------------------------

    def rollback(self, tenant: str, key: str, to_version: int, *, by: str, reason: str) -> MemoryVersion:
        target = next(v for v in self.history(tenant, key) if v.version == to_version)
        for row in self._rows[(tenant, key)]:
            if row.version > to_version and row.status in ("active", "superseded"):
                row.status = "rolled_back"
        restored = self.write(tenant, key, target.value, by,
                              evidence=[target.ref(), f"rollback:{reason}"],
                              evidence_tiers=[target.trust_tier],
                              reason=f"rollback to v{to_version}: {reason}")
        self._sink.emit("memory.rollback", ref=restored.ref(), restored_from=target.ref(), by=by, reason=reason)
        return restored

    def quarantine(self, tenant: str, key: str, version: int, *, by: str, reason: str) -> None:
        for row in self._rows.get((tenant, key), []):
            if row.version == version:
                row.status = "quarantined"
        self._sink.emit("memory.quarantine", ref=f"memory://{tenant}/{key}@{version}", by=by, reason=reason)

    def dependents(self, tenant: str, key: str, versions: Iterable[int]) -> list[str]:
        """Runs that read any of these versions: the re-adjudication list."""
        wanted = set(versions)
        return sorted({r.run_id for r in self._reads
                       if r.tenant == tenant and r.key == key and r.version in wanted})

    def shred_tenant(self, tenant: str, *, by: str, reason: str) -> None:
        """Erasure or offboarding: destroy the KEK; every row stays, unreadable forever."""
        self._kms.destroy_tenant_keys(tenant)
        self._sink.emit("memory.shred", tenant=tenant, by=by, reason=reason)


# --- re-adjudication ---------------------------------------------------------------

class ReadjudicationPlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: new_id("rdj"))
    tenant: str
    key: str
    bad_versions: list[int]
    affected_runs: list[str]
    created_by: str
    reason: str
    created_at: datetime = Field(default_factory=utcnow)
    status: Literal["open", "in_progress", "closed"] = "open"


def plan_readjudication(store: MemoryStore, tenant: str, key: str, bad_versions: Iterable[int], *,
                        by: str, reason: str) -> ReadjudicationPlan:
    bad = sorted(set(bad_versions))
    return ReadjudicationPlan(tenant=tenant, key=key, bad_versions=bad,
                              affected_runs=store.dependents(tenant, key, bad), created_by=by, reason=reason)
