# palisade/compliance/evidence.py (sketch)
import hashlib, json
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel, Field
from palisade.core.types import DecisionRecord, utcnow

class EvidencePacket(BaseModel):
    request_id: str
    period_start: datetime
    period_end: datetime
    chain_verified: bool
    first_hash: str
    last_hash: str
    record_count: int
    negative_assurance: dict[str, int]         # query name -> row count (expected 0)
    roe_versions: list[dict]                   # engagement_id, version, signer_key_id, signature
    approvals: list[dict]                      # rows of q_irreversible_approvals
    replayed_runs: dict[str, list[DecisionRecord]]   # run_id -> Ledger.replay(run_id) for the auditor's sample
    kill_events: list[dict]
    catalog_rows: str                          # the questionnaire excerpt
    assembled_at: datetime = Field(default_factory=utcnow)

    def write(self, out_dir: Path) -> str:
        out_dir.mkdir(parents=True, exist_ok=True)
        body = self.model_dump_json(indent=2).encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        (out_dir / f"{self.request_id}.json").write_bytes(body)
        (out_dir / f"{self.request_id}.sha256").write_text(digest)
        return digest
