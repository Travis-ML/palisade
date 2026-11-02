from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel


class DatasetAttestation(BaseModel):
    dataset_id: str
    version: str
    content_hash: str                   # over the canonical, ordered training set
    sources: list[str]                  # where every example came from
    curation: list[str]                 # dedup, PII scrub, label audit, adversarial seeding
    label_audit_fraction: float         # share of labels a human re-checked
    attested_by: str
    attested_at: datetime
    signature: Optional[str] = None


class ModelLineage(BaseModel):
    model_id: str
    version: str                        # what ModelCallRecord.model_version carries
    base_model: str                     # "hf://<org>/<base>@<revision>"
    method: Literal["full_sft", "lora", "distillation"]
    dataset: DatasetAttestation
    training_config_hash: str
    eval_report_id: str                 # the Chapter 15 EvalReport that gated promotion
    weights_provenance: str             # path to provenance.yaml (Section 6.6)
    promoted_by: str
    promoted_at: datetime
