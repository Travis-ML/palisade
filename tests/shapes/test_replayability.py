from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional, Protocol

from palisade.core.types import DecisionRecord
from palisade.ledger.ledger import Ledger


class ContextStore(Protocol):
    """Content-addressed store of assembled contexts (Chapter 5), keyed by hash."""
    def get(self, context_hash: str) -> Optional[dict]: ...


@dataclass
class Reconstruction:
    record: DecisionRecord
    context: Optional[dict]
    missing: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing


def reconstruct(ledger: Ledger, contexts: ContextStore, record: DecisionRecord) -> Reconstruction:
    r = Reconstruction(record=record, context=contexts.get(record.context_hash))
    if r.context is None:
        r.missing.append("context: no content for context_hash")
    if record.model_call is None and record.proposed_action is not None:
        r.missing.append("model_call: action without an inference record")
    if not record.reasoning_summary and record.proposed_action is not None:
        r.missing.append("reasoning_summary: empty")
    if record.proposed_action is not None and record.policy_decision is None:
        r.missing.append("policy_decision: action proposed but never adjudicated")
    pd = record.policy_decision
    if pd is not None:
        if not pd.rule_id:
            r.missing.append("policy_decision.rule_id: empty")
        if pd.verdict == "escalate" and record.approval is None and record.execution is not None:
            r.missing.append("approval: escalated action executed without an approval record")
    if record.approval is not None and not record.approval.presented_context_hash:
        r.missing.append("approval.presented_context_hash: approver's view not recorded")
    if record.execution is not None:
        if record.execution.status == "ok" and not record.execution.result_hash:
            r.missing.append("execution.result_hash: outcome not captured")
        if pd is not None and pd.verdict == "deny":
            r.missing.append("execution: denied action has an execution record")
    for item in record.retrieved:
        if not item.content_hash or not item.version:
            r.missing.append(f"retrieved[{item.item_id}]: unversioned or unhashed")
    # The run must be whole: steps contiguous from 1, chain intact.
    run = ledger.replay(record.run_id)
    steps = [x.step for x in run]
    if steps != list(range(1, len(run) + 1)):
        r.missing.append(f"run: steps not contiguous {steps}")
    return r


def test_replayability(ledger: Ledger, contexts: ContextStore, sample: int = 25, seed: Optional[int] = None) -> None:
    assert ledger.verify_chain(), f"chain broken: {ledger.last_break}"
    records = list(ledger)
    assert records, "empty ledger"
    rng = random.Random(seed)
    picks = rng.sample(records, k=min(sample, len(records)))
    failures = [reconstruct(ledger, contexts, rec) for rec in picks]
    failures = [f for f in failures if not f.complete]
    assert not failures, "\n".join(
        f"{f.record.record_id}: {'; '.join(f.missing)}" for f in failures
    )
