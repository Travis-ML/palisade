"""palisade/context/gardener.py: find stale knowledge, propose fixes as PRs, never write the store."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from palisade.core.types import (ActionClass, ActionDomain, BlastRadius, ProposedAction,
                                 Reversibility, utcnow)
from palisade.context.retriever import KnowledgeStore

PR_CLASS = ActionClass(domain=ActionDomain.INTERNAL_CHANGE, reversibility=Reversibility.REVERSIBLE,
                       blast_radius=BlastRadius.SINGLE)


class KnowledgeGardener:
    def __init__(self, store: KnowledgeStore, index_meta: dict[str, dict[str, Any]], cmdb_export: dict[str, dict]) -> None:
        self._store, self._meta, self._cmdb = store, index_meta, cmdb_export

    def findings(self) -> list[dict[str, Any]]:
        now = utcnow()
        out: list[dict[str, Any]] = []
        for item_id, meta in self._meta.items():
            due = meta["last_verified"] + timedelta(days=meta.get("review_interval_days", 90))
            if due < now:
                out.append({"item_id": item_id, "kind": "stale", "due": due.isoformat()})
            for link in meta.get("links", []):
                if self._store.get(link) is None:
                    out.append({"item_id": item_id, "kind": "broken_link", "target": link})
            if item_id.startswith("assets/hosts/"):
                host = item_id.rsplit("/", 1)[1]
                authoritative = self._cmdb.get(host)
                if authoritative and authoritative.get("role") != meta.get("role"):
                    out.append({"item_id": item_id, "kind": "drift", "field": "role",
                                "stored": meta.get("role"), "authoritative": authoritative["role"]})
        return out

    def propose(self, findings: list[dict[str, Any]]) -> ProposedAction:
        body = "\n".join(f"- {f['item_id']}: {f['kind']} {f.get('target') or f.get('field') or ''}".rstrip()
                         for f in findings)
        return ProposedAction(
            tool_name="scm_open_pr", action_class=PR_CLASS, target_ids=["repo:knowledge"],
            arguments={"repo": "knowledge", "branch": f"gardener/{utcnow():%Y%m%d}",
                       "title": f"Knowledge gardening: {len(findings)} findings",
                       "body": body, "changes": [f for f in findings if f["kind"] == "drift"]},
            rationale="Scheduled gardening run; see findings in body. Human review required before merge.",
        )
