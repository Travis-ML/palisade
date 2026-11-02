# palisade/compliance/mapping.py
from __future__ import annotations
from collections import defaultdict
from pathlib import Path
from typing import Literal
import yaml
from pydantic import BaseModel, Field

class Evidence(BaseModel):
    source: Literal["ledger", "policy_repo", "roe_store", "broker", "eval_reports", "idp", "ci"]
    query: str                 # a named query in palisade/compliance/queries.sql, or a path
    what_it_shows: str

class Control(BaseModel):
    id: str
    name: str
    layer: str
    owner: str
    chapter: int
    statement: str
    acceptance_test: str
    frameworks: dict[str, list[str]]     # framework key -> requirement identifiers
    evidence: list[Evidence] = Field(default_factory=list)

class Catalog(BaseModel):
    version: str
    frameworks: dict[str, str]           # framework key -> display name
    controls: list[Control]

    @classmethod
    def load(cls, path: str | Path) -> "Catalog":
        return cls.model_validate(yaml.safe_load(Path(path).read_text()))

    def matrix(self) -> str:
        keys = list(self.frameworks)
        rows = ["| Control | " + " | ".join(self.frameworks[k] for k in keys) + " |",
                "|---|" + "---|" * len(keys)]
        for c in self.controls:
            cells = [", ".join(c.frameworks.get(k, [])) for k in keys]
            rows.append(f"| **{c.id}** {c.name} | " + " | ".join(cells) + " |")
        return "\n".join(rows)

    def reverse_index(self) -> dict[str, dict[str, list[str]]]:
        idx: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for c in self.controls:
            for fw, reqs in c.frameworks.items():
                for r in reqs:
                    idx[fw][r].append(c.id)
        return {fw: dict(sorted(m.items())) for fw, m in sorted(idx.items())}

    def coverage(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for c in self.controls:
            for fw in c.frameworks:
                counts[fw] += 1
        return dict(sorted(counts.items()))

    def questionnaire(self, framework: str) -> str:
        idx = self.reverse_index().get(framework, {})
        by_id = {c.id: c for c in self.controls}
        out = [f"## {self.frameworks[framework]}", ""]
        for req, ids in idx.items():
            out.append(f"**{req}**")
            for cid in ids:
                c = by_id[cid]
                ev = "; ".join(f"{e.source}: {e.query}" for e in c.evidence) or "see chapter"
                out.append(f"- {cid} {c.name} (Chapter {c.chapter}). Evidence: {ev}")
            out.append("")
        return "\n".join(out)

if __name__ == "__main__":
    import sys
    cat = Catalog.load(sys.argv[1] if len(sys.argv) > 1 else "palisade/compliance/controls.yaml")
    print(cat.matrix())
    print()
    print(yaml.safe_dump(cat.coverage(), sort_keys=False))
