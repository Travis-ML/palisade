from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

ENRICHERS = {"siem": enrich_from_siem, "edr": enrich_from_edr,
             "idp": enrich_from_idp, "intel": enrich_from_intel}


def enrich(alert: dict) -> dict:                                   # sectioning
    with ThreadPoolExecutor(max_workers=len(ENRICHERS)) as pool:
        futures = {name: pool.submit(fn, alert) for name, fn in ENRICHERS.items()}
        return {name: f.result(timeout=30) for name, f in futures.items()}


class VerdictLabel(BaseModel):
    label: Literal["benign", "suspicious", "malicious"]


def vote(evidence: dict, n: int = 3, required: int = 3) -> str | None:   # voting
    labels = [llm(f"Given this evidence, give a verdict.\n{json.dumps(evidence)}", VerdictLabel).label
              for _ in range(n)]
    top, count = Counter(labels).most_common(1)[0]
    return top if count >= required else None   # None: no agreement, no autonomous action, escalate
