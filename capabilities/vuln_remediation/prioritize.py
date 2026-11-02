# palisade/capabilities/vuln_remediation/prioritize.py
from typing import Literal

from pydantic import BaseModel, Field

Exposure = Literal["internet", "partner", "internal", "isolated"]
Tier = Literal["tier0", "tier1", "tier2", "tier3"]  # tier0 = most critical


class PriorityInput(BaseModel):
    finding_id: str
    cvss_base: float | None
    in_kev: bool
    known_ransomware_use: bool
    epss: float | None                  # None when unscored
    reachable: bool | None              # None when analysis unavailable
    exposure: Exposure
    process_privilege: Literal["root", "service", "user", "sandboxed"]
    reach_count: int                    # downstream assets reachable from this one
    holds_regulated_data: bool
    asset_tier: Tier


class PriorityScore(BaseModel):
    finding_id: str
    exploitability: float = Field(ge=0.0, le=1.0)
    blast_radius: float = Field(ge=0.0, le=1.0)
    criticality: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0, le=1.0)
    floor: float = Field(ge=0.0, le=1.0)   # the agent may not rank below this
    rationale: list[str]


def exploitability(p: PriorityInput) -> tuple[float, list[str]]:
    notes: list[str] = []
    if p.in_kev:
        e = 1.0
        notes.append("CISA KEV: exploitation confirmed in the wild")
        if p.known_ransomware_use:
            notes.append("KEV flags known ransomware campaign use")
    elif p.epss is not None:
        e = p.epss
        notes.append(f"EPSS {p.epss:.3f} (30-day exploitation probability)")
    else:
        e = 0.05 if p.cvss_base is None else min(p.cvss_base / 10.0, 1.0) * 0.3
        notes.append("no KEV/EPSS signal; CVSS used as weak prior")
    if p.reachable is False:
        e *= 0.25
        notes.append("vulnerable code not reachable per SCA reachability analysis")
    exposure_weight = {"internet": 1.0, "partner": 0.8, "internal": 0.5, "isolated": 0.2}
    e = min(1.0, e * (0.5 + 0.5 * exposure_weight[p.exposure]))
    notes.append(f"exposure={p.exposure}")
    return e, notes


def blast_radius(p: PriorityInput) -> tuple[float, list[str]]:
    priv = {"root": 1.0, "service": 0.7, "user": 0.4, "sandboxed": 0.15}[p.process_privilege]
    b = 0.6 * priv + 0.4 * min(1.0, p.reach_count / 50.0)
    return b, [f"privilege={p.process_privilege}", f"reachable_assets={p.reach_count}"]


def criticality(p: PriorityInput) -> tuple[float, list[str]]:
    tier = {"tier0": 1.0, "tier1": 0.75, "tier2": 0.45, "tier3": 0.2}[p.asset_tier]
    c = min(1.0, tier + (0.2 if p.holds_regulated_data else 0.0))
    return c, [f"asset_tier={p.asset_tier}", f"regulated_data={p.holds_regulated_data}"]


def score(p: PriorityInput) -> PriorityScore:
    e, en = exploitability(p)
    b, bn = blast_radius(p)
    c, cn = criticality(p)
    # A KEV finding on an internet-exposed asset never drops below the
    # organization's "fix now" line, whatever the agent later argues.
    floor = 0.6 if (p.in_kev and p.exposure == "internet") else 0.0
    return PriorityScore(finding_id=p.finding_id, exploitability=e, blast_radius=b,
                         criticality=c, score=max(e * b * c, floor), floor=floor,
                         rationale=en + bn + cn)


# palisade/capabilities/vuln_remediation/prioritize.py (continued)
MAX_ADJUST = 0.25


class AgentRanking(BaseModel):
    finding_id: str
    adjusted_score: float = Field(ge=0.0, le=1.0)
    adjustment_evidence: list[str]
    duplicate_of: str | None = None


def validate_ranking(computed: PriorityScore, proposed: AgentRanking) -> AgentRanking:
    delta = proposed.adjusted_score - computed.score
    if abs(delta) > MAX_ADJUST:
        raise ValueError(f"adjustment {delta:+.2f} exceeds {MAX_ADJUST}")
    if proposed.adjusted_score < computed.floor:
        raise ValueError(f"below floor {computed.floor}; requires human accept-risk")
    if delta != 0 and not proposed.adjustment_evidence:
        raise ValueError("adjustment without cited evidence")
    return proposed
