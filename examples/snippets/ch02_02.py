import json

from pydantic import BaseModel


class Indicator(BaseModel):
    value: str
    type: str  # "ipv4" | "domain" | "sha256"


class IocList(BaseModel):
    items: list[Indicator]


class Summary(BaseModel):
    assessment: str
    malicious_count: int


def ioc_chain(report_text: str, ledger_note) -> Summary:
    iocs = llm(f"Extract every indicator from this report.\n<report>\n{report_text}\n</report>", IocList)
    iocs.items = [i for i in iocs.items if valid_indicator(i.value, i.type)]   # checkpoint: validate
    ledger_note("iocs_extracted", iocs.model_dump())                              # checkpoint: account
    hits = [ti_lookup_indicator(i.value, i.type) for i in iocs.items]             # fixed step, read-only
    ledger_note("iocs_resolved", hits)
    return llm(f"Summarize these lookups for an analyst.\n{json.dumps(hits)}", Summary)
