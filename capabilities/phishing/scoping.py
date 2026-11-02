# palisade/capabilities/phishing/scoping.py
from __future__ import annotations

from palisade.core.types import RunBudget, RunState

SCOPING_TOOLS = ["mail_search_messages", "siem_query", "idp_get_signins", "ti_lookup_indicator"]   # all observe or enrich
SCOPING_BUDGET = RunBudget(max_steps=20, max_wall_seconds=300, max_tokens=80_000, max_cost_usd=0.60, max_tool_calls=24,
                           per_tool_limits={"mail_search_messages": 8, "siem_query": 8, "idp_get_signins": 6})


def scoping_goal(fingerprint: dict, delivered_at: str) -> str:
    return (f"[phishing scope] Starting fingerprint {fingerprint} delivered from {delivered_at}. Expand the fingerprint only "
            "through evidence (shared sender, return-path domain, URL host, attachment hash). Enumerate recipients, "
            "recipients who clicked (proxy hits on the URL hosts after delivery), and clickers who authenticated from an "
            "unfamiliar location or device within 60 minutes of the click. Report facts with query citations as a "
            "CampaignScope; do not propose remediation.")


def determine_scope(loop_factory, agent, roe, fingerprint: dict, delivered_at: str) -> RunState:
    loop = loop_factory(agent=agent, roe=roe, tools=SCOPING_TOOLS)
    return loop.run(scoping_goal(fingerprint, delivered_at), SCOPING_BUDGET)   # the CampaignScope is reconstructed from the ledger
