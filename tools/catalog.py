"""
palisade/tools/catalog.py

The action taxonomy applied to Palisade's tools. Classification is a harness decision,
recorded here, reviewed in PRs, never inferred from a model's output or a tool's
self-description. Chapter 11 adds target-based escalation.
"""
from __future__ import annotations

from pydantic import BaseModel

from palisade.core.types import ActionClass, ActionDomain, BlastRadius, Plane, Reversibility

D, R, B = ActionDomain, Reversibility, BlastRadius


class CatalogEntry(BaseModel):
    tool_name: str
    action_class: ActionClass
    plane: Plane            # the only plane on which this tool may be served
    summary: str            # one line for reviewers; the model sees the ToolSpec description (Chapter 7)


def _entry(name: str, domain: ActionDomain, rev: Reversibility, blast: BlastRadius,
           plane: Plane, summary: str) -> CatalogEntry:
    return CatalogEntry(tool_name=name, plane=plane, summary=summary,
                        action_class=ActionClass(domain=domain, reversibility=rev, blast_radius=blast))


TOOL_CATALOG: dict[str, CatalogEntry] = {e.tool_name: e for e in [
    _entry("siem_query",              D.OBSERVE,            R.REVERSIBLE,      B.SINGLE, Plane.DEFENSIVE, "Read-only SIEM query."),
    _entry("edr_get_host",            D.OBSERVE,            R.REVERSIBLE,      B.SINGLE, Plane.DEFENSIVE, "Read one host's EDR record."),
    _entry("ti_lookup_indicator",     D.ENRICH,             R.REVERSIBLE,      B.SINGLE, Plane.DEFENSIVE, "Look up one indicator."),
    _entry("sandbox_detonate",        D.ENRICH,             R.REVERSIBLE,      B.SINGLE, Plane.DEFENSIVE, "Detonate in the no-egress sandbox."),
    _entry("scanner_run",             D.OBSERVE,            R.REVERSIBLE,      B.GROUP,  Plane.DEFENSIVE, "Scan an asset group."),
    _entry("ticket_create",           D.INTERNAL_CHANGE,    R.SEMI_REVERSIBLE, B.SINGLE, Plane.DEFENSIVE, "Create a ticket."),
    _entry("scm_open_pr",             D.INTERNAL_CHANGE,    R.SEMI_REVERSIBLE, B.SINGLE, Plane.DEFENSIVE, "Open a PR on a branch; never writes to main."),
    _entry("notify_user",             D.INTERNAL_CHANGE,    R.IRREVERSIBLE,    B.SINGLE, Plane.DEFENSIVE, "Message one user; cannot be recalled."),
    _entry("edr_isolate_host",        D.PRODUCTION_CONTROL, R.SEMI_REVERSIBLE, B.SINGLE, Plane.DEFENSIVE, "Isolate one host, server-enforced TTL."),
    _entry("edr_release_host",        D.PRODUCTION_CONTROL, R.REVERSIBLE,      B.SINGLE, Plane.DEFENSIVE, "Release one host from isolation; undoes edr_isolate_host."),
    _entry("idp_revoke_sessions",     D.PRODUCTION_CONTROL, R.SEMI_REVERSIBLE, B.SINGLE, Plane.DEFENSIVE, "Revoke one user's sessions."),
    _entry("idp_disable_account",     D.PRODUCTION_CONTROL, R.SEMI_REVERSIBLE, B.SINGLE, Plane.DEFENSIVE, "Disable one account; consequences may not reverse."),
    _entry("mail_quarantine_message", D.PRODUCTION_CONTROL, R.SEMI_REVERSIBLE, B.SINGLE, Plane.DEFENSIVE, "Quarantine one message; release possible."),
    _entry("mail_purge_campaign",     D.PRODUCTION_CONTROL, R.SEMI_REVERSIBLE, B.GROUP,  Plane.DEFENSIVE, "Move a campaign to quarantine in every mailbox; release possible."),
    _entry("range_emulate_step",      D.OFFENSE,            R.IRREVERSIBLE,    B.GROUP,  Plane.OFFENSIVE, "One approved emulation step inside the range."),
]}


def action_classes(catalog: dict[str, CatalogEntry] = TOOL_CATALOG) -> dict[str, ActionClass]:
    """The shape Chapter 2's adapter consumes."""
    return {name: entry.action_class for name, entry in catalog.items()}


def tools_for_plane(plane: Plane, catalog: dict[str, CatalogEntry] = TOOL_CATALOG) -> list[str]:
    """The shape Chapter 4's plane binding consumes."""
    return sorted(name for name, entry in catalog.items() if entry.plane == plane)
