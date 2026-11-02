# palisade/capabilities/response/library.py
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Annotated, Any, Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from palisade.core.types import ActionClass, ActionDomain, BlastRadius, Reversibility
from palisade.roe import REVERSIBLE_ALTERNATIVES

D, R, B = ActionDomain, Reversibility, BlastRadius

UserId = Annotated[str, Field(pattern=r"^u\.[a-z0-9._-]{1,40}$")]
HostId = Annotated[str, Field(pattern=r"^host-[0-9]{4}$")]
Reason = Annotated[str, Field(min_length=8, max_length=300)]
Ttl = Annotated[int, Field(ge=15, le=1440)]            # containment on a host or an account: 15 minutes to 24 hours


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")          # an unknown argument is a rejected plan, not a shrug


class IdpRevokeSessions(_Args):
    user_id: UserId
    reason: Reason


class IdpDisableAccount(_Args):
    user_id: UserId
    ttl_minutes: Ttl
    reason: Reason


class IdpEnableAccount(_Args):
    user_id: UserId
    reason: Reason


class IdpResetCredential(_Args):                       # the five-question intent travels on the PlanStep, not here
    user_id: UserId
    reason: Reason


class EdrIsolateHost(_Args):
    host_id: HostId
    ttl_minutes: Ttl
    reason: Reason


class EdrReleaseHost(_Args):
    host_id: HostId
    reason: Reason


class FwBlockIndicator(_Args):
    indicator: Annotated[str, Field(min_length=1, max_length=253)]
    indicator_type: Literal["ip", "domain", "url", "sha256"]
    ttl_minutes: Annotated[int, Field(ge=15, le=10080)]    # at most 7 days
    reason: Reason

    @model_validator(mode="after")
    def _single_address(self) -> "FwBlockIndicator":
        if self.indicator_type == "ip":
            ipaddress.ip_address(self.indicator)        # a CIDR raises, so a range cannot ride in as an "ip"
        return self


class FwBlockRange(_Args):
    cidr: str
    ttl_minutes: Annotated[int, Field(ge=15)]
    reason: Reason


class MailQuarantineMessage(_Args):
    message_id: Annotated[str, Field(min_length=1, max_length=200)]
    mailbox: Annotated[str, Field(pattern=r"^[^@\s]+@[^@\s]+$")]
    reason: Reason


class MailPurgeCampaign(_Args):
    fingerprint: Annotated[str, Field(pattern=r"^fp_[0-9a-f]{12}$")]
    max_mailboxes: Annotated[int, Field(ge=1, le=5000)]
    reason: Reason


class TicketCreate(_Args):
    summary: Annotated[str, Field(min_length=8, max_length=200)]
    severity: Literal["low", "medium", "high", "critical"]
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    assignee_group: str


class NotifyUser(_Args):
    user_id: UserId
    template_id: str                                    # a closed set, enforced by Chapter 22's notification module
    slots: dict[str, str] = Field(default_factory=dict)
    channel: Literal["email", "chat"]


@dataclass(frozen=True)
class LibraryEntry:
    """One library entry. The class and the reversal come from here, never from the agent."""
    name: str
    action_class: ActionClass
    arguments: type[_Args]
    reversal: Callable[[dict[str, Any]], Optional[dict[str, Any]]]


def _ac(domain: ActionDomain, rev: Reversibility, blast: BlastRadius) -> ActionClass:
    return ActionClass(domain=domain, reversibility=rev, blast_radius=blast)


def _call(tool: str, **arguments: Any) -> dict[str, Any]:
    return {"tool_name": tool, "arguments": arguments}


def _none(_: dict[str, Any]) -> Optional[dict[str, Any]]:
    return None


PC = D.PRODUCTION_CONTROL
LIBRARY: dict[str, LibraryEntry] = {s.name: s for s in [
    LibraryEntry("idp_revoke_sessions", _ac(PC, R.SEMI_REVERSIBLE, B.SINGLE), IdpRevokeSessions, _none),
    LibraryEntry("idp_disable_account", _ac(PC, R.SEMI_REVERSIBLE, B.SINGLE), IdpDisableAccount,
             lambda a: _call("idp_enable_account", user_id=a["user_id"], reason="reversal of idp_disable_account")),
    LibraryEntry("idp_enable_account", _ac(PC, R.REVERSIBLE, B.SINGLE), IdpEnableAccount,
             lambda a: _call("idp_disable_account", user_id=a["user_id"], ttl_minutes=240, reason="re-disable after enable")),
    LibraryEntry("idp_reset_credential", _ac(PC, R.IRREVERSIBLE, B.SINGLE), IdpResetCredential, _none),
    LibraryEntry("edr_isolate_host", _ac(PC, R.SEMI_REVERSIBLE, B.SINGLE), EdrIsolateHost,
             lambda a: _call("edr_release_host", host_id=a["host_id"], reason="reversal of edr_isolate_host")),
    LibraryEntry("edr_release_host", _ac(PC, R.REVERSIBLE, B.SINGLE), EdrReleaseHost,
             lambda a: _call("edr_isolate_host", host_id=a["host_id"], ttl_minutes=240, reason="re-isolate")),
    LibraryEntry("fw_block_indicator", _ac(PC, R.REVERSIBLE, B.SINGLE), FwBlockIndicator,
             lambda a: _call("fw_unblock_indicator", indicator=a["indicator"], reason="reversal of fw_block_indicator")),
    LibraryEntry("fw_block_range", _ac(PC, R.REVERSIBLE, B.ENTERPRISE), FwBlockRange,
             lambda a: _call("fw_unblock_range", cidr=a["cidr"], reason="reversal of fw_block_range")),
    LibraryEntry("mail_quarantine_message", _ac(PC, R.SEMI_REVERSIBLE, B.SINGLE), MailQuarantineMessage,
             lambda a: _call("mail_release_message", message_id=a["message_id"], mailbox=a["mailbox"])),
    LibraryEntry("mail_purge_campaign", _ac(PC, R.SEMI_REVERSIBLE, B.GROUP), MailPurgeCampaign,
             lambda a: _call("mail_release_message", fingerprint=a["fingerprint"])),
    LibraryEntry("ticket_create", _ac(D.INTERNAL_CHANGE, R.SEMI_REVERSIBLE, B.SINGLE), TicketCreate, _none),
    LibraryEntry("notify_user", _ac(D.INTERNAL_CHANGE, R.IRREVERSIBLE, B.SINGLE), NotifyUser, _none),
]}

# Tools the executor may call to undo an earlier step. They are on the servers but not in LIBRARY, so a plan
# cannot name them: the planner's vocabulary stays the twelve tools above.
REVERSAL_ONLY = frozenset({"fw_unblock_indicator", "fw_unblock_range", "mail_release_message"})


def reversible_sibling(tool_name: str) -> Optional[str]:
    """The gentler tool to prefer over this one, using Chapter 11's map, if that tool is in the library."""
    sibling = REVERSIBLE_ALTERNATIVES.get(tool_name)
    return sibling if sibling in LIBRARY else None


def is_host_tool(tool_name: str) -> bool:
    """Host-level tools destroy or hide evidence of what ran there; the validator wants evidence collected first."""
    return tool_name.startswith("edr_")
