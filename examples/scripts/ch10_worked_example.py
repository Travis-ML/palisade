import hashlib, json
from datetime import timedelta

from palisade.core.types import (
    ActionClass, ActionDomain, BlastRadius, FiveQuestionIntent, GlassBoxVerdict,
    Hypothesis, ProposedAction, QueryLogEntry, Reversibility, utcnow,
)

raw_alert = {
    "alert_id": "SIEM-2026-10-04-118827",
    "rule": "O365: New inbox rule hides messages after risky sign-in",
    "severity": "high",
    "user": "u.ramirez",
    "host": "host-4471",
    "src_ip": "185.220.101.47",
    "sign_in_country": "NL",
    "rule_name": "..",
    "rule_actions": ["MoveToFolder:RSS Subscriptions", "MarkAsRead"],
    "description": "Inbox rule created 4m after sign-in from unfamiliar location.",
}
raw_hash = hashlib.sha256(json.dumps(raw_alert, sort_keys=True).encode()).hexdigest()
t0 = utcnow()

def h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

verdict = GlassBoxVerdict(
    run_id="run_7f3a9c21e0b4",
    raw_input=raw_alert,
    raw_input_hash=raw_hash,
    query_log=[
        QueryLogEntry(at=t0, tool_name="siem_query",
            arguments_redacted={"query": "SigninLogs | where UserPrincipalName == 'tok_email_mgtikt6qt2xyl4at' "
                                         "| where TimeGenerated > ago(14d) | summarize by Location, IPAddress, AppDisplayName"},
            result_hash=h("r1")),
        QueryLogEntry(at=t0 + timedelta(seconds=9), tool_name="ti_lookup_indicator",
            arguments_redacted={"indicator": "tok_ipv4_z5htvdmv7ryyznx6", "type": "ipv4"},
            result_hash=h("r2")),
        QueryLogEntry(at=t0 + timedelta(seconds=14), tool_name="edr_get_host",
            arguments_redacted={"host_id": "host-4471"}, result_hash=h("r3")),
        QueryLogEntry(at=t0 + timedelta(seconds=31), tool_name="siem_query",
            arguments_redacted={"query": "OfficeActivity | where UserId == 'tok_email_mgtikt6qt2xyl4at' "
                                         "| where Operation in ('New-InboxRule','Set-InboxRule') | project TimeGenerated, Parameters"},
            result_hash=h("r4")),
        QueryLogEntry(at=t0 + timedelta(seconds=52), tool_name="notify_user",
            arguments_redacted={"user": "u.ramirez", "channel": "chatops",
                                "question": "Did you create an inbox rule named '..' in the last hour?"},
            result_hash=h("r5")),
    ],
    hypotheses=[
        Hypothesis(label="malicious", weight=0.72,
            statement="Account takeover: attacker signed in from a Tor exit and created a hiding rule "
                      "to suppress security notifications.",
            supporting_evidence=[
                "ti_lookup_indicator: src_ip is a known Tor exit node (3 feeds, high confidence)",
                "siem_query#1: no sign-in from NL or this ASN in the prior 14 days",
                "siem_query#4: rule name '..' and target folder 'RSS Subscriptions' match the "
                "hiding-rule pattern in runbook RB-O365-014 v7",
                "notify_user: no response within 10 minutes"],
            contradicting_evidence=[
                "edr_get_host: host-4471 shows no new processes, persistence, or EDR alerts in the window"]),
        Hypothesis(label="suspicious", weight=0.21,
            statement="Legitimate user travelling on a privacy VPN, created a rule to tidy newsletters.",
            supporting_evidence=["edr_get_host: endpoint clean", "User is in Sales; travel plausible"],
            contradicting_evidence=[
                "Rule name '..' is not a tidying name",
                "Hidden folder plus MarkAsRead is the documented concealment pattern",
                "No out-of-office or travel record in calendar enrichment"]),
        Hypothesis(label="benign", weight=0.07,
            statement="Admin-driven rule migration during a tenant mailbox move.",
            supporting_evidence=[],
            contradicting_evidence=[
                "siem_query#4: rule created by the user principal, not an admin",
                "No change ticket references this mailbox"]),
    ],
    chosen="malicious",
    confidence=0.72,
    evidence_weighting=(
        "Tor-exit source plus a never-before-seen location would be suspicious alone; combined with a rule "
        "whose name and actions match RB-O365-014's concealment signature within four minutes of the sign-in, "
        "the malicious branch dominates. The clean endpoint lowers confidence (an attacker holding only cloud "
        "credentials leaves no endpoint trace, so it does not refute the hypothesis, but it removes a confirming "
        "signal). The user did not answer the ChatOps question, which neither confirms nor refutes. Confidence "
        "is 0.72, below the 0.85 threshold for the pre-approved reversible path, so the recommended action escalates."
    ),
    recommended_action=ProposedAction(
        tool_name="idp_revoke_sessions",
        arguments={"user_id": "u.ramirez", "reason": "Suspected account takeover, alert SIEM-2026-10-04-118827"},
        action_class=ActionClass(domain=ActionDomain.PRODUCTION_CONTROL,
                                 reversibility=Reversibility.IRREVERSIBLE,
                                 blast_radius=BlastRadius.SINGLE),
        target_ids=["user:u.ramirez"],
        intent=FiveQuestionIntent(
            intent="Cut off the attacker's live sessions before mail is exfiltrated or used for internal phishing.",
            necessity="Disabling the account is more disruptive; revoking sessions forces re-authentication "
                      "with MFA and leaves the account usable.",
            harm="If wrong, the user re-authenticates once. Minutes of inconvenience, no data loss.",
            data="Tor exit source (3 feeds), first-seen location, concealment rule matching RB-O365-014, "
                 "4-minute dwell between events.",
            alternatives="Wait for user reply (rejected: dwell time favors the attacker); disable account "
                         "(rejected: higher harm, not needed yet); do nothing (rejected: hiding rule shows intent).",
        ),
        rationale="Revoking sessions is the least disruptive action that stops an in-progress takeover.",
    ),
)
