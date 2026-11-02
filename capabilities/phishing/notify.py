# palisade/capabilities/phishing/notify.py
from __future__ import annotations

from pydantic import BaseModel, Field

from palisade.capabilities.phishing.context import URL_RE
from palisade.capabilities.phishing.models import CampaignScope

CLAIM_SLOTS = {"received": "recipient", "clicked": "clicked", "entered_credentials": "authenticated", "account_reset": "reset"}
PORTAL = "https://security.palisade.example/"


class NotificationDraft(BaseModel):
    template_id: str
    audience: list[str] = Field(min_length=1)
    slots: dict[str, str]


class ToneCheckFailed(Exception):
    pass


def tone_check(draft: NotificationDraft, scope: CampaignScope, templates, classifier, settings) -> dict[str, str]:
    """Returns rendered text per recipient, or raises. Claims must be evidenced per recipient; tone must pass; links must be the portal."""
    if draft.template_id not in templates:
        raise ToneCheckFailed("template.unknown")
    rendered: dict[str, str] = {}
    for user in draft.audience:
        for slot, evidence_list in CLAIM_SLOTS.items():
            if draft.slots.get(slot) == "true" and user not in getattr(scope, evidence_list):
                raise ToneCheckFailed(f"claim.unsupported:{slot}:{user}")       # no "you were compromised" without evidence
        text = templates[draft.template_id].render(user=user, **draft.slots)
        if any(u for u in URL_RE.findall(text) if not u.startswith(PORTAL)):
            raise ToneCheckFailed(f"link.not_portal:{user}")
        score = classifier.score(text, rubric="plain, non-blaming, specific, no urgency, no threats")
        if score < settings.min_tone_score:
            raise ToneCheckFailed(f"tone.below_threshold:{score:.2f}:{user}")
        rendered[user] = text
    if len(draft.audience) > settings.notify_audience_approval_threshold:
        raise ToneCheckFailed(f"audience.requires_senior_approval:{len(draft.audience)}")   # the approval request goes to the senior approver
    return rendered
