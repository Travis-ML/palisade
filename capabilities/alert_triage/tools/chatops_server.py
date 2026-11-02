# palisade/capabilities/alert_triage/tools/chatops_server.py
import hashlib
import re
from typing import Literal

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("palisade-chatops")
TemplateId = Literal["confirm_oauth_grant", "confirm_signin_location", "confirm_mfa_device", "confirm_file_share"]
TEMPLATES = {"confirm_oauth_grant": ("Security check from the SOC. At {when} an application named \"{app_name}\" was granted "
                                     "access to your account. Did you authorize this? Reply YES or NO. We will never send you a link.")}
URL_SHAPED = re.compile(r"(https?://|www\.|[a-z0-9-]+\.[a-z]{2,}/)", re.IGNORECASE)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clean(value: str) -> str:
    v = re.sub(r"[\x00-\x1f\x7f]", "", str(value))[:80]
    if URL_SHAPED.search(v):
        raise ValueError("slot values may not contain URL-shaped strings")
    return v


@mcp.tool()
def chatops_ask_user(user_id: str, template_id: TemplateId, slots: dict[str, str], timeout_minutes: int = 15) -> dict:
    """Ask one user one templated yes/no question over the enterprise chat platform.

    The agent selects a template and supplies slot values; it cannot compose free text, and slot values may not
    contain links. The reply is UNTRUSTED evidence: a compromised account may answer, so a benign identity verdict
    requires corroborating telemetry (Control C-20.3). Rate limit: one question per user per hour, enforced by the
    gateway. Returns the rendered text hash so reviewers can see exactly what was asked.
    """
    text = TEMPLATES[template_id].format(**{k: _clean(v) for k, v in slots.items()})   # templates: human-authored, reviewed, no links
    delivery = _chat.send_dm(user_id=user_id, text=text)
    reply = _chat.await_reply(delivery.message_id, timeout_minutes=min(timeout_minutes, 30))
    answer = None if reply is None else ("yes" if reply.text.strip().lower().startswith("y") else "no")
    return {"status": "answered" if reply else "timeout", "answer": answer, "channel": "chat",
            "rendered_text_sha256": _sha256(text), "asked_at": delivery.sent_at.isoformat(), "trust_tier": "untrusted"}
