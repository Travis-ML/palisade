from palisade.core.types import AutonomyTier

FAMILY_PLAYBOOKS = {"phishing": phishing_playbook, "malware": malware_playbook,
                    "identity": identity_playbook}
FAMILY_CEILING = {"phishing": AutonomyTier.ACT_WITHIN_SCOPE,
                  "malware": AutonomyTier.ACT_WITH_APPROVAL,
                  "identity": AutonomyTier.DRAFT}


class FamilyLabel(BaseModel):
    family: str
    confidence: float


def route(alert: dict):
    label = llm(f"Classify this alert's family.\n<alert>\n{json.dumps(alert)}\n</alert>", FamilyLabel)
    if label.family not in FAMILY_PLAYBOOKS or label.confidence < 0.7:
        return escalate_to_human(alert, reason=f"unrouted: {label.family} @ {label.confidence:.2f}")
    return FAMILY_PLAYBOOKS[label.family](alert, ceiling=FAMILY_CEILING[label.family])
