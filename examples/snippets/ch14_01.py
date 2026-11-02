from palisade.core.types import TrustTier
from palisade.guardrails.input import tag

desc = tag(alert["description"], TrustTier.UNTRUSTED, "alert:sentinel:rule-4471/description")
runbook = tag(kb.get("runbooks/lateral-smb.md"), TrustTier.ENTERPRISE, "kb:runbooks/lateral-smb.md@v12")
