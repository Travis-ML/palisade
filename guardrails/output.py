# palisade/guardrails/output.py (guard and DLP)
import re
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, ValidationError
from palisade.core.types import ActionClass, FiveQuestionIntent, Plane, ProposedAction

class OutputRejected(Exception):
    def __init__(self, rule_id: str, detail: str) -> None:
        super().__init__(f"{rule_id}: {detail}")
        self.rule_id, self.detail = rule_id, detail

class ToolContract(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    name: str
    plane: Plane
    action_class: ActionClass
    args_model: type[BaseModel]
    extracts_targets: str = ""        # the argument that carries the target id, if any

class ToolCallEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    arguments: dict[str, Any]
    rationale: str = ""
    intent: Optional[FiveQuestionIntent] = None

class OutputGuard:
    def __init__(self, registry: dict[str, ToolContract], plane: Plane) -> None:
        self._registry, self._plane = registry, plane

    def validate_proposal(self, raw: dict[str, Any]) -> ProposedAction:
        try:
            env = ToolCallEnvelope.model_validate(raw)
        except ValidationError as exc:
            raise OutputRejected("output.malformed_envelope", _brief(exc)) from None
        contract = self._registry.get(env.tool_name)
        if contract is None:
            raise OutputRejected("output.oov_tool", f"'{env.tool_name}' is not a registered tool")
        if contract.plane is not self._plane:
            raise OutputRejected("output.wrong_plane", f"'{env.tool_name}' belongs to the {contract.plane.value} plane")
        try:
            args = contract.args_model.model_validate(env.arguments)
        except ValidationError as exc:
            raise OutputRejected("output.schema_violation", _brief(exc)) from None
        targets: list[str] = []
        if contract.extracts_targets:
            value = getattr(args, contract.extracts_targets)
            targets = list(value) if isinstance(value, list) else [str(value)]
        return ProposedAction(
            tool_name=contract.name, arguments=args.model_dump(),      # the validated form, not the raw text
            action_class=contract.action_class,                         # from the registry, never from the model
            target_ids=targets, intent=env.intent, rationale=env.rationale)

def _brief(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:4])

class DLPFinding(BaseModel):
    kind: str
    count: int
    severity: Literal["low", "medium", "high", "critical"]

class DLPResult(BaseModel):
    action: Literal["allow", "redact", "deny"]
    findings: list[DLPFinding]
    text: str

_SECRET_SHAPES = {
    "aws_access_key_id": (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    "private_key_block": (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"), "critical"),
    "jwt": (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
    "bearer_token": (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*"), "high"),
    "palisade_canary": (re.compile(r"\bPCANARY-[0-9a-f]{12}\b"), "critical"),
}
_PII_SHAPES = {
    "us_ssn": (re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "high"),
    "payment_card": (re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), "high"),
    "email_bulk": (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "medium"),
}

def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 if d < 5 else d * 2 - 9
        total, alt = total + d, not alt
    return total % 10 == 0

class DLPScreen:
    def __init__(self, allowlist: Optional[set[str]] = None, bulk_email_threshold: int = 5,
                 pii_tools: Optional[set[str]] = None) -> None:
        self._allow = allowlist or set()
        self._bulk = bulk_email_threshold
        self._pii_tools = pii_tools or {"idp_revoke_sessions", "idp_disable_account", "notify_user"}

    def screen(self, text: str, destination: str) -> DLPResult:
        findings: list[DLPFinding] = []
        redacted = text
        for kind, (pat, sev) in _SECRET_SHAPES.items():
            hits = [m for m in pat.finditer(text) if m.group(0) not in self._allow]
            if hits:
                findings.append(DLPFinding(kind=kind, count=len(hits), severity=sev))
        for kind, (pat, sev) in _PII_SHAPES.items():
            matches = list(pat.finditer(text))
            if kind == "payment_card":
                matches = [m for m in matches if _luhn_ok(re.sub(r"\D", "", m.group(0)))]
            if kind == "email_bulk" and len(matches) < self._bulk:
                continue
            if matches:
                findings.append(DLPFinding(kind=kind, count=len(matches), severity=sev))
                for m in matches:
                    redacted = redacted.replace(m.group(0), f"<{kind}:redacted>")
        if not findings:
            return DLPResult(action="allow", findings=[], text=text)
        has_secret = any(f.kind in _SECRET_SHAPES for f in findings)
        if destination == "range_egress" or has_secret:
            return DLPResult(action="deny", findings=findings, text="")
        if destination.startswith("tool:") and destination.removeprefix("tool:") in self._pii_tools:
            return DLPResult(action="allow", findings=findings, text=text)
        return DLPResult(action="redact", findings=findings, text=redacted)
