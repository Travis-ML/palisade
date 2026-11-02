# palisade/hitl/gate.py (first part; Section 13.6.3 adds the approval gate to this file)
from enum import Enum

from palisade.core.types import ActionClass, ActionDomain, AutonomyTier, Plane
from palisade.roe import ceiling_for                      # Chapter 11: the only place a ceiling is defined

class HitlMode(str, Enum):
    IN_THE_LOOP = "in_the_loop"          # a human approves before the action runs
    ON_THE_LOOP = "on_the_loop"          # the action runs; a human watches the live stream and can stop it
    OVER_THE_LOOP = "over_the_loop"      # the action runs; humans review samples and aggregates afterward
    NOT_PERMITTED = "not_permitted"      # the ladder does not reach this combination

def select_mode(action_class: ActionClass, tier: AutonomyTier) -> HitlMode:
    domain = action_class.domain
    plane = Plane.OFFENSIVE if domain is ActionDomain.OFFENSE else Plane.DEFENSIVE
    rule = ceiling_for(action_class, plane)
    tier = AutonomyTier(min(tier, rule.max_tier))         # a class never holds a tier above its ceiling

    if domain in (ActionDomain.OBSERVE, ActionDomain.ENRICH):
        return HitlMode.OVER_THE_LOOP

    if domain is ActionDomain.OFFENSE:                    # the range contains it; a human gates the phase, then watches
        if tier < AutonomyTier.ACT_WITH_APPROVAL:
            return HitlMode.NOT_PERMITTED
        return HitlMode.IN_THE_LOOP if tier == AutonomyTier.ACT_WITH_APPROVAL else HitlMode.ON_THE_LOOP

    if domain is ActionDomain.INTERNAL_CHANGE:
        if rule.gate == "approval":                       # irreversible or enterprise-wide: a human every time
            return HitlMode.NOT_PERMITTED if tier < AutonomyTier.ACT_WITH_APPROVAL else HitlMode.IN_THE_LOOP
        if tier < AutonomyTier.DRAFT:
            return HitlMode.NOT_PERMITTED
        return HitlMode.IN_THE_LOOP if tier < AutonomyTier.ACT_WITHIN_SCOPE else HitlMode.OVER_THE_LOOP

    # production_control
    if tier < AutonomyTier.ACT_WITH_APPROVAL:
        return HitlMode.NOT_PERMITTED
    if rule.gate in ("five_question", "approval") or tier == AutonomyTier.ACT_WITH_APPROVAL:
        return HitlMode.IN_THE_LOOP                       # irreversible, enterprise, or group: permanently
    return HitlMode.ON_THE_LOOP


import hashlib
from typing import Callable, Optional
from pydantic import BaseModel
from palisade.core.types import GlassBoxVerdict, PolicyDecision, ProposedAction

class PresentedGlassBox(BaseModel):
    action: ProposedAction
    decision: PolicyDecision
    verdict: GlassBoxVerdict
    engagement_id: str
    reversal_path: str
    kill_scope: str
    evidence_ids: list[str]
    least_sure: list[str]
    calibration_note: str
    rendered: str
    hash: str

class GlassBoxPresenter:
    def __init__(self, calibration: Optional[Callable[[float], Optional[float]]] = None) -> None:
        self._calibration = calibration or (lambda c: None)   # confidence -> observed precision

    @staticmethod
    def evidence_id(result_hash: str) -> str:
        return f"ev_{result_hash[:8]}"

    def present(self, action, decision, verdict, engagement_id, reversal_path, kill_scope) -> PresentedGlassBox:
        evidence_ids = [self.evidence_id(q.result_hash) for q in verdict.query_log if q.result_hash]
        least_sure = self._least_sure(verdict)
        observed = self._calibration(verdict.confidence)
        note = (f"agent-reported {verdict.confidence:.2f}; observed precision at this band: {observed:.2f}"
                if observed is not None else f"agent-reported {verdict.confidence:.2f}; no calibration data")
        rendered = self._render(action, decision, verdict, engagement_id, reversal_path,
                                kill_scope, evidence_ids, least_sure, note)
        return PresentedGlassBox(
            action=action, decision=decision, verdict=verdict, engagement_id=engagement_id,
            reversal_path=reversal_path, kill_scope=kill_scope, evidence_ids=evidence_ids,
            least_sure=least_sure, calibration_note=note, rendered=rendered,
            hash=hashlib.sha256(rendered.encode("utf-8")).hexdigest())

    @staticmethod
    def _least_sure(verdict: GlassBoxVerdict) -> list[str]:
        notes: list[str] = []
        ranked = sorted(verdict.hypotheses, key=lambda h: h.weight, reverse=True)
        if len(ranked) >= 2:
            margin = ranked[0].weight - ranked[1].weight
            notes.append(f"margin between top hypotheses: {margin:.2f}")
            if margin < 0.25:
                notes.append("LOW MARGIN: the verdict is close; read the second hypothesis")
        for h in ranked:
            for c in h.contradicting_evidence:
                notes.append(f"{c} contradicts the '{h.label}' branch")
        failed = [q for q in verdict.query_log if not q.result_hash]
        if failed:
            notes.append(f"{len(failed)} query(ies) returned no result; evidence may be incomplete")
        return notes


import re
from typing import Literal
from pydantic import BaseModel, Field
from palisade.core.types import FiveQuestionIntent, ProposedAction

class GateToolFacts(BaseModel):
    name: str
    reversible_alternatives: list[str] = Field(default_factory=list)
    reversal_path: str = "none registered"

class IntentScore(BaseModel):
    per_question: dict[str, int]
    total: int
    verdict: Literal["accept", "deeper_review", "reject"]
    findings: list[str]

BOILERPLATE = {"", "n/a", "na", "none", "no", "yes", "see above", "as above", "as described",
               "tbd", "unknown", "not applicable", "nothing", "same as above"}
_WORD = re.compile(r"[A-Za-z0-9_.:/-]+")

class IntentScorer:
    def __init__(self, tools: dict[str, GateToolFacts], min_words: int = 8) -> None:
        self._tools = tools
        self._min_words = min_words

    def score(self, intent: FiveQuestionIntent, action: ProposedAction,
              box: PresentedGlassBox) -> IntentScore:
        facts = self._tools.get(action.tool_name, GateToolFacts(name=action.tool_name))
        findings: list[str] = []
        scores = {
            "intent": self._score_intent(intent.intent, action, findings),
            "necessity": self._score_necessity(intent.necessity, facts, findings),
            "harm": self._score_harm(intent.harm, action, findings),
            "data": self._score_data(intent.data, box, findings),
            "alternatives": self._score_alternatives(intent.alternatives, action, findings),
        }
        total = sum(scores.values())
        if 0 in scores.values():
            verdict: Literal["accept", "deeper_review", "reject"] = "reject"
        elif total < 8:
            verdict = "deeper_review"
        else:
            verdict = "accept"
        return IntentScore(per_question=scores, total=total, verdict=verdict, findings=findings)

    def _present(self, text: str, q: str, findings: list[str]) -> bool:
        if text.strip().lower().rstrip(".") in BOILERPLATE:
            findings.append(f"{q}: boilerplate answer rejected")
            return False
        if len(_WORD.findall(text)) < self._min_words:
            findings.append(f"{q}: under {self._min_words} words")
            return False
        return True

    @staticmethod
    def _mentions_target(text: str, action: ProposedAction) -> bool:
        return any(t in text for t in action.target_ids) or action.tool_name in text

    def _score_intent(self, text, action, findings) -> int:
        if not self._present(text, "intent", findings):
            return 0
        if self._mentions_target(text, action):
            return 2
        findings.append("intent: does not name the target or tool")
        return 1

    def _score_necessity(self, text, facts, findings) -> int:
        if not self._present(text, "necessity", findings):
            return 0
        if facts.reversible_alternatives:
            if any(alt in text for alt in facts.reversible_alternatives):
                return 2
            findings.append(f"necessity: a reversible alternative is registered "
                            f"({', '.join(facts.reversible_alternatives)}) but not addressed")
            return 1
        return 2

    # _score_harm and _score_alternatives follow the same shape and implement the
    # rubric rows of Section 13.3.2: harm must name a target and a consequence word;
    # alternatives must name another registered tool.

    def _score_data(self, text, box, findings) -> int:
        if not self._present(text, "data", findings):
            return 0
        cited = set(re.findall(r"ev_[0-9a-f]{8}", text))
        if not cited:
            findings.append("data: cites no evidence id from the glass box")
            return 1
        unknown = cited - set(box.evidence_ids)
        if unknown:
            findings.append(f"data: cites evidence that does not exist: {sorted(unknown)}")
            return 0          # a fabricated citation is worse than none
        return 2


from typing import Callable, Optional, Protocol
from palisade.core.types import ApprovalRecord, BlastRadius, GlassBoxVerdict, PolicyDecision, ProposedAction, Reversibility, RulesOfEngagement

class ApproverRoute(BaseModel):
    approvers: list[str]
    channel: Literal["chatops", "page", "review_queue"]
    sla_seconds: int
    reason: str

class NoApproverError(RuntimeError):
    """No human with authority could be resolved. The gate fails closed."""

class EscalationRouter:
    """Encodes the table in Section 13.3.4. Shown abbreviated; the four branches
    build an ApproverRoute each, in the table's order."""

    def __init__(self, asset_owner: Callable[[str], Optional[str]],
                 on_duty_analysts: Callable[[], list[str]], ir_lead: Callable[[], Optional[str]]) -> None:
        self._asset_owner, self._on_duty, self._ir_lead = asset_owner, on_duty_analysts, ir_lead

    def route(self, action: ProposedAction, roe: RulesOfEngagement,
              intent_score: Optional[IntentScore]) -> ApproverRoute:
        ac = action.action_class
        weak = intent_score is not None and intent_score.verdict != "accept"
        if ac.domain is ActionDomain.OFFENSE:
            route = ApproverRoute(approvers=[roe.owner], channel="page", sla_seconds=900,
                                  reason="offensive plane: engagement owner decides")
        elif ac.reversibility is Reversibility.IRREVERSIBLE or ac.blast_radius is BlastRadius.ENTERPRISE or weak:
            route = ApproverRoute(approvers=list(roe.approvers), channel="page", sla_seconds=900,
                                  reason="irreversible, enterprise-wide, or weak intent: senior on-call")
        elif ac.blast_radius is BlastRadius.GROUP:
            owners = [o for o in (self._asset_owner(t) for t in action.target_ids) if o]
            lead = self._ir_lead()
            route = ApproverRoute(approvers=sorted(set(owners + ([lead] if lead else []))),
                                  channel="chatops", sla_seconds=1800, reason="group: asset owners plus IR lead")
        else:
            route = ApproverRoute(approvers=self._on_duty(), channel="chatops", sla_seconds=600,
                                  reason="single object, reversible: on-duty analyst pool")
        if not route.approvers:
            raise NoApproverError(f"no approver resolves for {action.tool_name} on {action.target_ids}")
        return route

class ApproverResponse(BaseModel):
    approver_id: str
    decision: Literal["approved", "denied", "modified"]
    justification: str
    attested_evidence_ids: list[str] = Field(default_factory=list)
    typed_target: Optional[str] = None
    modified_arguments: Optional[dict] = None

class ApproverChannel(Protocol):
    def ask(self, route: ApproverRoute, box: PresentedGlassBox) -> Optional[ApproverResponse]:
        """Return None on timeout. The gate treats None as a denial."""

class ApprovalGate:
    def __init__(self, presenter: GlassBoxPresenter, scorer: IntentScorer, router: EscalationRouter,
                 channel: ApproverChannel, roe_lookup: Callable[[str], Optional[RulesOfEngagement]],
                 reversal_paths: dict[str, str], min_attested: int = 3) -> None:
        self._presenter, self._scorer, self._router, self._channel = presenter, scorer, router, channel
        self._roe_lookup, self._reversal, self._min_attested = roe_lookup, reversal_paths, min_attested

    def request(self, action: ProposedAction, glass_box: GlassBoxVerdict,
                decision: PolicyDecision) -> ApprovalRecord:
        engagement_id = str(decision.evaluated_inputs.get("engagement_id", ""))
        roe = self._roe_lookup(engagement_id)
        box = self._presenter.present(
            action, decision, glass_box, engagement_id,
            reversal_path=self._reversal.get(action.tool_name, "none registered"),
            kill_scope=f"run:{glass_box.run_id}")
        if roe is None:
            return self._mechanical_denial(box, "no active RoE resolves for this engagement")

        ac = action.action_class
        needs_intent = (ac.reversibility is Reversibility.IRREVERSIBLE
                        or ac.blast_radius is BlastRadius.ENTERPRISE
                        or decision.rule_id == "ceiling.approval_required")
        score: Optional[IntentScore] = None
        if needs_intent:
            if action.intent is None:
                return self._mechanical_denial(box, "five-question intent missing")
            score = self._scorer.score(action.intent, action, box)
            if score.verdict == "reject":
                return self._mechanical_denial(box, "intent rejected: " + "; ".join(score.findings))

        try:
            route = self._router.route(action, roe, score)
        except NoApproverError as exc:
            return self._mechanical_denial(box, str(exc))

        response = self._channel.ask(route, box)
        if response is None:
            return self._mechanical_denial(box, f"no decision within {route.sla_seconds}s")
        if response.approver_id not in route.approvers:
            return self._mechanical_denial(box, f"{response.approver_id} is not a routed approver")
        problem = self._attestation_problem(response, box)
        if problem and response.decision != "denied":
            return self._mechanical_denial(box, problem)

        return ApprovalRecord(
            approver_id=response.approver_id, decision=response.decision,
            justification=response.justification, presented_context_hash=box.hash,
            modified_arguments=response.modified_arguments if response.decision == "modified" else None)

    def _attestation_problem(self, r: ApproverResponse, box: PresentedGlassBox) -> Optional[str]:
        required = min(self._min_attested, len(box.evidence_ids))
        if len(set(r.attested_evidence_ids)) < required:
            return f"attestation incomplete: {len(set(r.attested_evidence_ids))} of {required} evidence items"
        if not set(r.attested_evidence_ids) <= set(box.evidence_ids):
            return "attestation names evidence that was not presented"
        if box.action.action_class.blast_radius is BlastRadius.ENTERPRISE:
            if r.typed_target not in box.action.target_ids:
                return "enterprise blast radius requires the approver to type the target id"
        return None

    @staticmethod
    def _mechanical_denial(box: PresentedGlassBox, reason: str) -> ApprovalRecord:
        return ApprovalRecord(approver_id="system:approval_gate", decision="denied",
                              justification=reason, presented_context_hash=box.hash)
