from datetime import timedelta
from pathlib import Path
from palisade.core.types import ActionClass, ActionDomain, ApprovalRecord, AutonomyTier, BlastRadius, Plane, Reversibility, utcnow
from palisade.deploy.ladder import EvidenceBundle, PromotionRequest, TierRegistry, build_checklist, ceiling_for
from palisade.deploy.shadow import ShadowSink, ShadowComparer

class StubLedger:
    def append(self, rec): return rec.seal("").record_hash
class StubKill:
    def trip(self, scope, by, reason): print(f"kill switch: scope={scope} by={by}: {reason}")

verdict_class = ActionClass(domain=ActionDomain.ENRICH, reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.SINGLE)
reg = TierRegistry(StubLedger(), StubKill(), Path("ladder-fallback.jsonl"))


import random
random.seed(7)
sink = ShadowSink()
from palisade.core.types import GlassBoxVerdict, Hypothesis
for i in range(240):
    fam = "oauth_grant" if i < 30 else random.choice(["lateral_rdp", "mail_rule"])
    truth = random.choice(["benign", "malicious"])
    agree_p = 0.80 if fam == "oauth_grant" else 0.95
    agent = truth if random.random() < agree_p else ("benign" if truth == "malicious" else "malicious")
    v = GlassBoxVerdict(run_id=f"run_{i}", raw_input={"id": i}, raw_input_hash="x", query_log=[],
                        hypotheses=[Hypothesis(label="benign", statement="s", weight=0.5)], chosen=agent,
                        confidence=0.8, evidence_weighting="w")
    sink.capture(f"alert-{i}", "triage", fam, v)
    sink.human(f"alert-{i}", truth, "u.ramirez")
cmp = ShadowComparer(sink)
for fam, s in cmp.by_family("triage").items():
    print(f"{fam:<12} n={s.n:<4} rate={s.rate:.3f} ci=({s.ci_low:.3f}, {s.ci_high:.3f})")


overall = cmp.agreement("triage")
worst = min(cmp.by_family("triage").items(), key=lambda kv: kv[1].rate)
ev = EvidenceBundle(window_start=utcnow() - timedelta(weeks=5), window_end=utcnow(), sample_size=overall.n,
                    agreement_rate=overall.rate, agreement_ci_low=overall.ci_low, worst_family=worst[0],
                    worst_family_agreement=worst[1].rate, eval_report_id="eval_2026w40", eval_passed=True,
                    adversarial_passed=True, manifest_id="mft_abc", blast_radius_analysis="docs/triage-blast.md")
req = PromotionRequest(capability="triage", plane=Plane.DEFENSIVE, action_class=verdict_class,
                       from_tier=AutonomyTier.SHADOW, to_tier=AutonomyTier.SUGGEST, requested_by="u.ramirez", evidence=ev)
req.checklist = build_checklist(req.to_tier, ev)
for item in req.checklist:
    print(f"[{'PASS' if item.passed else 'FAIL'}] {item.item_id}: {item.measured}")
approval = ApprovalRecord(approver_id="gov.decider", decision="approved", justification="", presented_context_hash="h")
try:
    reg.promote(req, approval)
except ValueError as e:
    print("refused:", e)


req.justification = "oauth_grant family held at SUGGEST pending 170 more samples; tracked in PRM-14"
print("promoted:", reg.promote(req, approval)[:12], "->", reg.effective("triage", verdict_class).name)
bad = ActionClass(domain=ActionDomain.PRODUCTION_CONTROL, reversibility=Reversibility.IRREVERSIBLE, blast_radius=BlastRadius.SINGLE)
print("ceiling for irreversible:", ceiling_for(bad).name)
reg.drop_to_shadow("all", "u.ramirez", "lab drill")
print("after drop:", reg.effective("triage", verdict_class).name)
