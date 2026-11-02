import json
from palisade.evals.poc_scorecard import GlassBoxConformance, Scorecard, CriterionResult

mapping = {"raw_input": "input", "hypotheses": "analysis.branches", "query_log": "analysis.queries",
           "chosen": "verdict.label", "confidence": "verdict.confidence", "evidence_weighting": "analysis.why"}
fed, export = json.load(open("fed.json")), json.load(open("export.json"))
report = GlassBoxConformance(mapping).check(export, fed)
print(f"conformant {report.conformant}/{report.checked}; passed={report.passed}")
for f in report.failures:
    print(" ", f["id"], f["reason"], f["detail"])

card = Scorecard(product="vendor-x", version="poc-2026-10", results=[
    CriterionResult(criterion="depth", score=4, tested_by="u.ramirez", evidence=["poc/depth.log"]),
    CriterionResult(criterion="explainability", score=3, tested_by="u.ramirez", evidence=["conformance.json"]),
    CriterionResult(criterion="safety_rails", score=5, tested_by="u.ramirez", evidence=["rails.log"]),
    CriterionResult(criterion="adversarial_governance", score=0, tested_by="", vendor_stated_only=True),
    CriterionResult(criterion="identity", score=2, tested_by="iam-team", evidence=["identity.kql.out"]),
])
print(f"weighted {card.weighted_total():.1f}/{card.max_total():.0f}; max initial tier = {card.max_initial_tier().name}")
