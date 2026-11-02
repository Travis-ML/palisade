from palisade.guardrails.output import OutputGuard, OutputRejected

guard = OutputGuard(registry, plane=Plane.DEFENSIVE)
try:
    action = guard.validate_proposal(model_turn_json)
except OutputRejected as exc:
    ledger.append(step_record(rejected=exc.rule_id, detail=exc.detail))   # denied actions are recorded
    # the loop may give the model one corrective turn, then halts the step
