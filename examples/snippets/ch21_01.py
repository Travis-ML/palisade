from palisade.ledger.ledger import Ledger
ledger = Ledger.open("/var/lib/palisade/ledger")
for r in ledger.replay("run_..."):
    tool = r.proposed_action.tool_name if r.proposed_action else "-"
    status = r.execution.status if r.execution else "-"
    print(r.step, r.agent_id.rsplit("/", 1)[-1], tool, r.proposed_action.target_ids if r.proposed_action else "", r.policy_decision.verdict if r.policy_decision else "", status, r.reasoning_summary[:60])
