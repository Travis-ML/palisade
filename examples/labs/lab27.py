from datetime import timedelta
from palisade.core.types import ActionClass, ActionDomain, BlastRadius, Plane, ProposedAction, Reversibility, RunBudget, RunState
from palisade.finops.governor import BudgetExceeded, BudgetScope, CostGovernor, PriceTable

prices = PriceTable(per_million_input={"m": 3.0}, per_million_output={"m": 15.0},
                    tool_unit_usd={"ti_lookup_indicator": 0.02, "sandbox_detonate": 0.40})
gov = CostGovernor(prices, [BudgetScope(scope_id="capability:phishing", limit_usd=40.0, window=timedelta(days=1))],
                   velocity_limit_usd_per_min=1000.0)      # breaker effectively off for steps 2 and 3; see "what to notice"
enrich = ActionClass(domain=ActionDomain.ENRICH, reversibility=Reversibility.REVERSIBLE, blast_radius=BlastRadius.SINGLE)
urls = [f"https://{i}.example.test/x" for i in range(3000)]


def run(label, budget, dedupe):
    state = RunState(agent_id="spiffe://palisade.example/agent/phishing", plane=Plane.DEFENSIVE, engagement_id=None, goal="analyze report")
    scopes = ["capability:phishing"]
    seen, calls, halted = set(), {}, None
    for u in urls:
        key = "campaign" if dedupe else u              # the gateway's dedupe collapses a campaign to one key
        if key in seen:
            continue
        seen.add(key)
        for tool in ("ti_lookup_indicator", "sandbox_detonate"):
            limit = budget.per_tool_limits.get(tool)
            if state.tool_calls >= budget.max_tool_calls or (limit is not None and calls.get(tool, 0) >= limit):
                halted = f"run budget ({tool})"
                break
            action = ProposedAction(tool_name=tool, arguments={"url": u}, action_class=enrich)
            try:
                est = gov.check_tool_call(state, budget, scopes, action)
            except BudgetExceeded as exc:
                halted = str(exc)
                break
            gov.settle(state, scopes, est)
            state.tool_calls += 1
            calls[tool] = calls.get(tool, 0) + 1
        if halted:
            break
    print(f"{label:<34} tool_calls={state.tool_calls:<5} cost=${state.cost_usd:7.2f} halted={halted}")

run("run budget only", RunBudget(max_tool_calls=100, max_cost_usd=50.0), dedupe=False)


from palisade.core.types import utcnow
gov._spend.clear()
run("per-tool limits + dedupe", RunBudget(max_tool_calls=100, max_cost_usd=50.0,
                                           per_tool_limits={"ti_lookup_indicator": 50, "sandbox_detonate": 10}), dedupe=True)
gov._spend["capability:phishing"] = [(utcnow(), 39.99)]
run("capability cap exhausted", RunBudget(max_tool_calls=100, max_cost_usd=50.0), dedupe=False)
