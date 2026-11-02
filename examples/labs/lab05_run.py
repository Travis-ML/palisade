state = loop.run("Contain host-4471", RunBudget(max_steps=50, max_tool_calls=100))
print(state.halt_reason, state.step, state.tool_calls)
for rec in ledger.records:
    tool = rec.proposed_action.tool_name if rec.proposed_action else "-"
    done = rec.execution.status if rec.execution else "-"
    print(f"{rec.step:02d} {tool:<18} {done:<6} {rec.reasoning_summary[:40]}  prev={rec.prev_hash[:8]} hash={rec.record_hash[:8]}")
