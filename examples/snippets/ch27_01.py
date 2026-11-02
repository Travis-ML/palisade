scopes = [f"capability:{self.capability}", f"tenant:{state.tenant_id}", "global"]   # in GovernedLoop.step (Chapter 5)
try:
    self.governor.check_model_call(state, budget, scopes, decision.model_id, est_in=ctx.token_estimate, est_out=1024)
except BudgetExceeded as exc:
    return self.halt(state, reason=str(exc).split(":")[0])     # "budget.capability:phishing"
turn = decision.client.complete(ctx.messages, tools=self.tools)
self.governor.settle(state, scopes, self.governor.prices.model_cost(decision.model_id, turn.usage.input_tokens, turn.usage.output_tokens))
