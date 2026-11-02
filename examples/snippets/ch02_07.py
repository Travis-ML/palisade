from palisade.core.types import RunBudget, RunState


def autonomous(goal: str, state: RunState, budget: RunBudget, step_fn) -> RunState:
    while not state.halted and state.step < budget.max_steps and state.cost_usd < budget.max_cost_usd:
        state = step_fn(state)              # one governed step: assemble, call, authorize, execute, record
    return state
