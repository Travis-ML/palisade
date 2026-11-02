from palisade.core.types import AgentIdentity, AutonomyTier, DecisionRecord, RunState

def governed_step(state: RunState, agent: AgentIdentity, tier: AutonomyTier, tools: list[dict],
                  ctx, model, gateway, gate, broker, ledger) -> RunState:
    assembled = ctx.assemble(state, retrieved=[])                       # 1. assemble context, hash it
    turn = model.complete(assembled.messages, tools)                   # 2. model call
    record = DecisionRecord(run_id=state.run_id, step=state.step, agent_id=agent.agent_id,
                            plane=agent.plane, engagement_id=state.engagement_id, autonomy_tier=tier,
                            context_hash=assembled.hash, reasoning_summary=turn.text[:2000])
    if turn.proposed_actions:                                           # the model proposes...
        action = turn.proposed_actions[0]
        decision = gateway.authorize(action, agent, state)             # 3. ...the harness disposes
        approval = gate.request(action, turn.text, decision) if decision.verdict == "escalate" else None
        record.proposed_action, record.policy_decision, record.approval = action, decision, approval
        allowed = decision.verdict == "allow" or (approval is not None and approval.decision == "approved")
        if allowed:
            broker.issue(agent, action, action.target_ids[0], [action.tool_name], ttl=300)
            record.execution = gateway.execute(action, decision, approval)   # 4. execute, scoped credential
    state.last_record_hash = ledger.append(record.seal(state.last_record_hash))  # 5. ledger, before next call
    state.step += 1
    return state
