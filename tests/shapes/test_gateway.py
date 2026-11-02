# tests/test_gateway.py (shape, not exhaustive)
@pytest.mark.asyncio
async def test_unknown_tool_is_denied(gateway, agent, state, isolate_proposal):
    d = gateway.authorize(isolate_proposal(tool_name="run_edr_command",
                                           arguments={"cmd": "isolate host-4471"}), agent, state)
    assert d.verdict == "deny" and d.rule_id == "gateway.unknown_tool"

@pytest.mark.asyncio
async def test_execute_requires_matching_authorization(gateway, isolate_proposal, allow_decision):
    rec = await gateway.execute(isolate_proposal(), allow_decision)   # never authorized
    assert rec.status == "halted"

@pytest.mark.asyncio
async def test_engine_down_is_deny(gateway_with_broken_engine, agent, state, isolate_proposal):
    d = gateway_with_broken_engine.authorize(isolate_proposal(), agent, state)
    assert d.verdict == "deny" and d.rule_id == "engine.unavailable"
