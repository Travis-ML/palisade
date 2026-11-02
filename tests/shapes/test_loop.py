def test_repeated_action_halts_before_third_execution() -> None:
    client = ScriptedClient([[("edr_isolate_host", {"host_id": "host-4471"})]])  # same proposal forever
    loop, gateway, ledger = make_loop(client)
    state = loop.run("Contain host-4471", RunBudget())
    assert state.halt_reason == "anomaly.repeated_action"
    assert gateway.executed == ["edr_isolate_host", "edr_isolate_host"]
    assert ledger.records[-1].reasoning_summary == "halt: anomaly.repeated_action"
