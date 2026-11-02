def test_agent_identity_cannot_reach_broker(agent_svid, broker_endpoint):
    with pytest.raises(TlsHandshakeError):
        connect(broker_endpoint, client_cert=agent_svid)   # only the gateway's SVID is accepted

def test_single_use(broker, triage, isolate, allow):
    cred = broker.issue(triage, isolate, "edr:host:host-4471", ["isolate"], timedelta(minutes=5), decision=allow)
    broker.redeem(cred.token, "edr:host:host-4471", "isolate")
    with pytest.raises(BrokerError):
        broker.redeem(cred.token, "edr:host:host-4471", "isolate")

def test_kill_switch_revokes_workers_too(broker, triage, worker, isolate, allow):
    broker.issue(triage, isolate, "edr:host:host-4471", ["isolate"], timedelta(minutes=5), decision=allow)
    broker.issue(worker, isolate, "edr:host:host-4471", ["isolate"], timedelta(minutes=5), decision=allow)
    assert broker.revoke_all(triage.agent_id) == 2 and broker.live_grants() == []
