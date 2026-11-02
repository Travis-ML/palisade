# tests/test_memory.py (shape)
AGENT = "spiffe://palisade.example/agent/triage"

def test_tier_floor(store):
    mv = store.write("tenant-acme", "host/host-4471/last_investigation",
                     {"verdict": "benign", "record": "rec_1a2b"}, AGENT,
                     evidence=["rec_1a2b", "result:9f3e2a1b"],
                     evidence_tiers=[TrustTier.ENTERPRISE, TrustTier.UNTRUSTED])
    assert mv.trust_tier == TrustTier.UNTRUSTED

def test_tampered_row_refuses_read(store, sink):
    store.write("tenant-acme", "host/host-4471/x", {"a": 1}, AGENT, evidence=["rec_1"], evidence_tiers=[TrustTier.VERIFIED])
    row = store._rows[("tenant-acme", "host/host-4471/x")][0]
    row.header["written_by"] = "u.ramirez"          # forge attribution
    with pytest.raises(MemoryIntegrityError):
        store.read("tenant-acme", "host/host-4471/x", run_id="run_t")
    assert any(e["kind"] == "memory.integrity_failure" for e in sink.events)

def test_cross_tenant_row_fails_closed(store):
    store.write("tenant-acme", "user/u.ramirez/baseline", {"geo": ["US", "PT"]}, AGENT, evidence=["rec_2"], evidence_tiers=[TrustTier.VERIFIED])
    row = store._rows.pop(("tenant-acme", "user/u.ramirez/baseline"))[0]
    row.tenant = "tenant-beta"
    store._rows[("tenant-beta", "user/u.ramirez/baseline")] = [row]
    with pytest.raises(MemoryIntegrityError):
        store.read("tenant-beta", "user/u.ramirez/baseline", run_id="run_x")
