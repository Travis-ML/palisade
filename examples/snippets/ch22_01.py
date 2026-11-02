report = gateway.call("sandbox_detonate", {"artifact_ref": "att_...", "artifact_type": "attachment",
                                           "profile": "ubuntu-browser", "timeout_seconds": 60})
for e in report.egress_attempts:
    print(e.destination, e.protocol, e.blocked)
print(report.trust_tier, report.verdict_signal)
