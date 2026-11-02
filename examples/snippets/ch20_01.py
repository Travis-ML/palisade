from palisade.ledger.ledger import Ledger
from palisade.memory import MemoryStore
from palisade.labs.common import lab_kms        # a process-local LocalKms (Appendix I.8)

ledger = Ledger.open("/var/lib/palisade/ledger")
assert ledger.verify_chain()
records = ledger.replay("run_...")                 # the run_id from step 2
for r in records:
    print(r.step, r.proposed_action.tool_name if r.proposed_action else "model/note", r.record_hash[:12])

# Chapter 9's store: reads are attributed to a run and decrypted under the tenant's key.
memory = MemoryStore(kms=lab_kms(), writers={"spiffe://palisade.example/agent/triage"}, sink=ledger)
version = memory.read("tenant-acme", "verdict:vrd_...", run_id="run_lab20_replay")   # the verdict_id from step 2
verdict = version.value
