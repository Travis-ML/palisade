import hashlib, json
assert hashlib.sha256(json.dumps(verdict["raw_input"], sort_keys=True, separators=(",", ":")).encode()).hexdigest() == verdict["raw_input_hash"]
assert {q["result_hash"] for q in verdict["query_log"]} <= {r.execution.result_hash for r in records if r.execution}
