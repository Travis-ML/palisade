-- Which decisions consumed a specific memory version? (ledger schema, Chapter 10)
SELECT d.run_id, d.step, d.record_id, d.proposed_action->>'tool_name' AS tool
FROM decision_records AS d,
     jsonb_array_elements(d.retrieved) AS r
WHERE r->>'source' = 'memory://tenant-acme/host/host-4471/last_investigation@2'
ORDER BY d.timestamp;
