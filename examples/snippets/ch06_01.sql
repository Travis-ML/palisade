SELECT run_id, step, proposed_action->>'tool_name' AS tool,
       policy_decision->>'verdict' AS verdict
FROM decision_records
WHERE model_call->>'model_id' = 'log-classifier'
  AND model_call->>'model_version' = '2026.09.2'
  AND timestamp BETWEEN '2026-09-20' AND '2026-10-04'
ORDER BY timestamp;
