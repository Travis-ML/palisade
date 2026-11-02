-- q_executed_without_policy: Control A2. Expected result: zero rows.
SELECT record_id, timestamp, agent_id, proposed_action->>'tool_name' AS tool
FROM decision_records
WHERE execution IS NOT NULL
  AND policy_decision IS NULL
  AND timestamp >= :period_start AND timestamp < :period_end;

-- q_executed_without_roe: Control A3. Expected result: zero rows.
SELECT record_id, timestamp, agent_id, proposed_action->>'tool_name' AS tool
FROM decision_records
WHERE execution IS NOT NULL
  AND (execution->>'status') = 'ok'
  AND (proposed_action->'action_class'->>'domain') IN ('production_control', 'offense')
  AND engagement_id IS NULL
  AND timestamp >= :period_start AND timestamp < :period_end;

-- q_escalated_executed_without_approval: Control A7 / A2. Expected result: zero rows.
SELECT record_id, timestamp, agent_id, proposed_action->>'tool_name' AS tool,
       policy_decision->>'rule_id' AS rule_id
FROM decision_records
WHERE execution IS NOT NULL
  AND (execution->>'status') = 'ok'
  AND (policy_decision->>'verdict') = 'escalate'
  AND (approval IS NULL OR (approval->>'decision') NOT IN ('approved', 'modified'))
  AND timestamp >= :period_start AND timestamp < :period_end;

-- q_irreversible_approvals: Control A7. The positive evidence an auditor samples from.
SELECT record_id, timestamp, agent_id, engagement_id,
       proposed_action->>'tool_name'              AS tool,
       proposed_action->'target_ids'              AS targets,
       policy_decision->>'rule_id'                AS rule_id,
       approval->>'approver_id'                   AS approver,
       approval->>'decision'                      AS approver_decision,
       approval->>'justification'                 AS justification,
       approval->>'presented_context_hash'        AS approver_saw,
       execution->>'status'                       AS status
FROM decision_records
WHERE (proposed_action->'action_class'->>'reversibility') = 'irreversible'
  AND execution IS NOT NULL
  AND timestamp >= :period_start AND timestamp < :period_end
ORDER BY timestamp;

-- q_kill_events: Control A14.
SELECT record_id, timestamp, run_id, agent_id, plane, reasoning_summary
FROM decision_records
WHERE human_intervention = 'kill'
  AND timestamp >= :period_start AND timestamp < :period_end
ORDER BY timestamp;

-- q_engine_unavailable_halts: Control A13. Pairs each halt with any later execution in the same run.
SELECT h.run_id, h.timestamp AS halted_at,
       COUNT(e.record_id) AS executions_after_halt      -- expected 0 for every run
FROM decision_records h
LEFT JOIN decision_records e
       ON e.run_id = h.run_id AND e.timestamp > h.timestamp AND e.execution IS NOT NULL
WHERE (h.policy_decision->>'rule_id') = 'engine.unavailable'
  AND h.timestamp >= :period_start AND h.timestamp < :period_end
GROUP BY h.run_id, h.timestamp
HAVING COUNT(e.record_id) > 0;                         -- so this query itself returns zero rows
