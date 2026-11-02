-- Self-inflicted outages: incidents whose cause links to a response execution record. Target: zero rows.
SELECT i.incident_id, i.opened_at, r.record_id, r.proposed_action_tool, r.target_ids
FROM incidents i JOIN decision_records r ON r.record_id = i.caused_by_record_id
WHERE r.engagement_id = 'eng_2026q4_soc_response' AND i.opened_at >= now() - interval '90 days';

-- Within-scope vs escalated, trailing 30 days.
SELECT COUNT(*) FILTER (WHERE escalations = 0)::numeric / COUNT(*) AS within_scope_share
FROM (SELECT run_id, COUNT(*) FILTER (WHERE policy_verdict = 'escalate') AS escalations
      FROM decision_records WHERE engagement_id = 'eng_2026q4_soc_response'
        AND timestamp >= now() - interval '30 days' GROUP BY run_id) runs;
