-- what executed without a human, and what was refused, last 24 hours
SELECT capability, action_class_key,
       COUNT(*) FILTER (WHERE verdict = 'allow' AND exec_status = 'ok')  AS autonomous_ok,
       COUNT(*) FILTER (WHERE verdict = 'deny')                           AS denied,
       MODE() WITHIN GROUP (ORDER BY rule_id) FILTER (WHERE verdict = 'deny') AS top_deny_rule
FROM decision_records
WHERE ts >= now() - interval '24 hours' AND tool_name IS NOT NULL
GROUP BY capability, action_class_key
ORDER BY denied DESC, autonomous_ok DESC;
