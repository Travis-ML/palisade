-- halts by reason, last 7 days: the panel that separates "budget too tight" from "agent is looping"
SELECT capability, halt_reason, COUNT(*) AS runs,
       ROUND(AVG(steps), 1) AS avg_steps, ROUND(AVG(cost_usd), 4) AS avg_cost
FROM (
  SELECT run_id, capability, MAX(halt_reason) AS halt_reason, MAX(step) AS steps, SUM(cost_usd) AS cost_usd
  FROM decision_records
  WHERE ts >= now() - interval '7 days'
  GROUP BY run_id, capability
) r
WHERE halt_reason IS NOT NULL
GROUP BY capability, halt_reason
ORDER BY runs DESC;
