-- agreement (shadow / sample review) and override (gated actions), 7-day window, per capability
WITH agree AS (
  SELECT capability, detection_family,
         COUNT(*) AS n,
         AVG(CASE WHEN agent_verdict = human_verdict THEN 1.0 ELSE 0.0 END) AS agreement
  FROM shadow_observations
  WHERE observed_at >= now() - interval '7 days' AND human_verdict IS NOT NULL
  GROUP BY capability, detection_family
),
override AS (
  SELECT capability,
         COUNT(*) FILTER (WHERE approval_decision IN ('denied', 'modified'))::float
           / NULLIF(COUNT(*), 0) AS override_rate,
         COUNT(*) AS gated
  FROM decision_records
  WHERE ts >= now() - interval '7 days' AND verdict = 'escalate' AND approval_decision IS NOT NULL
  GROUP BY capability
)
SELECT a.capability, a.detection_family, a.n, ROUND(a.agreement, 3) AS agreement,
       o.gated, ROUND(o.override_rate, 3) AS override_rate
FROM agree a LEFT JOIN override o USING (capability)
ORDER BY a.agreement ASC;
