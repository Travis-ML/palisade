-- daily cost per capability with cost per verdict (unit economics)
SELECT date_trunc('day', c.ts) AS day, c.capability,
       SUM(c.cost_usd) AS cost_usd,
       COUNT(DISTINCT c.run_id) AS runs,
       ROUND(SUM(c.cost_usd) / NULLIF(COUNT(DISTINCT c.run_id), 0), 4) AS cost_per_run
FROM cost_events c
WHERE c.ts >= now() - interval '30 days'
GROUP BY 1, 2 ORDER BY 1 DESC, cost_usd DESC;

-- monthly chargeback per tenant, split by capability
SELECT date_trunc('month', ts) AS month, tenant_id, capability, SUM(cost_usd) AS cost_usd
FROM cost_events WHERE tenant_id IS NOT NULL
GROUP BY 1, 2, 3 ORDER BY 1 DESC, cost_usd DESC;

-- anomaly: today's spend per capability against the 28-day daily median
WITH daily AS (
  SELECT capability, date_trunc('day', ts) AS day, SUM(cost_usd) AS cost
  FROM cost_events WHERE ts >= now() - interval '29 days' GROUP BY 1, 2
), med AS (
  SELECT capability, percentile_cont(0.5) WITHIN GROUP (ORDER BY cost) AS median_cost
  FROM daily WHERE day < date_trunc('day', now()) GROUP BY capability
)
SELECT d.capability, d.cost AS today, m.median_cost, ROUND(d.cost / NULLIF(m.median_cost, 0), 2) AS ratio
FROM daily d JOIN med m USING (capability)
WHERE d.day = date_trunc('day', now()) AND d.cost > 3 * m.median_cost;
