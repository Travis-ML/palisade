-- Hunt outcomes and cycle time per month: true positives, detections shipped, documented negatives.
SELECT date_trunc('month', started_at)::date AS month,
       COUNT(*) FILTER (WHERE outcome = 'true_positive')      AS true_positives,
       COUNT(*) FILTER (WHERE outcome = 'detection_shipped')  AS detections_shipped,
       COUNT(*) FILTER (WHERE outcome = 'documented_negative') AS negatives,
       ROUND(AVG(EXTRACT(EPOCH FROM concluded_at - started_at)) / 3600, 1) AS cycle_hours,
       ROUND(AVG(cost_units), 1) AS avg_cost_units,
       ROUND(100.0 * SUM(denied_queries) / NULLIF(SUM(queries + denied_queries), 0), 1) AS pct_denied
FROM hunts GROUP BY month ORDER BY month;
