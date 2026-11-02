-- Mean time to remediate by severity band, last 90 days, merged fixes only.
SELECT severity, COUNT(*) AS fixed,
       ROUND(AVG(EXTRACT(EPOCH FROM merged_at - first_seen)) / 86400, 1) AS mttr_days,
       ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP
             (ORDER BY EXTRACT(EPOCH FROM merged_at - first_seen)) / 86400, 1) AS p50_days
FROM vuln_findings
WHERE merged_at >= now() - interval '90 days'
GROUP BY severity ORDER BY severity;
