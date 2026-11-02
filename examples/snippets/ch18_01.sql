-- Findings per KLOC by principle, trailing 8 weeks vs the prior 8: is the trend down?
WITH w AS (
  SELECT principle_id,
         COUNT(*) FILTER (WHERE raised_at >= now() - interval '8 weeks')           AS recent,
         COUNT(*) FILTER (WHERE raised_at <  now() - interval '8 weeks'
                            AND raised_at >= now() - interval '16 weeks')         AS prior,
         AVG(kloc_at_raise)                                                       AS kloc
  FROM review_findings GROUP BY principle_id)
SELECT principle_id, ROUND(recent / NULLIF(kloc, 0), 2) AS recent_per_kloc,
       ROUND(prior / NULLIF(kloc, 0), 2) AS prior_per_kloc
FROM w ORDER BY recent_per_kloc DESC;
