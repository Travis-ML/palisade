-- Fix acceptance (merge) rate and regression rate for AI-proposed fixes.
-- regressed: the fix broke something, or the finding reappeared within 30 days.
SELECT COUNT(*) AS proposed,
       ROUND(100.0 * COUNT(*) FILTER (WHERE merged_at IS NOT NULL) / COUNT(*), 1) AS acceptance_pct,
       ROUND(100.0 * COUNT(*) FILTER (WHERE regressed)
             / NULLIF(COUNT(*) FILTER (WHERE merged_at IS NOT NULL), 0), 2)      AS regression_pct
FROM vuln_findings
WHERE ai_proposed AND first_seen >= now() - interval '180 days';
