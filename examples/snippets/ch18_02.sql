-- Time-to-fix at PR time vs post-merge, and developer acceptance rate, last 90 days.
SELECT ROUND(AVG(EXTRACT(EPOCH FROM pr_fixed_at - raised_at)) / 3600, 1)         AS pr_fix_hours,
       ROUND(AVG(EXTRACT(EPOCH FROM post_merge_fixed_at - raised_at)) / 86400, 1) AS post_merge_fix_days,
       ROUND(100.0 * COUNT(*) FILTER (WHERE disposition IN ('applied', 'modified'))
             / COUNT(*), 1)                                                        AS acceptance_pct
FROM review_findings
WHERE raised_at >= now() - interval '90 days';
