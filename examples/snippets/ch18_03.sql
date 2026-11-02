-- Recurrence: the same principle raised against the same team again within 60 days
-- of a fixed finding. Is the organization learning, or just fixing?
SELECT a.team, a.principle_id, COUNT(*) AS recurrences
FROM review_findings a JOIN review_findings b
  ON a.team = b.team AND a.principle_id = b.principle_id
 AND b.raised_at BETWEEN a.pr_fixed_at AND a.pr_fixed_at + interval '60 days'
WHERE a.pr_fixed_at IS NOT NULL
GROUP BY a.team, a.principle_id ORDER BY recurrences DESC;
