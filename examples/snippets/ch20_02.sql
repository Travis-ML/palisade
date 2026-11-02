-- Agreement and override by detection family, trailing seven days.
SELECT v.detection_family, COUNT(*) AS reviewed,
       AVG(CASE WHEN s.decision = 'approved' THEN 1.0 ELSE 0.0 END)               AS agreement_rate,
       AVG(CASE WHEN s.decision IN ('denied', 'modified') THEN 1.0 ELSE 0.0 END) AS override_rate
FROM verdicts v JOIN reviewer_stamps s ON s.verdict_id = v.verdict_id
WHERE s.decided_at >= now() - interval '7 days'
GROUP BY v.detection_family ORDER BY override_rate DESC;
