-- False-positive rate of AI-authored detections after 30 days in production, vs precision at merge.
SELECT rule_id, precision_at_merge, fp_rate_30d, alerts_30d
FROM detections
WHERE merged_at <= now() - interval '30 days'
ORDER BY fp_rate_30d DESC;
