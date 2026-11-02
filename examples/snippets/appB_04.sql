SELECT engagement_id,
       count(*) FILTER (WHERE policy_decision->>'rule_id' LIKE 'roe.scope.%'
                          AND policy_decision->>'verdict' = 'deny') AS proposed_deviations,
       count(*) FILTER (WHERE execution->>'status' = 'ok'
                          AND NOT in_roe_scope(engagement_id, proposed_action->'target_ids')) AS executed_deviations
FROM records
WHERE plane = 'offensive'
GROUP BY engagement_id;
