SELECT capability_of(agent_id) AS capability,
       proposed_action->'action_class'->>'domain' AS domain,
       date_trunc('week', ts) AS week,
       count(*) FILTER (WHERE approval->>'decision' IN ('denied','modified')
                           OR human_intervention = 'override')::numeric
         / NULLIF(count(*) FILTER (WHERE approval IS NOT NULL
                                       OR (policy_decision->>'verdict' = 'allow'
                                           AND execution IS NOT NULL)), 0) AS override_rate
FROM records
WHERE proposed_action IS NOT NULL
GROUP BY 1, 2, 3;
