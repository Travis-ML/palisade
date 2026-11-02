SELECT capability_of(r.agent_id) AS capability,
       date_trunc('week', r.ts) AS week,
       count(*) FILTER (WHERE v.reviewer_stamp->>'decision' = 'approved')::numeric
         / NULLIF(count(*) FILTER (WHERE v.reviewer_stamp IS NOT NULL), 0) AS agreement_rate
FROM verdicts v
JOIN (SELECT run_id, min(agent_id) AS agent_id, max(ts) AS ts
      FROM records GROUP BY run_id) r USING (run_id)
GROUP BY 1, 2 ORDER BY 1, 2;
