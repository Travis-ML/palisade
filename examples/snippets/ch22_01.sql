-- Share of recipients remediated before click, trailing 30 days.
SELECT COUNT(*) FILTER (WHERE q.executed_at IS NOT NULL AND (c.clicked_at IS NULL OR c.clicked_at > q.executed_at))::numeric
       / COUNT(*) AS remediated_before_click
FROM campaign_recipients r
LEFT JOIN quarantine_executions q ON q.campaign_id = r.campaign_id AND q.mailbox = r.mailbox
LEFT JOIN click_evidence c ON c.campaign_id = r.campaign_id AND c.user_id = r.user_id
WHERE r.delivered_at >= now() - interval '30 days';
