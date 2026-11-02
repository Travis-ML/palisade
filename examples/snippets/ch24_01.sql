-- Containment integrity for an engagement, over the isolated substrate.
-- All three must read clean, or the capability is halted for review.
SELECT
  SUM(CASE WHEN event_type = 'egress'          THEN 1 ELSE 0 END) AS egress_events,        -- target 0
  SUM(CASE WHEN event_type = 'scope_deviation' THEN 1 ELSE 0 END) AS scope_deviations,     -- target 0
  AVG(CASE WHEN artifact_id IS NOT NULL
           THEN provenance_present::int END)                       AS provenance_coverage   -- target 1.0
FROM decision_records
WHERE engagement_id = 'eng_2026q4_range_07'
  AND plane = 'offensive';
