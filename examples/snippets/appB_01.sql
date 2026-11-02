-- One row per DecisionRecord; columns match the pydantic fields.
CREATE TABLE records (
  record_id        text PRIMARY KEY,
  run_id           text NOT NULL,
  step             integer NOT NULL,
  ts               timestamptz NOT NULL,      -- DecisionRecord.timestamp
  agent_id         text NOT NULL,
  plane            text NOT NULL,
  engagement_id    text,
  autonomy_tier    integer NOT NULL,
  context_hash     text NOT NULL,
  retrieved        jsonb NOT NULL DEFAULT '[]',
  model_call       jsonb,
  reasoning_summary text,
  proposed_action  jsonb,
  policy_decision  jsonb,
  approval         jsonb,
  execution        jsonb,
  human_intervention text,
  prev_hash        text,
  record_hash      text NOT NULL
);

-- One row per GlassBoxVerdict.
CREATE TABLE verdicts (
  verdict_id        text PRIMARY KEY,
  run_id            text NOT NULL,
  raw_input         jsonb NOT NULL,
  raw_input_hash    text NOT NULL,
  query_log         jsonb NOT NULL,
  hypotheses        jsonb NOT NULL,
  chosen            text NOT NULL,
  confidence        numeric NOT NULL,
  evidence_weighting text,
  recommended_action jsonb,
  reviewer_stamp    jsonb
);
