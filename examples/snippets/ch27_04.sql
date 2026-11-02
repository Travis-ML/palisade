CREATE TABLE cost_events (
  event_id        TEXT PRIMARY KEY,
  ts              TIMESTAMPTZ NOT NULL,
  run_id          TEXT NOT NULL,
  step            INT  NOT NULL,
  record_hash     TEXT NOT NULL,               -- joins to the ledger row that incurred it
  capability      TEXT NOT NULL,
  plane           TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  tenant_id       TEXT,
  engagement_id   TEXT,
  kind            TEXT NOT NULL CHECK (kind IN ('model', 'tool')),
  model_id        TEXT, model_version TEXT, routing_rule TEXT,
  input_tokens    INT,  output_tokens INT,
  tool_name       TEXT, units NUMERIC, unit TEXT,   -- 1 lookup; 3.2 GB scanned; 1 detonation
  cost_usd        NUMERIC(12, 6) NOT NULL,
  cost_center     TEXT                          -- showback or chargeback target
);
CREATE INDEX ON cost_events (capability, ts);
CREATE INDEX ON cost_events (tenant_id, ts);
