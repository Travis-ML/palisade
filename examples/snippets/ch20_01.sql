-- 30-day pre-deployment baseline, one row per day x tenant x detection family x source x severity.
-- Populated from the SIEM, the ticketing system, and the shift roster. Signed when complete.
CREATE TABLE triage_baseline_daily (
    day                      DATE        NOT NULL,
    tenant_id                TEXT        NOT NULL,
    detection_family         TEXT        NOT NULL,
    source                   TEXT        NOT NULL,   -- siem | edr | idp | email | cloud
    severity                 TEXT        NOT NULL,
    alerts_received          INTEGER     NOT NULL,
    alerts_closed            INTEGER     NOT NULL,
    alerts_escalated         INTEGER     NOT NULL,
    closed_true_positive     INTEGER     NOT NULL,
    closed_false_positive    INTEGER     NOT NULL,
    closed_benign_confirmed  INTEGER     NOT NULL,   -- real activity, authorized
    time_to_triage_p50_s     INTEGER,
    time_to_triage_p95_s     INTEGER,
    PRIMARY KEY (day, tenant_id, detection_family, source, severity)
);
