-- Chyren SELIN Series — Myelin Store Schema v1.0
-- Encrypted local SQLite database for ARCHON governance audit log.
-- All personal identity data NEVER leaves this device.

CREATE TABLE IF NOT EXISTS selin_identity (
    id          INTEGER PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    basepoint_seal TEXT NOT NULL,
    seal_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS adccl_runs (
    run_id      TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    prompt_hash TEXT NOT NULL,
    v_score     REAL NOT NULL,
    j_penalty   REAL NOT NULL,
    chi_invariant REAL NOT NULL,
    passed      INTEGER NOT NULL,  -- 0 = false, 1 = true
    rejection_reason TEXT,
    model_endpoint TEXT NOT NULL,
    raw_output_snippet TEXT,
    prev_hash   TEXT,   -- row_hash of the previous row ('' for the first): hash chain
    row_hash    TEXT    -- SHA-256 over prev_hash and this row's fields (work order item 3)
);

CREATE TABLE IF NOT EXISTS preflight_log (
    id          INTEGER PRIMARY KEY,
    checked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    endpoint    TEXT NOT NULL,
    schema_adherence INTEGER NOT NULL,  -- 0/1
    chi_compliance INTEGER NOT NULL,     -- 0/1
    model_name  TEXT,
    latency_ms  INTEGER,
    result      TEXT NOT NULL  -- "PASS" | "FAIL"
);

CREATE INDEX IF NOT EXISTS idx_adccl_runs_created ON adccl_runs(created_at);
CREATE INDEX IF NOT EXISTS idx_adccl_runs_passed ON adccl_runs(passed);
