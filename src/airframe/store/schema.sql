-- airframe result store
--
-- Deliberately plain sqlite3 + hand-written SQL, no ORM. Two reasons:
--   1. The schema IS the contract between every layer (pytest plugin writes it; ML,
--      triage, dashboard and MCP all read it). Keeping it visible keeps the contract honest.
--   2. An ORM would hide exactly the part worth learning.
--
-- Conventions:
--   * timestamps are TEXT ISO-8601 UTC   (sortable as strings, readable in a shell)
--   * durations / latencies are REAL seconds or milliseconds, unit named in the column
--   * *_json columns hold JSON blobs for genuinely schemaless payloads only

PRAGMA journal_mode = WAL;        -- concurrent readers while pytest writes
PRAGMA foreign_keys = ON;         -- OFF by default in sqlite; must be set per connection
PRAGMA synchronous = NORMAL;

-- ---------------------------------------------------------------- runs

-- One row per `pytest` invocation (or per manual KPI / analysis session).
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    dut_backend   TEXT    NOT NULL,          -- 'sim' | 'macos' | 'null'
    dut_identity  TEXT,                      -- sim seed+scenario, or real SSID/model
    seed          INTEGER,                   -- sim seed; NULL for real hardware
    git_sha       TEXT,
    invocation    TEXT,                      -- argv, for reproducibility
    env_json      TEXT,                      -- interpreter, OS, tool versions
    exit_status   INTEGER,
    notes         TEXT
);

-- ---------------------------------------------------------------- results

-- One row per test *attempt*. A test retried three times produces three rows.
-- This is the single most important design decision in the schema: retries are
-- recorded, never overwritten, because "passed on attempt 3" is a different and
-- far more actionable fact than "passed".
CREATE TABLE IF NOT EXISTS results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    nodeid          TEXT    NOT NULL,        -- pytest nodeid, the stable test identity
    suite           TEXT,                    -- connectivity | interop | performance | ...
    outcome         TEXT    NOT NULL,        -- passed|failed|skipped|xfailed|xpassed|error
    attempt         INTEGER NOT NULL DEFAULT 1,
    total_attempts  INTEGER NOT NULL DEFAULT 1,
    is_flake        INTEGER NOT NULL DEFAULT 0,  -- passed only after >=1 failed attempt
    duration_s      REAL,
    phase           TEXT,                    -- setup | call | teardown (where it died)
    failure_message TEXT,                    -- one-line summary
    failure_repr    TEXT,                    -- full traceback / longrepr
    skip_reason     TEXT,
    markers_json    TEXT,                    -- {"band":"5GHz","security":"wpa3_sae",...}
    params_json     TEXT,                    -- parametrize values
    artifact_dir    TEXT,                    -- where logs/pcaps for this attempt live
    started_at      TEXT,
    UNIQUE (run_id, nodeid, attempt)
);

CREATE INDEX IF NOT EXISTS idx_results_run      ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_nodeid   ON results(nodeid);
CREATE INDEX IF NOT EXISTS idx_results_outcome  ON results(outcome);
CREATE INDEX IF NOT EXISTS idx_results_flake    ON results(is_flake) WHERE is_flake = 1;

-- ---------------------------------------------------------------- KPIs

CREATE TABLE IF NOT EXISTS kpi_samples (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    result_id     INTEGER REFERENCES results(id) ON DELETE SET NULL,
    ts            TEXT    NOT NULL,
    network       TEXT,                      -- SSID or 'sim'
    band          TEXT,                      -- 2.4GHz | 5GHz | 6GHz
    endpoint_name TEXT    NOT NULL,          -- 'jio_dns', 'cloudflare_bom', 'gateway'
    endpoint_host TEXT,
    probe         TEXT    NOT NULL,          -- icmp_rtt|dns|tcp_connect|tls|http_ttfb|throughput|loss|jitter
    value         REAL,                      -- NULL when ok=0
    unit          TEXT    NOT NULL,          -- 'ms' | 'mbps' | 'pct'
    ok            INTEGER NOT NULL DEFAULT 1,
    error         TEXT
);

CREATE INDEX IF NOT EXISTS idx_kpi_lookup ON kpi_samples(network, band, endpoint_name, probe);
CREATE INDEX IF NOT EXISTS idx_kpi_ts     ON kpi_samples(ts);

-- Robust baselines. Median + MAD rather than mean + stddev, because latency
-- distributions are heavy-tailed and a single 2-second stall would move a mean
-- far enough to hide every subsequent regression. See kpi/regression.py.
CREATE TABLE IF NOT EXISTS baselines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_key    TEXT    NOT NULL UNIQUE,    -- 'network|band|endpoint|probe'
    n            INTEGER NOT NULL,
    median       REAL    NOT NULL,
    mad          REAL    NOT NULL,           -- median absolute deviation
    p95          REAL,
    p99          REAL,
    min_value    REAL,
    max_value    REAL,
    unit         TEXT,
    updated_at   TEXT    NOT NULL
);

-- ---------------------------------------------------------------- logs

CREATE TABLE IF NOT EXISTS log_templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    template    TEXT    NOT NULL UNIQUE,     -- 'assoc resp status=<*> bssid=<*>'
    param_count INTEGER NOT NULL DEFAULT 0,
    hit_count   INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT,
    last_seen   TEXT
);

CREATE TABLE IF NOT EXISTS log_lines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    result_id    INTEGER REFERENCES results(id) ON DELETE CASCADE,
    template_id  INTEGER REFERENCES log_templates(id) ON DELETE SET NULL,
    ts           TEXT,
    monotonic_ms INTEGER,                    -- the clock used for correlation
    level        TEXT,                       -- DEBUG|INFO|NOTICE|WARN|ERROR
    component    TEXT,                       -- wifid | supplicant | dhcp | driver
    message      TEXT    NOT NULL,
    params_json  TEXT,                       -- values extracted by the template miner
    raw          TEXT
);

CREATE INDEX IF NOT EXISTS idx_log_result   ON log_lines(result_id);
CREATE INDEX IF NOT EXISTS idx_log_template ON log_lines(template_id);
CREATE INDEX IF NOT EXISTS idx_log_mono     ON log_lines(monotonic_ms);

-- ---------------------------------------------------------------- ML

CREATE TABLE IF NOT EXISTS failure_clusters (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    label             INTEGER NOT NULL,      -- -1 == DBSCAN noise
    size              INTEGER NOT NULL,
    signature         TEXT,                  -- human-readable cluster summary
    exemplar_result_id INTEGER REFERENCES results(id) ON DELETE SET NULL,
    created_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS cluster_members (
    cluster_id INTEGER NOT NULL REFERENCES failure_clusters(id) ON DELETE CASCADE,
    result_id  INTEGER NOT NULL REFERENCES results(id) ON DELETE CASCADE,
    distance   REAL,
    PRIMARY KEY (cluster_id, result_id)
);

-- ---------------------------------------------------------------- triage

CREATE TABLE IF NOT EXISTS triage_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id       INTEGER NOT NULL REFERENCES results(id) ON DELETE CASCADE,
    run_id          INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    provider        TEXT    NOT NULL,        -- groq | mock | anthropic
    model           TEXT,
    root_cause      TEXT,
    confidence      REAL,                    -- 0.0 - 1.0
    suggested_owner TEXT,                    -- wifi_driver|supplicant|dhcp|isp|test_bug|unknown
    evidence_json   TEXT,                    -- list of cited evidence
    bug_report_md   TEXT,
    tool_calls      INTEGER DEFAULT 0,       -- agentic loop iterations
    tokens_in       INTEGER,
    tokens_out      INTEGER,
    latency_s       REAL,
    created_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_triage_result ON triage_reports(result_id);

-- ---------------------------------------------------------------- artifacts

CREATE TABLE IF NOT EXISTS artifacts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    result_id INTEGER REFERENCES results(id) ON DELETE CASCADE,
    kind      TEXT    NOT NULL,              -- log | pcap | json | html | timeline
    path      TEXT    NOT NULL,
    bytes     INTEGER,
    sha256    TEXT,
    created_at TEXT   NOT NULL
);

-- ---------------------------------------------------------------- views

-- Latest attempt per test per run: the "did it end up green" question.
CREATE VIEW IF NOT EXISTS v_final_results AS
SELECT r.*
FROM results r
JOIN (
    SELECT run_id, nodeid, MAX(attempt) AS max_attempt
    FROM results GROUP BY run_id, nodeid
) m ON m.run_id = r.run_id AND m.nodeid = r.nodeid AND m.max_attempt = r.attempt;

-- Flake leaderboard across all history.
CREATE VIEW IF NOT EXISTS v_flake_rate AS
SELECT nodeid,
       COUNT(*)                                             AS attempts,
       SUM(CASE WHEN outcome = 'failed' THEN 1 ELSE 0 END)   AS failures,
       SUM(is_flake)                                         AS flakes,
       ROUND(1.0 * SUM(is_flake) / COUNT(*), 4)              AS flake_rate
FROM results
GROUP BY nodeid
HAVING attempts > 1
ORDER BY flake_rate DESC, attempts DESC;
