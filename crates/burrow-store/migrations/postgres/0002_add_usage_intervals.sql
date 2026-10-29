-- The usage ledger. Rows are appended as the event log is consumed and never
-- updated; usage_open holds the one interval per sandbox still running up,
-- and usage_cursors how far each node's events have been consumed.
CREATE TABLE usage_intervals (
    id             BIGSERIAL PRIMARY KEY,
    sandbox_id     TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    template       TEXT NOT NULL,
    metadata_json  TEXT NOT NULL,
    state          TEXT NOT NULL,
    vcpus          BIGINT NOT NULL,
    mem_mib        BIGINT NOT NULL,
    started_at     BIGINT NOT NULL,
    ended_at       BIGINT NOT NULL,
    cpu_usage_usec BIGINT NOT NULL,
    rx_bytes       BIGINT NOT NULL,
    tx_bytes       BIGINT NOT NULL,
    closed_by      TEXT NOT NULL
);
CREATE INDEX usage_by_start ON usage_intervals(started_at);
CREATE INDEX usage_by_sandbox ON usage_intervals(sandbox_id, id);
CREATE TABLE usage_open (
    sandbox_id          TEXT PRIMARY KEY,
    node_id             TEXT NOT NULL,
    template            TEXT NOT NULL,
    metadata_json       TEXT NOT NULL,
    state               TEXT NOT NULL,
    vcpus               BIGINT NOT NULL,
    mem_mib             BIGINT NOT NULL,
    started_at          BIGINT NOT NULL,
    cpu_usage_usec      BIGINT NOT NULL,
    rx_bytes            BIGINT NOT NULL,
    tx_bytes            BIGINT NOT NULL,
    seen_at             BIGINT NOT NULL,
    seen_cpu_usage_usec BIGINT NOT NULL,
    seen_rx_bytes       BIGINT NOT NULL,
    seen_tx_bytes       BIGINT NOT NULL
);
CREATE INDEX usage_open_by_node ON usage_open(node_id);
CREATE TABLE usage_cursors (
    node_id  TEXT PRIMARY KEY,
    node_seq BIGINT NOT NULL
);
