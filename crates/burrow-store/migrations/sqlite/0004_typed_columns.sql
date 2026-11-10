-- Enum-valued columns hold the proto enum's number instead of its name, and
-- every timestamp is unix milliseconds. SQLite cannot retype a column, so each
-- table is rebuilt.
CREATE TABLE sessions_new (
    id           TEXT PRIMARY KEY,
    sandbox_id   TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms  INTEGER NOT NULL DEFAULT 0,
    started_by   INTEGER NOT NULL,
    ended_by     INTEGER NOT NULL DEFAULT 0
);
INSERT INTO sessions_new (id, sandbox_id, started_at_ms, ended_at_ms, started_by, ended_by)
SELECT id, sandbox_id, started_at * 1000, ended_at * 1000,
       CASE started_by WHEN 'boot' THEN 1 WHEN 'restore' THEN 2 WHEN 'resume' THEN 3 ELSE 0 END,
       CASE ended_by WHEN 'suspended' THEN 1 WHEN 'deleted' THEN 2 WHEN 'failed' THEN 3
                     WHEN 'unknown' THEN 4 WHEN 'stopped' THEN 5 ELSE 0 END
FROM sessions;
DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
CREATE INDEX sessions_by_sandbox ON sessions(sandbox_id, started_at_ms DESC);

CREATE TABLE events_new (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id        TEXT NOT NULL DEFAULT '',
    node_seq       INTEGER NOT NULL DEFAULT 0,
    at             INTEGER NOT NULL,
    sandbox_id     TEXT NOT NULL,
    kind           INTEGER NOT NULL,
    state          INTEGER NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    template       TEXT NOT NULL DEFAULT '',
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    cpu_usage_usec INTEGER NOT NULL DEFAULT 0,
    rx_bytes       INTEGER NOT NULL DEFAULT 0,
    tx_bytes       INTEGER NOT NULL DEFAULT 0,
    vcpus          INTEGER NOT NULL DEFAULT 0,
    mem_mib        INTEGER NOT NULL DEFAULT 0
);
INSERT INTO events_new
SELECT seq, node_id, node_seq, at, sandbox_id,
       CASE kind WHEN 'created' THEN 1 WHEN 'started' THEN 2 WHEN 'agent_ready' THEN 3
                 WHEN 'stopped' THEN 4 WHEN 'destroyed' THEN 5 WHEN 'snapshot_created' THEN 6
                 WHEN 'recovered' THEN 7 ELSE 0 END,
       state, detail, template, metadata_json, cpu_usage_usec, rx_bytes, tx_bytes, vcpus, mem_mib
FROM events;
DROP TABLE events;
ALTER TABLE events_new RENAME TO events;
CREATE UNIQUE INDEX events_by_origin ON events(node_id, node_seq) WHERE node_id != '';
CREATE INDEX events_by_sandbox ON events(sandbox_id, seq);
CREATE INDEX events_by_time ON events(at);

CREATE TABLE audit_egress_new (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms          INTEGER NOT NULL,
    sandbox_id     TEXT NOT NULL,
    source_ip      TEXT NOT NULL,
    destination    TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    allowed        INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    bytes_sent     INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL
);
INSERT INTO audit_egress_new
SELECT id, CAST(strftime('%s', at) AS INTEGER) * 1000, sandbox_id, source_ip, destination, host,
       port, allowed, reason, bytes_sent, bytes_received
FROM audit_egress;
DROP TABLE audit_egress;
ALTER TABLE audit_egress_new RENAME TO audit_egress;
CREATE INDEX audit_by_sandbox ON audit_egress(sandbox_id, id DESC);
CREATE INDEX audit_by_time ON audit_egress(at_ms);

CREATE TABLE usage_intervals_new (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_id     TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    template       TEXT NOT NULL,
    metadata_json  TEXT NOT NULL,
    state          INTEGER NOT NULL,
    vcpus          INTEGER NOT NULL,
    mem_mib        INTEGER NOT NULL,
    started_at     INTEGER NOT NULL,
    ended_at       INTEGER NOT NULL,
    cpu_usage_usec INTEGER NOT NULL,
    rx_bytes       INTEGER NOT NULL,
    tx_bytes       INTEGER NOT NULL,
    closed_by      TEXT NOT NULL
);
INSERT INTO usage_intervals_new
SELECT id, sandbox_id, node_id, template, metadata_json,
       CASE state WHEN 'running' THEN 1 WHEN 'suspended' THEN 2 WHEN 'stopped' THEN 3 ELSE 0 END,
       vcpus, mem_mib, started_at, ended_at, cpu_usage_usec, rx_bytes, tx_bytes, closed_by
FROM usage_intervals;
DROP TABLE usage_intervals;
ALTER TABLE usage_intervals_new RENAME TO usage_intervals;
CREATE INDEX usage_by_start ON usage_intervals(started_at);
CREATE INDEX usage_by_sandbox ON usage_intervals(sandbox_id, id);

CREATE TABLE usage_open_new (
    sandbox_id          TEXT PRIMARY KEY,
    node_id             TEXT NOT NULL,
    template            TEXT NOT NULL,
    metadata_json       TEXT NOT NULL,
    state               INTEGER NOT NULL,
    vcpus               INTEGER NOT NULL,
    mem_mib             INTEGER NOT NULL,
    started_at          INTEGER NOT NULL,
    cpu_usage_usec      INTEGER NOT NULL,
    rx_bytes            INTEGER NOT NULL,
    tx_bytes            INTEGER NOT NULL,
    seen_at             INTEGER NOT NULL,
    seen_cpu_usage_usec INTEGER NOT NULL,
    seen_rx_bytes       INTEGER NOT NULL,
    seen_tx_bytes       INTEGER NOT NULL
);
INSERT INTO usage_open_new
SELECT sandbox_id, node_id, template, metadata_json,
       CASE state WHEN 'running' THEN 1 WHEN 'suspended' THEN 2 WHEN 'stopped' THEN 3 ELSE 0 END,
       vcpus, mem_mib, started_at, cpu_usage_usec, rx_bytes, tx_bytes, seen_at,
       seen_cpu_usage_usec, seen_rx_bytes, seen_tx_bytes
FROM usage_open;
DROP TABLE usage_open;
ALTER TABLE usage_open_new RENAME TO usage_open;
CREATE INDEX usage_open_by_node ON usage_open(node_id);
