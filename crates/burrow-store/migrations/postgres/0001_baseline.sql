-- The schema as of 2026-10-27, when migrations replaced the schema the
-- store used to apply on every start. A database from before then is not
-- adopted: start it fresh.

CREATE TABLE replicas (
    id           TEXT PRIMARY KEY,
    address      TEXT NOT NULL,
    last_seen_ms BIGINT NOT NULL
);
CREATE TABLE nodes (
    id                TEXT PRIMARY KEY,
    idx               BIGINT NOT NULL UNIQUE,
    info              BYTEA NOT NULL,
    status            BYTEA NOT NULL,
    wg_key            TEXT NOT NULL DEFAULT '',
    wg_endpoint       TEXT NOT NULL DEFAULT '',
    last_heartbeat_ms BIGINT NOT NULL,
    is_reported       BIGINT NOT NULL DEFAULT 0,
    total_vcpus       BIGINT NOT NULL DEFAULT 0,
    committed_vcpus   BIGINT NOT NULL DEFAULT 0,
    free_mem_mib      BIGINT NOT NULL DEFAULT 0,
    reserved_vcpus    BIGINT NOT NULL DEFAULT 0,
    reserved_mem_mib  BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE claims (
    key          TEXT PRIMARY KEY,
    sandbox_id   TEXT NOT NULL,
    at           BIGINT NOT NULL
);
CREATE INDEX claims_by_sandbox ON claims(sandbox_id);
CREATE TABLE sandboxes (
    id           TEXT PRIMARY KEY,
    template     TEXT NOT NULL,
    record       BYTEA NOT NULL,
    state        BIGINT NOT NULL,
    lease_block  BIGINT NOT NULL,
    tap          TEXT NOT NULL,
    ports_json   TEXT NOT NULL DEFAULT '[]',
    suspended_at BIGINT NOT NULL DEFAULT 0,
    share_json   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    sandbox_id   TEXT NOT NULL,
    started_at   BIGINT NOT NULL,
    ended_at     BIGINT NOT NULL DEFAULT 0,
    started_by   TEXT NOT NULL,
    ended_by     TEXT NOT NULL DEFAULT '',
    seq          BIGSERIAL
);
CREATE INDEX sessions_by_sandbox ON sessions(sandbox_id, started_at DESC);
CREATE TABLE placements (
    id           TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    record       BYTEA NOT NULL
);
CREATE INDEX placements_by_node ON placements(node_id);
CREATE TABLE tombstones (
    sandbox_id   TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    at           BIGINT NOT NULL
);
CREATE INDEX tombstones_by_node ON tombstones(node_id);
CREATE TABLE secrets (
    name         TEXT PRIMARY KEY,
    value        TEXT NOT NULL
);
CREATE TABLE events (
    seq            BIGSERIAL PRIMARY KEY,
    node_id        TEXT NOT NULL DEFAULT '',
    node_seq       BIGINT NOT NULL DEFAULT 0,
    at             BIGINT NOT NULL,
    sandbox_id     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    state          BIGINT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    template       TEXT NOT NULL DEFAULT '',
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    cpu_usage_usec BIGINT NOT NULL DEFAULT 0,
    rx_bytes       BIGINT NOT NULL DEFAULT 0,
    tx_bytes       BIGINT NOT NULL DEFAULT 0,
    vcpus          BIGINT NOT NULL DEFAULT 0,
    mem_mib        BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX events_by_origin ON events(node_id, node_seq) WHERE node_id != '';
CREATE INDEX events_by_sandbox ON events(sandbox_id, seq);
CREATE INDEX events_by_time ON events(at);
CREATE TABLE audit_egress (
    id             BIGSERIAL PRIMARY KEY,
    at             TEXT NOT NULL,
    sandbox_id     TEXT NOT NULL,
    source_ip      TEXT NOT NULL,
    destination    TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           BIGINT NOT NULL,
    allowed        BIGINT NOT NULL,
    reason         TEXT NOT NULL,
    bytes_sent     BIGINT NOT NULL,
    bytes_received BIGINT NOT NULL
);
CREATE INDEX audit_by_sandbox ON audit_egress(sandbox_id, id DESC);
CREATE INDEX audit_by_time ON audit_egress(at);
