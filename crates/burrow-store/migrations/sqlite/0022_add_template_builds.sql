-- Templates as immutable builds. A build is named by the digest of its
-- manifest, which is only known once it finishes, so a build in progress is
-- keyed by its id and has no digest yet. Tags are an append-only log of
-- assignments; a tag resolves to its newest assignment whose build is ready.
-- untagged_at is when a build lost its last tag assignment, 0 while it has
-- one; retention counts from it. node_builds caches which nodes report
-- holding which build, for placement and display only.
CREATE TABLE templates (
    name       TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    deleted_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE template_builds (
    id            TEXT PRIMARY KEY,
    digest        TEXT UNIQUE,
    template      TEXT NOT NULL,
    status        TEXT NOT NULL,
    manifest      TEXT NOT NULL DEFAULT '',
    parent_digest TEXT NOT NULL DEFAULT '',
    node_id       TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    finished_at   INTEGER NOT NULL DEFAULT 0,
    untagged_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX template_builds_template ON template_builds (template);
CREATE TABLE template_tags (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    template    TEXT NOT NULL,
    tag         TEXT NOT NULL,
    digest      TEXT NOT NULL,
    assigned_at INTEGER NOT NULL
);
CREATE INDEX template_tags_name ON template_tags (template, tag);
CREATE INDEX template_tags_digest ON template_tags (digest);
CREATE TABLE node_builds (
    node_id TEXT NOT NULL,
    digest  TEXT NOT NULL,
    seen_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, digest)
);
CREATE INDEX node_builds_digest ON node_builds (digest);
