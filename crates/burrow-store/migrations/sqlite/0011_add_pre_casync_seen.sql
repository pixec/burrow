-- When the orchestrator last heard from a node on a build that keeps chunks
-- in the format before casync. Nodes delete that format's objects only once
-- none has been heard from for a day, and node write-offs and address pool
-- changes leave this alone. Seeded with the upgrade, since any node of an
-- existing fleet may be on such a build.
CREATE TABLE pre_casync_seen (
    id    INTEGER PRIMARY KEY,
    at_ms INTEGER NOT NULL
);
INSERT INTO pre_casync_seen (id, at_ms) VALUES (1, CAST(strftime('%s', 'now') AS INTEGER) * 1000);
