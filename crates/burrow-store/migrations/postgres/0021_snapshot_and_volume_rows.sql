-- Every snapshot and volume that should exist, written before a node is
-- asked to make one. A node destroys a snapshot or volume no row names, so a
-- delete is the row's absence and succeeds without the node, and what the
-- object store holds is collected once no row references it.
CREATE TABLE snapshots (
    id    TEXT PRIMARY KEY,
    at_ms BIGINT NOT NULL
);
CREATE TABLE volumes (
    name  TEXT PRIMARY KEY,
    at_ms BIGINT NOT NULL
);
-- Temporary, for the release that adds these tables; the next drops both:
-- nodes and the object store held snapshots and volumes before these tables
-- did. Each node records what it holds at its first heartbeat, a node
-- registering anew included, and the leader records what the object store
-- holds before it first collects anything. Until then no snapshot or volume
-- is destroyed for want of a row.
ALTER TABLE nodes ADD COLUMN is_inventory_recorded BIGINT NOT NULL DEFAULT 0;
CREATE TABLE stored_inventory (
    id          BIGINT PRIMARY KEY,
    is_recorded BIGINT NOT NULL
);
INSERT INTO stored_inventory (id, is_recorded) VALUES (1, 0);
