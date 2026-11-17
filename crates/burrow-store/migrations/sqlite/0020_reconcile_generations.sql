-- A node runs only what the store lists for it at the generation it lists.
-- Every placement change raises the generation, and a sandbox a node holds
-- with no matching row is destroyed there, so a delete is the row's absence
-- and needs no tombstone. Placements and node records from before this keep
-- generation 0 on both sides and still match.
DROP TABLE tombstones;
ALTER TABLE placements ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
-- When a node was last asked to act on this placement and has not answered
-- yet; 0 once it has. Exempts the row from going missing while the node works.
ALTER TABLE placements ADD COLUMN pending_since_ms INTEGER NOT NULL DEFAULT 0;
-- Consecutive complete listings from its node that left the row out.
ALTER TABLE placements ADD COLUMN missed INTEGER NOT NULL DEFAULT 0;
-- Digest of what the node last reported about the sandbox, so a heartbeat
-- rewrites only what changed.
ALTER TABLE placements ADD COLUMN report_hash INTEGER NOT NULL DEFAULT 0;
ALTER TABLE placements ADD COLUMN usage_at_ms INTEGER NOT NULL DEFAULT 0;
-- The last heartbeat applied from the node, which numbers them.
ALTER TABLE nodes ADD COLUMN report_seq INTEGER NOT NULL DEFAULT 0;
-- A node's own copy of each sandbox's generation.
ALTER TABLE sandboxes ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
-- The row's primary key now claims the id, and a placement's generation
-- decides who places a sandbox no node holds.
DELETE FROM claims WHERE key LIKE 'id:%' OR key LIKE 'adopt:%';
