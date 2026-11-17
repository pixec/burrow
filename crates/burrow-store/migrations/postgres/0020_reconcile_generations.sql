-- A node runs only what the store lists for it at the generation it lists.
-- Every placement change raises the generation, and a sandbox a node holds
-- with no matching row is destroyed there, so a delete is the row's absence
-- and needs no tombstone. Placements and node records from before this keep
-- generation 0 on both sides and still match.
DROP TABLE tombstones;
ALTER TABLE placements ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
-- When a node was last asked to act on this placement and has not answered
-- yet; 0 once it has. Exempts the row from going missing while the node works.
ALTER TABLE placements ADD COLUMN pending_since_ms BIGINT NOT NULL DEFAULT 0;
-- Consecutive complete listings from its node that left the row out.
ALTER TABLE placements ADD COLUMN missed BIGINT NOT NULL DEFAULT 0;
-- Digest of what the node last reported about the sandbox, so a heartbeat
-- rewrites only what changed.
ALTER TABLE placements ADD COLUMN report_hash BIGINT NOT NULL DEFAULT 0;
-- Usage totals, written apart from the record and its version every so often.
ALTER TABLE placements ADD COLUMN usage_at_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE placements ADD COLUMN cpu_usage_usec BIGINT NOT NULL DEFAULT 0;
ALTER TABLE placements ADD COLUMN rx_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE placements ADD COLUMN tx_bytes BIGINT NOT NULL DEFAULT 0;
-- The last heartbeat applied from the node, which numbers them.
ALTER TABLE nodes ADD COLUMN report_seq BIGINT NOT NULL DEFAULT 0;
-- A node's own copy of each sandbox's generation.
ALTER TABLE sandboxes ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;
-- The row's primary key now claims the id, and a placement's generation
-- decides who places a sandbox no node holds.
DELETE FROM claims WHERE key LIKE 'id:%' OR key LIKE 'adopt:%';
-- When each row was last written, by the database's clock, and the ids of
-- rows deleted, so a replica catching up reads only what changed.
ALTER TABLE placements ADD COLUMN changed_at_ms BIGINT NOT NULL DEFAULT 0;
CREATE INDEX placements_changed_at ON placements (changed_at_ms);
CREATE TABLE placement_deletes (id TEXT NOT NULL, at_ms BIGINT NOT NULL);
CREATE INDEX placement_deletes_at ON placement_deletes (at_ms);
CREATE FUNCTION placement_changed() RETURNS trigger AS $$
BEGIN
    NEW.changed_at_ms := (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;
CREATE TRIGGER placement_changed BEFORE INSERT OR UPDATE ON placements
    FOR EACH ROW EXECUTE FUNCTION placement_changed();
CREATE FUNCTION placement_deleted() RETURNS trigger AS $$
BEGIN
    INSERT INTO placement_deletes (id, at_ms)
        VALUES (OLD.id, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT);
    RETURN OLD;
END
$$ LANGUAGE plpgsql;
CREATE TRIGGER placement_deleted AFTER DELETE ON placements
    FOR EACH ROW EXECUTE FUNCTION placement_deleted();
