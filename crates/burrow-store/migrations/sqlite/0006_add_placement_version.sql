-- Bumped by every write of a placement, so a replica writes over the row it
-- read and not over one another replica wrote since.
ALTER TABLE placements ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
