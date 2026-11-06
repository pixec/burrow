-- Who may use a secret: empty for everyone, as before scoping existed, or a
-- JSON object naming sandboxes and tags. Bound into the sealed value's
-- context, so a row whose scope is rewritten no longer unseals.
ALTER TABLE secrets ADD COLUMN scope TEXT NOT NULL DEFAULT '';
