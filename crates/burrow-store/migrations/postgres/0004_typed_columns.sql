-- Enum-valued columns hold the proto enum's number instead of its name, and
-- every timestamp is unix milliseconds.
ALTER TABLE sessions
    ALTER COLUMN started_by TYPE BIGINT USING
        CASE started_by WHEN 'boot' THEN 1 WHEN 'restore' THEN 2 WHEN 'resume' THEN 3 ELSE 0 END,
    ALTER COLUMN ended_by DROP DEFAULT,
    ALTER COLUMN ended_by TYPE BIGINT USING
        CASE ended_by WHEN 'suspended' THEN 1 WHEN 'deleted' THEN 2 WHEN 'failed' THEN 3
                      WHEN 'unknown' THEN 4 WHEN 'stopped' THEN 5 ELSE 0 END,
    ALTER COLUMN ended_by SET DEFAULT 0;
UPDATE sessions SET started_at = started_at * 1000, ended_at = ended_at * 1000;
ALTER TABLE sessions RENAME COLUMN started_at TO started_at_ms;
ALTER TABLE sessions RENAME COLUMN ended_at TO ended_at_ms;

ALTER TABLE events
    ALTER COLUMN kind TYPE BIGINT USING
        CASE kind WHEN 'created' THEN 1 WHEN 'started' THEN 2 WHEN 'agent_ready' THEN 3
                  WHEN 'stopped' THEN 4 WHEN 'destroyed' THEN 5 WHEN 'snapshot_created' THEN 6
                  WHEN 'recovered' THEN 7 ELSE 0 END;

ALTER TABLE audit_egress
    ALTER COLUMN at TYPE BIGINT USING (EXTRACT(EPOCH FROM at::timestamptz) * 1000)::bigint;
ALTER TABLE audit_egress RENAME COLUMN at TO at_ms;

ALTER TABLE usage_intervals
    ALTER COLUMN state TYPE BIGINT USING
        CASE state WHEN 'running' THEN 1 WHEN 'suspended' THEN 2 WHEN 'stopped' THEN 3 ELSE 0 END;
ALTER TABLE usage_open
    ALTER COLUMN state TYPE BIGINT USING
        CASE state WHEN 'running' THEN 1 WHEN 'suspended' THEN 2 WHEN 'stopped' THEN 3 ELSE 0 END;
