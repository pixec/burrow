-- Bumped by each replica as it takes the leadership. The leader's writes are
-- conditional on the term it holds, so a replica that lost the leadership
-- without noticing yet cannot act as leader.
CREATE TABLE leader_epoch (
    id    BIGINT PRIMARY KEY,
    epoch BIGINT NOT NULL
);
INSERT INTO leader_epoch (id, epoch) VALUES (1, 0);
