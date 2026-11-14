-- The fleet's sandbox address pool, which the orchestrator hands every node
-- at registration. Seeded with the pool every fleet had before it was
-- configurable, so an upgrade changes no address.
CREATE TABLE address_pool (
    id              INTEGER PRIMARY KEY,
    v4              TEXT NOT NULL,
    v6              TEXT NOT NULL,
    blocks_per_node INTEGER NOT NULL
);
INSERT INTO address_pool (id, v4, v6, blocks_per_node) VALUES (1, '10.99.0.0/16', 'fd99:b070::/48', 256);
