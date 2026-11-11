-- Address pools, operator configuration: an encoded burrow.common.v1.IpPool.
CREATE TABLE ip_pools (
    name   TEXT PRIMARY KEY,
    record BYTEA NOT NULL
);

-- One row per address handed out. The primary key is what keeps two replicas
-- from allocating one address twice. `state` is a PublicIpState number; a
-- released address stays quarantined until available_at_ms, then may be
-- taken again.
CREATE TABLE public_ips (
    address         TEXT PRIMARY KEY,
    pool            TEXT NOT NULL,
    owner           TEXT NOT NULL,
    state           BIGINT NOT NULL,
    available_at_ms BIGINT NOT NULL DEFAULT 0,
    record          BYTEA NOT NULL
);
CREATE INDEX public_ips_pool ON public_ips (pool);
