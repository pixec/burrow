//! Durable state for burrow, on SQLite or PostgreSQL through sqlx.
//!
//! Both tiers use this crate with different tables. A node stores everything
//! needed to reattach to its own sandboxes after a restart: the address lease,
//! the tap name, and the published ports, none of which can be re-derived. It
//! is always SQLite, because a node must keep working with the control plane
//! gone. The orchestrator stores which sandbox lives on which node, its
//! tombstones, sealed secrets and the fleet's event log, on SQLite for a single
//! process or PostgreSQL for several.
//!
//! One [`Store`] serves both backends, and every query is written once:
//! placeholders are `$N`, which both drivers accept, conflicts are `ON
//! CONFLICT`, and integers are 64-bit on both sides. Only the schema and the
//! odd ordering column differ, and those are chosen per backend.

pub use sqlx;

use std::path::Path;
use std::str::FromStr as _;

use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("gave up choosing a {0} under contention")]
    Contended(&'static str),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// A node's record of one sandbox it owns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRow {
    pub id: String,
    pub template: String,
    /// Encoded `burrow.common.v1.Sandbox`. Kept opaque so the store needs no
    /// dependency on the proto crate and cannot drift from its definition.
    pub record: Vec<u8>,
    pub state: i32,
    /// IPAM block index; reserved on startup so a recovered sandbox keeps its
    /// address rather than having it handed to a new one.
    pub lease_block: u32,
    pub tap: String,
    /// Ports published on the node's address.
    pub ports: Vec<PortRow>,
    /// The sandbox's tailcat share, if it has one.
    pub share: Option<ShareRow>,
    /// Unix seconds the sandbox entered SUSPENDED; 0 while it is running.
    /// Persisted because `suspended_ttl_secs` is measured from it, and a node
    /// restart that reset it would let a sandbox outlive its retention forever.
    pub suspended_at: i64,
}

/// One published port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRow {
    pub host_port: u16,
    pub guest_port: u16,
    pub is_udp: bool,
}

/// A sandbox's tailcat share: the keys its address is made of and what the
/// share admits. The keys are what keep the address stable across a daemon
/// restart, which is why they are stored rather than regenerated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRow {
    /// `privkey:<hex>`.
    pub key: String,
    /// `psk:<hex>`.
    pub preshared_key: String,
    /// Guest TCP ports admitted; empty means every port.
    pub ports: Vec<u16>,
    /// `nodekey:<hex>` of each admitted client; empty admits any.
    pub allowed_clients: Vec<String>,
    /// Unix seconds the current keys were issued.
    pub created_at: i64,
    /// Guest UDP ports admitted; `is_all_udp_shared` admits every one.
    pub udp_ports: Vec<u16>,
    pub is_all_udp_shared: bool,
    /// Source each connection from the last pong-verified public IPv4.
    pub is_ip_transparent: bool,
}

/// One VM boot inside a sandbox's life.
///
/// Timestamps are unix seconds; `ended_at` is 0 while the session is open, and
/// stays 0 for one the node died during, because nothing observed when that VM
/// actually stopped, and inventing a time would be worse than saying so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub sandbox_id: String,
    pub started_at: i64,
    pub ended_at: i64,
    pub started_by: String,
    /// Empty while the session is open.
    pub ended_by: String,
}

/// One lifecycle event, as a node recorded it or as the orchestrator copied
/// it from a node.
///
/// `seq` is the position in whichever log holds the row. On a node `node_id`
/// is empty and `node_seq` is 0; on the orchestrator they name the row's
/// origin, and no origin is ever stored twice.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventRow {
    pub seq: u64,
    pub node_id: String,
    pub node_seq: u64,
    pub at_unix_ms: i64,
    pub sandbox_id: String,
    pub kind: String,
    pub state: i32,
    pub detail: String,
    pub template: String,
    pub metadata_json: String,
    pub cpu_usage_usec: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub vcpus: u32,
    pub mem_mib: u32,
}

/// One recorded egress attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRow {
    pub at: String,
    pub sandbox_id: String,
    pub source_ip: String,
    pub destination: String,
    pub host: String,
    pub port: u32,
    pub is_allowed: bool,
    pub reason: String,
    pub bytes_sent: i64,
    pub bytes_received: i64,
}

#[derive(Debug, Clone, Default)]
pub struct EgressFilter {
    pub sandbox_id: Option<String>,
    /// Only records the proxy refused.
    pub is_denied_only: bool,
    /// RFC 3339 lower bound, compared lexically (the format sorts correctly).
    pub since: Option<String>,
    pub limit: u32,
}

/// An orchestrator's record of where a sandbox lives.
#[derive(Debug, Clone)]
pub struct PlacementRow {
    pub id: String,
    pub node_id: String,
    pub record: Vec<u8>,
}

/// A sandbox a caller deleted while its node was unreachable.
///
/// The delete could not be carried out on the node, so the record is dropped
/// here and this is what remembers the intent: if the node ever comes back
/// still holding the sandbox, the orchestrator destroys it there rather than
/// adopting it.
/// A node as the control plane records it, shared by every orchestrator
/// replica.
///
/// `info` and `status` are the encoded protobufs, opaque here for the same
/// reason as a placement's record. The capacity columns are copied out of
/// `status` so a reservation can be checked and taken in one statement, which
/// is what stops two replicas from both fitting a sandbox into the last slot.
#[derive(Debug, Clone, Default)]
pub struct NodeRow {
    pub id: String,
    /// Slice of the sandbox address pool. Unique across the fleet.
    pub index: u32,
    pub info: Vec<u8>,
    pub status: Vec<u8>,
    pub wireguard_public_key: String,
    pub wireguard_endpoint: String,
    pub last_heartbeat_ms: i64,
    pub is_reported: bool,
    pub total_vcpus: u32,
    pub committed_vcpus: u32,
    pub free_mem_mib: u64,
    /// Capacity promised to sandboxes placed since the last heartbeat.
    pub reserved_vcpus: u32,
    pub reserved_mem_mib: u64,
}

#[derive(Debug, Clone)]
pub struct TombstoneRow {
    pub sandbox_id: String,
    pub node_id: String,
    /// Unix seconds the delete was accepted, so tombstones can age out.
    pub at: i64,
}

#[derive(Clone)]
enum Db {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Runs `$body` against whichever pool the store holds. The body is compiled
/// once per backend, so a query written in it has to be valid on both.
macro_rules! on_pool {
    ($store:expr, $pool:ident => $body:expr) => {
        match &$store.db {
            Db::Sqlite($pool) => $body,
            Db::Postgres($pool) => $body,
        }
    };
}

#[derive(Clone)]
pub struct Store {
    db: Db,
}

#[cfg(unix)]
fn precreate(path: &Path, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(mode)
        .open(path);
    restrict(path, mode);
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn precreate(_path: &Path, _mode: u32) {}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) {}

fn split_json<T: serde::de::DeserializeOwned + Default>(text: &str) -> T {
    serde_json::from_str(text).unwrap_or_default()
}

impl Store {
    /// Opens (creating if needed) a SQLite database and applies the schema.
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
            restrict(parent, 0o700);
        }
        // The database holds tenant policies, placements and the egress audit
        // trail, so it is created private rather than inheriting the umask,
        // and created *here*, before sqlite touches it, so it is never briefly
        // world-readable. The directory is locked down too, since sqlite's own
        // `-wal` and `-shm` sidecars are created by the library with default
        // permissions.
        precreate(path, 0o600);
        // WAL keeps readers from blocking the writer; NORMAL is the usual
        // durability/throughput trade for WAL and is right for state that is
        // reconciled against reality on startup anyway.
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        SQLITE_MIGRATIONS.run(&pool).await?;
        Ok(Self {
            db: Db::Sqlite(pool),
        })
    }

    /// A private in-memory SQLite database, for tests. One connection, held
    /// for the store's life, because each in-memory connection is its own
    /// database.
    pub async fn open_in_memory() -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:")?)
            .await?;
        SQLITE_MIGRATIONS.run(&pool).await?;
        Ok(Self {
            db: Db::Sqlite(pool),
        })
    }

    /// Connects to PostgreSQL and applies the schema. `url` is a libpq URL;
    /// `sslmode` in it decides whether TLS is required, preferred (the
    /// default) or off.
    pub async fn connect_postgres(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
        // The migrator holds a Postgres advisory lock while it runs, so
        // replicas starting together apply each migration once.
        POSTGRES_MIGRATIONS.run(&pool).await?;
        Ok(Self {
            db: Db::Postgres(pool),
        })
    }

    pub fn is_postgres(&self) -> bool {
        matches!(self.db, Db::Postgres(_))
    }

    /// The Postgres pool, for the few callers that need a session of their
    /// own, such as holding an advisory lock.
    pub fn postgres_pool(&self) -> Option<&PgPool> {
        match &self.db {
            Db::Postgres(pool) => Some(pool),
            Db::Sqlite(_) => None,
        }
    }

    pub async fn put_sandbox(&self, row: &SandboxRow) -> Result<()> {
        let ports = serde_json::to_string(&row.ports)?;
        let share = match &row.share {
            Some(share) => serde_json::to_string(share)?,
            None => String::new(),
        };
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO sandboxes
                (id, template, record, state, lease_block, tap, ports_json, suspended_at, share_json)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO UPDATE SET
                template=excluded.template, record=excluded.record,
                state=excluded.state, lease_block=excluded.lease_block,
                tap=excluded.tap, ports_json=excluded.ports_json,
                suspended_at=excluded.suspended_at, share_json=excluded.share_json",
        )
        .bind(&row.id)
        .bind(&row.template)
        .bind(&row.record)
        .bind(row.state as i64)
        .bind(row.lease_block as i64)
        .bind(&row.tap)
        .bind(&ports)
        .bind(row.suspended_at)
        .bind(&share)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn set_sandbox_state(&self, id: &str, state: i32, record: &[u8]) -> Result<()> {
        on_pool!(self, pool => sqlx::query("UPDATE sandboxes SET state=$2, record=$3 WHERE id=$1")
            .bind(id)
            .bind(state as i64)
            .bind(record)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    pub async fn delete_sandbox(&self, id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM sandboxes WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxRow>> {
        type Raw = (
            String,
            String,
            Vec<u8>,
            i64,
            i64,
            String,
            String,
            i64,
            String,
        );
        let rows: Vec<Raw> = on_pool!(self, pool => sqlx::query_as(
            "SELECT id, template, record, state, lease_block, tap, ports_json, suspended_at, share_json
             FROM sandboxes ORDER BY id",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, template, record, state, lease_block, tap, ports, suspended_at, share)| {
                    SandboxRow {
                        id,
                        template,
                        record,
                        state: state as i32,
                        lease_block: lease_block as u32,
                        tap,
                        ports: split_json(&ports),
                        share: serde_json::from_str(&share).ok(),
                        suspended_at,
                    }
                },
            )
            .collect())
    }

    pub async fn put_session(&self, row: &SessionRow) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO sessions (id, sandbox_id, started_at, ended_at, started_by, ended_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO UPDATE SET
                ended_at=excluded.ended_at, ended_by=excluded.ended_by",
        )
        .bind(&row.id)
        .bind(&row.sandbox_id)
        .bind(row.started_at)
        .bind(row.ended_at)
        .bind(&row.started_by)
        .bind(&row.ended_by)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Marks one session closed. `ended_at` of 0 records that the session
    /// ended without anything observing when.
    pub async fn end_session(&self, id: &str, ended_at: i64, ended_by: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "UPDATE sessions SET ended_at=$2, ended_by=$3 WHERE id=$1 AND ended_by=''",
        )
        .bind(id)
        .bind(ended_at)
        .bind(ended_by)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Closes every session left open by a previous run of this daemon.
    ///
    /// A VMM does not survive its parent, so a session still open at startup
    /// belongs to a VM that is already gone. `ended_at` stays unset because
    /// nothing recorded when that happened.
    pub async fn close_open_sessions(&self, ended_by: &str) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("UPDATE sessions SET ended_by=$1 WHERE ended_by=''")
            .bind(ended_by)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    /// Insertion order, as a column both backends can sort by: SQLite's
    /// implicit rowid, or the serial Postgres adds in its place.
    fn session_order(&self) -> &'static str {
        if self.is_postgres() { "seq" } else { "rowid" }
    }

    /// A sandbox's sessions, newest first.
    pub async fn list_sessions(&self, sandbox_id: &str) -> Result<Vec<SessionRow>> {
        let sql = format!(
            "SELECT id, sandbox_id, started_at, ended_at, started_by, ended_by
             FROM sessions WHERE sandbox_id=$1 ORDER BY started_at DESC, {} DESC",
            self.session_order()
        );
        let rows: Vec<(String, String, i64, i64, String, String)> =
            on_pool!(self, pool => sqlx::query_as(&sql).bind(sandbox_id).fetch_all(pool).await)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, sandbox_id, started_at, ended_at, started_by, ended_by)| SessionRow {
                    id,
                    sandbox_id,
                    started_at,
                    ended_at,
                    started_by,
                    ended_by,
                },
            )
            .collect())
    }

    /// Keeps only a sandbox's `keep` most recent sessions, returning how many
    /// were evicted.
    ///
    /// Applied as a session is opened, which is the one moment the count grows.
    /// A sandbox that is suspended and resumed every minute would otherwise
    /// grow this table for as long as it lives.
    pub async fn retain_recent_sessions(&self, sandbox_id: &str, keep: usize) -> Result<usize> {
        // Ordered by insertion as well as time, so sessions opened within the
        // same second still evict oldest-first rather than in an arbitrary
        // order.
        let sql = format!(
            "DELETE FROM sessions WHERE sandbox_id=$1 AND id NOT IN (
                SELECT id FROM sessions WHERE sandbox_id=$1
                ORDER BY started_at DESC, {} DESC LIMIT $2
             )",
            self.session_order()
        );
        let done = on_pool!(self, pool => sqlx::query(&sql)
            .bind(sandbox_id)
            .bind(keep as i64)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    /// Drops every session of a sandbox. Its sessions describe that sandbox's
    /// VMs and have no owner once it is gone.
    pub async fn delete_sessions(&self, sandbox_id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM sessions WHERE sandbox_id=$1")
            .bind(sandbox_id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    /// Appends an event, returning its position, or 0 when the same origin
    /// was already recorded, which is how a reconnecting tail stays exact.
    pub async fn append_event(&self, row: &EventRow) -> Result<u64> {
        let seq: Option<(i64,)> = on_pool!(self, pool => sqlx::query_as(
            "INSERT INTO events
               (node_id, node_seq, at, sandbox_id, kind, state, detail, template,
                metadata_json, cpu_usage_usec, rx_bytes, tx_bytes, vcpus, mem_mib)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT DO NOTHING
             RETURNING seq",
        )
        .bind(&row.node_id)
        .bind(row.node_seq as i64)
        .bind(row.at_unix_ms)
        .bind(&row.sandbox_id)
        .bind(&row.kind)
        .bind(row.state as i64)
        .bind(&row.detail)
        .bind(&row.template)
        .bind(&row.metadata_json)
        .bind(row.cpu_usage_usec as i64)
        .bind(row.rx_bytes as i64)
        .bind(row.tx_bytes as i64)
        .bind(row.vcpus as i64)
        .bind(row.mem_mib as i64)
        .fetch_optional(pool)
        .await)?;
        Ok(seq.map_or(0, |(seq,)| seq as u64))
    }

    /// Events after `after_seq`, oldest first, at most `limit`.
    pub async fn list_events(
        &self,
        after_seq: u64,
        sandbox_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<EventRow>> {
        type Raw = (
            i64,
            String,
            i64,
            i64,
            String,
            String,
            i64,
            String,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            i64,
        );
        // The optional filter is spelled into the SQL rather than written as
        // `$2 IS NULL OR ...`: Postgres cannot infer the type of a parameter
        // compared only with NULL.
        let mut sql = String::from(
            "SELECT seq, node_id, node_seq, at, sandbox_id, kind, state, detail, template,
                    metadata_json, cpu_usage_usec, rx_bytes, tx_bytes, vcpus, mem_mib
             FROM events WHERE seq > $1",
        );
        if sandbox_id.is_some() {
            sql.push_str(" AND sandbox_id = $3");
        }
        sql.push_str(" ORDER BY seq LIMIT $2");
        let rows: Vec<Raw> = on_pool!(self, pool => {
            let mut query = sqlx::query_as(&sql).bind(after_seq as i64).bind(limit as i64);
            if let Some(id) = sandbox_id {
                query = query.bind(id);
            }
            query.fetch_all(pool).await
        })?;
        Ok(rows
            .into_iter()
            .map(|r| EventRow {
                seq: r.0 as u64,
                node_id: r.1,
                node_seq: r.2 as u64,
                at_unix_ms: r.3,
                sandbox_id: r.4,
                kind: r.5,
                state: r.6 as i32,
                detail: r.7,
                template: r.8,
                metadata_json: r.9,
                cpu_usage_usec: r.10 as u64,
                rx_bytes: r.11 as u64,
                tx_bytes: r.12 as u64,
                vcpus: r.13 as u32,
                mem_mib: r.14 as u32,
            })
            .collect())
    }

    /// The highest `node_seq` copied from a node, so a tail resumes where the
    /// last one stopped.
    pub async fn last_event_seq_for_node(&self, node_id: &str) -> Result<u64> {
        let last: (Option<i64>,) = on_pool!(self, pool => sqlx::query_as(
            "SELECT MAX(node_seq) FROM events WHERE node_id=$1",
        )
        .bind(node_id)
        .fetch_one(pool)
        .await)?;
        Ok(last.0.unwrap_or(0) as u64)
    }

    /// Drops events recorded before `before_unix_ms`, returning how many.
    pub async fn prune_events(&self, before_unix_ms: i64) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM events WHERE at < $1")
            .bind(before_unix_ms)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    pub async fn insert_egress(&self, row: &EgressRow) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO audit_egress
               (at, sandbox_id, source_ip, destination, host, port, allowed, reason,
                bytes_sent, bytes_received)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&row.at)
        .bind(&row.sandbox_id)
        .bind(&row.source_ip)
        .bind(&row.destination)
        .bind(&row.host)
        .bind(row.port as i64)
        .bind(row.is_allowed as i64)
        .bind(&row.reason)
        .bind(row.bytes_sent)
        .bind(row.bytes_received)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Most recent egress records first, optionally narrowed.
    pub async fn query_egress(&self, filter: &EgressFilter) -> Result<Vec<EgressRow>> {
        // Predicates are fixed strings with bound parameters; the filter never
        // reaches the SQL text.
        let mut sql = String::from(
            "SELECT at, sandbox_id, source_ip, destination, host, port, allowed, reason,
                    bytes_sent, bytes_received
             FROM audit_egress WHERE 1=1",
        );
        let mut next = 2;
        if filter.sandbox_id.is_some() {
            sql.push_str(&format!(" AND sandbox_id = ${next}"));
            next += 1;
        }
        if filter.is_denied_only {
            sql.push_str(" AND allowed = 0");
        }
        if filter.since.is_some() {
            sql.push_str(&format!(" AND at >= ${next}"));
        }
        sql.push_str(" ORDER BY id DESC LIMIT $1");
        let limit = if filter.limit == 0 { 100 } else { filter.limit } as i64;

        type Raw = (
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            i64,
            i64,
        );
        let rows: Vec<Raw> = on_pool!(self, pool => {
            let mut query = sqlx::query_as(&sql).bind(limit);
            if let Some(id) = &filter.sandbox_id {
                query = query.bind(id);
            }
            if let Some(since) = &filter.since {
                query = query.bind(since);
            }
            query.fetch_all(pool).await
        })?;
        Ok(rows
            .into_iter()
            .map(|r| EgressRow {
                at: r.0,
                sandbox_id: r.1,
                source_ip: r.2,
                destination: r.3,
                host: r.4,
                port: r.5 as u32,
                is_allowed: r.6 != 0,
                reason: r.7,
                bytes_sent: r.8,
                bytes_received: r.9,
            })
            .collect())
    }

    /// Drops audit records older than `cutoff`, returning how many.
    ///
    /// Audit volume is unbounded otherwise: a busy sandbox can generate
    /// thousands of records a minute and nothing else would ever remove them.
    pub async fn prune_egress(&self, cutoff: &str) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM audit_egress WHERE at < $1")
            .bind(cutoff)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    pub async fn put_placement(&self, row: &PlacementRow) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO placements (id, node_id, record) VALUES ($1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET node_id=excluded.node_id, record=excluded.record",
        )
        .bind(&row.id)
        .bind(&row.node_id)
        .bind(&row.record)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn get_placement(&self, id: &str) -> Result<Option<PlacementRow>> {
        let row: Option<(String, String, Vec<u8>)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT id, node_id, record FROM placements WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(|(id, node_id, record)| PlacementRow {
            id,
            node_id,
            record,
        }))
    }

    /// The sandbox holding a claim, if anyone does.
    pub async fn claim_holder(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT sandbox_id FROM claims WHERE key=$1",
        )
        .bind(key)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(|(id,)| id))
    }

    pub async fn delete_placement(&self, id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM placements WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    /// Drops every placement on a node. Used when a node re-registers, since
    /// its sandboxes did not survive whatever restarted it.
    pub async fn delete_placements_for_node(&self, node_id: &str) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM placements WHERE node_id=$1")
            .bind(node_id)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    pub async fn list_placements(&self) -> Result<Vec<PlacementRow>> {
        let rows: Vec<(String, String, Vec<u8>)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT id, node_id, record FROM placements ORDER BY id",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(|(id, node_id, record)| PlacementRow {
                id,
                node_id,
                record,
            })
            .collect())
    }

    pub async fn put_tombstone(&self, row: &TombstoneRow) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO tombstones (sandbox_id, node_id, at) VALUES ($1, $2, $3)
             ON CONFLICT (sandbox_id) DO UPDATE SET node_id=excluded.node_id, at=excluded.at",
        )
        .bind(&row.sandbox_id)
        .bind(&row.node_id)
        .bind(row.at)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn delete_tombstone(&self, sandbox_id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM tombstones WHERE sandbox_id=$1")
            .bind(sandbox_id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    pub async fn list_tombstones(&self) -> Result<Vec<TombstoneRow>> {
        let rows: Vec<(String, String, i64)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT sandbox_id, node_id, at FROM tombstones ORDER BY sandbox_id",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(|(sandbox_id, node_id, at)| TombstoneRow {
                sandbox_id,
                node_id,
                at,
            })
            .collect())
    }

    /// Drops tombstones recorded before `cutoff` (unix seconds), returning how
    /// many. A node that never comes back must not accumulate them forever.
    pub async fn prune_tombstones(&self, cutoff: i64) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM tombstones WHERE at < $1")
            .bind(cutoff)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO secrets (name, value) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET value=excluded.value",
        )
        .bind(name)
        .bind(value)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn get_secret(&self, name: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT value FROM secrets WHERE name=$1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(|(value,)| value))
    }

    pub async fn list_secret_names(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT name FROM secrets ORDER BY name",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    pub async fn delete_secret(&self, name: &str) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM secrets WHERE name=$1")
            .bind(name)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }
}

impl Store {
    /// Records a node registering, choosing its address slice, and returns
    /// the slice.
    ///
    /// A returning node keeps its slice; a node that claims one keeps the
    /// claim unless another node holds it; anything else gets the lowest free
    /// one. The slice column is unique, so two replicas registering two nodes
    /// at once cannot hand out one slice twice: the loser's insert fails and
    /// it chooses again. `None` when every slice below `max` is taken.
    pub async fn register_node(
        &self,
        row: &NodeRow,
        claimed: Option<u32>,
        max: u32,
    ) -> Result<Option<u32>> {
        for _ in 0..8 {
            let held: Vec<(String, i64)> = on_pool!(self, pool => sqlx::query_as(
                "SELECT id, idx FROM nodes",
            )
            .fetch_all(pool)
            .await)?;
            let taken: std::collections::HashSet<u32> = held
                .iter()
                .filter(|(id, _)| id != &row.id)
                .map(|(_, idx)| *idx as u32)
                .collect();
            let existing = held
                .iter()
                .find(|(id, _)| id == &row.id)
                .map(|(_, idx)| *idx as u32);
            let index = match (existing, claimed) {
                (_, Some(claimed)) if !taken.contains(&claimed) => claimed,
                (Some(existing), _) if !taken.contains(&existing) => existing,
                _ => match (0..max).find(|candidate| !taken.contains(candidate)) {
                    Some(free) => free,
                    None => return Ok(None),
                },
            };
            let written = on_pool!(self, pool => sqlx::query(
                "INSERT INTO nodes
                   (id, idx, info, status, wg_key, wg_endpoint, last_heartbeat_ms,
                    is_reported, total_vcpus, committed_vcpus, free_mem_mib,
                    reserved_vcpus, reserved_mem_mib)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, 0, 0, 0, 0)
                 ON CONFLICT (id) DO UPDATE SET
                   idx=excluded.idx, info=excluded.info, status=excluded.status,
                   wg_key=excluded.wg_key, wg_endpoint=excluded.wg_endpoint,
                   last_heartbeat_ms=excluded.last_heartbeat_ms, is_reported=0,
                   total_vcpus=excluded.total_vcpus, reserved_vcpus=0, reserved_mem_mib=0",
            )
            .bind(&row.id)
            .bind(index as i64)
            .bind(&row.info)
            .bind(&row.status)
            .bind(&row.wireguard_public_key)
            .bind(&row.wireguard_endpoint)
            .bind(row.last_heartbeat_ms)
            .bind(row.total_vcpus as i64)
            .execute(pool)
            .await
            .map(drop));
            match written {
                Ok(()) => return Ok(Some(index)),
                // Another replica took the slice between the read and the
                // write; read again and choose again.
                Err(sqlx::Error::Database(err)) if err.is_unique_violation() => continue,
                Err(err) => return Err(err.into()),
            }
        }
        Err(StoreError::Contended("address slice"))
    }

    /// Records a heartbeat. Returns false for a node the fleet does not know,
    /// which is the signal for it to register again.
    ///
    /// Clears the node's reservations: the status it carries was sampled
    /// after them, so it already accounts for what they held.
    pub async fn heartbeat_node(&self, row: &NodeRow) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE nodes SET info=$2, status=$3, last_heartbeat_ms=$4, is_reported=1,
                total_vcpus=$5, committed_vcpus=$6, free_mem_mib=$7,
                reserved_vcpus=0, reserved_mem_mib=0
             WHERE id=$1",
        )
        .bind(&row.id)
        .bind(&row.info)
        .bind(&row.status)
        .bind(row.last_heartbeat_ms)
        .bind(row.total_vcpus as i64)
        .bind(row.committed_vcpus as i64)
        .bind(row.free_mem_mib as i64)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeRow>> {
        type Raw = (
            String,
            i64,
            Vec<u8>,
            Vec<u8>,
            String,
            String,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        );
        let rows: Vec<Raw> = on_pool!(self, pool => sqlx::query_as(
            "SELECT id, idx, info, status, wg_key, wg_endpoint, last_heartbeat_ms, is_reported,
                    total_vcpus, committed_vcpus, free_mem_mib, reserved_vcpus, reserved_mem_mib
             FROM nodes ORDER BY id",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(|r| NodeRow {
                id: r.0,
                index: r.1 as u32,
                info: r.2,
                status: r.3,
                wireguard_public_key: r.4,
                wireguard_endpoint: r.5,
                last_heartbeat_ms: r.6,
                is_reported: r.7 != 0,
                total_vcpus: r.8 as u32,
                committed_vcpus: r.9 as u32,
                free_mem_mib: r.10 as u64,
                reserved_vcpus: r.11 as u32,
                reserved_mem_mib: r.12 as u64,
            })
            .collect())
    }

    pub async fn delete_node(&self, id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM nodes WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    /// Takes capacity on a node if it still has it, in one statement.
    ///
    /// The fit check and the charge are the same `UPDATE`, so it is atomic on
    /// both backends: of two replicas racing for the last slot on a node,
    /// exactly one sees a row change. A node that has not reported a cpu
    /// count is trusted on cpu, as placement always has.
    pub async fn reserve_capacity(&self, node_id: &str, vcpus: u32, mem_mib: u64) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE nodes SET reserved_vcpus = reserved_vcpus + $2,
                              reserved_mem_mib = reserved_mem_mib + $3
             WHERE id=$1
               AND (total_vcpus = 0 OR committed_vcpus + reserved_vcpus + $2 <= total_vcpus)
               AND (is_reported = 0 OR free_mem_mib - reserved_mem_mib >= $3)",
        )
        .bind(node_id)
        .bind(vcpus as i64)
        .bind(mem_mib as i64)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }

    /// Gives back capacity a placement took and no longer needs.
    pub async fn release_capacity(&self, node_id: &str, vcpus: u32, mem_mib: u64) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "UPDATE nodes SET
                reserved_vcpus = CASE WHEN reserved_vcpus > $2 THEN reserved_vcpus - $2 ELSE 0 END,
                reserved_mem_mib = CASE WHEN reserved_mem_mib > $3 THEN reserved_mem_mib - $3 ELSE 0 END
             WHERE id=$1",
        )
        .bind(node_id)
        .bind(vcpus as i64)
        .bind(mem_mib as i64)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Claims a unique key, an id or a name, for a sandbox. True when the
    /// claim is this sandbox's, whether just taken or already held by it.
    ///
    /// The key is the primary key, so of two replicas creating one name at
    /// once exactly one insert lands. A claim lives as long as the sandbox and
    /// is released with it.
    pub async fn claim(&self, key: &str, sandbox_id: &str, at: i64) -> Result<bool> {
        let holder: Option<(String,)> = on_pool!(self, pool => sqlx::query_as(
            "INSERT INTO claims (key, sandbox_id, at) VALUES ($1, $2, $3)
             ON CONFLICT (key) DO UPDATE SET at = claims.at
             RETURNING sandbox_id",
        )
        .bind(key)
        .bind(sandbox_id)
        .bind(at)
        .fetch_optional(pool)
        .await)?;
        Ok(holder.is_some_and(|(holder,)| holder == sandbox_id))
    }

    pub async fn release_claim(&self, key: &str, sandbox_id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM claims WHERE key=$1 AND sandbox_id=$2")
            .bind(key)
            .bind(sandbox_id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    /// Releases every claim a sandbox holds, its id and its name.
    pub async fn release_claims(&self, sandbox_id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM claims WHERE sandbox_id=$1")
            .bind(sandbox_id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    /// [`release_claims`](Self::release_claims), unless the sandbox is placed
    /// anywhere but `node_id`. A node that stops reporting a sandbox may only
    /// mean it moved, and a replica that has not caught up with the move
    /// would otherwise free a name that is still in use.
    pub async fn release_claims_unless_moved(&self, sandbox_id: &str, node_id: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "DELETE FROM claims WHERE sandbox_id=$1
               AND NOT EXISTS (SELECT 1 FROM placements WHERE id=$1 AND node_id<>$2)",
        )
            .bind(sandbox_id)
            .bind(node_id)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
    }

    /// Drops claims older than `before` held by sandboxes with no placement:
    /// a create that a replica abandoned by dying half way through.
    pub async fn sweep_claims(&self, before: i64) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query(
            "DELETE FROM claims WHERE at < $1
               AND sandbox_id NOT IN (SELECT id FROM placements)",
        )
        .bind(before)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }
}

impl Store {
    /// Records that an orchestrator replica is alive at `address`.
    pub async fn touch_replica(&self, id: &str, address: &str, now_ms: i64) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO replicas (id, address, last_seen_ms) VALUES ($1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET address=excluded.address, last_seen_ms=excluded.last_seen_ms",
        )
        .bind(id)
        .bind(address)
        .bind(now_ms)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Addresses of replicas seen since `since_ms`.
    pub async fn replica_addresses(&self, since_ms: i64) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT DISTINCT address FROM replicas WHERE last_seen_ms >= $1 ORDER BY address",
        )
        .bind(since_ms)
        .fetch_all(pool)
        .await)?;
        Ok(rows.into_iter().map(|(address,)| address).collect())
    }
}

/// The numbered migrations under `migrations/`, embedded at build time.
///
/// Each backend has its own directory and the two are numbered in step: a
/// change to the schema is one new file in each, never an edit to an applied
/// one. The migrator records what it applied and refuses to start if an
/// applied file has changed since.
static SQLITE_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[cfg(test)]
mod tests {

    /// A database from before migrations is refused, not adopted: the
    /// baseline creates every table outright, so it fails on one that exists.
    #[tokio::test]
    async fn a_database_from_before_migrations_is_refused() {
        let path = std::env::temp_dir().join(format!(
            "burrow-legacy-{}-{}.db",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let pool = SqlitePoolOptions::new()
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(&path)
                        .create_if_missing(true),
                )
                .await
                .unwrap();
            sqlx::query("CREATE TABLE sandboxes (id TEXT PRIMARY KEY)")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }
        assert!(Store::open(&path).await.is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// The two backends are migrated in step: the same numbers, the same
    /// names, so a change cannot reach one and not the other.
    #[test]
    fn both_backends_have_the_same_migrations() {
        let names = |migrator: &sqlx::migrate::Migrator| -> Vec<(i64, String)> {
            migrator
                .iter()
                .map(|m| (m.version, m.description.to_string()))
                .collect()
        };
        assert!(!names(&SQLITE_MIGRATIONS).is_empty());
        assert_eq!(names(&SQLITE_MIGRATIONS), names(&POSTGRES_MIGRATIONS));
    }

    #[tokio::test]
    async fn events_append_in_order_and_an_origin_is_recorded_once() {
        let store = Store::open_in_memory().await.unwrap();
        let row = |node_seq: u64, kind: &str| EventRow {
            node_id: "node1".into(),
            node_seq,
            at_unix_ms: 1_000 + node_seq as i64,
            sandbox_id: "sbx_a".into(),
            kind: kind.into(),
            ..Default::default()
        };
        assert_eq!(store.append_event(&row(1, "created")).await.unwrap(), 1);
        assert_eq!(store.append_event(&row(2, "started")).await.unwrap(), 2);
        // A reconnecting tail replays what was already copied.
        assert_eq!(store.append_event(&row(2, "started")).await.unwrap(), 0);
        let listed = store.list_events(1, Some("sbx_a"), 10).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, "started");
        assert_eq!(store.last_event_seq_for_node("node1").await.unwrap(), 2);
        assert_eq!(store.last_event_seq_for_node("node2").await.unwrap(), 0);
        assert_eq!(store.prune_events(1_002).await.unwrap(), 1);
    }
    use super::*;

    fn row(id: &str, block: u32) -> SandboxRow {
        SandboxRow {
            id: id.into(),
            template: "default".into(),
            record: Vec::new(),
            state: 2,
            lease_block: block,
            tap: format!("bt{block}"),
            ports: vec![PortRow {
                host_port: 20000,
                guest_port: 8000,
                is_udp: false,
            }],
            share: None,
            suspended_at: 0,
        }
    }

    #[tokio::test]
    async fn a_share_survives_a_reload() {
        let store = Store::open_in_memory().await.unwrap();
        let mut shared = row("sbx_a", 1);
        shared.share = Some(ShareRow {
            key: "privkey:00".into(),
            preshared_key: "psk:00".into(),
            ports: vec![22, 8080],
            allowed_clients: vec!["nodekey:11".into()],
            created_at: 1_800_000_000,
            udp_ports: vec![53],
            is_all_udp_shared: false,
            is_ip_transparent: true,
        });
        store.put_sandbox(&shared).await.unwrap();
        store.put_sandbox(&row("sbx_b", 2)).await.unwrap();
        let rows = store.list_sandboxes().await.unwrap();
        assert_eq!(rows[0].share, shared.share);
        assert_eq!(rows[1].share, None);
    }

    /// `suspended_ttl_secs` is measured from this, so a restart that lost it
    /// would either delete everything at once or never.
    #[tokio::test]
    async fn the_suspension_timestamp_survives_a_reload() {
        let store = Store::open_in_memory().await.unwrap();
        let mut suspended = row("sbx_a", 1);
        suspended.state = 4;
        suspended.suspended_at = 1_800_000_000;
        store.put_sandbox(&suspended).await.unwrap();
        assert_eq!(
            store.list_sandboxes().await.unwrap()[0].suspended_at,
            1_800_000_000
        );
    }

    #[tokio::test]
    async fn sandboxes_round_trip_including_ports() {
        let store = Store::open_in_memory().await.unwrap();
        store.put_sandbox(&row("sbx_a", 1)).await.unwrap();
        let listed = store.list_sandboxes().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].lease_block, 1);
        assert_eq!(listed[0].tap, "bt1");
        assert_eq!(
            listed[0].ports,
            vec![PortRow {
                host_port: 20000,
                guest_port: 8000,
                is_udp: false
            }]
        );
    }

    #[tokio::test]
    async fn writing_the_same_sandbox_twice_updates_rather_than_duplicates() {
        let store = Store::open_in_memory().await.unwrap();
        store.put_sandbox(&row("sbx_a", 1)).await.unwrap();
        let mut updated = row("sbx_a", 1);
        updated.state = 4;
        store.put_sandbox(&updated).await.unwrap();
        let listed = store.list_sandboxes().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, 4);
    }

    #[tokio::test]
    async fn state_changes_are_persisted_on_their_own() {
        let store = Store::open_in_memory().await.unwrap();
        store.put_sandbox(&row("sbx_a", 1)).await.unwrap();
        store
            .set_sandbox_state("sbx_a", 4, b"\x01\x02".as_slice())
            .await
            .unwrap();
        let listed = store.list_sandboxes().await.unwrap();
        assert_eq!(listed[0].state, 4);
        assert_eq!(listed[0].record, b"\x01\x02".as_slice());
    }

    #[tokio::test]
    async fn deleting_removes_the_row() {
        let store = Store::open_in_memory().await.unwrap();
        store.put_sandbox(&row("sbx_a", 1)).await.unwrap();
        store.delete_sandbox("sbx_a").await.unwrap();
        assert!(store.list_sandboxes().await.unwrap().is_empty());
    }

    fn session(id: &str, sandbox: &str, started_at: i64) -> SessionRow {
        SessionRow {
            id: id.into(),
            sandbox_id: sandbox.into(),
            started_at,
            ended_at: 0,
            started_by: "boot".into(),
            ended_by: String::new(),
        }
    }

    #[tokio::test]
    async fn sessions_come_back_newest_first_per_sandbox() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .put_session(&session("s1", "sbx_a", 100))
            .await
            .unwrap();
        store
            .put_session(&session("s2", "sbx_a", 200))
            .await
            .unwrap();
        store
            .put_session(&session("s3", "sbx_b", 300))
            .await
            .unwrap();

        let listed = store.list_sessions("sbx_a").await.unwrap();
        assert_eq!(
            listed.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["s2", "s1"]
        );
        assert_eq!(store.list_sessions("sbx_b").await.unwrap().len(), 1);
        assert!(store.list_sessions("sbx_missing").await.unwrap().is_empty());
    }

    /// A sandbox suspended and resumed on a loop would otherwise grow this
    /// table for as long as it lives, so the oldest go first, and only that
    /// sandbox's.
    #[tokio::test]
    async fn retention_evicts_the_oldest_sessions_of_that_sandbox_only() {
        let store = Store::open_in_memory().await.unwrap();
        for i in 0..10 {
            store
                .put_session(&session(&format!("s{i}"), "sbx_a", 100 + i))
                .await
                .unwrap();
        }
        store
            .put_session(&session("other", "sbx_b", 1))
            .await
            .unwrap();

        assert_eq!(store.retain_recent_sessions("sbx_a", 4).await.unwrap(), 6);
        let left = store.list_sessions("sbx_a").await.unwrap();
        assert_eq!(
            left.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["s9", "s8", "s7", "s6"]
        );
        assert_eq!(store.list_sessions("sbx_b").await.unwrap().len(), 1);

        // Already within the bound: nothing to give up.
        assert_eq!(store.retain_recent_sessions("sbx_a", 4).await.unwrap(), 0);
    }

    /// Sessions opened inside the same second still evict oldest-first, or a
    /// burst of resumes would drop an arbitrary subset.
    #[tokio::test]
    async fn sessions_sharing_a_timestamp_evict_in_insertion_order() {
        let store = Store::open_in_memory().await.unwrap();
        for i in 0..5 {
            store
                .put_session(&session(&format!("s{i}"), "sbx_a", 100))
                .await
                .unwrap();
        }
        store.retain_recent_sessions("sbx_a", 2).await.unwrap();
        let left = store.list_sessions("sbx_a").await.unwrap();
        assert_eq!(
            left.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["s4", "s3"]
        );
    }

    /// A VMM does not survive the daemon, so a session still open on startup
    /// belongs to a VM that is gone. Nothing observed when, which is why the
    /// end time stays unset rather than being backfilled with "now".
    #[tokio::test]
    async fn sessions_open_at_startup_are_closed_without_an_end_time() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .put_session(&session("s1", "sbx_a", 100))
            .await
            .unwrap();
        let mut closed = session("s2", "sbx_a", 200);
        closed.ended_at = 250;
        closed.ended_by = "suspended".into();
        store.put_session(&closed).await.unwrap();

        assert_eq!(store.close_open_sessions("unknown").await.unwrap(), 1);
        let listed = store.list_sessions("sbx_a").await.unwrap();
        let open = listed.iter().find(|s| s.id == "s1").unwrap();
        assert_eq!(open.ended_by, "unknown");
        assert_eq!(open.ended_at, 0);
        // An already-closed session keeps the reason it was closed with.
        let done = listed.iter().find(|s| s.id == "s2").unwrap();
        assert_eq!(done.ended_by, "suspended");
        assert_eq!(done.ended_at, 250);
    }

    #[tokio::test]
    async fn closing_a_session_twice_keeps_the_first_reason() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .put_session(&session("s1", "sbx_a", 100))
            .await
            .unwrap();
        store.end_session("s1", 150, "suspended").await.unwrap();
        store.end_session("s1", 999, "deleted").await.unwrap();
        let row = &store.list_sessions("sbx_a").await.unwrap()[0];
        assert_eq!(row.ended_by, "suspended");
        assert_eq!(row.ended_at, 150);
    }

    #[tokio::test]
    async fn deleting_a_sandbox_takes_its_sessions() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .put_session(&session("s1", "sbx_a", 100))
            .await
            .unwrap();
        store
            .put_session(&session("s2", "sbx_b", 100))
            .await
            .unwrap();
        store.delete_sessions("sbx_a").await.unwrap();
        assert!(store.list_sessions("sbx_a").await.unwrap().is_empty());
        assert_eq!(store.list_sessions("sbx_b").await.unwrap().len(), 1);
    }

    fn egress(sandbox: &str, allowed: bool, at: &str) -> EgressRow {
        EgressRow {
            at: at.into(),
            sandbox_id: sandbox.into(),
            source_ip: "10.99.0.6".into(),
            destination: "1.2.3.4:443".into(),
            host: "example.com".into(),
            port: 443,
            is_allowed: allowed,
            reason: if allowed {
                "allowed"
            } else {
                "host not in allowlist"
            }
            .into(),
            bytes_sent: 10,
            bytes_received: 20,
        }
    }

    #[tokio::test]
    async fn egress_records_come_back_newest_first() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .insert_egress(&egress("a", true, "2026-01-01T00:00:00Z"))
            .await
            .unwrap();
        store
            .insert_egress(&egress("a", false, "2026-01-02T00:00:00Z"))
            .await
            .unwrap();
        let rows = store.query_egress(&EgressFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].at, "2026-01-02T00:00:00Z");
    }

    #[tokio::test]
    async fn egress_can_be_filtered() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .insert_egress(&egress("a", true, "2026-01-01T00:00:00Z"))
            .await
            .unwrap();
        store
            .insert_egress(&egress("b", false, "2026-01-02T00:00:00Z"))
            .await
            .unwrap();

        let by_sandbox = store
            .query_egress(&EgressFilter {
                sandbox_id: Some("a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_sandbox.len(), 1);

        let denied = store
            .query_egress(&EgressFilter {
                is_denied_only: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(denied.len(), 1);
        assert!(!denied[0].is_allowed);

        let since = store
            .query_egress(&EgressFilter {
                since: Some("2026-01-02T00:00:00Z".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(since.len(), 1);
    }

    #[tokio::test]
    async fn pruning_removes_only_old_records() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .insert_egress(&egress("a", true, "2026-01-01T00:00:00Z"))
            .await
            .unwrap();
        store
            .insert_egress(&egress("a", true, "2026-06-01T00:00:00Z"))
            .await
            .unwrap();
        assert_eq!(store.prune_egress("2026-03-01T00:00:00Z").await.unwrap(), 1);
        assert_eq!(
            store
                .query_egress(&EgressFilter::default())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// The file holds tenant policies and the egress audit trail, so it must
    /// not be readable by every account on the host.
    #[tokio::test]
    #[cfg(unix)]
    async fn the_database_and_its_directory_are_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("burrow-store-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state.db");
        let store = Store::open(&path).await.unwrap();
        store
            .put_placement(&PlacementRow {
                id: "a".into(),
                node_id: "n1".into(),
                record: Vec::new(),
            })
            .await
            .unwrap();

        let file = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file, 0o600, "database is {file:o}");
        // The sidecars sqlite creates itself are only covered by the
        // directory's permissions.
        let parent = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent, 0o700, "directory is {parent:o}");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn placements_can_be_dropped_per_node() {
        let store = Store::open_in_memory().await.unwrap();
        for (id, node) in [("a", "n1"), ("b", "n1"), ("c", "n2")] {
            store
                .put_placement(&PlacementRow {
                    id: id.into(),
                    node_id: node.into(),
                    record: Vec::new(),
                })
                .await
                .unwrap();
        }
        assert_eq!(store.delete_placements_for_node("n1").await.unwrap(), 2);
        let left = store.list_placements().await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].node_id, "n2");
    }

    #[tokio::test]
    async fn claims_of_a_sandbox_that_moved_are_kept() {
        let store = Store::open_in_memory().await.unwrap();
        for (id, node) in [("moved", "n2"), ("gone", "n1")] {
            store.claim(&format!("name:{id}"), id, 1).await.unwrap();
            store
                .put_placement(&PlacementRow {
                    id: id.into(),
                    node_id: node.into(),
                    record: Vec::new(),
                })
                .await
                .unwrap();
        }
        for id in ["moved", "gone"] {
            store.release_claims_unless_moved(id, "n1").await.unwrap();
        }
        assert_eq!(
            store.claim_holder("name:moved").await.unwrap().as_deref(),
            Some("moved")
        );
        assert_eq!(store.claim_holder("name:gone").await.unwrap(), None);
    }

    /// A delete accepted while the node was down has to outlive the process
    /// that accepted it, or a node returning days later is simply re-adopted.
    #[tokio::test]
    async fn tombstones_round_trip_and_can_be_cleared() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .put_tombstone(&TombstoneRow {
                sandbox_id: "sbx_a".into(),
                node_id: "n1".into(),
                at: 1_800_000_000,
            })
            .await
            .unwrap();
        let listed = store.list_tombstones().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].node_id, "n1");
        assert_eq!(listed[0].at, 1_800_000_000);

        store.delete_tombstone("sbx_a").await.unwrap();
        assert!(store.list_tombstones().await.unwrap().is_empty());
    }

    /// A node that never returns must not leave its tombstones behind forever.
    #[tokio::test]
    async fn old_tombstones_are_pruned() {
        let store = Store::open_in_memory().await.unwrap();
        for (id, at) in [("old", 1_000), ("new", 9_000)] {
            store
                .put_tombstone(&TombstoneRow {
                    sandbox_id: id.into(),
                    node_id: "n1".into(),
                    at,
                })
                .await
                .unwrap();
        }
        assert_eq!(store.prune_tombstones(5_000).await.unwrap(), 1);
        let left = store.list_tombstones().await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].sandbox_id, "new");
    }
}
