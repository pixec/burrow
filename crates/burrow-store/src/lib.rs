//! Durable state for burrow, on SQLite or PostgreSQL through sqlx.
//!
//! Both tiers use this crate with different tables. A node stores everything
//! needed to reattach to its own sandboxes after a restart: the address lease,
//! the tap name, and the published ports, none of which can be re-derived. It
//! is always SQLite, because a node must keep working with the control plane
//! gone. The orchestrator stores which sandbox lives on which node, sealed
//! secrets and the fleet's event log, on SQLite for a single process or
//! PostgreSQL for several.
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
    /// The placement generation the orchestrator gave this node the sandbox
    /// at, reported back with it.
    pub generation: u64,
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
    /// Unix milliseconds the current keys were issued.
    pub created_at_ms: i64,
    /// Guest UDP ports admitted; `is_all_udp_shared` admits every one.
    pub udp_ports: Vec<u16>,
    pub is_all_udp_shared: bool,
    /// Source each connection from the last pong-verified public IPv4.
    pub is_ip_transparent: bool,
}

/// One VM boot inside a sandbox's life.
///
/// `ended_at_ms` is 0 while the session is open, and stays 0 for one the node
/// died during, because nothing observed when that VM actually stopped, and
/// inventing a time would be worse than saying so. `started_by` and `ended_by`
/// are `burrow.common.v1.SessionStart` and `SessionEnd`; `ended_by` is 0
/// while the session is open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRow {
    pub id: String,
    pub sandbox_id: String,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub started_by: i32,
    pub ended_by: i32,
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
    /// A `burrow.common.v1.EventKind`.
    pub kind: i32,
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

impl From<EventRow> for burrow_proto::common::v1::Event {
    fn from(row: EventRow) -> Self {
        Self {
            seq: row.seq,
            node_id: row.node_id,
            node_seq: row.node_seq,
            at_unix_ms: row.at_unix_ms,
            sandbox_id: row.sandbox_id,
            kind: row.kind,
            state: row.state,
            detail: row.detail,
            template: row.template,
            tags: serde_json::from_str(&row.metadata_json).unwrap_or_default(),
            cpu_usage_usec: row.cpu_usage_usec,
            rx_bytes: row.rx_bytes,
            tx_bytes: row.tx_bytes,
            vcpus: row.vcpus,
            mem_mib: row.mem_mib,
        }
    }
}

/// One recorded egress attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRow {
    pub at_ms: i64,
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
    /// Unix milliseconds lower bound.
    pub since_ms: Option<i64>,
    pub limit: u32,
}

/// An orchestrator's record of where a sandbox lives: every sandbox that
/// should exist has one, written before any node is asked to act on it.
#[derive(Debug, Clone, Default)]
pub struct PlacementRow {
    pub id: String,
    pub node_id: String,
    pub record: Vec<u8>,
    /// Bumped by every write of the row.
    pub version: i64,
    /// Raised by every change of node. A node holding the sandbox at any
    /// other generation holds a stale copy.
    pub generation: i64,
    /// When a node was asked to act on this placement, 0 once it answered.
    pub pending_since_ms: i64,
}

type PlacementRaw = (String, String, Vec<u8>, i64, i64, i64);

const PLACEMENT_COLUMNS: &str = "id, node_id, record, version, generation, pending_since_ms";
const PLACEMENT_COLUMNS_OF_P: &str =
    "p.id, p.node_id, p.record, p.version, p.generation, p.pending_since_ms";

fn placement_row(r: PlacementRaw) -> PlacementRow {
    PlacementRow {
        id: r.0,
        node_id: r.1,
        record: r.2,
        version: r.3,
        generation: r.4,
        pending_since_ms: r.5,
    }
}

/// Keeps a lost placement with no node when `unplaced` carries its record,
/// and deletes it with its claims otherwise, while it is still on the node
/// and at the generation it was read at. False when a move got there first.
/// A macro rather than a function, so it runs on either backend's
/// transaction inside `on_pool!`.
macro_rules! settle_lost {
    ($tx:expr, $row:expr, $unplaced:expr) => {{
        let row: &PlacementRow = $row;
        let settled = match $unplaced {
            Some(record) => sqlx::query(
                "UPDATE placements SET node_id='', record=$4, pending_since_ms=0, missed=0,
                    version=version + 1
                 WHERE id=$1 AND node_id=$2 AND generation=$3",
            )
            .bind(&row.id)
            .bind(&row.node_id)
            .bind(row.generation)
            .bind(record)
            .execute(&mut *$tx)
            .await?
            .rows_affected(),
            None => {
                let done = sqlx::query(
                    "DELETE FROM placements WHERE id=$1 AND node_id=$2 AND generation=$3",
                )
                .bind(&row.id)
                .bind(&row.node_id)
                .bind(row.generation)
                .execute(&mut *$tx)
                .await?
                .rows_affected();
                if done == 1 {
                    sqlx::query("DELETE FROM claims WHERE sandbox_id=$1")
                        .bind(&row.id)
                        .execute(&mut *$tx)
                        .await?;
                }
                done
            }
        };
        settled == 1
    }};
}

/// Rows rewritten from a heartbeat per statement.
const RESTATE_BATCH: usize = 500;

/// How many consecutive complete listings may leave a placement out before
/// it is lost. One can always be a listing sampled before the sandbox
/// landed; two in a row cannot.
pub const LOST_AFTER_MISSES: i64 = 2;

/// One sandbox in a node's complete listing.
#[derive(Debug, Clone, Serialize)]
pub struct ReportedSandbox {
    #[serde(rename = "i")]
    pub id: String,
    #[serde(rename = "g")]
    pub generation: i64,
    /// Digest of what the node says about the sandbox, compared against the
    /// row's so only what changed is rewritten.
    #[serde(rename = "h")]
    pub hash: i64,
    /// 1 for a create or adopt its node is still carrying out, which keeps
    /// the row from going missing and leaves its record alone.
    #[serde(rename = "f")]
    pub in_flight: i64,
}

/// A node's heartbeat, as [`Store::reconcile_node`] applies it.
#[derive(Debug, Clone, Default)]
pub struct NodeReport {
    /// The node's status columns, written with the report.
    pub node: NodeRow,
    /// The node's own number for the report, rising with every one it sends.
    pub seq: i64,
    pub sandboxes: Vec<ReportedSandbox>,
    /// Rows a node was asked to act on after this are not yet missing.
    pub pending_after_ms: i64,
    /// Rows whose usage figures were last written before this are rewritten.
    pub usage_before_ms: i64,
    /// Reported rows still pending since before this are returned as
    /// unanswered.
    pub unanswered_before_ms: i64,
    /// Every snapshot the node holds, and every volume but those a sandbox
    /// owns, which go with it.
    pub snapshots: Vec<String>,
    /// Snapshots the node deleted on its own, whose rows go.
    pub swept_snapshots: Vec<String>,
    pub volumes: Vec<String>,
}

pub enum Reconciled {
    /// No node by that id: it must register again.
    Unknown,
    /// A report no newer than one already applied. Nothing was changed.
    Stale,
    Applied(NodeReconciled),
}

#[derive(Debug, Default)]
pub struct NodeReconciled {
    /// Rows no node held that the node holds at their generation, placed
    /// back on it: nothing has placed them since it held them, so its copy
    /// is current. A node written off and back keeps what it still has.
    pub replaced: Vec<PlacementRow>,
    /// What the node holds that no row lists for it at that generation.
    pub destroy: Vec<(String, i64)>,
    pub lost: Vec<Lost>,
    /// Rows rewritten from the report, as written.
    pub restated: Vec<PlacementRow>,
    /// Rows the node holds whose create or adopt never had its answer
    /// recorded.
    pub unanswered: Vec<String>,
    /// Snapshots and volumes the node holds that no row names.
    pub destroy_snapshots: Vec<String>,
    pub destroy_volumes: Vec<String>,
}

/// What [`Store::remove_volume_unless_mounted`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum VolumeRemoval {
    Removed,
    Missing,
    /// Kept: this sandbox mounts it.
    Mounted(String),
}

/// A placement whose node no longer holds it, and the record it was kept
/// with when it was kept unplaced.
#[derive(Debug)]
pub struct Lost {
    pub row: PlacementRow,
    pub unplaced: Option<Vec<u8>>,
}

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
    /// Host CPU the node may commit, its cores times its overcommit, in
    /// thousandths of a CPU. 0 for a node that has not reported its cores.
    pub cpu_capacity_millis: u64,
    /// Host CPU committed on the node, in thousandths of a CPU.
    pub committed_cpu_millis: u64,
    pub free_mem_mib: u64,
    /// Capacity promised to sandboxes placed since the last heartbeat.
    pub reserved_cpu_millis: i64,
    pub reserved_mem_mib: i64,
}

/// One allocated or quarantined public address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRow {
    pub address: String,
    pub pool: String,
    pub owner: String,
    /// A `burrow.common.v1.PublicIpState`.
    pub state: i32,
    /// Unix milliseconds a quarantined address may be taken again.
    pub available_at_ms: i64,
    /// Encoded `burrow.common.v1.PublicIp`.
    pub record: Vec<u8>,
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

type EventRaw = (
    i64,
    String,
    i64,
    i64,
    String,
    i64,
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

const EVENT_COLUMNS: &str = "seq, node_id, node_seq, at, sandbox_id, kind, state, detail,
    template, metadata_json, cpu_usage_usec, rx_bytes, tx_bytes, vcpus, mem_mib";

fn event_row(r: EventRaw) -> EventRow {
    EventRow {
        seq: r.0 as u64,
        node_id: r.1,
        node_seq: r.2 as u64,
        at_unix_ms: r.3,
        sandbox_id: r.4,
        kind: r.5 as i32,
        state: r.6 as i32,
        detail: r.7,
        template: r.8,
        metadata_json: r.9,
        cpu_usage_usec: r.10 as u64,
        rx_bytes: r.11 as u64,
        tx_bytes: r.12 as u64,
        vcpus: r.13 as u32,
        mem_mib: r.14 as u32,
    }
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

    /// Locks the rows a select reads until the transaction ends, where the
    /// backend has row locks; SQLite has one writer at a time.
    fn row_lock(&self) -> &'static str {
        match self.is_postgres() {
            true => " FOR UPDATE",
            false => "",
        }
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
                (id, template, record, state, lease_block, tap, ports_json, suspended_at, share_json,
                 generation)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (id) DO UPDATE SET
                template=excluded.template, record=excluded.record,
                state=excluded.state, lease_block=excluded.lease_block,
                tap=excluded.tap, ports_json=excluded.ports_json,
                suspended_at=excluded.suspended_at, share_json=excluded.share_json,
                generation=excluded.generation",
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
        .bind(row.generation as i64)
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
            i64,
        );
        let rows: Vec<Raw> = on_pool!(self, pool => sqlx::query_as(
            "SELECT id, template, record, state, lease_block, tap, ports_json, suspended_at,
                    share_json, generation
             FROM sandboxes ORDER BY id",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    template,
                    record,
                    state,
                    lease_block,
                    tap,
                    ports,
                    suspended_at,
                    share,
                    generation,
                )| {
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
                        generation: generation as u64,
                    }
                },
            )
            .collect())
    }

    pub async fn put_session(&self, row: &SessionRow) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO sessions (id, sandbox_id, started_at_ms, ended_at_ms, started_by, ended_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO UPDATE SET
                ended_at_ms=excluded.ended_at_ms, ended_by=excluded.ended_by",
        )
        .bind(&row.id)
        .bind(&row.sandbox_id)
        .bind(row.started_at_ms)
        .bind(row.ended_at_ms)
        .bind(row.started_by as i64)
        .bind(row.ended_by as i64)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Marks one session closed. `ended_at_ms` of 0 records that the session
    /// ended without anything observing when.
    pub async fn end_session(&self, id: &str, ended_at_ms: i64, ended_by: i32) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "UPDATE sessions SET ended_at_ms=$2, ended_by=$3 WHERE id=$1 AND ended_by=0",
        )
        .bind(id)
        .bind(ended_at_ms)
        .bind(ended_by as i64)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// Closes every session left open by a previous run of this daemon.
    ///
    /// A VMM does not survive its parent, so a session still open at startup
    /// belongs to a VM that is already gone. `ended_at_ms` stays unset because
    /// nothing recorded when that happened.
    pub async fn close_open_sessions(&self, ended_by: i32) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("UPDATE sessions SET ended_by=$1 WHERE ended_by=0")
            .bind(ended_by as i64)
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
            "SELECT id, sandbox_id, started_at_ms, ended_at_ms, started_by, ended_by
             FROM sessions WHERE sandbox_id=$1 ORDER BY started_at_ms DESC, {} DESC",
            self.session_order()
        );
        let rows: Vec<(String, String, i64, i64, i64, i64)> =
            on_pool!(self, pool => sqlx::query_as(&sql).bind(sandbox_id).fetch_all(pool).await)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, sandbox_id, started_at_ms, ended_at_ms, started_by, ended_by)| SessionRow {
                    id,
                    sandbox_id,
                    started_at_ms,
                    ended_at_ms,
                    started_by: started_by as i32,
                    ended_by: ended_by as i32,
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
                ORDER BY started_at_ms DESC, {} DESC LIMIT $2
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
        .bind(row.kind as i64)
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
        // The optional filter is spelled into the SQL rather than written as
        // `$2 IS NULL OR ...`: Postgres cannot infer the type of a parameter
        // compared only with NULL.
        let mut sql = format!("SELECT {EVENT_COLUMNS} FROM events WHERE seq > $1");
        if sandbox_id.is_some() {
            sql.push_str(" AND sandbox_id = $3");
        }
        sql.push_str(" ORDER BY seq LIMIT $2");
        let rows: Vec<EventRaw> = on_pool!(self, pool => {
            let mut query = sqlx::query_as(&sql).bind(after_seq as i64).bind(limit as i64);
            if let Some(id) = sandbox_id {
                query = query.bind(id);
            }
            query.fetch_all(pool).await
        })?;
        Ok(rows.into_iter().map(event_row).collect())
    }

    /// One node's events after `after_node_seq`, in the node's order.
    pub async fn list_node_events(
        &self,
        node_id: &str,
        after_node_seq: u64,
        limit: usize,
    ) -> Result<Vec<EventRow>> {
        let sql = format!(
            "SELECT {EVENT_COLUMNS} FROM events WHERE node_id=$1 AND node_seq > $2
             ORDER BY node_seq LIMIT $3"
        );
        let rows: Vec<EventRaw> = on_pool!(self, pool => sqlx::query_as(&sql)
            .bind(node_id)
            .bind(after_node_seq as i64)
            .bind(limit as i64)
            .fetch_all(pool)
            .await)?;
        Ok(rows.into_iter().map(event_row).collect())
    }

    /// The latest event recorded for a sandbox.
    pub async fn last_event_of(&self, sandbox_id: &str) -> Result<Option<EventRow>> {
        let sql = format!(
            "SELECT {EVENT_COLUMNS} FROM events WHERE sandbox_id=$1 ORDER BY seq DESC LIMIT 1"
        );
        let row: Option<EventRaw> = on_pool!(self, pool => sqlx::query_as(&sql)
            .bind(sandbox_id)
            .fetch_optional(pool)
            .await)?;
        Ok(row.map(event_row))
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
               (at_ms, sandbox_id, source_ip, destination, host, port, allowed, reason,
                bytes_sent, bytes_received)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(row.at_ms)
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
            "SELECT at_ms, sandbox_id, source_ip, destination, host, port, allowed, reason,
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
        if filter.since_ms.is_some() {
            sql.push_str(&format!(" AND at_ms >= ${next}"));
        }
        sql.push_str(" ORDER BY id DESC LIMIT $1");
        let limit = if filter.limit == 0 { 100 } else { filter.limit } as i64;

        type Raw = (
            i64,
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
            if let Some(since) = filter.since_ms {
                query = query.bind(since);
            }
            query.fetch_all(pool).await
        })?;
        Ok(rows
            .into_iter()
            .map(|r| EgressRow {
                at_ms: r.0,
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
    pub async fn prune_egress(&self, cutoff_ms: i64) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM audit_egress WHERE at_ms < $1")
            .bind(cutoff_ms)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    /// Writes a placement ahead of asking its node to act, for a sandbox id
    /// no row has yet. False when one does.
    pub async fn insert_placement(&self, row: &PlacementRow) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "INSERT INTO placements
               (id, node_id, record, version, generation, pending_since_ms, missed, report_hash,
                usage_at_ms)
             VALUES ($1, $2, $3, 1, $4, $5, 0, 0, 0)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&row.id)
        .bind(&row.node_id)
        .bind(&row.record)
        .bind(row.generation)
        .bind(row.pending_since_ms)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done == 1)
    }

    /// Takes the record a node answered with for the placement it was asked
    /// to act on, while the row still names that node at that generation.
    /// `is_settled` clears the row's pending mark.
    pub async fn update_placement(
        &self,
        row: &PlacementRow,
        report_hash: i64,
        is_settled: bool,
    ) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE placements SET record=$4, report_hash=$5, version=version + 1,
                pending_since_ms = CASE WHEN $6 THEN 0 ELSE pending_since_ms END,
                missed = CASE WHEN $6 THEN 0 ELSE missed END
             WHERE id=$1 AND node_id=$2 AND generation=$3",
        )
        .bind(&row.id)
        .bind(&row.node_id)
        .bind(row.generation)
        .bind(&row.record)
        .bind(report_hash)
        .bind(is_settled)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done == 1)
    }

    /// Marks a placement pending with `record`, while it is still on its
    /// node at its generation, ahead of asking that node to act on it.
    pub async fn mark_placement_pending(
        &self,
        row: &PlacementRow,
        report_hash: i64,
        now_ms: i64,
    ) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE placements SET record=$4, report_hash=$5, pending_since_ms=$6, missed=0,
                version=version + 1
             WHERE id=$1 AND node_id=$2 AND generation=$3",
        )
        .bind(&row.id)
        .bind(&row.node_id)
        .bind(row.generation)
        .bind(&row.record)
        .bind(report_hash)
        .bind(now_ms)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done == 1)
    }

    /// Hands a placement to `to_node` at the next generation, while it is
    /// still on `from_node` (`""` for none) at `generation`, and marks it
    /// pending until that node answers. Returns the new generation, or
    /// `None` when another call placed or removed the sandbox first.
    pub async fn move_placement(
        &self,
        id: &str,
        from_node: &str,
        generation: i64,
        to_node: &str,
        record: &[u8],
        now_ms: i64,
    ) -> Result<Option<i64>> {
        let row: Option<(i64,)> = on_pool!(self, pool => sqlx::query_as(
            "UPDATE placements SET node_id=$4, record=$5, generation=generation + 1,
                pending_since_ms=$6, missed=0, version=version + 1
             WHERE id=$1 AND node_id=$2 AND generation=$3
             RETURNING generation",
        )
        .bind(id)
        .bind(from_node)
        .bind(generation)
        .bind(to_node)
        .bind(record)
        .bind(now_ms)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(|(generation,)| generation))
    }

    /// Takes a placement off its node, while it is still on `node_id` at
    /// `generation`, for a sandbox the object store can bring back.
    pub async fn unplace_placement(
        &self,
        id: &str,
        node_id: &str,
        generation: i64,
        record: &[u8],
    ) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE placements SET node_id='', record=$4, pending_since_ms=0, missed=0,
                version=version + 1
             WHERE id=$1 AND node_id=$2 AND generation=$3",
        )
        .bind(id)
        .bind(node_id)
        .bind(generation)
        .bind(record)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done == 1)
    }

    /// Deletes a sandbox: its row and every claim it holds, in one
    /// transaction, so its name is free the moment it is gone. Returns the
    /// row there was.
    pub async fn remove_placement(&self, id: &str) -> Result<Option<PlacementRow>> {
        let row: Option<PlacementRaw> = on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let row = sqlx::query_as(&format!(
                "DELETE FROM placements WHERE id=$1 RETURNING {PLACEMENT_COLUMNS}"
            ))
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM claims WHERE sandbox_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            row
        });
        Ok(row.map(placement_row))
    }

    /// [`remove_placement`](Self::remove_placement), only while the row is
    /// still on `node_id` at `generation`: a create that failed takes back
    /// the row it wrote and nothing written since.
    pub async fn remove_placement_at(
        &self,
        id: &str,
        node_id: &str,
        generation: i64,
    ) -> Result<bool> {
        let done = on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let done = sqlx::query(
                "DELETE FROM placements WHERE id=$1 AND node_id=$2 AND generation=$3",
            )
            .bind(id)
            .bind(node_id)
            .bind(generation)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if done == 1 {
                sqlx::query("DELETE FROM claims WHERE sandbox_id=$1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            done
        });
        Ok(done == 1)
    }

    pub async fn get_placement(&self, id: &str) -> Result<Option<PlacementRow>> {
        let row: Option<PlacementRaw> = on_pool!(self, pool => sqlx::query_as(&format!(
            "SELECT {PLACEMENT_COLUMNS} FROM placements WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(placement_row))
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

    /// Writes a snapshot's row ahead of asking a node to take it. False when
    /// one exists.
    pub async fn insert_snapshot(&self, id: &str, at_ms: i64) -> Result<bool> {
        self.insert_named("snapshots", "id", id, at_ms).await
    }

    /// Deletes a snapshot's row, returning whether there was one.
    pub async fn remove_snapshot(&self, id: &str) -> Result<bool> {
        self.remove_named("snapshots", "id", id).await
    }

    pub async fn snapshot_ids(&self) -> Result<std::collections::HashSet<String>> {
        self.list_named("snapshots", "id").await
    }

    /// Writes a volume's row ahead of asking a node to make it. False when
    /// one exists.
    pub async fn insert_volume(&self, name: &str, at_ms: i64) -> Result<bool> {
        self.insert_named("volumes", "name", name, at_ms).await
    }

    /// Deletes a volume's row, returning whether there was one.
    pub async fn remove_volume(&self, name: &str) -> Result<bool> {
        self.remove_named("volumes", "name", name).await
    }

    /// Deletes a volume's row unless a sandbox's record, as `mounts` reads
    /// it, mounts the volume: checked in the same transaction as the delete,
    /// against every sandbox the store has, running or not, placed or not.
    pub async fn remove_volume_unless_mounted(
        &self,
        name: &str,
        mounts: impl Fn(&[u8]) -> bool,
    ) -> Result<VolumeRemoval> {
        let lock = self.row_lock();
        let removal = on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let held: Option<(String,)> =
                sqlx::query_as(&format!("SELECT name FROM volumes WHERE name=$1{lock}"))
                    .bind(name)
                    .fetch_optional(&mut *tx)
                    .await?;
            if held.is_none() {
                tx.commit().await?;
                VolumeRemoval::Missing
            } else {
                let rows: Vec<(String, Vec<u8>)> =
                    sqlx::query_as("SELECT id, record FROM placements ORDER BY id")
                        .fetch_all(&mut *tx)
                        .await?;
                match rows.into_iter().find(|(_, record)| mounts(record)) {
                    Some((id, _)) => {
                        tx.rollback().await?;
                        VolumeRemoval::Mounted(id)
                    }
                    None => {
                        sqlx::query("DELETE FROM volumes WHERE name=$1")
                            .bind(name)
                            .execute(&mut *tx)
                            .await?;
                        tx.commit().await?;
                        VolumeRemoval::Removed
                    }
                }
            }
        });
        Ok(removal)
    }

    pub async fn volume_names(&self) -> Result<std::collections::HashSet<String>> {
        self.list_named("volumes", "name").await
    }

    async fn insert_named(&self, table: &str, key: &str, value: &str, at_ms: i64) -> Result<bool> {
        let sql = format!(
            "INSERT INTO {table} ({key}, at_ms) VALUES ($1, $2) ON CONFLICT ({key}) DO NOTHING"
        );
        let done = on_pool!(self, pool => sqlx::query(&sql)
            .bind(value)
            .bind(at_ms)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done == 1)
    }

    async fn remove_named(&self, table: &str, key: &str, value: &str) -> Result<bool> {
        let sql = format!("DELETE FROM {table} WHERE {key}=$1");
        let done = on_pool!(self, pool => sqlx::query(&sql)
            .bind(value)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done == 1)
    }

    async fn list_named(
        &self,
        table: &str,
        key: &str,
    ) -> Result<std::collections::HashSet<String>> {
        let sql = format!("SELECT {key} FROM {table}");
        let rows: Vec<(String,)> = on_pool!(self, pool => sqlx::query_as(&sql)
            .fetch_all(pool)
            .await)?;
        Ok(rows.into_iter().map(|(value,)| value).collect())
    }

    /// Whether what the object store held before snapshots and volumes had
    /// rows has been recorded.
    ///
    /// Temporary, like [`Self::record_stored_inventory`]: it exists for the
    /// release that gives snapshots and volumes rows, and the release after
    /// removes both, the `stored_inventory` table, the nodes'
    /// `is_inventory_recorded` column, the recording branch of
    /// [`Self::reconcile_node`] and the orchestrator's
    /// `record_stored_inventory`.
    pub async fn is_stored_inventory_recorded(&self) -> Result<bool> {
        let row: (i64,) = on_pool!(self, pool => sqlx::query_as(
            "SELECT is_recorded FROM stored_inventory WHERE id=1",
        )
        .fetch_one(pool)
        .await)?;
        Ok(row.0 != 0)
    }

    /// Records, once, the snapshots and volumes the object store holds.
    /// Temporary: see [`Self::is_stored_inventory_recorded`].
    pub async fn record_stored_inventory(
        &self,
        snapshots: &[String],
        volumes: &[String],
        at_ms: i64,
    ) -> Result<()> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            for id in snapshots {
                sqlx::query("INSERT INTO snapshots (id, at_ms) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
                    .bind(id)
                    .bind(at_ms)
                    .execute(&mut *tx)
                    .await?;
            }
            for name in volumes {
                sqlx::query("INSERT INTO volumes (name, at_ms) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING")
                    .bind(name)
                    .bind(at_ms)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("UPDATE stored_inventory SET is_recorded=1 WHERE id=1")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
        });
        Ok(())
    }

    pub async fn list_placements(&self) -> Result<Vec<PlacementRow>> {
        let rows: Vec<PlacementRaw> = on_pool!(self, pool => sqlx::query_as(&format!(
            "SELECT {PLACEMENT_COLUMNS} FROM placements ORDER BY id"
        ))
        .fetch_all(pool)
        .await)?;
        Ok(rows.into_iter().map(placement_row).collect())
    }

    /// Applies one node's heartbeat in one transaction: its status, and its
    /// complete listing of sandboxes compared against the placements.
    ///
    /// A report numbered at or below the last one applied for the node is
    /// ignored whole, so a delayed one cannot bring back what a later one
    /// settled. Otherwise the listing is compared by set difference:
    ///
    /// * reported sandboxes whose row has no node and their generation are
    ///   placed back on this node;
    /// * reported sandboxes no row lists for this node at their generation
    ///   come back in [`NodeReconciled::destroy`], for the node to destroy;
    /// * rows for this node the listing leaves out count a miss, unless a
    ///   node was asked to act on them after `pending_after_ms`, and a row
    ///   at two consecutive misses is lost: `lose` decides it as it does for
    ///   a write-off, given the kind and detail of the sandbox's last event
    ///   from this node;
    /// * rows whose report digest changed, or whose usage was last written
    ///   before `usage_before_ms`, are rewritten with what `restate` makes of
    ///   them.
    pub async fn reconcile_node(
        &self,
        report: &NodeReport,
        restate: impl Fn(&PlacementRow) -> Option<(Vec<u8>, i64)>,
        lose: impl Fn(&PlacementRow, Option<(i32, String)>) -> Option<Vec<u8>>,
    ) -> Result<Reconciled> {
        let listing = serde_json::to_string(&report.sandboxes)?;
        let (create, clear, fill) = if self.is_postgres() {
            (
                "CREATE TEMP TABLE IF NOT EXISTS reported
                   (id TEXT PRIMARY KEY, generation BIGINT NOT NULL, hash BIGINT NOT NULL,
                    in_flight BIGINT NOT NULL)
                   ON COMMIT DELETE ROWS",
                None,
                "INSERT INTO reported (id, generation, hash, in_flight)
                 SELECT i, g, h, f
                 FROM jsonb_to_recordset($1::jsonb) AS x(i TEXT, g BIGINT, h BIGINT, f BIGINT)
                 WHERE true ON CONFLICT (id) DO NOTHING",
            )
        } else {
            (
                "CREATE TEMP TABLE IF NOT EXISTS reported
                   (id TEXT PRIMARY KEY, generation INTEGER NOT NULL, hash INTEGER NOT NULL,
                    in_flight INTEGER NOT NULL)",
                Some("DELETE FROM reported"),
                "INSERT INTO reported (id, generation, hash, in_flight)
                 SELECT json_extract(value, '$.i'), json_extract(value, '$.g'),
                        json_extract(value, '$.h'), json_extract(value, '$.f')
                 FROM json_each($1) WHERE true ON CONFLICT (id) DO NOTHING",
            )
        };
        let node = &report.node;
        let lock = self.row_lock();
        let snapshots = serde_json::to_string(&report.snapshots)?;
        let volumes = serde_json::to_string(&report.volumes)?;
        let unnamed = |table: &str, key: &str| match self.is_postgres() {
            true => format!(
                "SELECT x FROM jsonb_array_elements_text($1::jsonb) AS x
                 WHERE NOT EXISTS (SELECT 1 FROM {table} t WHERE t.{key} = x) ORDER BY x"
            ),
            false => format!(
                "SELECT value FROM json_each($1)
                 WHERE NOT EXISTS (SELECT 1 FROM {table} t WHERE t.{key} = value) ORDER BY value"
            ),
        };
        let (unnamed_snapshots, unnamed_volumes) =
            (unnamed("snapshots", "id"), unnamed("volumes", "name"));
        let record = |table: &str, key: &str| match self.is_postgres() {
            true => format!(
                "INSERT INTO {table} ({key}, at_ms)
                 SELECT x, $2 FROM jsonb_array_elements_text($1::jsonb) AS x
                 WHERE true ON CONFLICT ({key}) DO NOTHING"
            ),
            false => format!(
                "INSERT INTO {table} ({key}, at_ms) SELECT value, $2 FROM json_each($1)
                 WHERE true ON CONFLICT ({key}) DO NOTHING"
            ),
        };
        let (record_snapshots, record_volumes) =
            (record("snapshots", "id"), record("volumes", "name"));
        let outcome = on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let applied = sqlx::query(
                "UPDATE nodes SET info=$2, status=$3, last_heartbeat_ms=$4, is_reported=1,
                    cpu_capacity_millis=$5, committed_cpu_millis=$6, free_mem_mib=$7,
                    reserved_cpu_millis=0, reserved_mem_mib=0, report_seq=$8
                 WHERE id=$1 AND report_seq < $8",
            )
            .bind(&node.id)
            .bind(&node.info)
            .bind(&node.status)
            .bind(node.last_heartbeat_ms)
            .bind(node.cpu_capacity_millis as i64)
            .bind(node.committed_cpu_millis as i64)
            .bind(node.free_mem_mib as i64)
            .bind(report.seq)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if applied == 0 {
                let known: Option<(i64,)> = sqlx::query_as("SELECT report_seq FROM nodes WHERE id=$1")
                    .bind(&node.id)
                    .fetch_optional(&mut *tx)
                    .await?;
                tx.commit().await?;
                match known {
                    Some(_) => Reconciled::Stale,
                    None => Reconciled::Unknown,
                }
            } else {
                sqlx::query(create).execute(&mut *tx).await?;
                if let Some(clear) = clear {
                    sqlx::query(clear).execute(&mut *tx).await?;
                }
                sqlx::query(fill).bind(&listing).execute(&mut *tx).await?;

                let replaced: Vec<PlacementRaw> = sqlx::query_as(&format!(
                    "UPDATE placements SET node_id=$1, missed=0, version=version + 1
                     WHERE node_id='' AND EXISTS (SELECT 1 FROM reported r
                        WHERE r.id = placements.id AND r.generation = placements.generation)
                     RETURNING {PLACEMENT_COLUMNS}"
                ))
                .bind(&node.id)
                .fetch_all(&mut *tx)
                .await?;
                let destroy: Vec<(String, i64)> = sqlx::query_as(
                    "SELECT r.id, r.generation FROM reported r
                     WHERE NOT EXISTS (SELECT 1 FROM placements p
                        WHERE p.id = r.id AND p.node_id = $1 AND p.generation = r.generation)
                     ORDER BY r.id",
                )
                .bind(&node.id)
                .fetch_all(&mut *tx)
                .await?;
                sqlx::query(
                    "UPDATE placements SET missed=0
                     WHERE node_id=$1 AND missed > 0 AND EXISTS (SELECT 1 FROM reported r
                        WHERE r.id = placements.id AND r.generation = placements.generation)",
                )
                .bind(&node.id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "UPDATE placements SET missed=missed + 1
                     WHERE node_id=$1 AND pending_since_ms <= $2 AND NOT EXISTS (
                        SELECT 1 FROM reported r
                        WHERE r.id = placements.id AND r.generation = placements.generation)",
                )
                .bind(&node.id)
                .bind(report.pending_after_ms)
                .execute(&mut *tx)
                .await?;

                let missing: Vec<PlacementRaw> = sqlx::query_as(&format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM placements
                     WHERE node_id=$1 AND missed >= {LOST_AFTER_MISSES} ORDER BY id{lock}"
                ))
                .bind(&node.id)
                .fetch_all(&mut *tx)
                .await?;
                let mut lost = Vec::with_capacity(missing.len());
                for row in missing.into_iter().map(placement_row) {
                    let last: Option<(i64, String)> = sqlx::query_as(
                        "SELECT kind, detail FROM events WHERE sandbox_id=$1 AND node_id=$2
                         ORDER BY seq DESC LIMIT 1",
                    )
                    .bind(&row.id)
                    .bind(&node.id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let unplaced = lose(&row, last.map(|(kind, detail)| (kind as i32, detail)));
                    if settle_lost!(tx, &row, unplaced.as_deref()) {
                        lost.push(Lost { row, unplaced });
                    }
                }

                let stale: Vec<PlacementRaw> = sqlx::query_as(&format!(
                    "SELECT {PLACEMENT_COLUMNS_OF_P} FROM placements p
                     JOIN reported r ON r.id = p.id AND r.generation = p.generation
                     WHERE p.node_id=$1 AND r.in_flight = 0
                       AND (p.report_hash <> r.hash OR p.usage_at_ms < $2)
                     ORDER BY p.id"
                ))
                .bind(&node.id)
                .bind(report.usage_before_ms)
                .fetch_all(&mut *tx)
                .await?;
                let mut changed = Vec::new();
                let mut hashes = Vec::new();
                for mut row in stale.into_iter().map(placement_row) {
                    let Some((record, hash)) = restate(&row) else {
                        continue;
                    };
                    row.record = record;
                    changed.push(row);
                    hashes.push(hash);
                }
                // Written in batches of one statement each: a row at a time
                // is a round trip each, which at a node's thousands of
                // sandboxes is most of the heartbeat. Each row is written
                // only over the version read, on this node at its
                // generation: the read took no lock, and an edit or a move
                // committed since wins, to be restated at the next beat.
                let mut written = std::collections::HashSet::new();
                for (rows, hashes) in changed.chunks(RESTATE_BATCH).zip(hashes.chunks(RESTATE_BATCH)) {
                    let values = (0..rows.len())
                        .map(|i| {
                            let n = 5 * i + 3;
                            format!("(${n}, ${}, ${}, ${}, ${})", n + 1, n + 2, n + 3, n + 4)
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    let sql = format!(
                        "UPDATE placements SET record=v.column4, report_hash=v.column5,
                            usage_at_ms=$1, version=placements.version + 1
                         FROM (VALUES {values}) AS v
                         WHERE placements.id = v.column1 AND placements.version = v.column2
                           AND placements.generation = v.column3 AND placements.node_id = $2
                         RETURNING placements.id"
                    );
                    let mut query = sqlx::query_as::<_, (String,)>(&sql)
                        .bind(report.node.last_heartbeat_ms)
                        .bind(&node.id);
                    for (row, hash) in rows.iter().zip(hashes) {
                        query = query
                            .bind(&row.id)
                            .bind(row.version)
                            .bind(row.generation)
                            .bind(&row.record)
                            .bind(*hash);
                    }
                    written.extend(query.fetch_all(&mut *tx).await?.into_iter().map(|(id,)| id));
                }
                let restated: Vec<PlacementRow> = changed
                    .into_iter()
                    .filter(|row| written.contains(&row.id))
                    .map(|row| PlacementRow {
                        version: row.version + 1,
                        ..row
                    })
                    .collect();

                for id in &report.swept_snapshots {
                    sqlx::query("DELETE FROM snapshots WHERE id=$1")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                }
                // Temporary, with the columns it reads: records what a node
                // held before snapshots and volumes had rows, and destroys
                // nothing for want of a row until the object store's holdings
                // are recorded. The release after this ships removes it.
                let recorded: (i64, i64) = sqlx::query_as(
                    "SELECT is_inventory_recorded,
                        (SELECT is_recorded FROM stored_inventory WHERE id=1)
                     FROM nodes WHERE id=$1",
                )
                .bind(&node.id)
                .fetch_one(&mut *tx)
                .await?;
                let (destroy_snapshots, destroy_volumes) = match recorded {
                    (_, 0) if recorded.0 != 0 => (Vec::new(), Vec::new()),
                    (0, _) => {
                        for (sql, listing) in
                            [(&record_snapshots, &snapshots), (&record_volumes, &volumes)]
                        {
                            sqlx::query(sql)
                                .bind(listing)
                                .bind(node.last_heartbeat_ms)
                                .execute(&mut *tx)
                                .await?;
                        }
                        sqlx::query("UPDATE nodes SET is_inventory_recorded=1 WHERE id=$1")
                            .bind(&node.id)
                            .execute(&mut *tx)
                            .await?;
                        (Vec::new(), Vec::new())
                    }
                    _ => {
                        let unnamed_snapshots: Vec<(String,)> = sqlx::query_as(&unnamed_snapshots)
                            .bind(&snapshots)
                            .fetch_all(&mut *tx)
                            .await?;
                        let unnamed_volumes: Vec<(String,)> = sqlx::query_as(&unnamed_volumes)
                            .bind(&volumes)
                            .fetch_all(&mut *tx)
                            .await?;
                        (
                            unnamed_snapshots.into_iter().map(|(id,)| id).collect(),
                            unnamed_volumes.into_iter().map(|(name,)| name).collect(),
                        )
                    }
                };

                let unanswered: Vec<(String,)> = sqlx::query_as(
                    "SELECT p.id FROM placements p
                     JOIN reported r ON r.id = p.id AND r.generation = p.generation
                     WHERE p.node_id=$1 AND r.in_flight = 0 AND p.pending_since_ms > 0
                       AND p.pending_since_ms <= $2
                     ORDER BY p.id",
                )
                .bind(&node.id)
                .bind(report.unanswered_before_ms)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Reconciled::Applied(NodeReconciled {
                    replaced: replaced.into_iter().map(placement_row).collect(),
                    destroy,
                    lost,
                    restated,
                    unanswered: unanswered.into_iter().map(|(id,)| id).collect(),
                    destroy_snapshots,
                    destroy_volumes,
                })
            }
        });
        Ok(outcome)
    }

    /// Stores an unscoped secret, clearing any scope the name had.
    pub async fn put_secret(&self, name: &str, value: &str) -> Result<()> {
        self.put_secret_scoped(name, value, "").await
    }

    /// Stores a secret with its scope, both replacing whatever the name held.
    pub async fn put_secret_scoped(&self, name: &str, value: &str, scope: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO secrets (name, value, scope) VALUES ($1, $2, $3)
             ON CONFLICT (name) DO UPDATE SET value=excluded.value, scope=excluded.scope",
        )
        .bind(name)
        .bind(value)
        .bind(scope)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn get_secret(&self, name: &str) -> Result<Option<String>> {
        Ok(self.get_secret_scoped(name).await?.map(|(value, _)| value))
    }

    /// A secret's sealed value and its scope, empty when it has none.
    pub async fn get_secret_scoped(&self, name: &str) -> Result<Option<(String, String)>> {
        let row: Option<(String, String)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT value, scope FROM secrets WHERE name=$1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await)?;
        Ok(row)
    }

    pub async fn list_secret_names(&self) -> Result<Vec<String>> {
        Ok(self
            .list_secret_scopes()
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// Every secret's name and scope, by name. Never a value.
    pub async fn list_secret_scopes(&self) -> Result<Vec<(String, String)>> {
        let rows: Vec<(String, String)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT name, scope FROM secrets ORDER BY name",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows)
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
    pub async fn put_ip_pool(&self, name: &str, record: &[u8]) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO ip_pools (name, record) VALUES ($1, $2)
             ON CONFLICT (name) DO UPDATE SET record=excluded.record",
        )
        .bind(name)
        .bind(record)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn list_ip_pools(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let rows: Vec<(String, Vec<u8>)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT name, record FROM ip_pools ORDER BY name",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows)
    }

    pub async fn delete_ip_pool(&self, name: &str) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query("DELETE FROM ip_pools WHERE name=$1")
            .bind(name)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }

    /// Takes `row.address` for its owner. False when another allocation, or a
    /// quarantine still running at `now_ms`, holds it; a quarantine that has
    /// run out is cleared first, in the same statement's race.
    pub async fn claim_ip(&self, row: &IpRow, now_ms: i64) -> Result<bool> {
        on_pool!(self, pool => sqlx::query(
            "DELETE FROM public_ips WHERE address=$1 AND state=$2 AND available_at_ms <= $3",
        )
        .bind(&row.address)
        .bind(burrow_proto::common::v1::PublicIpState::Quarantined as i64)
        .bind(now_ms)
        .execute(pool)
        .await
        .map(drop))?;
        let done = on_pool!(self, pool => sqlx::query(
            "INSERT INTO public_ips (address, pool, owner, state, available_at_ms, record)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (address) DO NOTHING",
        )
        .bind(&row.address)
        .bind(&row.pool)
        .bind(&row.owner)
        .bind(row.state as i64)
        .bind(row.available_at_ms)
        .bind(&row.record)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }

    /// Replaces an address's row.
    pub async fn put_ip(&self, row: &IpRow) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "INSERT INTO public_ips (address, pool, owner, state, available_at_ms, record)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (address) DO UPDATE SET pool=excluded.pool, owner=excluded.owner,
             state=excluded.state, available_at_ms=excluded.available_at_ms, record=excluded.record",
        )
        .bind(&row.address)
        .bind(&row.pool)
        .bind(&row.owner)
        .bind(row.state as i64)
        .bind(row.available_at_ms)
        .bind(&row.record)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    pub async fn get_ip(&self, address: &str) -> Result<Option<IpRow>> {
        Ok(self
            .list_ips()
            .await?
            .into_iter()
            .find(|row| row.address == address))
    }

    pub async fn list_ips(&self) -> Result<Vec<IpRow>> {
        let rows: Vec<(String, String, String, i64, i64, Vec<u8>)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT address, pool, owner, state, available_at_ms, record FROM public_ips ORDER BY address",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(
                |(address, pool, owner, state, available_at_ms, record)| IpRow {
                    address,
                    pool,
                    owner,
                    state: state as i32,
                    available_at_ms,
                    record,
                },
            )
            .collect())
    }

    pub async fn delete_ip(&self, address: &str) -> Result<()> {
        on_pool!(self, pool => sqlx::query("DELETE FROM public_ips WHERE address=$1")
            .bind(address)
            .execute(pool)
            .await
            .map(drop))?;
        Ok(())
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
                    is_reported, cpu_capacity_millis, committed_cpu_millis, free_mem_mib,
                    reserved_cpu_millis, reserved_mem_mib, is_inventory_recorded)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, 0, 0, 0, 0, 0)
                 ON CONFLICT (id) DO UPDATE SET
                   idx=excluded.idx, info=excluded.info, status=excluded.status,
                   wg_key=excluded.wg_key, wg_endpoint=excluded.wg_endpoint,
                   last_heartbeat_ms=excluded.last_heartbeat_ms, is_reported=0,
                   cpu_capacity_millis=excluded.cpu_capacity_millis, reserved_cpu_millis=0,
                   reserved_mem_mib=0",
            )
            .bind(&row.id)
            .bind(index as i64)
            .bind(&row.info)
            .bind(&row.status)
            .bind(&row.wireguard_public_key)
            .bind(&row.wireguard_endpoint)
            .bind(row.last_heartbeat_ms)
            .bind(row.cpu_capacity_millis as i64)
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

    /// The last report applied from a node, which its next must exceed.
    pub async fn node_report_seq(&self, id: &str) -> Result<i64> {
        let row: Option<(i64,)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT report_seq FROM nodes WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map_or(0, |(seq,)| seq))
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
                    cpu_capacity_millis, committed_cpu_millis, free_mem_mib, reserved_cpu_millis,
                    reserved_mem_mib
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
                cpu_capacity_millis: r.8 as u64,
                committed_cpu_millis: r.9 as u64,
                free_mem_mib: r.10 as u64,
                reserved_cpu_millis: r.11,
                reserved_mem_mib: r.12,
            })
            .collect())
    }

    /// Removes a node silent since before `before_ms`, for the leader of
    /// `epoch` only, and settles every placement on it in the same
    /// transaction: `lose` gives the record of one the object store can
    /// bring back, which is kept with no node, and `None` for one it cannot,
    /// which is deleted with its claims. `None` when the node has been heard
    /// from since, or a later leader has taken over.
    pub async fn write_off_node(
        &self,
        id: &str,
        before_ms: i64,
        epoch: i64,
        lose: impl Fn(&PlacementRow) -> Option<Vec<u8>>,
    ) -> Result<Option<Vec<Lost>>> {
        let lock = self.row_lock();
        let lost = on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let done = sqlx::query(
                "DELETE FROM nodes WHERE id=$1 AND last_heartbeat_ms < $2
                   AND (SELECT epoch FROM leader_epoch WHERE id=1) = $3",
            )
            .bind(id)
            .bind(before_ms)
            .bind(epoch)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if done == 1 {
                let rows: Vec<PlacementRaw> = sqlx::query_as(&format!(
                    "SELECT {PLACEMENT_COLUMNS} FROM placements WHERE node_id=$1 ORDER BY id{lock}"
                ))
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
                let mut lost = Vec::with_capacity(rows.len());
                for row in rows.into_iter().map(placement_row) {
                    let unplaced = lose(&row);
                    if settle_lost!(tx, &row, unplaced.as_deref()) {
                        lost.push(Lost { row, unplaced });
                    }
                }
                tx.commit().await?;
                Some(lost)
            } else {
                tx.commit().await?;
                None
            }
        });
        Ok(lost)
    }

    /// Records that a node on a build from before casync chunks was heard
    /// from at `at_ms`. Never moves back.
    pub async fn note_pre_casync_node(&self, at_ms: i64) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "UPDATE pre_casync_seen SET at_ms=$1 WHERE id=1 AND at_ms < $1",
        )
        .bind(at_ms)
        .execute(pool)
        .await
        .map(drop))?;
        Ok(())
    }

    /// When a node on a build from before casync chunks was last heard from,
    /// in Unix milliseconds.
    pub async fn pre_casync_seen_at(&self) -> Result<i64> {
        let (at_ms,): (i64,) = on_pool!(self, pool => sqlx::query_as(
            "SELECT at_ms FROM pre_casync_seen WHERE id=1",
        )
        .fetch_one(pool)
        .await)?;
        Ok(at_ms)
    }

    /// The fleet's sandbox address pool: its v4 and v6 CIDRs and the blocks
    /// in each node's slice.
    pub async fn address_pool(&self) -> Result<(String, String, u32)> {
        let (v4, v6, blocks): (String, String, i64) = on_pool!(self, pool => sqlx::query_as(
            "SELECT v4, v6, blocks_per_node FROM address_pool WHERE id=1",
        )
        .fetch_one(pool)
        .await)?;
        Ok((v4, v6, blocks as u32))
    }

    /// Changes the fleet's sandbox address pool, unless a sandbox is placed
    /// anywhere, since every one has an address from the pool it replaces.
    /// Every node is forgotten with it, so each registers again and is given
    /// the new one. False, changing nothing, while a sandbox is placed.
    pub async fn change_address_pool(&self, v4: &str, v6: &str, blocks: u32) -> Result<bool> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let (placed,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM placements")
                .fetch_one(&mut *tx)
                .await?;
            if placed > 0 {
                tx.rollback().await?;
                return Ok(false);
            }
            sqlx::query("UPDATE address_pool SET v4=$1, v6=$2, blocks_per_node=$3 WHERE id=1")
                .bind(v4)
                .bind(v6)
                .bind(i64::from(blocks))
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM nodes").execute(&mut *tx).await?;
            tx.commit().await?;
        });
        Ok(true)
    }

    /// Starts a leader's term, returning its epoch.
    pub async fn next_leader_epoch(&self) -> Result<i64> {
        let (epoch,): (i64,) = on_pool!(self, pool => sqlx::query_as(
            "UPDATE leader_epoch SET epoch = epoch + 1 WHERE id=1 RETURNING epoch",
        )
        .fetch_one(pool)
        .await)?;
        Ok(epoch)
    }

    /// The epoch of the current leader's term.
    pub async fn leader_epoch(&self) -> Result<i64> {
        let (epoch,): (i64,) = on_pool!(self, pool => sqlx::query_as(
            "SELECT epoch FROM leader_epoch WHERE id=1",
        )
        .fetch_one(pool)
        .await)?;
        Ok(epoch)
    }

    /// Takes capacity on a node if it still has it, in one statement.
    ///
    /// The fit check and the charge are the same `UPDATE`, so it is atomic on
    /// both backends: of two replicas racing for the last slot on a node,
    /// exactly one sees a row change. A node that has not reported a cpu
    /// count is trusted on cpu, as placement always has. CPU is in
    /// thousandths of a CPU, and a node's capacity already carries its
    /// overcommit.
    pub async fn reserve_capacity(
        &self,
        node_id: &str,
        cpu_millis: u64,
        mem_mib: u64,
    ) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE nodes SET reserved_cpu_millis = reserved_cpu_millis + $2,
                              reserved_mem_mib = reserved_mem_mib + $3
             WHERE id=$1
               AND (cpu_capacity_millis = 0
                    OR committed_cpu_millis + reserved_cpu_millis + $2 <= cpu_capacity_millis)
               AND (is_reported = 0 OR free_mem_mib - reserved_mem_mib >= $3)",
        )
        .bind(node_id)
        .bind(cpu_millis as i64)
        .bind(mem_mib as i64)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }

    /// Gives back capacity a placement took, or a reported sandbox held, and
    /// no longer needs. Below zero is a credit until the node's next heartbeat
    /// reports what was freed.
    pub async fn release_capacity(
        &self,
        node_id: &str,
        cpu_millis: u64,
        mem_mib: u64,
    ) -> Result<()> {
        on_pool!(self, pool => sqlx::query(
            "UPDATE nodes SET
                reserved_cpu_millis = reserved_cpu_millis - $2,
                reserved_mem_mib = reserved_mem_mib - $3
             WHERE id=$1",
        )
        .bind(node_id)
        .bind(cpu_millis as i64)
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

/// One closed stretch a sandbox spent in one state at one shape. Appended,
/// never updated: the usage inside it is the difference of the sandbox's
/// totals at its two bounds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageRow {
    /// Ledger position; 0 until written.
    pub id: u64,
    pub sandbox_id: String,
    pub node_id: String,
    pub template: String,
    pub metadata_json: String,
    /// A `burrow.api.v1.UsageState`.
    pub state: i32,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub cpu_usage_usec: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub closed_by: String,
}

/// A sandbox's interval that has not closed yet: the totals it began with,
/// and the latest totals a heartbeat reported for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenUsageRow {
    pub sandbox_id: String,
    pub node_id: String,
    pub template: String,
    pub metadata_json: String,
    pub state: i32,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub started_at_ms: i64,
    pub cpu_usage_usec: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub seen_at_ms: i64,
    pub seen_cpu_usage_usec: u64,
    pub seen_rx_bytes: u64,
    pub seen_tx_bytes: u64,
}

/// A change to one sandbox's open interval, applied only if the interval is
/// still the one it was computed from: `expected` is the `started_at_ms` read,
/// `None` for no open interval at all.
#[derive(Debug, Clone)]
pub struct OpenUsageChange {
    pub sandbox_id: String,
    pub expected: Option<i64>,
    pub next: Option<OpenUsageRow>,
}

/// What the ledger writer commits at once: closed rows, open-interval changes,
/// and optionally how far one node's events have now been consumed, moving
/// from `from` to `to`.
#[derive(Debug, Clone, Default)]
pub struct UsageCommit {
    pub cursor: Option<(String, u64, u64)>,
    pub rows: Vec<UsageRow>,
    pub changes: Vec<OpenUsageChange>,
}

#[derive(Debug, Clone, Default)]
pub struct UsageFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub sandbox_id: Option<String>,
    pub after_id: u64,
    pub limit: u32,
}

type UsageRaw = (
    i64,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    String,
);

type OpenUsageRaw = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
);

const OPEN_USAGE_COLUMNS: &str = "sandbox_id, node_id, template, metadata_json, state, vcpus,
    mem_mib, started_at, cpu_usage_usec, rx_bytes, tx_bytes, seen_at, seen_cpu_usage_usec,
    seen_rx_bytes, seen_tx_bytes";

fn open_usage_row(r: OpenUsageRaw) -> OpenUsageRow {
    OpenUsageRow {
        sandbox_id: r.0,
        node_id: r.1,
        template: r.2,
        metadata_json: r.3,
        state: r.4 as i32,
        vcpus: r.5 as u32,
        mem_mib: r.6 as u32,
        started_at_ms: r.7,
        cpu_usage_usec: r.8 as u64,
        rx_bytes: r.9 as u64,
        tx_bytes: r.10 as u64,
        seen_at_ms: r.11,
        seen_cpu_usage_usec: r.12 as u64,
        seen_rx_bytes: r.13 as u64,
        seen_tx_bytes: r.14 as u64,
    }
}

/// The ledger's transaction lock: "ledger" in ASCII.
const LEDGER_LOCK: i64 = 0x6c65_6467_6572;

/// Binds an open interval to `$2..=$15`, after the sandbox id in `$1`.
macro_rules! bind_open {
    ($query:expr, $row:expr) => {
        $query
            .bind(&$row.node_id)
            .bind(&$row.template)
            .bind(&$row.metadata_json)
            .bind($row.state as i64)
            .bind($row.vcpus as i64)
            .bind($row.mem_mib as i64)
            .bind($row.started_at_ms)
            .bind($row.cpu_usage_usec as i64)
            .bind($row.rx_bytes as i64)
            .bind($row.tx_bytes as i64)
            .bind($row.seen_at_ms)
            .bind($row.seen_cpu_usage_usec as i64)
            .bind($row.seen_rx_bytes as i64)
            .bind($row.seen_tx_bytes as i64)
    };
}

impl Store {
    /// How far the ledger has consumed each node's log.
    pub async fn usage_cursors(&self) -> Result<Vec<(String, u64)>> {
        let rows: Vec<(String, i64)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT node_id, node_seq FROM usage_cursors ORDER BY node_id",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows.into_iter().map(|(id, seq)| (id, seq as u64)).collect())
    }

    pub async fn open_usage(&self, sandbox_id: &str) -> Result<Option<OpenUsageRow>> {
        let sql = format!("SELECT {OPEN_USAGE_COLUMNS} FROM usage_open WHERE sandbox_id=$1");
        let row: Option<OpenUsageRaw> = on_pool!(self, pool => sqlx::query_as(&sql)
            .bind(sandbox_id)
            .fetch_optional(pool)
            .await)?;
        Ok(row.map(open_usage_row))
    }

    /// Every open interval, or those on one node.
    pub async fn list_open_usage(&self, node_id: Option<&str>) -> Result<Vec<OpenUsageRow>> {
        let mut sql = format!("SELECT {OPEN_USAGE_COLUMNS} FROM usage_open");
        if node_id.is_some() {
            sql.push_str(" WHERE node_id=$1");
        }
        sql.push_str(" ORDER BY sandbox_id");
        let rows: Vec<OpenUsageRaw> = on_pool!(self, pool => {
            let mut query = sqlx::query_as(&sql);
            if let Some(node_id) = node_id {
                query = query.bind(node_id);
            }
            query.fetch_all(pool).await
        })?;
        Ok(rows.into_iter().map(open_usage_row).collect())
    }

    /// Records the totals a heartbeat carried against each open interval on
    /// the node, as `(sandbox_id, cpu_usage_usec, rx_bytes, tx_bytes)`.
    ///
    /// Only ever moves a reading forward, and never onto an interval that
    /// began after it, so a heartbeat racing the event that reopened an
    /// interval cannot pull it back.
    pub async fn observe_usage(
        &self,
        node_id: &str,
        at_ms: i64,
        totals: &[(String, u64, u64, u64)],
    ) -> Result<()> {
        if totals.is_empty() {
            return Ok(());
        }
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            for (sandbox_id, cpu, rx, tx_bytes) in totals {
                sqlx::query(
                    "UPDATE usage_open SET seen_at=$3, seen_cpu_usage_usec=$4,
                       seen_rx_bytes=$5, seen_tx_bytes=$6
                     WHERE sandbox_id=$1 AND node_id=$2 AND seen_at < $3 AND started_at <= $3",
                )
                .bind(sandbox_id)
                .bind(node_id)
                .bind(at_ms)
                .bind(*cpu as i64)
                .bind(*rx as i64)
                .bind(*tx_bytes as i64)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        });
        Ok(())
    }

    /// Applies a ledger step atomically. Returns false, changing nothing, when
    /// another writer got there first: the cursor or an open interval is no
    /// longer what the step was computed from.
    pub async fn commit_usage(&self, commit: &UsageCommit) -> Result<bool> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            // One commit at a time, so ids are handed out in the order rows
            // become visible and a reader paging by id never passes one that
            // commits later. SQLite has a single writer already.
            if self.is_postgres() {
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(LEDGER_LOCK)
                    .execute(&mut *tx)
                    .await?;
            }
            if let Some((node_id, from, to)) = &commit.cursor {
                let moved = if *from == 0 {
                    sqlx::query(
                        "INSERT INTO usage_cursors (node_id, node_seq) VALUES ($1, $2)
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(node_id)
                    .bind(*to as i64)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                } else {
                    sqlx::query("UPDATE usage_cursors SET node_seq=$3 WHERE node_id=$1 AND node_seq=$2")
                        .bind(node_id)
                        .bind(*from as i64)
                        .bind(*to as i64)
                        .execute(&mut *tx)
                        .await?
                        .rows_affected()
                };
                if moved != 1 {
                    tx.rollback().await?;
                    return Ok(false);
                }
            }
            for change in &commit.changes {
                let applied = match (&change.expected, &change.next) {
                    (None, None) => 1,
                    (Some(started), None) => sqlx::query(
                        "DELETE FROM usage_open WHERE sandbox_id=$1 AND started_at=$2",
                    )
                    .bind(&change.sandbox_id)
                    .bind(*started)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected(),
                    (None, Some(next)) => {
                        let query = sqlx::query(
                            "INSERT INTO usage_open (sandbox_id, node_id, template, metadata_json,
                               state, vcpus, mem_mib, started_at, cpu_usage_usec, rx_bytes,
                               tx_bytes, seen_at, seen_cpu_usage_usec, seen_rx_bytes, seen_tx_bytes)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(&change.sandbox_id);
                        bind_open!(query, next).execute(&mut *tx).await?.rows_affected()
                    }
                    // A heartbeat may have read further than the step did; the
                    // later reading is kept.
                    (Some(started), Some(next)) => {
                        let query = sqlx::query(
                            "UPDATE usage_open SET node_id=$2, template=$3, metadata_json=$4,
                               state=$5, vcpus=$6, mem_mib=$7, started_at=$8, cpu_usage_usec=$9,
                               rx_bytes=$10, tx_bytes=$11,
                               seen_at=CASE WHEN $12 >= seen_at THEN $12 ELSE seen_at END,
                               seen_cpu_usage_usec=CASE WHEN $12 >= seen_at THEN $13 ELSE seen_cpu_usage_usec END,
                               seen_rx_bytes=CASE WHEN $12 >= seen_at THEN $14 ELSE seen_rx_bytes END,
                               seen_tx_bytes=CASE WHEN $12 >= seen_at THEN $15 ELSE seen_tx_bytes END
                             WHERE sandbox_id=$1 AND started_at=$16",
                        )
                        .bind(&change.sandbox_id);
                        bind_open!(query, next)
                            .bind(*started)
                            .execute(&mut *tx)
                            .await?
                            .rows_affected()
                    }
                };
                if applied != 1 {
                    tx.rollback().await?;
                    return Ok(false);
                }
            }
            for row in &commit.rows {
                sqlx::query(
                    "INSERT INTO usage_intervals (sandbox_id, node_id, template, metadata_json,
                       state, vcpus, mem_mib, started_at, ended_at, cpu_usage_usec, rx_bytes,
                       tx_bytes, closed_by)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                )
                .bind(&row.sandbox_id)
                .bind(&row.node_id)
                .bind(&row.template)
                .bind(&row.metadata_json)
                .bind(row.state as i64)
                .bind(row.vcpus as i64)
                .bind(row.mem_mib as i64)
                .bind(row.started_at_ms)
                .bind(row.ended_at_ms)
                .bind(row.cpu_usage_usec as i64)
                .bind(row.rx_bytes as i64)
                .bind(row.tx_bytes as i64)
                .bind(&row.closed_by)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        });
        Ok(true)
    }

    /// Ledger rows by id, ascending, that start inside the filter's window.
    pub async fn list_usage(&self, filter: &UsageFilter) -> Result<Vec<UsageRow>> {
        let mut sql = String::from(
            "SELECT id, sandbox_id, node_id, template, metadata_json, state, vcpus, mem_mib,
                    started_at, ended_at, cpu_usage_usec, rx_bytes, tx_bytes, closed_by
             FROM usage_intervals WHERE id > $1",
        );
        let mut next = 3;
        let mut clause = |sql: &mut String, text: &str| {
            sql.push_str(&text.replace('?', &format!("${next}")));
            next += 1;
        };
        if filter.from_ms.is_some() {
            clause(&mut sql, " AND started_at >= ?");
        }
        if filter.to_ms.is_some() {
            clause(&mut sql, " AND started_at < ?");
        }
        if filter.sandbox_id.is_some() {
            clause(&mut sql, " AND sandbox_id = ?");
        }
        sql.push_str(" ORDER BY id LIMIT $2");
        let rows: Vec<UsageRaw> = on_pool!(self, pool => {
            let mut query = sqlx::query_as(&sql)
                .bind(filter.after_id as i64)
                .bind(filter.limit as i64);
            if let Some(from) = filter.from_ms {
                query = query.bind(from);
            }
            if let Some(to) = filter.to_ms {
                query = query.bind(to);
            }
            if let Some(id) = &filter.sandbox_id {
                query = query.bind(id);
            }
            query.fetch_all(pool).await
        })?;
        Ok(rows
            .into_iter()
            .map(|r| UsageRow {
                id: r.0 as u64,
                sandbox_id: r.1,
                node_id: r.2,
                template: r.3,
                metadata_json: r.4,
                state: r.5 as i32,
                vcpus: r.6 as u32,
                mem_mib: r.7 as u32,
                started_at_ms: r.8,
                ended_at_ms: r.9,
                cpu_usage_usec: r.10 as u64,
                rx_bytes: r.11 as u64,
                tx_bytes: r.12 as u64,
                closed_by: r.13,
            })
            .collect())
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
    fn ip(address: &str, owner: &str) -> IpRow {
        IpRow {
            address: address.into(),
            pool: "rack-a".into(),
            owner: owner.into(),
            state: burrow_proto::common::v1::PublicIpState::Allocated as i32,
            available_at_ms: 0,
            record: vec![1, 2],
        }
    }

    #[tokio::test]
    async fn an_address_has_one_holder_and_waits_out_its_quarantine() {
        let store = Store::open_in_memory().await.unwrap();
        assert!(store.claim_ip(&ip("203.0.113.17", "a"), 0).await.unwrap());
        assert!(!store.claim_ip(&ip("203.0.113.17", "b"), 0).await.unwrap());

        let quarantined = IpRow {
            state: burrow_proto::common::v1::PublicIpState::Quarantined as i32,
            available_at_ms: 1_000,
            ..ip("203.0.113.17", "a")
        };
        store.put_ip(&quarantined).await.unwrap();
        assert!(!store.claim_ip(&ip("203.0.113.17", "b"), 999).await.unwrap());
        assert!(
            store
                .claim_ip(&ip("203.0.113.17", "b"), 1_000)
                .await
                .unwrap()
        );
        assert_eq!(
            store.get_ip("203.0.113.17").await.unwrap().unwrap().owner,
            "b"
        );

        store.put_ip_pool("rack-a", b"pool").await.unwrap();
        assert_eq!(store.list_ip_pools().await.unwrap().len(), 1);
        assert!(store.delete_ip_pool("rack-a").await.unwrap());
        store.delete_ip("203.0.113.17").await.unwrap();
        assert!(store.list_ips().await.unwrap().is_empty());
    }

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
        let row = |node_seq: u64, kind: i32| EventRow {
            node_id: "node1".into(),
            node_seq,
            at_unix_ms: 1_000 + node_seq as i64,
            sandbox_id: "sbx_a".into(),
            kind,
            ..Default::default()
        };
        assert_eq!(store.append_event(&row(1, 1)).await.unwrap(), 1);
        assert_eq!(store.append_event(&row(2, 2)).await.unwrap(), 2);
        // A reconnecting tail replays what was already copied.
        assert_eq!(store.append_event(&row(2, 2)).await.unwrap(), 0);
        let listed = store.list_events(1, Some("sbx_a"), 10).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, 2);
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
            generation: 0,
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
            created_at_ms: 1_800_000_000_000,
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

    fn session(id: &str, sandbox: &str, started_at_ms: i64) -> SessionRow {
        SessionRow {
            id: id.into(),
            sandbox_id: sandbox.into(),
            started_at_ms,
            ended_at_ms: 0,
            started_by: 1,
            ended_by: 0,
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
        closed.ended_at_ms = 250;
        closed.ended_by = 1;
        store.put_session(&closed).await.unwrap();

        assert_eq!(store.close_open_sessions(4).await.unwrap(), 1);
        let listed = store.list_sessions("sbx_a").await.unwrap();
        let open = listed.iter().find(|s| s.id == "s1").unwrap();
        assert_eq!(open.ended_by, 4);
        assert_eq!(open.ended_at_ms, 0);
        // An already-closed session keeps the reason it was closed with.
        let done = listed.iter().find(|s| s.id == "s2").unwrap();
        assert_eq!(done.ended_by, 1);
        assert_eq!(done.ended_at_ms, 250);
    }

    #[tokio::test]
    async fn closing_a_session_twice_keeps_the_first_reason() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .put_session(&session("s1", "sbx_a", 100))
            .await
            .unwrap();
        store.end_session("s1", 150, 1).await.unwrap();
        store.end_session("s1", 999, 2).await.unwrap();
        let row = &store.list_sessions("sbx_a").await.unwrap()[0];
        assert_eq!(row.ended_by, 1);
        assert_eq!(row.ended_at_ms, 150);
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

    fn egress(sandbox: &str, allowed: bool, at_ms: i64) -> EgressRow {
        EgressRow {
            at_ms,
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
            .insert_egress(&egress("a", true, 1_000))
            .await
            .unwrap();
        store
            .insert_egress(&egress("a", false, 2_000))
            .await
            .unwrap();
        let rows = store.query_egress(&EgressFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].at_ms, 2_000);
    }

    #[tokio::test]
    async fn egress_can_be_filtered() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .insert_egress(&egress("a", true, 1_000))
            .await
            .unwrap();
        store
            .insert_egress(&egress("b", false, 2_000))
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
                since_ms: Some(2_000),
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
            .insert_egress(&egress("a", true, 1_000))
            .await
            .unwrap();
        store
            .insert_egress(&egress("a", true, 6_000))
            .await
            .unwrap();
        assert_eq!(store.prune_egress(3_000).await.unwrap(), 1);
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
        assert!(store.insert_placement(&placed("a", "n1", 1)).await.unwrap());

        let file = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file, 0o600, "database is {file:o}");
        // The sidecars sqlite creates itself are only covered by the
        // directory's permissions.
        let parent = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent, 0o700, "directory is {parent:o}");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn placed(id: &str, node: &str, generation: i64) -> PlacementRow {
        PlacementRow {
            id: id.into(),
            node_id: node.into(),
            record: Vec::new(),
            generation,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_placement_moves_only_from_where_and_what_generation_it_was_read() {
        let store = Store::open_in_memory().await.unwrap();
        assert!(store.insert_placement(&placed("a", "n1", 1)).await.unwrap());
        assert!(!store.insert_placement(&placed("a", "n2", 1)).await.unwrap());
        assert_eq!(
            store
                .move_placement("a", "n1", 1, "n2", &[], 5)
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            store
                .move_placement("a", "n1", 1, "n3", &[], 6)
                .await
                .unwrap(),
            None
        );
        let row = store.get_placement("a").await.unwrap().unwrap();
        assert_eq!(
            (row.node_id.as_str(), row.generation, row.pending_since_ms),
            ("n2", 2, 5)
        );
        assert!(
            !store
                .update_placement(&placed("a", "n2", 1), 0, true)
                .await
                .unwrap()
        );
        assert!(
            store
                .update_placement(&placed("a", "n2", 2), 0, true)
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_placement("a")
                .await
                .unwrap()
                .unwrap()
                .pending_since_ms,
            0
        );
        assert!(!store.unplace_placement("a", "n1", 2, &[]).await.unwrap());
        assert!(store.unplace_placement("a", "n2", 2, &[]).await.unwrap());
        assert_eq!(
            store
                .move_placement("a", "", 2, "n1", &[], 7)
                .await
                .unwrap(),
            Some(3)
        );
    }

    /// A write-off or a lost listing settles the row it read. A move that
    /// committed after the read put the sandbox on another node, which the
    /// settling must not delete or take back.
    #[tokio::test]
    async fn a_lost_row_is_settled_only_as_it_was_read() {
        let store = Store::open_in_memory().await.unwrap();
        store.insert_placement(&placed("a", "n1", 1)).await.unwrap();
        let read = store.get_placement("a").await.unwrap().unwrap();
        store
            .move_placement("a", "n1", 1, "n2", &[], 5)
            .await
            .unwrap();
        let settled = async {
            on_pool!(store, pool => {
                let mut tx = pool.begin().await?;
                let settled = settle_lost!(tx, &read, None::<&[u8]>);
                tx.commit().await?;
                Ok::<_, sqlx::Error>(settled)
            })
        };
        assert!(!settled.await.unwrap());
        let row = store.get_placement("a").await.unwrap();
        assert_eq!(row.map(|row| row.node_id).as_deref(), Some("n2"));
    }

    /// A delete takes the sandbox's claims in the same transaction, so its
    /// name is free the moment the row is gone.
    #[tokio::test]
    async fn removing_a_placement_frees_its_claims() {
        let store = Store::open_in_memory().await.unwrap();
        store.claim("name:web", "a", 1).await.unwrap();
        assert!(store.insert_placement(&placed("a", "n1", 1)).await.unwrap());
        assert!(!store.remove_placement_at("a", "n1", 2).await.unwrap());
        assert_eq!(
            store.claim_holder("name:web").await.unwrap().as_deref(),
            Some("a")
        );
        let removed = store.remove_placement("a").await.unwrap().unwrap();
        assert_eq!(removed.node_id, "n1");
        assert_eq!(store.claim_holder("name:web").await.unwrap(), None);
        assert!(store.remove_placement("a").await.unwrap().is_none());
    }

    async fn reporting(store: &Store, node: &str) {
        store
            .register_node(
                &NodeRow {
                    id: node.into(),
                    ..Default::default()
                },
                None,
                8,
            )
            .await
            .unwrap();
    }

    fn report(node: &str, seq: i64, listed: &[(&str, i64)]) -> NodeReport {
        NodeReport {
            node: NodeRow {
                id: node.into(),
                last_heartbeat_ms: 1_000 + seq,
                ..Default::default()
            },
            seq,
            sandboxes: listed
                .iter()
                .map(|(id, generation)| ReportedSandbox {
                    id: id.to_string(),
                    generation: *generation,
                    hash: 0,
                    in_flight: 0,
                })
                .collect(),
            pending_after_ms: 100,
            usage_before_ms: 0,
            unanswered_before_ms: 50,
            snapshots: Vec::new(),
            swept_snapshots: Vec::new(),
            volumes: Vec::new(),
        }
    }

    async fn apply(store: &Store, report: &NodeReport) -> Reconciled {
        store
            .reconcile_node(
                report,
                |_| None,
                |row, _| (row.id == "durable").then(Vec::new),
            )
            .await
            .unwrap()
    }

    fn applied(outcome: Reconciled) -> NodeReconciled {
        match outcome {
            Reconciled::Applied(applied) => applied,
            Reconciled::Stale => panic!("stale"),
            Reconciled::Unknown => panic!("unknown"),
        }
    }

    /// A node holding a sandbox at a generation the store no longer lists
    /// for it holds a stale copy, and so does one holding a sandbox placed
    /// elsewhere or deleted.
    #[tokio::test]
    async fn a_node_destroys_what_the_store_does_not_list_for_it() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "n1").await;
        for row in [
            placed("kept", "n1", 3),
            placed("moved", "n2", 2),
            placed("old", "n1", 4),
        ] {
            store.insert_placement(&row).await.unwrap();
        }
        let out = applied(
            apply(
                &store,
                &report(
                    "n1",
                    1,
                    &[("kept", 3), ("moved", 1), ("old", 3), ("gone", 1)],
                ),
            )
            .await,
        );
        assert_eq!(
            out.destroy,
            [("gone".into(), 1), ("moved".into(), 1), ("old".into(), 3)]
        );
    }

    /// A node written off and back still holding a sandbox kept unplaced,
    /// at the generation the row has, holds the current copy: nothing placed
    /// it since. It is placed back there rather than destroyed. At an older
    /// generation it is a stale copy all the same.
    #[tokio::test]
    async fn a_returning_node_keeps_what_nothing_placed_since() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "n1").await;
        store
            .insert_placement(&placed("kept", "", 2))
            .await
            .unwrap();
        store
            .insert_placement(&placed("stale", "", 3))
            .await
            .unwrap();
        let out = applied(apply(&store, &report("n1", 1, &[("kept", 2), ("stale", 2)])).await);
        let replaced: Vec<_> = out.replaced.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(replaced, ["kept"]);
        assert_eq!(out.destroy, [("stale".into(), 2)]);
        assert_eq!(
            store.get_placement("kept").await.unwrap().unwrap().node_id,
            "n1"
        );
        assert_eq!(
            store.get_placement("stale").await.unwrap().unwrap().node_id,
            ""
        );
    }

    /// Reports are numbered by their node, and one no newer than the last
    /// applied changes nothing: a delayed one cannot count a miss, restate a
    /// sandbox or move the node's status back.
    #[tokio::test]
    async fn a_delayed_report_is_ignored() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "n1").await;
        store.insert_placement(&placed("a", "n1", 1)).await.unwrap();
        applied(apply(&store, &report("n1", 5, &[("a", 1)])).await);
        for seq in [5, 4] {
            assert!(matches!(
                apply(&store, &report("n1", seq, &[])).await,
                Reconciled::Stale
            ));
        }
        assert_eq!(store.node_report_seq("n1").await.unwrap(), 5);
        applied(apply(&store, &report("n1", 6, &[])).await);
        applied(apply(&store, &report("n1", 7, &[("a", 1)])).await);
        assert!(store.get_placement("a").await.unwrap().is_some());
        assert!(matches!(
            apply(&store, &report("nx", 1, &[])).await,
            Reconciled::Unknown
        ));
    }

    /// A row is lost only after two consecutive complete listings leave it
    /// out. One that comes back in between starts counting again, and a row
    /// whose node is still acting on it is not counted at all.
    #[tokio::test]
    async fn a_listing_that_leaves_a_row_out_once_loses_nothing() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "n1").await;
        store.insert_placement(&placed("a", "n1", 1)).await.unwrap();
        store
            .insert_placement(&PlacementRow {
                pending_since_ms: 500,
                ..placed("pending", "n1", 1)
            })
            .await
            .unwrap();
        store
            .insert_placement(&placed("durable", "n1", 1))
            .await
            .unwrap();
        assert!(
            applied(apply(&store, &report("n1", 1, &[])).await)
                .lost
                .is_empty()
        );
        assert!(
            applied(apply(&store, &report("n1", 2, &[("a", 1), ("durable", 1)])).await)
                .lost
                .is_empty()
        );
        assert!(
            applied(apply(&store, &report("n1", 3, &[])).await)
                .lost
                .is_empty()
        );
        let lost = applied(apply(&store, &report("n1", 4, &[])).await).lost;
        let ids: Vec<_> = lost
            .iter()
            .map(|l| (l.row.id.as_str(), l.unplaced.is_some()))
            .collect();
        assert_eq!(ids, [("a", false), ("durable", true)]);
        assert!(store.get_placement("a").await.unwrap().is_none());
        assert_eq!(
            store
                .get_placement("durable")
                .await
                .unwrap()
                .unwrap()
                .node_id,
            ""
        );
        assert!(store.get_placement("pending").await.unwrap().is_some());
    }

    /// A node holding snapshots and volumes no row names destroys them,
    /// except at the first heartbeat of a node from before they had rows,
    /// which records what it holds instead.
    #[tokio::test]
    async fn snapshots_and_volumes_no_row_names_are_destroyed() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "n1").await;
        store.insert_snapshot("snap_kept", 1).await.unwrap();
        store.insert_volume("data", 1).await.unwrap();
        let mut beat = report("n1", 1, &[]);
        beat.snapshots = vec!["snap_kept".into(), "snap_gone".into()];
        beat.volumes = vec!["data".into(), "scratch".into()];
        assert!(!store.is_stored_inventory_recorded().await.unwrap());
        store.record_stored_inventory(&[], &[], 1).await.unwrap();
        on_pool!(store, pool => sqlx::query("UPDATE nodes SET is_inventory_recorded=1")
            .execute(pool)
            .await
            .map(drop)
            .unwrap());
        let out = applied(apply(&store, &beat).await);
        assert_eq!(out.destroy_snapshots, ["snap_gone"]);
        assert_eq!(out.destroy_volumes, ["scratch"]);

        // A node known before the upgrade records what it holds, once.
        reporting(&store, "old").await;
        let mut sql_old = report("old", 1, &[]);
        on_pool!(store, pool => sqlx::query("UPDATE nodes SET is_inventory_recorded=0 WHERE id='old'")
            .execute(pool)
            .await
            .map(drop)
            .unwrap());
        sql_old.snapshots = vec!["snap_old".into()];
        sql_old.volumes = vec!["vol_old".into()];
        let out = applied(apply(&store, &sql_old).await);
        assert!(out.destroy_snapshots.is_empty() && out.destroy_volumes.is_empty());
        assert!(store.snapshot_ids().await.unwrap().contains("snap_old"));
        assert!(store.remove_volume("vol_old").await.unwrap());
        sql_old.seq = 2;
        assert_eq!(
            applied(apply(&store, &sql_old).await).destroy_volumes,
            ["vol_old"]
        );

        store
            .record_stored_inventory(&["snap_stored".into()], &["vol_stored".into()], 5)
            .await
            .unwrap();
        assert!(store.is_stored_inventory_recorded().await.unwrap());
        assert!(store.volume_names().await.unwrap().contains("vol_stored"));
    }

    /// While the snapshots and volumes from before their rows are still
    /// being recorded, a node registering anew, perhaps written off before
    /// the upgrade, records what it holds, and nothing is destroyed until the
    /// object store's holdings are recorded too.
    #[tokio::test]
    async fn nothing_from_before_rows_is_destroyed_while_it_is_recorded() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "returning").await;
        let mut beat = report("returning", 1, &[]);
        beat.snapshots = vec!["snap_before".into()];
        beat.volumes = vec!["vol_before".into()];
        let out = applied(apply(&store, &beat).await);
        assert!(out.destroy_snapshots.is_empty() && out.destroy_volumes.is_empty());
        assert!(store.snapshot_ids().await.unwrap().contains("snap_before"));

        beat.seq = 2;
        beat.snapshots.push("snap_fetched".into());
        let out = applied(apply(&store, &beat).await);
        assert!(
            out.destroy_snapshots.is_empty(),
            "{:?}",
            out.destroy_snapshots
        );
        store.record_stored_inventory(&[], &[], 1).await.unwrap();
        beat.seq = 3;
        let out = applied(apply(&store, &beat).await);
        assert_eq!(out.destroy_snapshots, ["snap_fetched"]);
    }

    /// Only rows whose report changed are rewritten, and a row the node
    /// holds whose create never had its answer recorded is named.
    #[tokio::test]
    async fn a_report_rewrites_only_what_changed() {
        let store = Store::open_in_memory().await.unwrap();
        reporting(&store, "n1").await;
        store
            .insert_placement(&placed("same", "n1", 1))
            .await
            .unwrap();
        store
            .insert_placement(&placed("changed", "n1", 1))
            .await
            .unwrap();
        store
            .insert_placement(&PlacementRow {
                pending_since_ms: 10,
                ..placed("unanswered", "n1", 1)
            })
            .await
            .unwrap();
        let mut beat = report("n1", 1, &[("same", 1), ("changed", 1), ("unanswered", 1)]);
        beat.sandboxes[1].hash = 7;
        let out = store
            .reconcile_node(
                &beat,
                |row| Some((vec![1], if row.id == "changed" { 7 } else { 0 })),
                |_, _| None,
            )
            .await
            .unwrap();
        let out = applied(out);
        let ids: Vec<_> = out.restated.iter().map(|row| row.id.as_str()).collect();
        assert_eq!(ids, ["changed"]);
        assert_eq!(out.unanswered, ["unanswered"]);
        beat.seq = 2;
        let again = applied(
            store
                .reconcile_node(&beat, |_| Some((vec![2], 7)), |_, _| None)
                .await
                .unwrap(),
        );
        assert!(again.restated.is_empty());
    }

    /// The last time an old-build node was heard from starts at the upgrade,
    /// only moves forward, and survives the nodes being forgotten.
    #[tokio::test]
    async fn a_pre_casync_node_is_remembered_past_the_nodes_table() {
        let store = Store::open_in_memory().await.unwrap();
        let seeded = store.pre_casync_seen_at().await.unwrap();
        assert!(seeded > 0);
        store.note_pre_casync_node(seeded + 10).await.unwrap();
        store.note_pre_casync_node(seeded + 5).await.unwrap();
        assert_eq!(store.pre_casync_seen_at().await.unwrap(), seeded + 10);
        assert!(
            store
                .change_address_pool("100.64.0.0/16", "fd00::/48", 256)
                .await
                .unwrap()
        );
        assert_eq!(store.pre_casync_seen_at().await.unwrap(), seeded + 10);
    }

    /// A store starts on the pool fleets had before it was configurable, and
    /// changes it only while no sandbox is placed, forgetting every node.
    #[tokio::test]
    async fn the_address_pool_changes_only_while_nothing_is_placed() {
        let store = Store::open_in_memory().await.unwrap();
        assert_eq!(
            store.address_pool().await.unwrap(),
            ("10.99.0.0/16".into(), "fd99:b070::/48".into(), 256)
        );
        let node = NodeRow {
            id: "n1".into(),
            ..Default::default()
        };
        store.register_node(&node, None, 8).await.unwrap();
        store
            .insert_placement(&placed("sbx_a", "n1", 1))
            .await
            .unwrap();
        assert!(
            !store
                .change_address_pool("100.64.0.0/16", "fd00::/48", 1024)
                .await
                .unwrap()
        );
        assert_eq!(store.address_pool().await.unwrap().2, 256);
        assert_eq!(store.list_nodes().await.unwrap().len(), 1);

        store.remove_placement("sbx_a").await.unwrap();
        assert!(
            store
                .change_address_pool("100.64.0.0/16", "fd00::/48", 1024)
                .await
                .unwrap()
        );
        assert_eq!(
            store.address_pool().await.unwrap(),
            ("100.64.0.0/16".into(), "fd00::/48".into(), 1024)
        );
        assert!(store.list_nodes().await.unwrap().is_empty());
    }

    /// The reservation checks a node's capacity, which carries its
    /// overcommit, rather than its cores.
    #[tokio::test]
    async fn capacity_is_reserved_up_to_the_overcommitted_cpu() {
        let store = Store::open_in_memory().await.unwrap();
        let node = NodeRow {
            id: "n1".into(),
            cpu_capacity_millis: 16_000,
            ..Default::default()
        };
        store.register_node(&node, None, 8).await.unwrap();
        let beat = NodeReport {
            node: NodeRow {
                committed_cpu_millis: 14_000,
                free_mem_mib: 4096,
                ..node.clone()
            },
            seq: 1,
            ..Default::default()
        };
        store
            .reconcile_node(&beat, |_| None, |_, _| None)
            .await
            .unwrap();
        assert!(store.reserve_capacity("n1", 1000, 128).await.unwrap());
        assert!(store.reserve_capacity("n1", 1000, 128).await.unwrap());
        assert!(!store.reserve_capacity("n1", 1000, 128).await.unwrap());
    }

    #[tokio::test]
    async fn a_node_is_written_off_only_by_the_current_leader_while_silent() {
        let store = Store::open_in_memory().await.unwrap();
        store
            .register_node(
                &NodeRow {
                    id: "n1".into(),
                    last_heartbeat_ms: 1_000,
                    ..Default::default()
                },
                None,
                8,
            )
            .await
            .unwrap();
        assert_eq!(store.leader_epoch().await.unwrap(), 0);
        let deposed = store.next_leader_epoch().await.unwrap();
        let current = store.next_leader_epoch().await.unwrap();
        assert_eq!(store.leader_epoch().await.unwrap(), current);
        assert!(store.insert_placement(&placed("a", "n1", 1)).await.unwrap());
        let lose = |_: &PlacementRow| None;
        assert!(
            store
                .write_off_node("n1", 2_000, deposed, lose)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .write_off_node("n1", 500, current, lose)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.get_placement("a").await.unwrap().is_some());
        let lost = store
            .write_off_node("n1", 2_000, current, lose)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lost.len(), 1);
        assert!(store.get_placement("a").await.unwrap().is_none());
        assert!(store.list_nodes().await.unwrap().is_empty());
    }
}
