//! Durable state for burrow.
//!
//! SQLite behind a blocking-pool actor: the daemons are single-node processes
//! whose write rate is bounded by sandbox lifecycle events, so a connection
//! pool and an async driver would add machinery without buying anything.
//!
//! Both tiers use this crate with different tables. The orchestrator stores which
//! sandbox lives on which node; a node stores everything needed to reattach to
//! its own sandboxes after a restart: the address lease, the tap name, and
//! the published ports, none of which can be re-derived.
//!

use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
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
    /// `[(host_port, guest_port)]`.
    pub ports: Vec<(u16, u16)>,
    /// The sandbox's tailcat share, if it has one.
    pub share: Option<ShareRow>,
    /// Unix seconds the sandbox entered SUSPENDED; 0 while it is running.
    /// Persisted because `suspended_ttl_secs` is measured from it, and a node
    /// restart that reset it would let a sandbox outlive its retention forever.
    pub suspended_at: i64,
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
    /// Guest UDP ports admitted; `all_udp` admits every one. Absent from rows
    /// written before UDP shares existed, which admitted none.
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    #[serde(default)]
    pub all_udp: bool,
    /// Source each connection from the last pong-verified public IPv4.
    /// Rows written before this existed take today's default rather than
    /// silently keeping the old behaviour.
    #[serde(default = "yes")]
    pub transparent_ip: bool,
}

fn yes() -> bool {
    true
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

/// One recorded egress attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressRow {
    pub at: String,
    pub sandbox_id: String,
    pub source_ip: String,
    pub destination: String,
    pub host: String,
    pub port: u32,
    pub allowed: bool,
    pub reason: String,
    pub bytes_sent: i64,
    pub bytes_received: i64,
}

#[derive(Debug, Clone, Default)]
pub struct EgressFilter {
    pub sandbox_id: Option<String>,
    /// Only records the proxy refused.
    pub denied_only: bool,
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
#[derive(Debug, Clone)]
pub struct TombstoneRow {
    pub sandbox_id: String,
    pub node_id: String,
    /// Unix seconds the delete was accepted, so tombstones can age out.
    pub at: i64,
}

pub struct Store {
    conn: std::sync::Mutex<Connection>,
}

/// Creates the database file with restrictive permissions if it does not
/// already exist, and tightens it if it does.
///
/// Best effort: a store that cannot be made private is still a working store,
/// and refusing to start over it would take the whole daemon down.
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

impl Store {
    /// Opens (creating if needed) the database and applies the schema.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
            restrict(parent, 0o700);
        }
        // The database holds tenant policies, placements and the egress audit
        // trail, so it is created private rather than inheriting the umask.
        // and created *here*, before sqlite touches it, so it is never briefly
        // world-readable. The directory is locked down too, since sqlite's own
        // `-wal` and `-shm` sidecars are created by the library with default
        // permissions.
        precreate(path, 0o600);
        let conn = Connection::open(path)?;
        // WAL keeps readers from blocking the writer; NORMAL is the usual
        // durability/throughput trade for WAL and is right for state that is
        // reconciled against reality on startup anyway.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn);
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    pub fn put_sandbox(&self, row: &SandboxRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sandboxes
                (id, template, record, state, lease_block, tap, ports_json, suspended_at, share_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                template=excluded.template, record=excluded.record,
                state=excluded.state, lease_block=excluded.lease_block,
                tap=excluded.tap, ports_json=excluded.ports_json,
                suspended_at=excluded.suspended_at, share_json=excluded.share_json",
            rusqlite::params![
                row.id,
                row.template,
                row.record,
                row.state,
                row.lease_block,
                row.tap,
                serde_json::to_string(&row.ports)?,
                row.suspended_at,
                match &row.share {
                    Some(share) => serde_json::to_string(share)?,
                    None => String::new(),
                },
            ],
        )?;
        Ok(())
    }

    pub fn set_sandbox_state(&self, id: &str, state: i32, record: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sandboxes SET state=?2, record=?3 WHERE id=?1",
            rusqlite::params![id, state, record],
        )?;
        Ok(())
    }

    pub fn delete_sandbox(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sandboxes WHERE id=?1", [id])?;
        Ok(())
    }

    pub fn list_sandboxes(&self) -> Result<Vec<SandboxRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, template, record, state, lease_block, tap, ports_json, suspended_at, share_json
             FROM sandboxes ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let ports_json: String = row.get(6)?;
                let share_json: String = row.get(8)?;
                Ok((
                    SandboxRow {
                        id: row.get(0)?,
                        template: row.get(1)?,
                        record: row.get(2)?,
                        state: row.get(3)?,
                        lease_block: row.get(4)?,
                        tap: row.get(5)?,
                        ports: Vec::new(),
                        share: None,
                        suspended_at: row.get(7)?,
                    },
                    ports_json,
                    share_json,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        rows.into_iter()
            .map(|(mut row, ports_json, share_json)| {
                row.ports = serde_json::from_str(&ports_json).unwrap_or_default();
                row.share = serde_json::from_str(&share_json).ok();
                Ok(row)
            })
            .collect()
    }

    pub fn put_session(&self, row: &SessionRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, sandbox_id, started_at, ended_at, started_by, ended_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                ended_at=excluded.ended_at, ended_by=excluded.ended_by",
            rusqlite::params![
                row.id,
                row.sandbox_id,
                row.started_at,
                row.ended_at,
                row.started_by,
                row.ended_by,
            ],
        )?;
        Ok(())
    }

    /// Marks one session closed. `ended_at` of 0 records that the session
    /// ended without anything observing when.
    pub fn end_session(&self, id: &str, ended_at: i64, ended_by: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET ended_at=?2, ended_by=?3 WHERE id=?1 AND ended_by=''",
            rusqlite::params![id, ended_at, ended_by],
        )?;
        Ok(())
    }

    /// Closes every session left open by a previous run of this daemon.
    ///
    /// A VMM does not survive its parent, so a session still open at startup
    /// belongs to a VM that is already gone. `ended_at` stays unset because
    /// nothing recorded when that happened.
    pub fn close_open_sessions(&self, ended_by: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute(
            "UPDATE sessions SET ended_by=?1 WHERE ended_by=''",
            [ended_by],
        )?)
    }

    /// A sandbox's sessions, newest first.
    pub fn list_sessions(&self, sandbox_id: &str) -> Result<Vec<SessionRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, sandbox_id, started_at, ended_at, started_by, ended_by
             FROM sessions WHERE sandbox_id=?1 ORDER BY started_at DESC, rowid DESC",
        )?;
        let rows = stmt
            .query_map([sandbox_id], |row| {
                Ok(SessionRow {
                    id: row.get(0)?,
                    sandbox_id: row.get(1)?,
                    started_at: row.get(2)?,
                    ended_at: row.get(3)?,
                    started_by: row.get(4)?,
                    ended_by: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Keeps only a sandbox's `keep` most recent sessions, returning how many
    /// were evicted.
    ///
    /// Applied as a session is opened, which is the one moment the count grows.
    /// A sandbox that is suspended and resumed every minute would otherwise
    /// grow this table for as long as it lives.
    pub fn retain_recent_sessions(&self, sandbox_id: &str, keep: usize) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        // Ordered by rowid as well as time, so sessions opened within the same
        // second still evict oldest-first rather than in an arbitrary order.
        Ok(conn.execute(
            "DELETE FROM sessions WHERE sandbox_id=?1 AND id NOT IN (
                SELECT id FROM sessions WHERE sandbox_id=?1
                ORDER BY started_at DESC, rowid DESC LIMIT ?2
             )",
            rusqlite::params![sandbox_id, keep as i64],
        )?)
    }

    /// Drops every session of a sandbox. Its sessions describe that sandbox's
    /// VMs and have no owner once it is gone.
    pub fn delete_sessions(&self, sandbox_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE sandbox_id=?1", [sandbox_id])?;
        Ok(())
    }

    pub fn insert_egress(&self, row: &EgressRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_egress
               (at, sandbox_id, source_ip, destination, host, port, allowed, reason,
                bytes_sent, bytes_received)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                row.at,
                row.sandbox_id,
                row.source_ip,
                row.destination,
                row.host,
                row.port,
                row.allowed,
                row.reason,
                row.bytes_sent,
                row.bytes_received,
            ],
        )?;
        Ok(())
    }

    /// Most recent egress records first, optionally narrowed.
    pub fn query_egress(&self, filter: &EgressFilter) -> Result<Vec<EgressRow>> {
        let conn = self.conn.lock().unwrap();
        // Predicates are fixed strings with bound parameters; the filter never
        // reaches the SQL text.
        let mut sql = String::from(
            "SELECT at, sandbox_id, source_ip, destination, host, port, allowed, reason,
                    bytes_sent, bytes_received
             FROM audit_egress WHERE 1=1",
        );
        if filter.sandbox_id.is_some() {
            sql.push_str(" AND sandbox_id = :sandbox_id");
        }
        if filter.denied_only {
            sql.push_str(" AND allowed = 0");
        }
        if filter.since.is_some() {
            sql.push_str(" AND at >= :since");
        }
        sql.push_str(" ORDER BY id DESC LIMIT :limit");

        let mut stmt = conn.prepare(&sql)?;
        let limit = if filter.limit == 0 { 100 } else { filter.limit };
        let mut params: Vec<(&str, &dyn rusqlite::ToSql)> = vec![(":limit", &limit)];
        if let Some(id) = &filter.sandbox_id {
            params.push((":sandbox_id", id));
        }
        if let Some(since) = &filter.since {
            params.push((":since", since));
        }

        let rows = stmt
            .query_map(params.as_slice(), |row| {
                Ok(EgressRow {
                    at: row.get(0)?,
                    sandbox_id: row.get(1)?,
                    source_ip: row.get(2)?,
                    destination: row.get(3)?,
                    host: row.get(4)?,
                    port: row.get(5)?,
                    allowed: row.get(6)?,
                    reason: row.get(7)?,
                    bytes_sent: row.get(8)?,
                    bytes_received: row.get(9)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Drops audit records older than `cutoff`, returning how many.
    ///
    /// Audit volume is unbounded otherwise: a busy sandbox can generate
    /// thousands of records a minute and nothing else would ever remove them.
    pub fn prune_egress(&self, cutoff: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM audit_egress WHERE at < ?1", [cutoff])?)
    }

    pub fn put_placement(&self, row: &PlacementRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO placements (id, node_id, record) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                node_id=excluded.node_id, record=excluded.record",
            rusqlite::params![row.id, row.node_id, row.record],
        )?;
        Ok(())
    }

    pub fn delete_placement(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM placements WHERE id=?1", [id])?;
        Ok(())
    }

    /// Drops every placement on a node. Used when a node re-registers, since
    /// its sandboxes did not survive whatever restarted it.
    pub fn delete_placements_for_node(&self, node_id: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM placements WHERE node_id=?1", [node_id])?)
    }

    pub fn list_placements(&self) -> Result<Vec<PlacementRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, node_id, record FROM placements ORDER BY id")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PlacementRow {
                    id: row.get(0)?,
                    node_id: row.get(1)?,
                    record: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn put_tombstone(&self, row: &TombstoneRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tombstones (sandbox_id, node_id, at) VALUES (?1, ?2, ?3)
             ON CONFLICT(sandbox_id) DO UPDATE SET
                node_id=excluded.node_id, at=excluded.at",
            rusqlite::params![row.sandbox_id, row.node_id, row.at],
        )?;
        Ok(())
    }

    pub fn delete_tombstone(&self, sandbox_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM tombstones WHERE sandbox_id=?1", [sandbox_id])?;
        Ok(())
    }

    pub fn list_tombstones(&self) -> Result<Vec<TombstoneRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT sandbox_id, node_id, at FROM tombstones ORDER BY sandbox_id")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(TombstoneRow {
                    sandbox_id: row.get(0)?,
                    node_id: row.get(1)?,
                    at: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Drops tombstones recorded before `cutoff` (unix seconds), returning how
    /// many. A node that never comes back must not accumulate them forever.
    pub fn prune_tombstones(&self, cutoff: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.execute("DELETE FROM tombstones WHERE at < ?1", [cutoff])?)
    }
}

/// Columns added after the schema first shipped.
///
/// `CREATE TABLE IF NOT EXISTS` leaves an existing database on the old shape,
/// so a column added later has to be added explicitly. Each statement is
/// expected to fail with "duplicate column" on a database that already has it,
/// which is why the result is discarded rather than checked.
fn migrate(conn: &Connection) {
    const ADDED_COLUMNS: &[&str] = &[
        "ALTER TABLE sandboxes ADD COLUMN suspended_at INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE sandboxes ADD COLUMN share_json TEXT NOT NULL DEFAULT ''",
    ];
    for statement in ADDED_COLUMNS {
        let _ = conn.execute(statement, []);
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sandboxes (
    id           TEXT PRIMARY KEY,
    template     TEXT NOT NULL,
    record       BLOB NOT NULL,
    state        INTEGER NOT NULL,
    lease_block  INTEGER NOT NULL,
    tap          TEXT NOT NULL,
    ports_json   TEXT NOT NULL DEFAULT '[]',
    suspended_at INTEGER NOT NULL DEFAULT 0,
    share_json   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    sandbox_id   TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER NOT NULL DEFAULT 0,
    started_by   TEXT NOT NULL,
    ended_by     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_by_sandbox ON sessions(sandbox_id, started_at DESC);
CREATE TABLE IF NOT EXISTS placements (
    id           TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    record       BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS placements_by_node ON placements(node_id);
CREATE TABLE IF NOT EXISTS tombstones (
    sandbox_id   TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tombstones_by_node ON tombstones(node_id);
CREATE TABLE IF NOT EXISTS audit_egress (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at             TEXT NOT NULL,
    sandbox_id     TEXT NOT NULL,
    source_ip      TEXT NOT NULL,
    destination    TEXT NOT NULL,
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    allowed        INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    bytes_sent     INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_sandbox ON audit_egress(sandbox_id, id DESC);
CREATE INDEX IF NOT EXISTS audit_by_time ON audit_egress(at);
";

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, block: u32) -> SandboxRow {
        SandboxRow {
            id: id.into(),
            template: "default".into(),
            record: Vec::new(),
            state: 2,
            lease_block: block,
            tap: format!("bt{block}"),
            ports: vec![(20000, 8000)],
            share: None,
            suspended_at: 0,
        }
    }

    #[test]
    fn a_share_survives_a_reload() {
        let store = Store::open_in_memory().unwrap();
        let mut shared = row("sbx_a", 1);
        shared.share = Some(ShareRow {
            key: "privkey:00".into(),
            preshared_key: "psk:00".into(),
            ports: vec![22, 8080],
            allowed_clients: vec!["nodekey:11".into()],
            created_at: 1_800_000_000,
            udp_ports: vec![53],
            all_udp: false,
            transparent_ip: true,
        });
        store.put_sandbox(&shared).unwrap();
        store.put_sandbox(&row("sbx_b", 2)).unwrap();
        let rows = store.list_sandboxes().unwrap();
        assert_eq!(rows[0].share, shared.share);
        assert_eq!(rows[1].share, None);
    }

    /// A share persisted before `transparent_ip` existed still loads, taking
    /// the current default, and a `proxy_protocol` field written by an older
    /// daemon is ignored.
    #[test]
    fn an_old_share_without_transparent_ip_loads() {
        let json = r#"{
            "key":"privkey:00",
            "preshared_key":"psk:00",
            "ports":[22],
            "allowed_clients":[],
            "proxy_protocol":false,
            "created_at":1
        }"#;
        let row: ShareRow = serde_json::from_str(json).unwrap();
        assert!(row.transparent_ip, "an old row takes today's default");
        assert!(!row.all_udp);
        assert!(row.udp_ports.is_empty());
    }

    /// `suspended_ttl_secs` is measured from this, so a restart that lost it
    /// would either delete everything at once or never.
    #[test]
    fn the_suspension_timestamp_survives_a_reload() {
        let store = Store::open_in_memory().unwrap();
        let mut suspended = row("sbx_a", 1);
        suspended.state = 4;
        suspended.suspended_at = 1_800_000_000;
        store.put_sandbox(&suspended).unwrap();
        assert_eq!(
            store.list_sandboxes().unwrap()[0].suspended_at,
            1_800_000_000
        );
    }

    #[test]
    fn sandboxes_round_trip_including_ports() {
        let store = Store::open_in_memory().unwrap();
        store.put_sandbox(&row("sbx_a", 1)).unwrap();
        let listed = store.list_sandboxes().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].lease_block, 1);
        assert_eq!(listed[0].tap, "bt1");
        assert_eq!(listed[0].ports, vec![(20000, 8000)]);
    }

    #[test]
    fn writing_the_same_sandbox_twice_updates_rather_than_duplicates() {
        let store = Store::open_in_memory().unwrap();
        store.put_sandbox(&row("sbx_a", 1)).unwrap();
        let mut updated = row("sbx_a", 1);
        updated.state = 4;
        store.put_sandbox(&updated).unwrap();
        let listed = store.list_sandboxes().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, 4);
    }

    #[test]
    fn state_changes_are_persisted_on_their_own() {
        let store = Store::open_in_memory().unwrap();
        store.put_sandbox(&row("sbx_a", 1)).unwrap();
        store
            .set_sandbox_state("sbx_a", 4, b"\x01\x02".as_slice())
            .unwrap();
        let listed = store.list_sandboxes().unwrap();
        assert_eq!(listed[0].state, 4);
        assert_eq!(listed[0].record, b"\x01\x02".as_slice());
    }

    #[test]
    fn deleting_removes_the_row() {
        let store = Store::open_in_memory().unwrap();
        store.put_sandbox(&row("sbx_a", 1)).unwrap();
        store.delete_sandbox("sbx_a").unwrap();
        assert!(store.list_sandboxes().unwrap().is_empty());
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

    #[test]
    fn sessions_come_back_newest_first_per_sandbox() {
        let store = Store::open_in_memory().unwrap();
        store.put_session(&session("s1", "sbx_a", 100)).unwrap();
        store.put_session(&session("s2", "sbx_a", 200)).unwrap();
        store.put_session(&session("s3", "sbx_b", 300)).unwrap();

        let listed = store.list_sessions("sbx_a").unwrap();
        assert_eq!(
            listed.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["s2", "s1"]
        );
        assert_eq!(store.list_sessions("sbx_b").unwrap().len(), 1);
        assert!(store.list_sessions("sbx_missing").unwrap().is_empty());
    }

    /// A sandbox suspended and resumed on a loop would otherwise grow this
    /// table for as long as it lives, so the oldest go first, and only that
    /// sandbox's.
    #[test]
    fn retention_evicts_the_oldest_sessions_of_that_sandbox_only() {
        let store = Store::open_in_memory().unwrap();
        for i in 0..10 {
            store
                .put_session(&session(&format!("s{i}"), "sbx_a", 100 + i))
                .unwrap();
        }
        store.put_session(&session("other", "sbx_b", 1)).unwrap();

        assert_eq!(store.retain_recent_sessions("sbx_a", 4).unwrap(), 6);
        let left = store.list_sessions("sbx_a").unwrap();
        assert_eq!(
            left.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["s9", "s8", "s7", "s6"]
        );
        assert_eq!(store.list_sessions("sbx_b").unwrap().len(), 1);

        // Already within the bound: nothing to give up.
        assert_eq!(store.retain_recent_sessions("sbx_a", 4).unwrap(), 0);
    }

    /// Sessions opened inside the same second still evict oldest-first, or a
    /// burst of resumes would drop an arbitrary subset.
    #[test]
    fn sessions_sharing_a_timestamp_evict_in_insertion_order() {
        let store = Store::open_in_memory().unwrap();
        for i in 0..5 {
            store
                .put_session(&session(&format!("s{i}"), "sbx_a", 100))
                .unwrap();
        }
        store.retain_recent_sessions("sbx_a", 2).unwrap();
        let left = store.list_sessions("sbx_a").unwrap();
        assert_eq!(
            left.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["s4", "s3"]
        );
    }

    /// A VMM does not survive the daemon, so a session still open on startup
    /// belongs to a VM that is gone. Nothing observed when, which is why the
    /// end time stays unset rather than being backfilled with "now".
    #[test]
    fn sessions_open_at_startup_are_closed_without_an_end_time() {
        let store = Store::open_in_memory().unwrap();
        store.put_session(&session("s1", "sbx_a", 100)).unwrap();
        let mut closed = session("s2", "sbx_a", 200);
        closed.ended_at = 250;
        closed.ended_by = "suspended".into();
        store.put_session(&closed).unwrap();

        assert_eq!(store.close_open_sessions("unknown").unwrap(), 1);
        let listed = store.list_sessions("sbx_a").unwrap();
        let open = listed.iter().find(|s| s.id == "s1").unwrap();
        assert_eq!(open.ended_by, "unknown");
        assert_eq!(open.ended_at, 0);
        // An already-closed session keeps the reason it was closed with.
        let done = listed.iter().find(|s| s.id == "s2").unwrap();
        assert_eq!(done.ended_by, "suspended");
        assert_eq!(done.ended_at, 250);
    }

    #[test]
    fn closing_a_session_twice_keeps_the_first_reason() {
        let store = Store::open_in_memory().unwrap();
        store.put_session(&session("s1", "sbx_a", 100)).unwrap();
        store.end_session("s1", 150, "suspended").unwrap();
        store.end_session("s1", 999, "deleted").unwrap();
        let row = &store.list_sessions("sbx_a").unwrap()[0];
        assert_eq!(row.ended_by, "suspended");
        assert_eq!(row.ended_at, 150);
    }

    #[test]
    fn deleting_a_sandbox_takes_its_sessions() {
        let store = Store::open_in_memory().unwrap();
        store.put_session(&session("s1", "sbx_a", 100)).unwrap();
        store.put_session(&session("s2", "sbx_b", 100)).unwrap();
        store.delete_sessions("sbx_a").unwrap();
        assert!(store.list_sessions("sbx_a").unwrap().is_empty());
        assert_eq!(store.list_sessions("sbx_b").unwrap().len(), 1);
    }

    fn egress(sandbox: &str, allowed: bool, at: &str) -> EgressRow {
        EgressRow {
            at: at.into(),
            sandbox_id: sandbox.into(),
            source_ip: "10.99.0.6".into(),
            destination: "1.2.3.4:443".into(),
            host: "example.com".into(),
            port: 443,
            allowed,
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

    #[test]
    fn egress_records_come_back_newest_first() {
        let store = Store::open_in_memory().unwrap();
        store
            .insert_egress(&egress("a", true, "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .insert_egress(&egress("a", false, "2026-01-02T00:00:00Z"))
            .unwrap();
        let rows = store.query_egress(&EgressFilter::default()).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].at, "2026-01-02T00:00:00Z");
    }

    #[test]
    fn egress_can_be_filtered() {
        let store = Store::open_in_memory().unwrap();
        store
            .insert_egress(&egress("a", true, "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .insert_egress(&egress("b", false, "2026-01-02T00:00:00Z"))
            .unwrap();

        let by_sandbox = store
            .query_egress(&EgressFilter {
                sandbox_id: Some("a".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(by_sandbox.len(), 1);

        let denied = store
            .query_egress(&EgressFilter {
                denied_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(denied.len(), 1);
        assert!(!denied[0].allowed);

        let since = store
            .query_egress(&EgressFilter {
                since: Some("2026-01-02T00:00:00Z".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(since.len(), 1);
    }

    #[test]
    fn pruning_removes_only_old_records() {
        let store = Store::open_in_memory().unwrap();
        store
            .insert_egress(&egress("a", true, "2026-01-01T00:00:00Z"))
            .unwrap();
        store
            .insert_egress(&egress("a", true, "2026-06-01T00:00:00Z"))
            .unwrap();
        assert_eq!(store.prune_egress("2026-03-01T00:00:00Z").unwrap(), 1);
        assert_eq!(
            store.query_egress(&EgressFilter::default()).unwrap().len(),
            1
        );
    }

    /// The file holds tenant policies and the egress audit trail, so it must
    /// not be readable by every account on the host.
    #[test]
    #[cfg(unix)]
    fn the_database_and_its_directory_are_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("burrow-store-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state.db");
        let store = Store::open(&path).unwrap();
        store
            .put_placement(&PlacementRow {
                id: "a".into(),
                node_id: "n1".into(),
                record: Vec::new(),
            })
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

    #[test]
    fn placements_can_be_dropped_per_node() {
        let store = Store::open_in_memory().unwrap();
        for (id, node) in [("a", "n1"), ("b", "n1"), ("c", "n2")] {
            store
                .put_placement(&PlacementRow {
                    id: id.into(),
                    node_id: node.into(),
                    record: Vec::new(),
                })
                .unwrap();
        }
        assert_eq!(store.delete_placements_for_node("n1").unwrap(), 2);
        let left = store.list_placements().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].node_id, "n2");
    }

    /// A delete accepted while the node was down has to outlive the process
    /// that accepted it, or a node returning days later is simply re-adopted.
    #[test]
    fn tombstones_round_trip_and_can_be_cleared() {
        let store = Store::open_in_memory().unwrap();
        store
            .put_tombstone(&TombstoneRow {
                sandbox_id: "sbx_a".into(),
                node_id: "n1".into(),
                at: 1_800_000_000,
            })
            .unwrap();
        let listed = store.list_tombstones().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].node_id, "n1");
        assert_eq!(listed[0].at, 1_800_000_000);

        store.delete_tombstone("sbx_a").unwrap();
        assert!(store.list_tombstones().unwrap().is_empty());
    }

    /// A node that never returns must not leave its tombstones behind forever.
    #[test]
    fn old_tombstones_are_pruned() {
        let store = Store::open_in_memory().unwrap();
        for (id, at) in [("old", 1_000), ("new", 9_000)] {
            store
                .put_tombstone(&TombstoneRow {
                    sandbox_id: id.into(),
                    node_id: "n1".into(),
                    at,
                })
                .unwrap();
        }
        assert_eq!(store.prune_tombstones(5_000).unwrap(), 1);
        let left = store.list_tombstones().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].sandbox_id, "new");
    }
}
