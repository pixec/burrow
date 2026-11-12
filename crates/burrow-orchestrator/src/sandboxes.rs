//! The orchestrator's sandbox registry: which sandbox lives on which node.
//!
//! Nodes stay authoritative: whatever a node reports replaces what is held
//! here. The store behind it covers only the case nodes cannot, a whole
//! fleet restarting at once.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use burrow_proto::common::v1 as common;

use crate::persist::{Change, Guard};

/// Placements are stored as encoded protobuf, so the record on disk is the
/// same shape as the one on the wire and cannot drift from it.
pub(crate) fn encode(sandbox: &common::Sandbox) -> Vec<u8> {
    use prost::Message as _;
    sandbox.encode_to_vec()
}

pub(crate) fn decode(bytes: &[u8]) -> Option<common::Sandbox> {
    use prost::Message as _;
    common::Sandbox::decode(bytes).ok()
}

/// The name a member answers to, defaulting to its sandbox id.
///
/// An id always works, so a sandbox is addressable without anyone having
/// chosen a name for it; an alias is what makes the address memorable.
fn alias_of(membership: &common::NetworkMembership, sandbox_id: &str) -> String {
    if membership.alias.is_empty() {
        sandbox_id.to_string()
    } else {
        membership.alias.clone()
    }
}

/// How long a freshly created sandbox is immune to being forgotten by a
/// heartbeat.
///
/// It covers a report sampled before the sandbox existed and only now
/// arriving: one heartbeat interval of sampling lag plus flight time. Wide,
/// because being wrong the other way only keeps a deleted sandbox's record for
/// one more heartbeat.
const SETTLING_GRACE: Duration = Duration::from_secs(30);

/// Whether a sandbox can be taken up by another node: suspended, with its
/// latest suspend in the object store, or running with a checkpoint there.
pub fn is_movable(sandbox: &common::Sandbox) -> bool {
    (sandbox.state == common::SandboxState::Suspended as i32 && sandbox.is_durable)
        || sandbox.checkpoint_at_unix_ms > 0
}

/// Restates a sandbox whose node was written off as what its checkpoint
/// brings back: stopped on a disk checkpoint, which a start boots, or
/// suspended on a memory one, which a resume restores. The reason says how
/// old the checkpoint is, and so what was lost.
pub(crate) fn lost_to_checkpoint(sandbox: &mut common::Sandbox, node_id: &str) {
    if sandbox.checkpoint_at_unix_ms == 0 || sandbox.state == common::SandboxState::Suspended as i32
    {
        return;
    }
    let is_memory = sandbox.checkpoint_kind == common::CheckpointKind::Memory as i32;
    sandbox.state = match is_memory {
        true => common::SandboxState::Suspended,
        false => common::SandboxState::Stopped,
    } as i32;
    sandbox.state_reason = format!(
        "node {node_id} was lost; recovers from its {} checkpoint of {}, and what it did after \
         that is gone",
        if is_memory { "memory" } else { "disk" },
        burrow_common::rfc3339_from_unix_secs(sandbox.checkpoint_at_unix_ms / 1000),
    );
}

/// What a heartbeat's state report changed. See [`SandboxRegistry::apply_states`].
#[derive(Debug, Default)]
pub struct Applied {
    /// Sandboxes whose state the node moved on its own.
    pub restated: usize,
    /// Placements dropped because the node no longer lists them.
    pub forgotten: usize,
    /// Ids the node lists that this registry holds no placement for.
    pub unknown: Vec<String>,
    /// Fenced sandboxes the node still holds the placement of.
    pub confirmed: Vec<String>,
    /// Fenced sandboxes another node adopted while this one was away.
    pub relinquished: Vec<String>,
    /// Ids the node still holds that a caller already deleted, for the
    /// caller to destroy there.
    pub tombstoned: Vec<String>,
}

/// How long a tombstone is kept before it is assumed no longer needed.
///
/// A node that comes back inside this window has its copy of the sandbox
/// destroyed; one that never comes back would otherwise leave the record here
/// forever.
pub const TOMBSTONE_TTL_SECS: i64 = 30 * 86_400;

/// How long a tombstoned sandbox's delete is left to run before a heartbeat
/// may send another.
const TOMBSTONE_DELETE_HOLD: Duration = Duration::from_secs(150);
/// The wait after a tombstoned sandbox's first failed delete, doubling up to
/// [`MAX_TOMBSTONE_RETRY`].
const TOMBSTONE_RETRY: Duration = Duration::from_secs(5);
const MAX_TOMBSTONE_RETRY: Duration = Duration::from_secs(300);

/// A delete that was accepted while the hosting node was unreachable.
#[derive(Debug, Clone)]
pub struct Tombstone {
    pub node_id: String,
    /// Unix seconds the delete was accepted.
    pub at: i64,
}

/// What a reconcile did with a node's reported inventory.
#[derive(Debug, Default)]
pub struct Reconciled {
    pub adopted: usize,
    pub forgotten: usize,
    /// Reported sandboxes a caller already deleted while this node was down.
    /// Not adopted; the caller destroys them on the node instead.
    pub tombstoned: Vec<String>,
}

#[derive(Default)]
pub struct SandboxRegistry {
    sandboxes: Mutex<HashMap<String, common::Sandbox>>,
    /// Sandboxes deleted while their node was unreachable, by sandbox id.
    ///
    /// The delete could not reach the node, so the placement was dropped on
    /// the orchestrator's word alone. This is what stops the node re-asserting
    /// the sandbox into existence if it ever comes back.
    tombstones: Mutex<HashMap<String, Tombstone>>,
    /// Per tombstoned id a heartbeat reported, the deletes that failed and
    /// when the next may be sent.
    tombstone_deletes: Mutex<HashMap<String, (u32, Instant)>>,
    /// Ids whose create is in flight.
    ///
    /// A record only enters `sandboxes` once its node has built the sandbox,
    /// which leaves a window of a second or two where a second create of the
    /// same caller-chosen id sees nothing and is placed too, on another node
    /// where the node's own duplicate check cannot see it either. Claiming the
    /// id here closes that window.
    creating: Mutex<HashSet<String>>,
    /// Names whose create is in flight, held for the same reason as `creating`.
    naming: Mutex<HashSet<String>>,
    /// Request ids whose create is in flight here, and the sandbox id each
    /// is building.
    requesting: Mutex<HashMap<String, String>>,
    /// Unplaced sandboxes being handed to a node, so two starts of one cannot
    /// give it to two.
    adopting: Mutex<HashSet<String>>,
    /// Ids whose create finished too recently to trust a heartbeat about them.
    ///
    /// A node samples its inventory and then sends it, so a sandbox created
    /// after the sample is simply not in the report. Reading that as "the node
    /// no longer has it" destroys the record of a sandbox that is running, and
    /// whose id the caller already holds. The id sits here for a grace window
    /// instead, after which the node has had a chance to list it.
    settling: Mutex<HashMap<String, Instant>>,
    /// Survives a restart of the whole fleet, the one case nodes cannot cover,
    /// and is what other orchestrator replicas read this one's changes from.
    store: Option<Arc<burrow_store::Store>>,
    /// Applies this registry's writes to `store`, in the order it made them.
    writer: Option<crate::persist::Writer>,
    /// When each sandbox's usage was last written, so usage, which moves on
    /// every heartbeat, reaches other replicas without a write per beat.
    usage_written: Mutex<HashMap<String, Instant>>,
    /// When the last applied reload started reading, held across a reload so
    /// callers arriving together share one read of the store.
    reloaded: tokio::sync::Mutex<Option<Instant>>,
}

/// How often a sandbox's usage figures are written back for other replicas.
const USAGE_WRITE_INTERVAL: Duration = Duration::from_secs(30);

impl SandboxRegistry {
    /// Opens a registry backed by durable storage, restoring what it holds.
    pub async fn with_store(store: Arc<burrow_store::Store>) -> Self {
        let mut sandboxes = HashMap::new();
        match store.list_placements().await {
            Ok(rows) => {
                for row in rows {
                    match decode(&row.record) {
                        Some(sandbox) => {
                            sandboxes.insert(sandbox.id.clone(), sandbox);
                        }
                        None => tracing::warn!(
                            sandbox = row.id,
                            "discarding an unreadable placement record"
                        ),
                    }
                }
                if !sandboxes.is_empty() {
                    tracing::info!(
                        count = sandboxes.len(),
                        "restored placements from the store"
                    );
                }
            }
            Err(err) => tracing::error!(%err, "could not read stored placements"),
        }

        let mut tombstones = HashMap::new();
        match store.list_tombstones().await {
            Ok(rows) => {
                for row in rows {
                    tombstones.insert(
                        row.sandbox_id,
                        Tombstone {
                            node_id: row.node_id,
                            at: row.at,
                        },
                    );
                }
                if !tombstones.is_empty() {
                    tracing::info!(
                        count = tombstones.len(),
                        "restored tombstones for sandboxes deleted while their node was down"
                    );
                }
            }
            Err(err) => tracing::error!(%err, "could not read stored tombstones"),
        }

        Self {
            sandboxes: Mutex::new(sandboxes),
            tombstones: Mutex::new(tombstones),
            tombstone_deletes: Mutex::new(HashMap::new()),
            creating: Mutex::new(HashSet::new()),
            naming: Mutex::new(HashSet::new()),
            requesting: Mutex::new(HashMap::new()),
            adopting: Mutex::new(HashSet::new()),
            settling: Mutex::new(HashMap::new()),
            writer: Some(crate::persist::Writer::spawn(Arc::clone(&store))),
            store: Some(store),
            usage_written: Mutex::new(HashMap::new()),
            reloaded: tokio::sync::Mutex::new(None),
        }
    }

    fn write(&self, op: crate::persist::Op) {
        if let Some(writer) = &self.writer {
            writer.send(op);
        }
    }

    /// Claims an id and a name in the store, so no other orchestrator replica
    /// can create the same ones, after claiming them in this process.
    ///
    /// The local claim comes first because it is free and covers the common
    /// case; the store's claim is the one that holds across replicas. A
    /// registry without a store is a single process and the local claim is
    /// all there is.
    pub async fn reserve_claimed(&self, id: &str, name: &str) -> Result<Reservation<'_>, String> {
        let reservation = self.reserve(id, name)?;
        let Some(store) = &self.store else {
            return Ok(reservation);
        };
        let now = burrow_common::unix_now();
        let mut keys = vec![(crate::persist::id_key(id), format!("sandbox {id} exists"))];
        if !name.is_empty() {
            keys.push((
                crate::persist::name_key(name),
                format!("a sandbox named {name} exists"),
            ));
        }
        for (key, taken) in keys {
            match store.claim(&key, id, now).await {
                Ok(true) => {}
                // Dropping the reservation releases whatever was claimed.
                Ok(false) => return Err(taken),
                Err(err) => return Err(format!("could not claim {key}: {err}")),
            }
        }
        Ok(reservation)
    }

    /// Claims a create's request id for `id`, here and in the store, so a
    /// retry of it through any replica waits for this create rather than
    /// making a second sandbox.
    pub async fn claim_request(
        &self,
        request: &str,
        id: &str,
    ) -> Result<RequestClaim<'_>, RequestTaken> {
        {
            let mut requesting = self.requesting.lock().unwrap();
            if requesting.contains_key(request) {
                return Err(RequestTaken::InFlight);
            }
            requesting.insert(request.to_string(), id.to_string());
        }
        let mut claim = RequestClaim {
            registry: self,
            request: request.to_string(),
            id: id.to_string(),
            is_stored: false,
        };
        let Some(store) = &self.store else {
            return Ok(claim);
        };
        let key = crate::persist::request_key(request);
        match store.claim(&key, id, burrow_common::unix_now()).await {
            Ok(true) => {
                claim.is_stored = true;
                Ok(claim)
            }
            Ok(false) => Err(RequestTaken::InFlight),
            Err(err) => Err(RequestTaken::Failed(format!(
                "could not claim {key}: {err}"
            ))),
        }
    }

    /// The sandbox a create with this request id made, here or through
    /// another replica.
    pub async fn by_request(&self, request: &str) -> Option<common::Sandbox> {
        let held = self
            .sandboxes
            .lock()
            .unwrap()
            .values()
            .find(|s| s.create_request_id == request)
            .cloned();
        if held.is_some() {
            return held;
        }
        let store = self.store.as_ref()?;
        let id = store
            .claim_holder(&crate::persist::request_key(request))
            .await
            .ok()
            .flatten()?;
        let row = store.get_placement(&id).await.ok().flatten()?;
        self.cache(row)
    }

    /// Replaces the cached placements and tombstones with the store's, for
    /// a replica catching up with writes other replicas made.
    ///
    /// `mark` is what this replica's writer had applied when the rows were
    /// read; if anything has been queued since, the rows may predate it and
    /// the reload is dropped rather than applied. Ids still being created
    /// here are kept as this replica has them, since their rows do not exist
    /// yet. A settled id is not: every write this replica queued has landed
    /// by the mark, so a row missing now was deleted, by another replica.
    ///
    /// A row that is new here, or names another node than this replica had,
    /// starts settling: a heartbeat sampled before another replica placed it
    /// would otherwise read as the node having let it go, and delete the row.
    pub fn reload(
        &self,
        mark: u64,
        placements: Vec<burrow_store::PlacementRow>,
        tombstones: Vec<burrow_store::TombstoneRow>,
    ) -> bool {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        if self.writer.as_ref().is_some_and(|w| w.enqueued() != mark) {
            return false;
        }
        let creating = self.creating.lock().unwrap();
        let mut settling = self.settling.lock().unwrap();
        let mut fresh: HashMap<String, common::Sandbox> = HashMap::new();
        for row in placements {
            let Some(mut sandbox) = decode(&row.record) else {
                continue;
            };
            // Usage moves on every heartbeat and is only written back now and
            // then, so a figure this replica already holds is the newer one.
            match sandboxes.get(&sandbox.id) {
                Some(held) => {
                    if held.cpu_usage_usec > sandbox.cpu_usage_usec {
                        sandbox.cpu_usage_usec = held.cpu_usage_usec;
                        sandbox.rx_bytes = held.rx_bytes;
                        sandbox.tx_bytes = held.tx_bytes;
                    }
                    if held.node_id != sandbox.node_id {
                        settling.insert(sandbox.id.clone(), Instant::now());
                    }
                }
                None => {
                    settling.insert(sandbox.id.clone(), Instant::now());
                }
            }
            fresh.insert(sandbox.id.clone(), sandbox);
        }
        for (id, sandbox) in sandboxes.iter() {
            if creating.contains(id) && !fresh.contains_key(id) {
                fresh.insert(id.clone(), sandbox.clone());
            }
        }
        *sandboxes = fresh;
        *self.tombstones.lock().unwrap() = tombstones
            .into_iter()
            .map(|row| {
                (
                    row.sandbox_id,
                    Tombstone {
                        node_id: row.node_id,
                        at: row.at,
                    },
                )
            })
            .collect();
        true
    }

    /// Catches up with the store unless a reload that started reading at or
    /// after `since` has already been applied.
    ///
    /// A caller passes when its call arrived: anything another replica
    /// finished before then is in the store by then, so such a reload saw it,
    /// and a listing does not need a read of its own. Listings arriving
    /// together, and the sync loop, share one read rather than each reading
    /// every placement.
    pub async fn reload_since(&self, since: Instant) -> burrow_store::Result<()> {
        let (Some(store), Some(writer)) = (&self.store, &self.writer) else {
            return Ok(());
        };
        let mut reloaded = self.reloaded.lock().await;
        if reloaded.is_some_and(|at| at >= since) {
            return Ok(());
        }
        let started = Instant::now();
        let mark = writer.flush().await;
        let placements = store.list_placements().await?;
        let tombstones = store.list_tombstones().await?;
        if self.reload(mark, placements, tombstones) {
            *reloaded = Some(started);
        }
        Ok(())
    }

    /// Finds a sandbox another replica created and this one has not caught
    /// up with yet, by id or by name, and caches it.
    ///
    /// The reload loop would bring it within a second; a caller who created
    /// a sandbox and used it at once, through a different replica, should not
    /// be told it does not exist in that second.
    pub async fn load(&self, reference: &str) -> Option<common::Sandbox> {
        let store = self.store.as_ref()?;
        let id = match store.get_placement(reference).await.ok().flatten() {
            Some(row) => return self.cache(row),
            None => store
                .claim_holder(&crate::persist::name_key(reference))
                .await
                .ok()
                .flatten()?,
        };
        let row = store.get_placement(&id).await.ok().flatten()?;
        self.cache(row)
    }

    /// Re-reads one sandbox from the store and caches what it says, for a
    /// replica about to act on a placement another replica may have changed
    /// since the last reload. A move does that, and a second is long enough
    /// for the caller to come back through this replica.
    ///
    /// Like [`reload`](Self::reload), the row is dropped if this replica has
    /// queued a write since reading it. A store that cannot be read answers
    /// with the cached copy: only a row the store confirms missing means the
    /// sandbox is gone.
    pub async fn refresh(&self, id: &str) -> Option<common::Sandbox> {
        let (Some(store), Some(writer)) = (&self.store, &self.writer) else {
            return self.get(id);
        };
        let mark = writer.flush().await;
        let row = store.get_placement(id).await;
        let mut sandboxes = self.sandboxes.lock().unwrap();
        if writer.enqueued() != mark {
            return sandboxes.get(id).cloned();
        }
        let row = match row {
            Ok(row) => row?,
            Err(err) => {
                tracing::warn!(sandbox = id, %err, "could not re-read a placement; using the cached one");
                return sandboxes.get(id).cloned();
            }
        };
        let sandbox = decode(&row.record)?;
        sandboxes.insert(sandbox.id.clone(), sandbox.clone());
        Some(sandbox)
    }

    fn cache(&self, row: burrow_store::PlacementRow) -> Option<common::Sandbox> {
        let sandbox = decode(&row.record)?;
        self.sandboxes
            .lock()
            .unwrap()
            .entry(sandbox.id.clone())
            .or_insert_with(|| sandbox.clone());
        Some(sandbox)
    }

    pub fn writer(&self) -> Option<&crate::persist::Writer> {
        self.writer.as_ref()
    }

    /// Claims an id, a name, or both for a create that is about to run.
    ///
    /// Either may be empty, meaning there is nothing to claim: a generated id
    /// cannot collide, and a sandbox need not be named at all. `Err` carries
    /// the reason, which is what a caller turns into ALREADY_EXISTS.
    ///
    /// Claiming rather than merely checking is what closes the window between a
    /// create being accepted and its record arriving; see `creating`.
    pub fn reserve(&self, id: &str, name: &str) -> Result<Reservation<'_>, String> {
        let sandboxes = self.sandboxes.lock().unwrap();
        let mut creating = self.creating.lock().unwrap();
        let mut naming = self.naming.lock().unwrap();

        if !id.is_empty() && (sandboxes.contains_key(id) || creating.contains(id)) {
            return Err(format!("sandbox {id} exists"));
        }
        if !name.is_empty() && (sandboxes.values().any(|s| s.name == name) || naming.contains(name))
        {
            return Err(format!("a sandbox named {name} exists"));
        }
        if !id.is_empty() {
            creating.insert(id.to_string());
        }
        if !name.is_empty() {
            naming.insert(name.to_string());
        }
        Ok(Reservation {
            registry: self,
            id: id.to_string(),
            name: name.to_string(),
        })
    }

    /// The id of the sandbox carrying this name, if one does.
    ///
    /// Names are unique, so a scan returns at most one. The map is small
    /// enough that indexing it would buy nothing a list already pays for.
    pub fn id_by_name(&self, name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        self.sandboxes
            .lock()
            .unwrap()
            .values()
            .find(|s| s.name == name)
            .map(|s| s.id.clone())
    }

    /// Map and store are both written under the registry lock, here and
    /// everywhere below.
    ///
    /// Persisting outside it lets a delete's row removal and an insert's row
    /// write interleave, and nothing re-reads the store until the next restart,
    /// so the divergence is permanent. The store is behind its own mutex
    /// and these methods are synchronous, so holding one lock across the other
    /// is a short critical section, not a deadlock.
    pub fn insert(&self, sandbox: common::Sandbox) {
        let guard = Guard::Fresh(sandbox.node_id.clone());
        self.record(sandbox, guard);
    }

    /// Takes the record the node it names answered with, unless the store
    /// has the sandbox elsewhere or gone by then.
    pub fn update(&self, sandbox: common::Sandbox) {
        let guard = Guard::On(sandbox.node_id.clone());
        self.record(sandbox, guard);
    }

    /// Takes the record of a sandbox its node has just claimed in the object
    /// store, which settles who holds it whatever the row said.
    pub fn adopted(&self, sandbox: common::Sandbox) {
        self.record(sandbox, Guard::Any);
    }

    fn record(&self, sandbox: common::Sandbox, guard: Guard) {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        self.persist(
            &sandbox.id,
            guard,
            Change::Replace(Box::new(sandbox.clone())),
        );
        self.settling
            .lock()
            .unwrap()
            .insert(sandbox.id.clone(), Instant::now());
        sandboxes.insert(sandbox.id.clone(), sandbox);
    }

    fn persist(&self, id: &str, guard: Guard, change: Change) {
        self.usage_written
            .lock()
            .unwrap()
            .insert(id.to_string(), Instant::now());
        self.write(crate::persist::Op::Update {
            id: id.to_string(),
            guard,
            change,
        });
    }

    /// Ages every settling entry out, as if `SETTLING_GRACE` had passed.
    ///
    /// Tests that are about what a heartbeat forgets have to get past the
    /// grace window without sleeping through it.
    #[cfg(test)]
    fn settled(&self) {
        self.settling.lock().unwrap().clear();
    }

    /// Drops a sandbox's row and the claims on its id and name, which is
    /// what frees the name for the next create on any replica, for a sandbox
    /// `node_id` let go of (`""` for one no node held).
    /// leaving the row and the claims alone if the store has it elsewhere.
    ///
    /// The report says only that the node let go. Another replica may have
    /// moved the sandbox off it a moment ago, through a release that left it
    /// unplaced until its adopt lands, and this replica's cache, still naming
    /// the node, would otherwise delete the row the move wrote. A move whose
    /// target then failed lost the sandbox outright.
    fn forget_on(&self, id: &str, node_id: &str) {
        self.usage_written.lock().unwrap().remove(id);
        self.write(crate::persist::Op::DeletePlacementOn {
            sandbox_id: id.to_string(),
            node_id: node_id.to_string(),
        });
        self.write(crate::persist::Op::ReleaseClaimsUnlessMoved {
            sandbox_id: id.to_string(),
            node_id: node_id.to_string(),
        });
    }

    pub fn get(&self, id: &str) -> Option<common::Sandbox> {
        self.sandboxes.lock().unwrap().get(id).cloned()
    }

    /// The node currently hosting a sandbox.
    pub fn node_of(&self, id: &str) -> Option<String> {
        self.sandboxes
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.node_id.clone())
    }

    pub fn remove(&self, id: &str) -> Option<common::Sandbox> {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let removed = sandboxes.remove(id);
        if let Some(sandbox) = &removed {
            self.forget_on(id, &sandbox.node_id);
        }
        removed
    }

    /// Drops a sandbox whose node could not be told, and remembers that it was.
    ///
    /// For a node that has missed its heartbeats and cannot be asked. The
    /// placement is removed anyway, or a permanently dead node would leave an
    /// undeletable sandbox holding its name and capacity; the tombstone records
    /// the intent, so a node that does come back has its copy destroyed rather
    /// than adopted.
    pub fn forget_deleted(&self, id: &str) -> Option<common::Sandbox> {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let removed = sandboxes.remove(id);
        if let Some(sandbox) = &removed {
            self.forget_on(id, &sandbox.node_id);
        }

        let node_id = removed
            .as_ref()
            .map(|s| s.node_id.clone())
            .unwrap_or_default();
        let at = burrow_common::unix_now();
        self.tombstones.lock().unwrap().insert(
            id.to_string(),
            Tombstone {
                node_id: node_id.clone(),
                at,
            },
        );
        self.write(crate::persist::Op::PutTombstone(
            burrow_store::TombstoneRow {
                sandbox_id: id.to_string(),
                node_id,
                at,
            },
        ));
        removed
    }

    pub fn is_tombstoned(&self, id: &str) -> bool {
        self.tombstones.lock().unwrap().contains_key(id)
    }

    /// Forgets a tombstone: the node no longer holds the sandbox, or never will.
    pub fn clear_tombstone(&self, id: &str) {
        self.tombstone_deletes.lock().unwrap().remove(id);
        if self.tombstones.lock().unwrap().remove(id).is_none() {
            return;
        }
        self.write(crate::persist::Op::DeleteTombstone(id.to_string()));
    }

    /// The tombstoned ids among `ids` whose delete is due, each held for
    /// [`TOMBSTONE_DELETE_HOLD`] so the next heartbeat does not send it again
    /// while it runs.
    pub fn due_tombstone_deletes(&self, ids: Vec<String>) -> Vec<String> {
        let now = Instant::now();
        let mut deletes = self.tombstone_deletes.lock().unwrap();
        ids.into_iter()
            .filter(|id| {
                let (_, next) = deletes.entry(id.clone()).or_insert((0, now));
                if *next > now {
                    return false;
                }
                *next = now + TOMBSTONE_DELETE_HOLD;
                true
            })
            .collect()
    }

    /// Backs off a tombstoned id whose delete failed.
    pub fn tombstone_delete_failed(&self, id: &str) {
        if let Some((failures, next)) = self.tombstone_deletes.lock().unwrap().get_mut(id) {
            *failures += 1;
            *next = Instant::now()
                + TOMBSTONE_RETRY
                    .saturating_mul(1 << (*failures - 1).min(16))
                    .min(MAX_TOMBSTONE_RETRY);
        }
    }

    /// Drops tombstones older than `ttl_secs`, returning how many.
    ///
    /// A node that never returns would otherwise accumulate them for the life
    /// of the cluster.
    pub fn prune_tombstones(&self, ttl_secs: i64) -> usize {
        let cutoff = burrow_common::unix_now().saturating_sub(ttl_secs);
        let mut tombstones = self.tombstones.lock().unwrap();
        let expired: Vec<String> = tombstones
            .iter()
            .filter(|(_, t)| t.at < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            tombstones.remove(id);
        }
        drop(tombstones);
        if !expired.is_empty() {
            self.write(crate::persist::Op::PruneTombstones(cutoff));
        }
        expired.len()
    }

    /// Drops every placement recorded against a node, returning what was held.
    ///
    /// For a node written off entirely, so the names and the capacity its
    /// sandboxes held come back. Deliberately leaves *no* tombstones: nothing
    /// was deleted here, the node was simply given up on, and if it ever does
    /// return its own inventory should be adopted as usual.
    ///
    /// A suspended sandbox whose state is in the object store is the
    /// exception. It does not need the node, so it is kept unplaced, with its
    /// name, for the next start to place on a node that can restore it. `info`
    /// is the dead node's, whose architecture and hypervisor version are
    /// stamped on a record that does not carry its own, and whose CPU, which
    /// wrote the saved memory, on every one. One holding public
    /// addresses is kept unplaced too, but only its own node can take it
    /// back: the addresses reach nowhere else.
    pub fn forget_node(
        &self,
        node_id: &str,
        info: &common::NodeInfo,
    ) -> (Vec<common::Sandbox>, Vec<common::Sandbox>) {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let mut dropped = Vec::new();
        let mut unplaced = Vec::new();
        sandboxes.retain(|_, sandbox| {
            if sandbox.node_id != node_id {
                return true;
            }
            if is_movable(sandbox) {
                lost_to_checkpoint(sandbox, node_id);
                sandbox.node_id.clear();
                if sandbox.arch.is_empty() {
                    sandbox.arch = info.arch.clone();
                    sandbox.hypervisor_version =
                        crate::registry::version_of(info, &sandbox.hypervisor).to_string();
                }
                sandbox.cpu = info.cpu.clone();
                unplaced.push(sandbox.clone());
                return true;
            }
            dropped.push(sandbox.clone());
            false
        });
        // Decided again in the store from the row as it stands, which may
        // have moved on since this replica cached it.
        for sandbox in unplaced.iter().chain(&dropped) {
            self.write(crate::persist::Op::WriteOff {
                sandbox_id: sandbox.id.clone(),
                node_id: node_id.to_string(),
                arch: info.arch.clone(),
                hypervisor_version: crate::registry::version_of(info, &sandbox.hypervisor)
                    .to_string(),
                cpu: info.cpu.clone(),
            });
            self.write(crate::persist::Op::ReleaseClaimsUnlessMoved {
                sandbox_id: sandbox.id.clone(),
                node_id: node_id.to_string(),
            });
        }
        (dropped, unplaced)
    }

    /// Claims the right to hand an unplaced sandbox to a node, here and in
    /// the store. `Err` carries why it could not be claimed.
    pub async fn claim_adoption(&self, id: &str) -> Result<Adoption<'_>, String> {
        let busy = || format!("sandbox {id} is already being placed");
        if !self.adopting.lock().unwrap().insert(id.to_string()) {
            return Err(busy());
        }
        let adoption = Adoption {
            registry: self,
            id: id.to_string(),
            holder: burrow_common::SandboxId::generate().to_string(),
            is_claimed: false,
        };
        let Some(store) = &self.store else {
            return Ok(adoption);
        };
        let mut adoption = adoption;
        match store
            .claim(
                &crate::persist::adopt_key(id),
                &adoption.holder,
                burrow_common::unix_now(),
            )
            .await
        {
            Ok(true) => {
                adoption.is_claimed = true;
                Ok(adoption)
            }
            Ok(false) => Err(busy()),
            Err(err) => Err(format!("could not claim {id} for placing: {err}")),
        }
    }

    /// Detaches a sandbox from its node, for a move that has released it there
    /// and not yet adopted it anywhere else.
    pub fn unplace(&self, sandbox: common::Sandbox) -> common::Sandbox {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        self.persist(
            &sandbox.id,
            Guard::On(sandbox.node_id.clone()),
            Change::Unplace {
                arch: sandbox.arch.clone(),
                hypervisor_version: sandbox.hypervisor_version.clone(),
                cpu: sandbox.cpu.clone(),
            },
        );
        let sandbox = common::Sandbox {
            node_id: String::new(),
            ..sandbox
        };
        sandboxes.insert(sandbox.id.clone(), sandbox.clone());
        sandbox
    }

    /// Replaces everything recorded against a node with what that node
    /// actually reports.
    ///
    /// Nodes own their sandboxes and persist them, so a node, not this cache,
    /// is the authority on what exists there. Adopting its list on every
    /// re-registration lets an orchestrator restart rebuild its whole view from
    /// the fleet.
    ///
    /// A sandbox a caller already deleted is the exception: the node was
    /// unreachable at the time, so adopting its copy back would undo a delete
    /// the caller was told had succeeded. Those ids come back in
    /// [`Reconciled::tombstoned`] to be destroyed on the node instead.
    pub fn reconcile_node(&self, node_id: &str, reported: Vec<common::Sandbox>) -> Reconciled {
        // Under the same lock as the map update: clearing the node's rows
        // first and taking the lock afterwards leaves a window in which an
        // insert writes a row this call has already decided to drop.
        //
        // Row by row rather than clearing the node first: between a clear and
        // the rewrite every sandbox on the node reads as gone to every other
        // replica, and a clear also takes rows this listing predates.
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let reported_ids: HashSet<String> = reported.iter().map(|s| s.id.clone()).collect();
        let creating = self.creating.lock().unwrap();
        let mut settling = self.settling.lock().unwrap();
        settling.retain(|_, at| at.elapsed() < SETTLING_GRACE);
        let before = sandboxes.len();
        sandboxes.retain(|id, s| {
            let keep = s.node_id != node_id
                || reported_ids.contains(id)
                || creating.contains(id)
                || settling.contains_key(id);
            if !keep {
                self.forget_on(id, node_id);
            }
            keep
        });
        drop(settling);
        drop(creating);
        let dropped = before - sandboxes.len();

        let tombstones = self.tombstones.lock().unwrap();
        let mut still_held = HashSet::new();
        let mut out = Reconciled::default();
        for mut sandbox in reported {
            if tombstones.contains_key(&sandbox.id) {
                still_held.insert(sandbox.id.clone());
                out.tombstoned.push(sandbox.id);
                continue;
            }
            // Adopted elsewhere while this node was away. The heartbeat tells
            // the node to let go of its copy; adopting it here would point the
            // placement back at state that is no longer the sandbox's.
            if let Some(held) = sandboxes.get(&sandbox.id)
                && !held.node_id.is_empty()
                && held.node_id != node_id
            {
                tracing::warn!(
                    node_id,
                    sandbox = sandbox.id,
                    holder = held.node_id,
                    "node reports a sandbox another node has adopted; not adopting it back"
                );
                continue;
            }
            // The node may not know its own id before registering; the
            // orchestrator is authoritative for that one field.
            sandbox.node_id = node_id.to_string();
            // A name is unique across the fleet, and this one may have been
            // reused while the node was away. The record is still adopted, but
            // the newer claim on the name keeps it.
            if !sandbox.name.is_empty() && self.name_taken(&sandboxes, &sandbox.name, &sandbox.id) {
                tracing::warn!(
                    node_id,
                    sandbox = sandbox.id,
                    name = sandbox.name,
                    "adopting a returning sandbox without its name; the name was \
                     reused while the node was away"
                );
                sandbox.name.clear();
            }
            self.write(crate::persist::Op::Claim {
                key: crate::persist::id_key(&sandbox.id),
                sandbox_id: sandbox.id.clone(),
            });
            if !sandbox.name.is_empty() {
                self.write(crate::persist::Op::Claim {
                    key: crate::persist::name_key(&sandbox.name),
                    sandbox_id: sandbox.id.clone(),
                });
            }
            self.persist(
                &sandbox.id,
                Guard::Adoptable(node_id.to_string()),
                Change::Replace(Box::new(sandbox.clone())),
            );
            sandboxes.insert(sandbox.id.clone(), sandbox);
            out.adopted += 1;
        }
        drop(tombstones);

        // Whatever the node no longer lists is gone from it for good, so the
        // tombstone has nothing left to guard against.
        let settled: Vec<String> = self
            .tombstones
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, t)| t.node_id == node_id && !still_held.contains(id.as_str()))
            .map(|(id, _)| id.clone())
            .collect();
        drop(sandboxes);
        for id in settled {
            self.clear_tombstone(&id);
        }

        out.forgotten = dropped;
        out
    }

    /// Narrows what a heartbeat confirms and relinquishes to what the store
    /// says, rather than this replica's copy, which may predate a move.
    ///
    /// Unfencing a sandbox lets its node resume it, and relinquishing one
    /// makes the node drop its copy, so either on a stale word can leave a
    /// sandbox running twice or nowhere. A row that cannot be read leaves the
    /// sandbox fenced.
    pub async fn verify_fences(&self, node_id: &str, applied: &mut Applied) {
        let Some(store) = &self.store else {
            return;
        };
        let mut confirmed = Vec::new();
        for id in std::mem::take(&mut applied.confirmed) {
            if let Ok(Some(row)) = store.get_placement(&id).await
                && row.node_id == node_id
            {
                confirmed.push(id);
            }
        }
        let mut relinquished = Vec::new();
        for id in std::mem::take(&mut applied.relinquished) {
            if let Ok(Some(row)) = store.get_placement(&id).await
                && !row.node_id.is_empty()
                && row.node_id != node_id
            {
                relinquished.push(id);
            }
        }
        applied.confirmed = confirmed;
        applied.relinquished = relinquished;
    }

    /// The ids among `ids` the store has no placement for, caching those it
    /// has.
    ///
    /// A node reporting a sandbox this replica has not cached usually means
    /// another replica created it in the last second, not that its record
    /// was lost, and only a lost record is worth a reconcile.
    pub async fn missing(&self, ids: &[String]) -> Vec<String> {
        let Some(store) = &self.store else {
            return ids.to_vec();
        };
        let mut missing = Vec::new();
        for id in ids {
            match store.get_placement(id).await {
                Ok(Some(row)) => {
                    if let Some(sandbox) = self.cache(row) {
                        self.settling
                            .lock()
                            .unwrap()
                            .insert(sandbox.id, Instant::now());
                    }
                }
                Ok(None) | Err(_) => missing.push(id.clone()),
            }
        }
        missing
    }

    /// Whether some *other* sandbox, or a create in flight, holds this name.
    fn name_taken(
        &self,
        sandboxes: &HashMap<String, common::Sandbox>,
        name: &str,
        except: &str,
    ) -> bool {
        sandboxes.values().any(|s| s.name == name && s.id != except)
            || self.naming.lock().unwrap().contains(name)
    }

    /// Applies a node's own view of the sandboxes it holds.
    ///
    /// Unlike [`reconcile_node`](Self::reconcile_node) this carries only ids and
    /// states, because it runs on every heartbeat. Anything the node no longer
    /// lists is gone: a sandbox that outlived its policy is destroyed there, and
    /// continuing to list it would be inventing one.
    ///
    /// Two things a report is *not* evidence of, both of them ordering rather
    /// than disagreement:
    ///
    /// * A sandbox created after the node sampled its inventory is missing from
    ///   the report because it did not exist yet, not because it is gone. Ids
    ///   still being created, and ids created inside [`SETTLING_GRACE`], are
    ///   therefore never dropped by a heartbeat.
    /// * An id the node lists that this registry has never heard of is a real
    ///   sandbox whose placement record was lost, by a restart without a store
    ///   or otherwise. It is returned in [`Applied::unknown`] so the caller can
    ///   pull the node's full listing; a state report carries no name, policy
    ///   or address, so there is nothing here to rebuild a record from.
    pub fn apply_states(
        &self,
        node_id: &str,
        reported: &[burrow_proto::node::v1::SandboxStateReport],
    ) -> Applied {
        let mut sandboxes = self.sandboxes.lock().unwrap();
        let mut out = Applied::default();

        // Only what actually moved is written back. A heartbeat arrives every
        // few seconds and almost always says nothing new; rewriting every
        // placement on the node each time is a disk write per sandbox per
        // heartbeat for no change at all.
        let tombstoned = self.tombstones.lock().unwrap();
        let mut changed = Vec::new();
        let mut restated = 0;
        for report in reported {
            // A node that was absent when a delete arrived keeps reporting the
            // sandbox until the delete is carried out. Nothing here may put it
            // back: the delete already succeeded for the caller.
            if tombstoned.contains_key(&report.sandbox_id) {
                out.tombstoned.push(report.sandbox_id.clone());
                continue;
            }
            let Some(sandbox) = sandboxes.get_mut(&report.sandbox_id) else {
                // Not ours yet: a create in flight is inserted only once the
                // node answers, and this report may have overtaken it.
                if !self.creating.lock().unwrap().contains(&report.sandbox_id) {
                    out.unknown.push(report.sandbox_id.clone());
                }
                continue;
            };
            if sandbox.node_id != node_id {
                if report.is_fenced && !sandbox.node_id.is_empty() {
                    out.relinquished.push(report.sandbox_id.clone());
                }
                continue;
            }
            if report.is_fenced {
                out.confirmed.push(report.sandbox_id.clone());
            }
            // Usage is taken on every heartbeat but never persisted here: it
            // moves constantly, the node holds the durable copy, and a
            // registry rebuilt from a node's reconcile gets it back anyway.
            sandbox.cpu_usage_usec = report.cpu_usage_usec;
            sandbox.rx_bytes = report.rx_bytes;
            sandbox.tx_bytes = report.tx_bytes;
            // Not counted as a restate, but written: only the replica this
            // node beats to hears it, and every other one would otherwise show
            // a sandbox created through it as `starting` for good.
            let is_confirmation_changed =
                sandbox.is_agent_unconfirmed != report.is_agent_unconfirmed;
            sandbox.is_agent_unconfirmed = report.is_agent_unconfirmed;
            if sandbox.state != report.state
                || sandbox.is_durable != report.is_durable
                || sandbox.state_reason != report.state_reason
                || sandbox.checkpoint_at_unix_ms != report.checkpoint_at_unix_ms
                || sandbox.checkpoint_kind != report.checkpoint_kind
            {
                sandbox.state = report.state;
                sandbox.is_durable = report.is_durable;
                sandbox.state_reason = report.state_reason.clone();
                sandbox.checkpoint_at_unix_ms = report.checkpoint_at_unix_ms;
                sandbox.checkpoint_kind = report.checkpoint_kind;
                restated += 1;
                changed.push(sandbox.clone());
            } else if is_confirmation_changed {
                changed.push(sandbox.clone());
            } else if self.writer.is_some()
                && self
                    .usage_written
                    .lock()
                    .unwrap()
                    .get(&sandbox.id)
                    .is_none_or(|at| at.elapsed() >= USAGE_WRITE_INTERVAL)
            {
                // Not a state change, so not counted as one; written so the
                // usage other replicas answer with is at most this old.
                changed.push(sandbox.clone());
            }
        }
        out.restated = restated;

        // Expired here, whatever the report says, rather than on a timer: this
        // is the only regular reader, and it runs every few seconds per node.
        let mut settling = self.settling.lock().unwrap();
        settling.retain(|_, at| at.elapsed() < SETTLING_GRACE);
        let mut gone = Vec::new();
        if reported.is_empty() {
            // "Lists nothing" is not the same claim as "held nothing": a node
            // that just restarted heartbeats before recover() has repopulated
            // its inventory, and erasing on that would destroy the record of
            // every sandbox it is about to bring back. Real deletions arrive
            // through DeleteSandbox, and a genuinely empty node is corrected
            // by the reconcile that follows its registration.
            if sandboxes.values().any(|s| s.node_id == node_id) {
                tracing::warn!(
                    node_id,
                    "heartbeat listed no sandboxes; keeping the recorded placements \
                     rather than forgetting them"
                );
            }
        } else {
            let known: std::collections::HashSet<&str> =
                reported.iter().map(|r| r.sandbox_id.as_str()).collect();
            let creating = self.creating.lock().unwrap();
            sandboxes.retain(|id, sandbox| {
                let keep = sandbox.node_id != node_id
                    || known.contains(id.as_str())
                    // Too new for this report to have seen; see the doc comment.
                    || creating.contains(id)
                    || settling.contains_key(id);
                if !keep {
                    gone.push(id.clone());
                }
                keep
            });
        }

        // Still under the lock: a delete racing this call must not have its
        // row rewritten by a snapshot taken before it ran.
        for sandbox in changed {
            self.persist(
                &sandbox.id.clone(),
                Guard::On(node_id.to_string()),
                Change::Restate(Box::new(sandbox)),
            );
        }
        for id in &gone {
            self.forget_on(id, node_id);
        }
        out.forgotten = gone.len();
        out
    }

    /// The node already hosting members of any of `networks`.
    ///
    /// Private-network membership is enforced per node, so a new member has to
    /// land where the existing ones are. Returns `None` when the networks are
    /// empty or have no members yet, which leaves placement unconstrained.
    pub fn node_hosting_networks(&self, networks: &[String]) -> Option<String> {
        if networks.is_empty() {
            return None;
        }
        let sandboxes = self.sandboxes.lock().unwrap();
        sandboxes.values().find_map(|sandbox| {
            let joined = sandbox
                .policy
                .iter()
                .flat_map(|p| p.networks.iter())
                .any(|m| networks.contains(&m.network));
            // An unplaced member is not anywhere, so it pins nothing.
            (joined && !sandbox.node_id.is_empty()).then(|| sandbox.node_id.clone())
        })
    }

    /// Guest addresses on each private network that live on *other* nodes.
    ///
    /// A node already knows its own members; what it cannot know is which
    /// remote addresses share a network with them, which is exactly what its
    /// firewall needs in order to let mesh traffic through.
    pub fn network_members(&self, for_node: &str) -> Vec<burrow_proto::node::v1::NetworkMembers> {
        let sandboxes = self.sandboxes.lock().unwrap();
        let mut by_network: std::collections::BTreeMap<
            String,
            Vec<burrow_proto::node::v1::NetworkMember>,
        > = std::collections::BTreeMap::new();

        for sandbox in sandboxes.values() {
            if sandbox.node_id == for_node || sandbox.guest_ip.is_empty() {
                continue;
            }
            for membership in sandbox.policy.iter().flat_map(|p| p.networks.iter()) {
                if membership.network.is_empty() {
                    continue;
                }
                by_network
                    .entry(membership.network.clone())
                    .or_default()
                    .push(burrow_proto::node::v1::NetworkMember {
                        sandbox_id: sandbox.id.clone(),
                        alias: alias_of(membership, &sandbox.id),
                        guest_ip: sandbox.guest_ip.clone(),
                    });
            }
        }

        by_network
            .into_iter()
            .map(|(network, members)| burrow_proto::node::v1::NetworkMembers { network, members })
            .collect()
    }

    /// Every sandbox, or only those carrying an exact `key=value` tag.
    ///
    /// Filtered here rather than fanned out: nodes reconcile this registry on
    /// registration and restate it on every heartbeat, so one map already holds
    /// the fleet.
    pub fn list_tagged(&self, tag: Option<(&str, &str)>) -> Vec<common::Sandbox> {
        let mut out: Vec<_> = self
            .sandboxes
            .lock()
            .unwrap()
            .values()
            .filter(|sandbox| match tag {
                Some((key, value)) => sandbox.tags.get(key).is_some_and(|held| held == value),
                None => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

/// A claim on a sandbox id and name, held for as long as its create is running.
pub struct Reservation<'a> {
    registry: &'a SandboxRegistry,
    id: String,
    name: String,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        // A create that never produced a record gives its store claims back
        // too, or the name would stay taken until the claim sweep.
        if !self.id.is_empty() && self.registry.get(&self.id).is_none() {
            self.registry
                .write(crate::persist::Op::ReleaseClaims(self.id.clone()));
        }
        self.registry.creating.lock().unwrap().remove(&self.id);
        self.registry.naming.lock().unwrap().remove(&self.name);
    }
}

/// Why a create could not claim its request id.
pub enum RequestTaken {
    /// Another create of it is running.
    InFlight,
    Failed(String),
}

/// A create's claim on its request id. Given back if the create made no
/// sandbox; otherwise kept in the store with the sandbox's other claims.
pub struct RequestClaim<'a> {
    registry: &'a SandboxRegistry,
    request: String,
    id: String,
    is_stored: bool,
}

impl Drop for RequestClaim<'_> {
    fn drop(&mut self) {
        self.registry
            .requesting
            .lock()
            .unwrap()
            .remove(&self.request);
        if self.is_stored && self.registry.get(&self.id).is_none() {
            self.registry.write(crate::persist::Op::ReleaseClaim {
                key: crate::persist::request_key(&self.request),
                holder: self.id.clone(),
            });
        }
    }
}

/// The right to hand one unplaced sandbox to a node, held for the attempt.
pub struct Adoption<'a> {
    registry: &'a SandboxRegistry,
    id: String,
    holder: String,
    is_claimed: bool,
}

impl Drop for Adoption<'_> {
    fn drop(&mut self) {
        if self.is_claimed {
            self.registry.write(crate::persist::Op::ReleaseClaim {
                key: crate::persist::adopt_key(&self.id),
                holder: self.holder.clone(),
            });
        }
        self.registry.adopting.lock().unwrap().remove(&self.id);
    }
}

#[cfg(test)]
mod reservation_tests {
    use super::*;

    fn registry() -> SandboxRegistry {
        SandboxRegistry::default()
    }

    #[test]
    fn an_id_being_created_cannot_be_claimed_twice() {
        let registry = registry();
        let first = registry.reserve("build-1", "").expect("first claim");
        assert!(registry.reserve("build-1", "").is_err());
        drop(first);
        // The create failed, so the id is free again.
        assert!(registry.reserve("build-1", "").is_ok());
    }

    #[test]
    fn an_id_that_belongs_to_a_sandbox_cannot_be_claimed() {
        let registry = registry();
        registry.insert(common::Sandbox {
            id: "build-1".into(),
            node_id: "node1".into(),
            ..Default::default()
        });
        assert!(registry.reserve("build-1", "").is_err());
        assert!(registry.reserve("build-2", "").is_ok());
    }

    #[test]
    fn a_name_is_claimed_for_as_long_as_its_create_runs() {
        let registry = registry();
        let claim = registry.reserve("", "api").expect("first claim");
        assert!(registry.reserve("", "api").is_err());
        // A different name, and a create with no name at all, are unaffected.
        assert!(registry.reserve("", "worker").is_ok());
        assert!(registry.reserve("", "").is_ok());
        drop(claim);
        assert!(registry.reserve("", "api").is_ok());
    }

    #[test]
    fn a_name_in_use_is_refused_and_resolves_to_its_sandbox() {
        let registry = registry();
        registry.insert(common::Sandbox {
            id: "sbx_1".into(),
            node_id: "node1".into(),
            name: "api".into(),
            ..Default::default()
        });
        assert_eq!(registry.id_by_name("api").as_deref(), Some("sbx_1"));
        assert_eq!(registry.id_by_name("worker"), None);
        // An empty name is not a name: unnamed sandboxes must not answer to it.
        assert_eq!(registry.id_by_name(""), None);

        let Err(taken) = registry.reserve("", "api") else {
            panic!("a name already in use must be refused");
        };
        assert!(taken.contains("api"), "{taken}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burrow_proto::node::v1::SandboxStateReport;

    fn sandbox(id: &str, node: &str, state: common::SandboxState) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: node.into(),
            state: state as i32,
            ..Default::default()
        }
    }

    fn report(id: &str, state: common::SandboxState) -> SandboxStateReport {
        SandboxStateReport {
            sandbox_id: id.into(),
            state: state as i32,
            ..Default::default()
        }
    }

    /// A sandbox moved here and then deleted through another replica used to
    /// come back on every reload: its settling mark, which keeps a fresh
    /// sandbox before its row exists, only expired on a heartbeat that listed
    /// something, and a node left empty by the delete never sent one.
    #[test]
    fn a_settled_sandbox_deleted_elsewhere_stays_deleted() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));
        registry.settling.lock().unwrap().insert(
            "a".into(),
            Instant::now() - SETTLING_GRACE - Duration::from_secs(1),
        );
        // The node is empty now, and says so.
        registry.apply_states("node1", &[]);
        assert!(registry.reload(0, Vec::new(), Vec::new()));
        assert!(registry.get("a").is_none());
        assert!(registry.settling.lock().unwrap().is_empty());
    }

    /// Within its grace too: a reload only applies once every write this
    /// replica queued has landed, so a missing row is a delete made through
    /// another replica. Keeping the id for the grace listed a deleted sandbox
    /// on one replica for half a minute.
    #[test]
    fn a_sandbox_still_settling_is_dropped_when_its_row_is_deleted() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));
        let _creating = registry.reserve("b", "").unwrap();
        registry.insert(sandbox("b", "node1", common::SandboxState::Running));
        assert!(registry.reload(0, Vec::new(), Vec::new()));
        assert!(registry.get("a").is_none());
        assert!(
            registry.get("b").is_some(),
            "a create in flight has no row yet"
        );
    }

    /// A row another replica just wrote settles here as well, so a heartbeat
    /// sampled before the placement does not read as the node letting go.
    #[test]
    fn a_row_placed_elsewhere_settles_on_reload() {
        let registry = SandboxRegistry::default();
        let row = |id: &str| burrow_store::PlacementRow {
            id: id.into(),
            node_id: "node1".into(),
            record: encode(&sandbox(id, "node1", common::SandboxState::Running)),
            version: 0,
        };
        assert!(registry.reload(0, vec![row("a"), row("b")], Vec::new()));
        let applied = registry.apply_states("node1", &[report("b", common::SandboxState::Running)]);
        assert_eq!(applied.forgotten, 0);
        assert!(registry.get("a").is_some());
    }

    /// A node suspends idle sandboxes without being asked, so the orchestrator
    /// must learn the new state from the node rather than assume the one it
    /// last caused.
    #[test]
    fn a_node_initiated_suspension_is_adopted() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));

        let applied =
            registry.apply_states("node1", &[report("a", common::SandboxState::Suspended)]);
        let (restated, forgotten) = (applied.restated, applied.forgotten);

        assert_eq!((restated, forgotten), (1, 0));
        assert_eq!(
            registry.get("a").unwrap().state,
            common::SandboxState::Suspended as i32
        );
    }

    /// A heartbeat is a snapshot of a moment, and that moment may be older
    /// than the sandbox. Reading "not in the report" as "gone" then erases the
    /// record of a sandbox the caller has already been handed the id of.
    /// A fenced node is waiting to hear whether its durable sandboxes are
    /// still its own. Those placed on it are confirmed, those another node
    /// took up are relinquished, and one nobody has a placement for is left
    /// to the reconcile.
    #[test]
    fn fenced_reports_are_confirmed_or_relinquished() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Suspended));
        registry.insert(sandbox("b", "node2", common::SandboxState::Running));
        let fenced = |id: &str| SandboxStateReport {
            is_fenced: true,
            is_durable: true,
            ..report(id, common::SandboxState::Suspended)
        };

        let applied = registry.apply_states("node1", &[fenced("a"), fenced("b"), fenced("c")]);

        assert_eq!(applied.confirmed, vec!["a".to_string()]);
        assert_eq!(applied.relinquished, vec!["b".to_string()]);
        assert_eq!(applied.unknown, vec!["c".to_string()]);
        assert!(registry.get("a").unwrap().is_durable);
        assert_eq!(
            registry.get("b").unwrap().state,
            common::SandboxState::Running as i32
        );
    }

    #[test]
    fn a_just_created_sandbox_survives_a_heartbeat_that_predates_it() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("old", "node1", common::SandboxState::Running));
        registry.settled();
        // Created after the node sampled the report below.
        registry.insert(sandbox("brand-new", "node1", common::SandboxState::Running));

        let applied =
            registry.apply_states("node1", &[report("old", common::SandboxState::Running)]);

        assert_eq!(applied.forgotten, 0);
        assert!(registry.get("brand-new").is_some());
        // And once the grace window is over, a report that still omits it is
        // taken at its word.
        registry.settled();
        let applied =
            registry.apply_states("node1", &[report("old", common::SandboxState::Running)]);
        assert_eq!(applied.forgotten, 1);
        assert!(registry.get("brand-new").is_none());
    }

    /// The id is claimed before the node is asked to build the sandbox, so a
    /// heartbeat can arrive while the create is still in flight.
    #[test]
    fn an_id_still_being_created_is_not_forgotten() {
        let registry = SandboxRegistry::default();
        let reserved = registry.reserve("in-flight", "").expect("free id");
        registry.insert(sandbox("in-flight", "node1", common::SandboxState::Running));
        // Not `settled()`: the point is that `creating` alone is enough.
        registry.settling.lock().unwrap().clear();

        let applied = registry.apply_states("node1", &[]);
        assert_eq!(applied.forgotten, 0);
        assert!(registry.get("in-flight").is_some());
        drop(reserved);
    }

    /// An orchestrator that lost its store still has a fleet full of running
    /// sandboxes. Ignoring the ids it does not recognise would leave them
    /// unreachable through the API for as long as the node stays registered.
    #[test]
    fn a_reported_sandbox_with_no_record_is_reported_for_reconciling() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("known", "node1", common::SandboxState::Running));
        registry.settled();

        let applied = registry.apply_states(
            "node1",
            &[
                report("known", common::SandboxState::Running),
                report("stranger", common::SandboxState::Running),
            ],
        );

        assert_eq!(applied.unknown, vec!["stranger".to_string()]);
        // Nothing is invented from a state report: it carries no name, policy
        // or address, so the caller pulls the node's full listing instead.
        assert!(registry.get("stranger").is_none());
    }

    /// A delete that could not reach its node stays deleted. The tombstone is
    /// the record of that, and it must not read as a sandbox to go adopt.
    #[test]
    fn a_tombstoned_id_is_not_reported_as_unknown() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("deleted", "node1", common::SandboxState::Running));
        registry.forget_deleted("deleted");
        registry.settled();

        let applied =
            registry.apply_states("node1", &[report("deleted", common::SandboxState::Running)]);
        assert!(applied.unknown.is_empty());
    }

    /// A sandbox that outlived its policy is destroyed on the node; continuing
    /// to list it would be inventing one.
    #[test]
    fn a_sandbox_the_node_no_longer_holds_is_forgotten() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("gone", "node1", common::SandboxState::Running));
        registry.insert(sandbox("kept", "node1", common::SandboxState::Running));
        registry.settled();

        let forgotten = registry
            .apply_states("node1", &[report("kept", common::SandboxState::Running)])
            .forgotten;

        assert_eq!(forgotten, 1);
        assert!(registry.get("gone").is_none());
        assert!(registry.get("kept").is_some());
    }

    /// One node's heartbeat says nothing about another node's sandboxes.
    #[test]
    fn another_nodes_sandboxes_are_left_alone() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("mine", "node1", common::SandboxState::Running));
        registry.insert(sandbox("theirs", "node2", common::SandboxState::Running));

        let forgotten = registry
            .apply_states("node1", &[report("mine", common::SandboxState::Running)])
            .forgotten;

        assert_eq!(forgotten, 0);
        assert!(registry.get("theirs").is_some());
    }

    /// A node cannot claim a sandbox the registry says lives somewhere else.
    #[test]
    fn a_node_cannot_restate_a_sandbox_it_does_not_host() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("elsewhere", "node2", common::SandboxState::Running));

        let restated = registry
            .apply_states(
                "node1",
                &[report("elsewhere", common::SandboxState::Suspended)],
            )
            .restated;

        assert_eq!(restated, 0);
        assert_eq!(
            registry.get("elsewhere").unwrap().state,
            common::SandboxState::Running as i32
        );
    }

    /// A node that has restarted heartbeats before it has finished recovering
    /// its sandboxes. Taking that empty list literally would erase the record
    /// of everything it is about to bring back.
    #[test]
    fn an_empty_report_is_not_read_as_an_empty_node() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));

        let applied = registry.apply_states("node1", &[]);
        let (restated, forgotten) = (applied.restated, applied.forgotten);

        assert_eq!((restated, forgotten), (0, 0));
        assert!(registry.get("a").is_some());
    }

    fn tagged(id: &str, pairs: &[(&str, &str)]) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: "node1".into(),
            tags: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_tag_filter_matches_the_whole_pair() {
        let registry = SandboxRegistry::default();
        registry.insert(tagged("a", &[("env", "staging"), ("team", "infra")]));
        registry.insert(tagged("b", &[("env", "prod")]));
        registry.insert(tagged("c", &[]));

        let staging = registry.list_tagged(Some(("env", "staging")));
        assert_eq!(staging.len(), 1);
        assert_eq!(staging[0].id, "a");

        // The key alone is not a match, and neither is the value alone.
        assert!(registry.list_tagged(Some(("env", "stag"))).is_empty());
        assert!(registry.list_tagged(Some(("team", "prod"))).is_empty());
        assert_eq!(registry.list_tagged(Some(("team", "infra"))).len(), 1);
        assert_eq!(registry.list_tagged(None).len(), 3);
    }

    #[test]
    fn an_unchanged_inventory_reports_no_churn() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("a", "node1", common::SandboxState::Running));
        let applied = registry.apply_states("node1", &[report("a", common::SandboxState::Running)]);
        let (restated, forgotten) = (applied.restated, applied.forgotten);
        assert_eq!((restated, forgotten), (0, 0));
    }

    fn named(id: &str, node: &str, name: &str) -> common::Sandbox {
        common::Sandbox {
            name: name.into(),
            ..sandbox(id, node, common::SandboxState::Running)
        }
    }

    /// The whole point of accepting a delete the node never heard: the name and
    /// the id come back immediately, rather than when the node does.
    #[test]
    fn a_delete_against_a_dead_node_frees_the_name() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));

        assert!(registry.reserve("b", "web").is_err());
        let forgotten = registry.forget_deleted("a").expect("the record");

        assert_eq!(forgotten.name, "web");
        assert!(registry.get("a").is_none());
        assert!(registry.reserve("b", "web").is_ok());
    }

    /// A node that was down for the delete still holds the sandbox, and says so
    /// the moment it returns. Adopting that would undo a delete the caller was
    /// already told had succeeded.
    #[test]
    fn a_tombstoned_sandbox_is_not_adopted_back() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        let outcome = registry.reconcile_node("node1", vec![named("a", "node1", "web")]);

        assert_eq!(outcome.adopted, 0);
        assert_eq!(outcome.tombstoned, vec!["a".to_string()]);
        assert!(registry.get("a").is_none());
        // Still held, so the tombstone stays until the node has destroyed it.
        assert!(registry.is_tombstoned("a"));
    }

    /// Heartbeats arrive every few seconds, long before the registration that
    /// reconciles. None of them may put a deleted sandbox back.
    #[test]
    fn a_heartbeat_cannot_resurrect_a_tombstoned_sandbox() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        let applied = registry.apply_states("node1", &[report("a", common::SandboxState::Running)]);

        assert!(registry.get("a").is_none());
        assert_eq!(applied.tombstoned, ["a"]);
    }

    /// A node that never went away reports a tombstoned sandbox on every
    /// heartbeat. Its delete is sent once while it runs, and after a failure
    /// again only once the backoff has passed.
    #[test]
    fn a_tombstoned_delete_is_sent_once_at_a_time_and_backed_off() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        assert_eq!(registry.due_tombstone_deletes(vec!["a".into()]), ["a"]);
        assert!(registry.due_tombstone_deletes(vec!["a".into()]).is_empty());
        registry.tombstone_delete_failed("a");
        assert!(registry.due_tombstone_deletes(vec!["a".into()]).is_empty());
        registry
            .tombstone_deletes
            .lock()
            .unwrap()
            .get_mut("a")
            .unwrap()
            .1 = Instant::now();
        assert_eq!(registry.due_tombstone_deletes(vec!["a".into()]), ["a"]);

        registry.clear_tombstone("a");
        assert!(!registry.is_tombstoned("a"));
        assert!(registry.tombstone_deletes.lock().unwrap().is_empty());
    }

    /// Once the node stops listing it, the delete has actually happened and
    /// there is nothing left for the tombstone to guard against.
    #[test]
    fn a_tombstone_is_cleared_once_the_node_lets_go() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_deleted("a");

        let outcome = registry.reconcile_node("node1", vec![]);

        assert!(outcome.tombstoned.is_empty());
        assert!(!registry.is_tombstoned("a"));
    }

    /// Writing a node off is not a delete. Nobody asked for its sandboxes to be
    /// destroyed, so if it ever comes back its own inventory is the truth.
    #[test]
    fn a_written_off_node_leaves_no_tombstones() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.insert(named("b", "node2", "api"));

        let (dropped, unplaced) = registry.forget_node("node1", &common::NodeInfo::default());

        assert_eq!((dropped.len(), unplaced.len()), (1, 0));
        assert!(registry.get("a").is_none());
        assert!(registry.get("b").is_some(), "another node is untouched");
        assert!(!registry.is_tombstoned("a"));
        assert!(registry.reserve("c", "web").is_ok(), "the name comes back");

        // And the sandbox is really still there, so a return re-adopts it.
        let outcome = registry.reconcile_node("node1", vec![named("a", "node1", "web")]);
        assert_eq!(outcome.adopted, 1);
        assert!(registry.get("a").is_some());
    }

    /// A name freed by writing the node off may already belong to someone else
    /// by the time the node returns. The sandbox is real and is adopted; the
    /// newer claim on the name is the one that holds.
    #[test]
    fn a_returning_sandbox_gives_up_a_name_that_was_reused() {
        let registry = SandboxRegistry::default();
        registry.insert(named("a", "node1", "web"));
        registry.forget_node("node1", &common::NodeInfo::default());
        registry.insert(named("b", "node2", "web"));

        let outcome = registry.reconcile_node("node1", vec![named("a", "node1", "web")]);

        assert_eq!(outcome.adopted, 1);
        assert_eq!(registry.get("a").expect("adopted").name, "");
        assert_eq!(registry.id_by_name("web").as_deref(), Some("b"));
    }

    fn durable(id: &str, node: &str, name: &str) -> common::Sandbox {
        common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            hypervisor: "firecracker".into(),
            ..named(id, node, name)
        }
    }

    /// A suspended sandbox whose state is in the object store does not need
    /// its node, so writing the node off leaves it to be placed again, name
    /// and all. Running or merely suspended ones go with the node as before.
    #[test]
    fn a_written_off_node_leaves_its_durable_sandboxes_unplaced() {
        let registry = SandboxRegistry::default();
        registry.insert(durable("a", "node1", "web"));
        registry.insert(common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            ..named("b", "node1", "api")
        });
        registry.insert(common::Sandbox {
            state: common::SandboxState::Running as i32,
            is_durable: true,
            ..named("c", "node1", "db")
        });

        let (dropped, unplaced) = registry.forget_node(
            "node1",
            &common::NodeInfo {
                arch: "x86_64".into(),
                hypervisor_versions: [("firecracker".to_string(), "1.16.1".to_string())].into(),
                cpu: Some(common::CpuFingerprint {
                    vendor: "GenuineIntel".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        assert_eq!((dropped.len(), unplaced.len()), (2, 1));
        let kept = registry.get("a").expect("kept unplaced");
        assert_eq!(kept.node_id, "");
        assert_eq!(
            (kept.arch.as_str(), kept.hypervisor_version.as_str()),
            ("x86_64", "1.16.1")
        );
        assert_eq!(kept.cpu.unwrap().vendor, "GenuineIntel");
        assert!(registry.reserve("", "web").is_err(), "the name stays held");
        assert!(registry.get("b").is_none());
        assert!(registry.get("c").is_none());
    }

    /// A running sandbox with a checkpoint survives its node, restated as
    /// what the checkpoint brings back and saying how old it is.
    #[test]
    fn a_written_off_node_leaves_its_checkpointed_sandboxes_recoverable() {
        let registry = SandboxRegistry::default();
        let running = |id: &str, kind: common::CheckpointKind| common::Sandbox {
            state: common::SandboxState::Running as i32,
            checkpoint_at_unix_ms: 1_787_000_000_000,
            checkpoint_kind: kind as i32,
            ..named(id, "node1", id)
        };
        registry.insert(running("disk", common::CheckpointKind::Disk));
        registry.insert(running("memory", common::CheckpointKind::Memory));

        let (dropped, unplaced) = registry.forget_node("node1", &common::NodeInfo::default());
        assert_eq!((dropped.len(), unplaced.len()), (0, 2));
        let disk = registry.get("disk").unwrap();
        assert_eq!(disk.state, common::SandboxState::Stopped as i32);
        assert!(disk.node_id.is_empty());
        assert!(
            disk.state_reason.contains("disk checkpoint of 2026-08-17T"),
            "{}",
            disk.state_reason
        );
        let memory = registry.get("memory").unwrap();
        assert_eq!(memory.state, common::SandboxState::Suspended as i32);
        assert!(memory.state_reason.contains("memory checkpoint"));
    }

    /// A node that comes back reporting a sandbox another node adopted while
    /// it was away must not take the placement back; one nobody adopted is
    /// its own again.
    #[test]
    fn a_returning_node_does_not_take_back_what_another_adopted() {
        let registry = SandboxRegistry::default();
        registry.insert(durable("a", "node1", "web"));
        registry.insert(durable("b", "node1", "api"));
        registry.forget_node("node1", &common::NodeInfo::default());
        registry.insert(common::Sandbox {
            state: common::SandboxState::Running as i32,
            ..named("a", "node2", "web")
        });

        let outcome = registry.reconcile_node(
            "node1",
            vec![durable("a", "node1", "web"), durable("b", "node1", "api")],
        );

        assert_eq!(outcome.adopted, 1);
        assert_eq!(registry.node_of("a").as_deref(), Some("node2"));
        assert_eq!(registry.node_of("b").as_deref(), Some("node1"));
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    fn sandbox(id: &str, node: &str) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: node.into(),
            template: "python".into(),
            state: common::SandboxState::Running as i32,
            guest_ip: "10.99.0.6".into(),
            ..Default::default()
        }
    }

    async fn store() -> (Arc<burrow_store::Store>, std::path::PathBuf) {
        let path =
            std::env::temp_dir().join(format!("burrow-placements-{}-{}.db", std::process::id(), {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }));
        let _ = std::fs::remove_file(&path);
        (
            Arc::new(burrow_store::Store::open(&path).await.unwrap()),
            path,
        )
    }

    /// The whole point: a fleet that restarts together should not lose the
    /// mapping from sandbox to node.
    #[tokio::test]
    async fn placements_survive_a_restart() {
        let (store, path) = store().await;
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store)).await;
            registry.insert(sandbox("sbx_a", "node1"));
            registry.insert(sandbox("sbx_b", "node2"));
            registry.writer().unwrap().flush().await;
        }

        let restored = SandboxRegistry::with_store(Arc::clone(&store)).await;
        assert_eq!(restored.node_of("sbx_a").as_deref(), Some("node1"));
        assert_eq!(restored.node_of("sbx_b").as_deref(), Some("node2"));
        assert_eq!(restored.get("sbx_a").unwrap().template, "python");
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_removed_sandbox_does_not_come_back() {
        let (store, path) = store().await;
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store)).await;
            registry.insert(sandbox("sbx_a", "node1"));
            registry.remove("sbx_a");
            registry.writer().unwrap().flush().await;
        }
        assert!(
            SandboxRegistry::with_store(Arc::clone(&store))
                .await
                .get("sbx_a")
                .is_none()
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Nodes stay authoritative: what a node reports replaces what was stored
    /// for it, including sandboxes it no longer has.
    #[tokio::test]
    async fn reconciling_a_node_rewrites_what_was_stored_for_it() {
        let (store, path) = store().await;
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store)).await;
            registry.insert(sandbox("gone", "node1"));
            registry.insert(sandbox("kept", "node1"));
            registry.insert(sandbox("elsewhere", "node2"));
            registry.settled();
            registry.reconcile_node("node1", vec![sandbox("kept", "node1")]);
            registry.writer().unwrap().flush().await;
        }

        let restored = SandboxRegistry::with_store(Arc::clone(&store)).await;
        assert!(restored.get("gone").is_none(), "a node's word is final");
        assert!(restored.get("kept").is_some());
        assert!(
            restored.get("elsewhere").is_some(),
            "another node's sandboxes are untouched"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A node-initiated state change has to reach disk too, or a restart
    /// resurrects the state the orchestrator last caused.
    #[tokio::test]
    async fn adopted_states_are_persisted() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store().await;
        {
            let registry = SandboxRegistry::with_store(Arc::clone(&store)).await;
            registry.insert(sandbox("sbx_a", "node1"));
            registry.insert(sandbox("dropped", "node1"));
            registry.settled();
            registry.apply_states(
                "node1",
                &[SandboxStateReport {
                    sandbox_id: "sbx_a".into(),
                    state: common::SandboxState::Suspended as i32,
                    ..Default::default()
                }],
            );
            registry.writer().unwrap().flush().await;
        }

        let restored = SandboxRegistry::with_store(Arc::clone(&store)).await;
        assert_eq!(
            restored.get("sbx_a").unwrap().state,
            common::SandboxState::Suspended as i32
        );
        assert!(restored.get("dropped").is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// Heartbeats arrive every few seconds and usually say nothing new;
    /// rewriting every placement each time is a write per sandbox per
    /// heartbeat for no change at all.
    #[tokio::test]
    async fn an_unchanged_heartbeat_writes_nothing() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store().await;
        let registry = SandboxRegistry::with_store(Arc::clone(&store)).await;
        registry.insert(sandbox("sbx_a", "node1"));

        registry.writer().unwrap().flush().await;
        let version = || async { store.get_placement("sbx_a").await.unwrap().unwrap().version };
        let before = version().await;
        registry.apply_states(
            "node1",
            &[SandboxStateReport {
                sandbox_id: "sbx_a".into(),
                state: common::SandboxState::Running as i32,
                ..Default::default()
            }],
        );
        registry.writer().unwrap().flush().await;
        assert_eq!(version().await, before);

        // A state that did move is still written.
        registry.apply_states(
            "node1",
            &[SandboxStateReport {
                sandbox_id: "sbx_a".into(),
                state: common::SandboxState::Suspended as i32,
                ..Default::default()
            }],
        );
        registry.writer().unwrap().flush().await;
        assert_eq!(version().await, before + 1);
        let _ = std::fs::remove_file(&path);
    }

    /// A replica a move did not run through still caches the sandbox on its
    /// source, and the source's next heartbeat no longer lists it. Forgetting
    /// it there used to delete the row the move had just left unplaced, so a
    /// move whose target failed lost the sandbox from every replica.
    #[tokio::test]
    async fn a_stale_replica_does_not_forget_a_sandbox_moved_off_the_node() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store().await;
        let mover = SandboxRegistry::with_store(Arc::clone(&store)).await;
        let stale = SandboxRegistry::with_store(Arc::clone(&store)).await;
        mover.insert(sandbox("sbx_a", "node1"));
        mover.insert(sandbox("sbx_b", "node1"));
        mover.writer().unwrap().flush().await;
        stale.refresh("sbx_a").await.unwrap();
        stale.refresh("sbx_b").await.unwrap();

        mover.unplace(sandbox("sbx_a", "node1"));
        mover.writer().unwrap().flush().await;
        let applied = stale.apply_states(
            "node1",
            &[SandboxStateReport {
                sandbox_id: "sbx_b".into(),
                state: common::SandboxState::Running as i32,
                ..Default::default()
            }],
        );
        stale.writer().unwrap().flush().await;

        assert_eq!(applied.forgotten, 1);
        let row = store.get_placement("sbx_a").await.unwrap().expect("kept");
        assert!(row.node_id.is_empty(), "{}", row.node_id);
        let _ = std::fs::remove_file(&path);
    }

    /// Every listing in replicated mode used to read every placement and
    /// tombstone from the store. One that arrives after a reload started
    /// shares it; one that arrives later still reads, so a delete another
    /// replica finished before the listing is not listed.
    #[tokio::test]
    async fn a_listing_shares_a_reload_that_started_after_it_arrived() {
        let (store, path) = store().await;
        let deleter = SandboxRegistry::with_store(Arc::clone(&store)).await;
        let lister = SandboxRegistry::with_store(Arc::clone(&store)).await;
        deleter.insert(sandbox("sbx_a", "node1"));
        deleter.writer().unwrap().flush().await;
        let before = Instant::now();
        lister.reload_since(Instant::now()).await.unwrap();
        assert!(lister.get("sbx_a").is_some());

        deleter.remove("sbx_a");
        deleter.writer().unwrap().flush().await;
        lister.reload_since(Instant::now()).await.unwrap();
        assert!(lister.get("sbx_a").is_none());

        // With the store unreadable, only a listing no reload covers reads it.
        let pool = burrow_store::sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
            .await
            .unwrap();
        burrow_store::sqlx::query("DROP TABLE tombstones")
            .execute(&pool)
            .await
            .unwrap();
        lister.reload_since(before).await.unwrap();
        assert!(lister.reload_since(Instant::now()).await.is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// A store read that failed used to read as a missing row, so a replica
    /// told a caller a sandbox it holds does not exist. It answers from its
    /// cache instead.
    #[tokio::test]
    async fn a_store_error_on_refresh_answers_from_the_cache() {
        let (store, path) = store().await;
        let registry = SandboxRegistry::with_store(Arc::clone(&store)).await;
        registry.insert(sandbox("sbx_a", "node1"));
        registry.writer().unwrap().flush().await;
        let pool = burrow_store::sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
            .await
            .unwrap();
        burrow_store::sqlx::query("DROP TABLE placements")
            .execute(&pool)
            .await
            .unwrap();
        assert!(store.get_placement("sbx_a").await.is_err());

        let cached = registry.refresh("sbx_a").await.expect("cached copy");
        assert_eq!(cached.node_id, "node1");
        let _ = std::fs::remove_file(&path);
    }

    /// A warm create is recorded unconfirmed, and only the replica its node
    /// beats to hears the guest answer. Every other replica kept the flag from
    /// the create's row, and its own copy over every row after, so it showed
    /// a running sandbox as `starting` for as long as it ran.
    #[tokio::test]
    async fn a_confirmed_agent_reaches_the_other_replicas() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store().await;
        let beaten = SandboxRegistry::with_store(Arc::clone(&store)).await;
        let other = SandboxRegistry::with_store(Arc::clone(&store)).await;
        beaten.insert(common::Sandbox {
            is_agent_unconfirmed: true,
            ..sandbox("sbx_a", "node1")
        });
        beaten.writer().unwrap().flush().await;
        assert!(other.refresh("sbx_a").await.unwrap().is_agent_unconfirmed);

        beaten.apply_states(
            "node1",
            &[SandboxStateReport {
                sandbox_id: "sbx_a".into(),
                state: common::SandboxState::Running as i32,
                is_agent_unconfirmed: false,
                ..Default::default()
            }],
        );
        beaten.writer().unwrap().flush().await;
        let mark = other.writer().unwrap().flush().await;
        let rows = store.list_placements().await.unwrap();
        assert!(other.reload(mark, rows, Vec::new()));
        assert!(!other.get("sbx_a").unwrap().is_agent_unconfirmed);
        let _ = std::fs::remove_file(&path);
    }

    /// A node's heartbeat reaching the replica that did not create its
    /// newest sandbox read that sandbox as a lost record, and the reconcile
    /// it set off cleared every row on the node before writing them back, so
    /// the other replica answered NOT_FOUND for all of them meanwhile.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sandbox_another_replica_just_created_is_looked_up_not_reconciled() {
        use burrow_proto::node::v1::SandboxStateReport;
        let (store, path) = store().await;
        let creator = SandboxRegistry::with_store(Arc::clone(&store)).await;
        let other = SandboxRegistry::with_store(Arc::clone(&store)).await;
        creator.insert(sandbox("sbx_old", "node1"));
        creator.writer().unwrap().flush().await;
        other.refresh("sbx_old").await.unwrap();
        creator.insert(sandbox("sbx_new", "node1"));
        creator.writer().unwrap().flush().await;

        let reports: Vec<_> = ["sbx_old", "sbx_new"]
            .into_iter()
            .map(|id| SandboxStateReport {
                sandbox_id: id.into(),
                state: common::SandboxState::Running as i32,
                ..Default::default()
            })
            .collect();
        let applied = other.apply_states("node1", &reports);
        assert_eq!(applied.unknown, vec!["sbx_new".to_string()]);
        assert!(other.missing(&applied.unknown).await.is_empty());
        assert_eq!(other.node_of("sbx_new").as_deref(), Some("node1"));
        assert!(other.missing(&["sbx_lost".to_string()]).await == vec!["sbx_lost"]);

        // A reconcile still running must never leave the node's rows absent.
        let watcher = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                for _ in 0..2_000 {
                    for id in ["sbx_old", "sbx_new"] {
                        assert!(store.get_placement(id).await.unwrap().is_some(), "{id}");
                    }
                    tokio::task::yield_now().await;
                }
            })
        };
        for _ in 0..50 {
            other.reconcile_node(
                "node1",
                vec![sandbox("sbx_old", "node1"), sandbox("sbx_new", "node1")],
            );
            other.writer().unwrap().flush().await;
        }
        watcher.await.unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A listing taken before another replica placed a sandbox on the node
    /// does not delete that sandbox's row.
    #[tokio::test]
    async fn a_reconcile_keeps_rows_its_listing_predates() {
        let (store, path) = store().await;
        let creator = SandboxRegistry::with_store(Arc::clone(&store)).await;
        let other = SandboxRegistry::with_store(Arc::clone(&store)).await;
        creator.insert(sandbox("sbx_new", "node1"));
        creator.writer().unwrap().flush().await;

        other.reconcile_node("node1", Vec::new());
        other.writer().unwrap().flush().await;
        assert!(store.get_placement("sbx_new").await.unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    async fn replicas() -> (
        Arc<burrow_store::Store>,
        std::path::PathBuf,
        SandboxRegistry,
        SandboxRegistry,
    ) {
        let (store, path) = store().await;
        let a = SandboxRegistry::with_store(Arc::clone(&store)).await;
        let b = SandboxRegistry::with_store(Arc::clone(&store)).await;
        (store, path, a, b)
    }

    async fn settle(registries: &[&SandboxRegistry]) {
        for registry in registries {
            registry.writer().unwrap().flush().await;
        }
    }

    fn suspended(id: &str) -> burrow_proto::node::v1::SandboxStateReport {
        burrow_proto::node::v1::SandboxStateReport {
            sandbox_id: id.into(),
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..Default::default()
        }
    }

    /// A move pauses the sandbox on its source before letting go, and that
    /// node's heartbeat to a replica the move did not run through restated
    /// the sandbox there, writing the source back over the move.
    #[tokio::test]
    async fn a_stale_heartbeat_does_not_put_a_moved_sandbox_back() {
        let (store, path, mover, stale) = replicas().await;
        mover.insert(sandbox("sbx_a", "node1"));
        mover.insert(sandbox("sbx_b", "node1"));
        settle(&[&mover]).await;
        stale.refresh("sbx_a").await.unwrap();
        stale.refresh("sbx_b").await.unwrap();

        mover.unplace(sandbox("sbx_a", "node1"));
        mover.adopted(sandbox("sbx_a", "node2"));
        settle(&[&mover]).await;
        stale.apply_states("node1", &[suspended("sbx_a"), suspended("sbx_b")]);
        settle(&[&stale]).await;

        let row = store.get_placement("sbx_a").await.unwrap().unwrap();
        assert_eq!(row.node_id, "node2");
        let b = decode(&store.get_placement("sbx_b").await.unwrap().unwrap().record).unwrap();
        assert_eq!(b.state, common::SandboxState::Suspended as i32);
        let _ = std::fs::remove_file(&path);
    }

    /// A heartbeat restate from a replica with an older copy wrote that whole
    /// copy back, undoing a change another replica had just made.
    #[tokio::test]
    async fn a_stale_heartbeat_keeps_what_another_replica_changed() {
        let (store, path, writer, stale) = replicas().await;
        writer.insert(sandbox("sbx_a", "node1"));
        settle(&[&writer]).await;
        stale.refresh("sbx_a").await.unwrap();

        let mut tagged = sandbox("sbx_a", "node1");
        tagged.tags.insert("team".into(), "infra".into());
        writer.update(tagged);
        settle(&[&writer]).await;
        stale.apply_states("node1", &[suspended("sbx_a")]);
        settle(&[&stale]).await;

        let row = decode(&store.get_placement("sbx_a").await.unwrap().unwrap().record).unwrap();
        assert_eq!(row.tags.get("team").map(String::as_str), Some("infra"));
        assert_eq!(row.state, common::SandboxState::Suspended as i32);
        let _ = std::fs::remove_file(&path);
    }

    /// A call that finished on a node after another replica deleted the
    /// sandbox wrote its row back.
    #[tokio::test]
    async fn a_late_answer_does_not_bring_back_a_deleted_sandbox() {
        let (store, path, deleter, late) = replicas().await;
        deleter.insert(sandbox("sbx_a", "node1"));
        settle(&[&deleter]).await;
        late.refresh("sbx_a").await.unwrap();

        deleter.remove("sbx_a");
        settle(&[&deleter]).await;
        late.update(sandbox("sbx_a", "node1"));
        settle(&[&late]).await;
        assert!(store.get_placement("sbx_a").await.unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// A listing the source node gave before a move let go of the sandbox
    /// took it back from the move while it was between nodes.
    #[tokio::test]
    async fn a_stale_listing_does_not_take_back_a_sandbox_being_moved() {
        let (store, path, mover, stale) = replicas().await;
        mover.insert(sandbox("sbx_a", "node1"));
        settle(&[&mover]).await;
        stale.refresh("sbx_a").await.unwrap();

        let _adoption = mover.claim_adoption("sbx_a").await.unwrap();
        mover.unplace(sandbox("sbx_a", "node1"));
        settle(&[&mover]).await;
        stale.reconcile_node("node1", vec![sandbox("sbx_a", "node1")]);
        settle(&[&stale]).await;

        let row = store.get_placement("sbx_a").await.unwrap().unwrap();
        assert!(row.node_id.is_empty(), "{}", row.node_id);
        let _ = std::fs::remove_file(&path);
    }

    /// The leader writes a node off from its own copy of what the node held,
    /// which may predate a suspend to the object store or a move.
    #[tokio::test]
    async fn a_write_off_acts_on_the_stored_row() {
        let (store, path, other, leader) = replicas().await;
        leader.insert(sandbox("sbx_kept", "node1"));
        leader.insert(sandbox("sbx_moved", "node1"));
        settle(&[&leader]).await;
        other.refresh("sbx_kept").await.unwrap();

        other.update(common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..sandbox("sbx_kept", "node1")
        });
        other.adopted(sandbox("sbx_moved", "node2"));
        settle(&[&other]).await;
        leader.forget_node("node1", &common::NodeInfo::default());
        settle(&[&leader]).await;

        let kept = store
            .get_placement("sbx_kept")
            .await
            .unwrap()
            .expect("kept");
        assert!(kept.node_id.is_empty(), "{}", kept.node_id);
        let moved = store
            .get_placement("sbx_moved")
            .await
            .unwrap()
            .expect("moved");
        assert_eq!(moved.node_id, "node2");
        let _ = std::fs::remove_file(&path);
    }

    fn fenced(id: &str) -> burrow_proto::node::v1::SandboxStateReport {
        burrow_proto::node::v1::SandboxStateReport {
            is_fenced: true,
            ..suspended(id)
        }
    }

    /// A node back from an outage reports its durable sandboxes fenced, and
    /// a replica whose copy predated another node adopting one confirmed it,
    /// letting the returning node resume it too; one whose copy predated a
    /// move back relinquished the only copy.
    #[tokio::test]
    async fn fences_are_lifted_and_copies_dropped_only_on_the_stores_word() {
        let (_store, path, mover, stale) = replicas().await;
        mover.insert(sandbox("sbx_gone", "node1"));
        mover.insert(sandbox("sbx_back", "node2"));
        settle(&[&mover]).await;
        stale.refresh("sbx_gone").await.unwrap();
        stale.refresh("sbx_back").await.unwrap();

        mover.adopted(sandbox("sbx_gone", "node2"));
        mover.adopted(sandbox("sbx_back", "node1"));
        settle(&[&mover]).await;
        let mut applied = stale.apply_states("node1", &[fenced("sbx_gone"), fenced("sbx_back")]);
        assert_eq!(applied.confirmed, vec!["sbx_gone".to_string()]);
        assert_eq!(applied.relinquished, vec!["sbx_back".to_string()]);
        stale.verify_fences("node1", &mut applied).await;
        assert!(applied.confirmed.is_empty(), "{:?}", applied.confirmed);
        assert!(
            applied.relinquished.is_empty(),
            "{:?}",
            applied.relinquished
        );

        // What the heartbeat does: fenced ids are read through first.
        for id in ["sbx_gone", "sbx_back"] {
            stale.refresh(id).await;
        }
        let mut applied = stale.apply_states("node1", &[fenced("sbx_gone"), fenced("sbx_back")]);
        stale.verify_fences("node1", &mut applied).await;
        assert_eq!(applied.confirmed, vec!["sbx_back".to_string()]);
        assert_eq!(applied.relinquished, vec!["sbx_gone".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    /// A running sandbox the leader last saw without a checkpoint, which has
    /// one in the store by now, is recovered from it rather than dropped.
    #[tokio::test]
    async fn a_write_off_restates_a_stored_checkpoint() {
        let (store, path, other, leader) = replicas().await;
        leader.insert(sandbox("sbx_a", "node1"));
        settle(&[&leader]).await;
        other.refresh("sbx_a").await.unwrap();
        other.apply_states(
            "node1",
            &[burrow_proto::node::v1::SandboxStateReport {
                sandbox_id: "sbx_a".into(),
                state: common::SandboxState::Running as i32,
                checkpoint_at_unix_ms: 1_787_000_000_000,
                checkpoint_kind: common::CheckpointKind::Disk as i32,
                ..Default::default()
            }],
        );
        settle(&[&other]).await;

        leader.forget_node("node1", &common::NodeInfo::default());
        settle(&[&leader]).await;
        let row = store.get_placement("sbx_a").await.unwrap().expect("kept");
        assert!(row.node_id.is_empty(), "{}", row.node_id);
        let stored = decode(&row.record).unwrap();
        assert_eq!(stored.state, common::SandboxState::Stopped as i32);
        assert!(
            stored.state_reason.contains("disk checkpoint"),
            "{}",
            stored.state_reason
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_registry_without_a_store_still_works() {
        let registry = SandboxRegistry::default();
        registry.insert(sandbox("sbx_a", "node1"));
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some("node1"));
        registry.remove("sbx_a");
        assert!(registry.get("sbx_a").is_none());
    }
}
