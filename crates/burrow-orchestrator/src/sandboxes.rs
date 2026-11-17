//! The orchestrator's sandbox registry: which sandbox lives on which node.
//!
//! The store holds every sandbox that should exist, and where. A row is
//! written before any node is asked to act on it, and every change of node
//! raises its generation, so a node runs only what the store lists for it at
//! the generation it lists. Each heartbeat carries the node's complete
//! listing, which is compared against the rows in one transaction, and the
//! node destroys whatever the store does not list for it: a sandbox deleted
//! while the node was away, one placed elsewhere since, or a stale copy of
//! one placed here again. A delete is the row's absence, so it needs no
//! tombstone and no reachable node. A sandbox kept unplaced when its node was
//! written off goes back to that node if it returns still holding it at the
//! same generation, since nothing has placed it since.
//!
//! The registry caches the rows for reads and routing, and catches up with
//! other replicas' writes once a second. Decisions are taken in the store.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use burrow_proto::common::v1 as common;
use burrow_proto::node::v1 as nodepb;
use tonic::Status;

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

/// The generation of every sandbox's first placement. A create, a fork and
/// a restore from a snapshot all make a new sandbox there.
pub const FIRST_GENERATION: i64 = 1;

/// How long a node may take to act on a placement before the row can go
/// missing from its listings. Far longer than any create or adopt takes; a
/// row still pending past it belonged to a replica that died mid-call.
pub const PENDING_DEADLINE_MS: i64 = 600_000;

/// How long a create or adopt the node finished may go without its answer
/// recorded before the record is fetched from the node.
const UNANSWERED_AFTER_MS: i64 = 60_000;

/// The detail of the event a node records when it releases a sandbox to the
/// object store for a move.
const RELEASED: &str = "released";

/// How often a sandbox's usage figures are written back for other replicas.
const USAGE_WRITE_INTERVAL_MS: i64 = 30_000;

/// The store keys a sandbox's uniqueness claims live under. The row itself
/// claims the id.
pub fn name_key(name: &str) -> String {
    format!("name:{name}")
}

pub fn request_key(request: &str) -> String {
    format!("request:{request}")
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

/// Whether a sandbox can be taken up by another node: suspended, with its
/// latest suspend in the object store, or running with a checkpoint there.
pub fn is_movable(sandbox: &common::Sandbox) -> bool {
    (sandbox.state == common::SandboxState::Suspended as i32 && sandbox.is_durable)
        || sandbox.checkpoint_at_unix_ms > 0
}

/// Restates a sandbox whose node was lost as what its checkpoint brings
/// back: stopped on a disk checkpoint, which a start boots, or suspended on a
/// memory one, which a resume restores. The reason says how old the
/// checkpoint is, and so what was lost.
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

/// What a lost sandbox is kept as: off its node, if the object store can
/// bring it back, stamped with where its state restores. `None` when it
/// cannot, and the row is deleted.
fn kept_unplaced(
    mut sandbox: common::Sandbox,
    node_id: &str,
    info: &common::NodeInfo,
) -> Option<common::Sandbox> {
    if !is_movable(&sandbox) {
        return None;
    }
    lost_to_checkpoint(&mut sandbox, node_id);
    sandbox.node_id.clear();
    if sandbox.arch.is_empty() {
        sandbox.arch = info.arch.clone();
        sandbox.hypervisor_version =
            crate::registry::version_of(info, &sandbox.hypervisor).to_string();
    }
    sandbox.cpu = info.cpu.clone();
    Some(sandbox)
}

/// The part of a node's report a row is rewritten from, as one digest. Usage
/// is left out: it moves on every heartbeat and is written on its own clock.
pub fn report_hash(report: &nodepb::SandboxStateReport) -> i64 {
    use prost::Message as _;
    let reported = nodepb::SandboxStateReport {
        state: report.state,
        is_agent_unconfirmed: report.is_agent_unconfirmed,
        is_durable: report.is_durable,
        state_reason: report.state_reason.clone(),
        checkpoint_at_unix_ms: report.checkpoint_at_unix_ms,
        checkpoint_kind: report.checkpoint_kind,
        activation: report.activation.clone(),
        ..Default::default()
    };
    // FNV-1a: stable across builds, unlike the standard library's hasher.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in reported.encode_to_vec() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash as i64
}

/// [`report_hash`] of what a record says.
pub fn record_hash(sandbox: &common::Sandbox) -> i64 {
    report_hash(&nodepb::SandboxStateReport {
        state: sandbox.state,
        is_agent_unconfirmed: sandbox.is_agent_unconfirmed,
        is_durable: sandbox.is_durable,
        state_reason: sandbox.state_reason.clone(),
        checkpoint_at_unix_ms: sandbox.checkpoint_at_unix_ms,
        checkpoint_kind: sandbox.checkpoint_kind,
        activation: sandbox.activation.clone(),
        ..Default::default()
    })
}

fn restated(mut sandbox: common::Sandbox, report: &nodepb::SandboxStateReport) -> common::Sandbox {
    sandbox.state = report.state;
    sandbox.is_durable = report.is_durable;
    sandbox.state_reason = report.state_reason.clone();
    sandbox.checkpoint_at_unix_ms = report.checkpoint_at_unix_ms;
    sandbox.checkpoint_kind = report.checkpoint_kind;
    sandbox.activation = report.activation.clone();
    sandbox.is_agent_unconfirmed = report.is_agent_unconfirmed;
    sandbox.cpu_usage_usec = report.cpu_usage_usec;
    sandbox.rx_bytes = report.rx_bytes;
    sandbox.tx_bytes = report.tx_bytes;
    sandbox
}

fn unavailable(err: burrow_store::StoreError) -> Status {
    Status::unavailable(format!("the store: {err}"))
}

/// A row as the cache holds it.
#[derive(Clone)]
struct Placed {
    sandbox: common::Sandbox,
    generation: i64,
}

/// The cached rows, indexed by what lookups and routing ask by, so none of
/// them walks every sandbox in the fleet.
#[derive(Default)]
struct Cache {
    placed: HashMap<String, Placed>,
    by_name: HashMap<String, String>,
    by_request: HashMap<String, String>,
    by_network: HashMap<String, std::collections::BTreeSet<String>>,
}

fn networks_of(sandbox: &common::Sandbox) -> impl Iterator<Item = &str> {
    sandbox
        .policy
        .iter()
        .flat_map(|p| p.networks.iter())
        .map(|m| m.network.as_str())
        .filter(|network| !network.is_empty())
}

impl Cache {
    fn get(&self, id: &str) -> Option<&Placed> {
        self.placed.get(id)
    }

    /// For usage figures only, which no index covers.
    fn get_mut(&mut self, id: &str) -> Option<&mut Placed> {
        self.placed.get_mut(id)
    }

    fn contains_key(&self, id: &str) -> bool {
        self.placed.contains_key(id)
    }

    fn values(&self) -> impl Iterator<Item = &Placed> {
        self.placed.values()
    }

    fn insert(&mut self, id: String, entry: Placed) -> Option<Placed> {
        let held = self.remove(&id);
        let sandbox = &entry.sandbox;
        if !sandbox.name.is_empty() {
            self.by_name.insert(sandbox.name.clone(), id.clone());
        }
        if !sandbox.create_request_id.is_empty() {
            self.by_request
                .insert(sandbox.create_request_id.clone(), id.clone());
        }
        for network in networks_of(sandbox) {
            self.by_network
                .entry(network.to_string())
                .or_default()
                .insert(id.clone());
        }
        self.placed.insert(id, entry);
        held
    }

    fn remove(&mut self, id: &str) -> Option<Placed> {
        let held = self.placed.remove(id)?;
        let sandbox = &held.sandbox;
        if self
            .by_name
            .get(&sandbox.name)
            .is_some_and(|held| held == id)
        {
            self.by_name.remove(&sandbox.name);
        }
        if self
            .by_request
            .get(&sandbox.create_request_id)
            .is_some_and(|held| held == id)
        {
            self.by_request.remove(&sandbox.create_request_id);
        }
        for network in networks_of(sandbox) {
            if let Some(members) = self.by_network.get_mut(network) {
                members.remove(id);
                if members.is_empty() {
                    self.by_network.remove(network);
                }
            }
        }
        Some(held)
    }

    /// The members of `network`.
    fn members(&self, network: &str) -> impl Iterator<Item = &Placed> {
        self.by_network
            .get(network)
            .into_iter()
            .flatten()
            .filter_map(|id| self.placed.get(id))
    }
}

/// A create whose node has not answered, which reads leave out: its row is
/// only the stub written ahead of it.
fn is_unanswered_create(row: &burrow_store::PlacementRow, sandbox: &common::Sandbox) -> bool {
    row.pending_since_ms > 0 && sandbox.state == common::SandboxState::Creating as i32
}

fn placed(row: &burrow_store::PlacementRow) -> Option<Placed> {
    let mut sandbox = decode(&row.record)?;
    if is_unanswered_create(row, &sandbox) {
        return None;
    }
    sandbox.node_id = row.node_id.clone();
    Some(Placed {
        sandbox,
        generation: row.generation,
    })
}

/// What writing off a node did with the sandboxes placed on it.
#[derive(Debug, Default)]
pub struct WrittenOff {
    pub dropped: Vec<common::Sandbox>,
    pub unplaced: Vec<common::Sandbox>,
}

/// What a node holds besides sandboxes, as one heartbeat lists it.
#[derive(Debug, Default)]
pub struct Holdings {
    pub snapshots: Vec<String>,
    /// Snapshots the node removed itself since its last applied heartbeat.
    pub swept_snapshots: Vec<String>,
    pub volumes: Vec<String>,
}

/// What a heartbeat's complete listing settled. See
/// [`SandboxRegistry::reconcile`].
#[derive(Debug, Default)]
pub struct Reconciled {
    /// Whether the report was applied. One no newer than the last applied
    /// for its node changes nothing and confirms nothing.
    pub is_applied: bool,
    /// Whether the store knows the node at all.
    pub is_known: bool,
    /// What the node holds that the store does not list for it at that
    /// generation, for the node to destroy.
    pub destroy: Vec<nodepb::SandboxGeneration>,
    pub restated: usize,
    /// Sandboxes no node held that the node still holds at their generation,
    /// placed back on it.
    pub replaced: Vec<String>,
    /// Rows its node no longer holds, deleted or kept unplaced.
    pub lost: Vec<String>,
    /// Rows the node holds whose create or adopt never had its answer
    /// recorded.
    pub unanswered: Vec<String>,
    /// Snapshots and volumes the node holds that no row names.
    pub destroy_snapshots: Vec<String>,
    pub destroy_volumes: Vec<String>,
}

pub struct SandboxRegistry {
    cache: Mutex<Cache>,
    store: Arc<burrow_store::Store>,
    /// Numbers this replica's own writes, so a reload that read the store
    /// before one does not undo it in the cache.
    seq: AtomicU64,
    /// The ids written since the last reload began, and when.
    written: Mutex<HashMap<String, u64>>,
    /// When the last applied reload started reading, held across a reload so
    /// callers arriving together share one read of the store.
    reloaded: tokio::sync::Mutex<Option<Instant>>,
}

impl SandboxRegistry {
    /// Opens the registry over the store, caching what it holds.
    pub async fn open(store: Arc<burrow_store::Store>) -> burrow_store::Result<Self> {
        let registry = Self {
            cache: Mutex::new(Cache::default()),
            store,
            seq: AtomicU64::new(0),
            written: Mutex::new(HashMap::new()),
            reloaded: tokio::sync::Mutex::new(None),
        };
        registry.reload_since(Instant::now()).await?;
        Ok(registry)
    }

    /// A registry over a private in-memory store.
    #[cfg(test)]
    pub async fn in_memory() -> Self {
        let store = burrow_store::Store::open_in_memory().await.unwrap();
        Self::open(Arc::new(store)).await.unwrap()
    }

    /// Places a settled sandbox at the first generation, replacing any row
    /// it had.
    #[cfg(test)]
    pub async fn put(&self, sandbox: common::Sandbox) {
        self.store.remove_placement(&sandbox.id).await.unwrap();
        let row = burrow_store::PlacementRow {
            id: sandbox.id.clone(),
            node_id: sandbox.node_id.clone(),
            record: encode(&sandbox),
            generation: FIRST_GENERATION,
            ..Default::default()
        };
        assert!(self.store.insert_placement(&row).await.unwrap());
        self.cache_row(&row);
    }

    pub fn store(&self) -> &Arc<burrow_store::Store> {
        &self.store
    }

    /// Sets what the cache holds for `id`, `None` for nothing, and notes the
    /// write so a reload already reading does not undo it.
    fn cached(&self, cache: &mut Cache, id: &str, entry: Option<Placed>) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.written.lock().unwrap().insert(id.to_string(), seq);
        match entry {
            Some(entry) => cache.insert(id.to_string(), entry),
            None => cache.remove(id),
        };
    }

    fn cache_row(&self, row: &burrow_store::PlacementRow) -> Option<common::Sandbox> {
        let mut cache = self.cache.lock().unwrap();
        let entry = placed(row);
        let sandbox = entry.as_ref().map(|entry| entry.sandbox.clone());
        self.cached(&mut cache, &row.id, entry);
        sandbox
    }

    /// Replaces the cache with the store's rows, for a replica catching up
    /// with writes other replicas made, keeping what this replica wrote
    /// after the read began.
    fn reload(&self, mark: u64, rows: Vec<burrow_store::PlacementRow>) {
        let mut cache = self.cache.lock().unwrap();
        let mut written = self.written.lock().unwrap();
        let mut fresh = Cache::default();
        for row in &rows {
            let Some(mut entry) = placed(row) else {
                continue;
            };
            // Usage moves on every heartbeat and is only written back now and
            // then, so a figure this replica already holds is the newer one.
            if let Some(held) = cache.get(&row.id)
                && held.generation == entry.generation
                && held.sandbox.cpu_usage_usec > entry.sandbox.cpu_usage_usec
            {
                entry.sandbox.cpu_usage_usec = held.sandbox.cpu_usage_usec;
                entry.sandbox.rx_bytes = held.sandbox.rx_bytes;
                entry.sandbox.tx_bytes = held.sandbox.tx_bytes;
            }
            fresh.insert(row.id.clone(), entry);
        }
        for (id, seq) in written.iter() {
            if *seq <= mark {
                continue;
            }
            match cache.get(id) {
                Some(entry) => fresh.insert(id.clone(), entry.clone()),
                None => fresh.remove(id),
            };
        }
        written.retain(|_, seq| *seq > mark);
        *cache = fresh;
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
        let mut reloaded = self.reloaded.lock().await;
        if reloaded.is_some_and(|at| at >= since) {
            return Ok(());
        }
        let started = Instant::now();
        let mark = self.seq.load(Ordering::SeqCst);
        let rows = self.store.list_placements().await?;
        self.reload(mark, rows);
        *reloaded = Some(started);
        Ok(())
    }

    /// Re-reads one sandbox from the store and caches what it says, for a
    /// caller about to act on it: another replica may have changed it since
    /// the last reload. A store that cannot be read answers with the cached
    /// copy; only a row the store confirms missing means the sandbox is gone.
    pub async fn refresh(&self, id: &str) -> Option<common::Sandbox> {
        match self.store.get_placement(id).await {
            Ok(Some(row)) => self.cache_row(&row),
            Ok(None) => {
                let mut cache = self.cache.lock().unwrap();
                if cache.contains_key(id) {
                    self.cached(&mut cache, id, None);
                }
                None
            }
            Err(err) => {
                tracing::warn!(sandbox = id, %err, "could not re-read a placement; using the cached one");
                self.get(id)
            }
        }
    }

    /// The sandbox and the generation the store has it at, read from the
    /// store, for a caller about to change where it is.
    pub async fn placed(&self, id: &str) -> Result<(common::Sandbox, i64), Status> {
        let row = self
            .store
            .get_placement(id)
            .await
            .map_err(unavailable)?
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        let sandbox = self
            .cache_row(&row)
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        Ok((sandbox, row.generation))
    }

    /// Finds a sandbox another replica created and this one has not caught
    /// up with yet, by id or by name, and caches it.
    pub async fn load(&self, reference: &str) -> Option<common::Sandbox> {
        if let Some(row) = self.store.get_placement(reference).await.ok().flatten() {
            return self.cache_row(&row);
        }
        let id = self
            .store
            .claim_holder(&name_key(reference))
            .await
            .ok()
            .flatten()?;
        let row = self.store.get_placement(&id).await.ok().flatten()?;
        self.cache_row(&row)
    }

    /// The sandbox a create with this request id made, here or through
    /// another replica.
    pub async fn by_request(&self, request: &str) -> Option<common::Sandbox> {
        let held = {
            let cache = self.cache.lock().unwrap();
            cache
                .by_request
                .get(request)
                .and_then(|id| cache.get(id))
                .map(|p| p.sandbox.clone())
        };
        if held.is_some() {
            return held;
        }
        let id = self
            .store
            .claim_holder(&request_key(request))
            .await
            .ok()
            .flatten()?;
        let row = self.store.get_placement(&id).await.ok().flatten()?;
        self.cache_row(&row)
    }

    /// Claims a name for a create, so no other create on any replica takes
    /// it. The id is claimed by the row written ahead of the create.
    pub async fn reserve(&self, id: &str, name: &str) -> Result<Reservation, Status> {
        let reservation = Reservation {
            store: Arc::clone(&self.store),
            id: id.to_string(),
            written_on: None,
            is_kept: false,
        };
        if !name.is_empty() {
            match self
                .store
                .claim(&name_key(name), id, burrow_common::unix_now())
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Err(Status::already_exists(format!(
                        "a sandbox named {name} exists"
                    )));
                }
                Err(err) => return Err(unavailable(err)),
            }
        }
        Ok(reservation)
    }

    /// Writes the row of a sandbox about to be created on `stub.node_id`,
    /// before that node is asked to build it.
    pub async fn write_ahead(
        &self,
        reservation: &mut Reservation,
        stub: common::Sandbox,
    ) -> Result<(), Status> {
        let stub = common::Sandbox {
            state: common::SandboxState::Creating as i32,
            ..stub
        };
        let row = burrow_store::PlacementRow {
            id: stub.id.clone(),
            node_id: stub.node_id.clone(),
            record: encode(&stub),
            generation: FIRST_GENERATION,
            pending_since_ms: burrow_common::unix_now_ms(),
            ..Default::default()
        };
        if !self
            .store
            .insert_placement(&row)
            .await
            .map_err(unavailable)?
        {
            return Err(Status::already_exists(format!(
                "sandbox {} exists",
                stub.id
            )));
        }
        reservation.written_on = Some(stub.node_id);
        Ok(())
    }

    /// Claims a create's request id for `id`, so a retry of it through any
    /// replica waits for this create rather than making a second sandbox.
    pub async fn claim_request(&self, request: &str, id: &str) -> Result<RequestClaim, Status> {
        let key = request_key(request);
        match self.store.claim(&key, id, burrow_common::unix_now()).await {
            Ok(true) => Ok(RequestClaim {
                store: Arc::clone(&self.store),
                key,
                id: id.to_string(),
            }),
            Ok(false) => Err(Status::aborted(format!(
                "a create with request id {request} is still running"
            ))),
            Err(err) => Err(unavailable(err)),
        }
    }

    /// Takes the record a node answered with for the placement it was asked
    /// to act on at `generation`, and clears the row's pending mark. False
    /// when the row has moved on, or gone, since.
    pub async fn settle(&self, sandbox: common::Sandbox, generation: i64) -> Result<bool, Status> {
        self.write_record(sandbox, generation, true).await
    }

    /// Takes the record a node answered a lifecycle call with, unless the
    /// store has the sandbox elsewhere or gone by then.
    pub async fn update(&self, sandbox: common::Sandbox) {
        let generation = match self.cache.lock().unwrap().get(&sandbox.id) {
            Some(held) if held.sandbox.node_id == sandbox.node_id => Some(held.generation),
            _ => None,
        };
        let generation = match generation {
            Some(generation) => generation,
            None => match self.store.get_placement(&sandbox.id).await {
                Ok(Some(row)) if row.node_id == sandbox.node_id => row.generation,
                Ok(_) => return,
                Err(err) => {
                    tracing::warn!(sandbox = sandbox.id, %err, "could not record a node's answer");
                    return;
                }
            },
        };
        if let Err(err) = self.write_record(sandbox.clone(), generation, false).await {
            tracing::warn!(sandbox = sandbox.id, %err, "could not record a node's answer");
        }
    }

    async fn write_record(
        &self,
        sandbox: common::Sandbox,
        generation: i64,
        is_settled: bool,
    ) -> Result<bool, Status> {
        let row = burrow_store::PlacementRow {
            id: sandbox.id.clone(),
            node_id: sandbox.node_id.clone(),
            record: encode(&sandbox),
            generation,
            ..Default::default()
        };
        let written = self
            .store
            .update_placement(&row, record_hash(&sandbox), is_settled)
            .await
            .map_err(unavailable)?;
        if written {
            let mut cache = self.cache.lock().unwrap();
            let id = sandbox.id.clone();
            self.cached(
                &mut cache,
                &id,
                Some(Placed {
                    sandbox,
                    generation,
                }),
            );
        } else {
            tracing::info!(
                sandbox = row.id,
                node = row.node_id,
                generation,
                "the stored placement moved on; not writing over it"
            );
        }
        Ok(written)
    }

    /// Marks a sandbox about to be released by `node_id` for a move: pending,
    /// so its node's listings leaving it out do not lose it while it uploads,
    /// and recorded as what the release leaves, suspended in the object
    /// store, so a move that dies before writing the row onto its target
    /// leaves something a start can place.
    pub async fn mark_releasing(
        &self,
        sandbox: &common::Sandbox,
        generation: i64,
    ) -> Result<(), Status> {
        let releasing = common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..sandbox.clone()
        };
        let row = burrow_store::PlacementRow {
            id: sandbox.id.clone(),
            node_id: sandbox.node_id.clone(),
            record: encode(&releasing),
            generation,
            ..Default::default()
        };
        let marked = self
            .store
            .mark_placement_pending(&row, record_hash(&releasing), burrow_common::unix_now_ms())
            .await
            .map_err(unavailable)?;
        if !marked {
            return Err(Status::aborted(format!(
                "sandbox {} was placed or deleted by another call",
                sandbox.id
            )));
        }
        Ok(())
    }

    /// Writes a sandbox onto `to_node` at the next generation, ahead of
    /// asking that node to adopt it, while the store still has it on
    /// `from_node` (`""` for none) at `generation`. Returns the new
    /// generation; refused when another call placed or removed it first.
    pub async fn move_to(
        &self,
        sandbox: &common::Sandbox,
        from_node: &str,
        generation: i64,
        to_node: &str,
    ) -> Result<i64, Status> {
        let moving = common::Sandbox {
            node_id: to_node.to_string(),
            ..sandbox.clone()
        };
        let next = self
            .store
            .move_placement(
                &sandbox.id,
                from_node,
                generation,
                to_node,
                &encode(&moving),
                burrow_common::unix_now_ms(),
            )
            .await
            .map_err(unavailable)?;
        let Some(next) = next else {
            let id = &sandbox.id;
            return Err(Status::aborted(match self.refresh(id).await {
                None => format!("sandbox {id} was deleted by another call"),
                Some(held) if held.node_id.is_empty() => {
                    format!("sandbox {id} was let go of by another call; start it to place it")
                }
                Some(held) => format!(
                    "sandbox {id} was placed on node {} by another call",
                    held.node_id
                ),
            }));
        };
        let mut cache = self.cache.lock().unwrap();
        self.cached(
            &mut cache,
            &sandbox.id,
            Some(Placed {
                sandbox: moving,
                generation: next,
            }),
        );
        Ok(next)
    }

    /// Takes a sandbox off `node_id`, where the store has it at
    /// `generation`, for one its state in the object store can bring back.
    pub async fn unplace(
        &self,
        sandbox: common::Sandbox,
        node_id: &str,
        generation: i64,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = common::Sandbox {
            node_id: String::new(),
            ..sandbox
        };
        if !self
            .store
            .unplace_placement(&sandbox.id, node_id, generation, &encode(&sandbox))
            .await
            .map_err(unavailable)?
        {
            return Err(Status::aborted(format!(
                "sandbox {} was placed by another call",
                sandbox.id
            )));
        }
        let mut cache = self.cache.lock().unwrap();
        self.cached(
            &mut cache,
            &sandbox.id.clone(),
            Some(Placed {
                sandbox: sandbox.clone(),
                generation,
            }),
        );
        Ok(sandbox)
    }

    /// Deletes a sandbox: its row and its claims, which frees its name on
    /// every replica at once. Returns what the row held, `None` when there
    /// was none. Whatever node still holds it destroys it when told, or at
    /// its next heartbeat.
    pub async fn remove(&self, id: &str) -> Result<Option<common::Sandbox>, Status> {
        let row = self.store.remove_placement(id).await.map_err(unavailable)?;
        let mut cache = self.cache.lock().unwrap();
        self.cached(&mut cache, id, None);
        Ok(row.and_then(|row| {
            let mut sandbox = decode(&row.record)?;
            sandbox.node_id = row.node_id;
            Some(sandbox)
        }))
    }

    pub fn get(&self, id: &str) -> Option<common::Sandbox> {
        self.cache
            .lock()
            .unwrap()
            .get(id)
            .map(|p| p.sandbox.clone())
    }

    /// The node currently hosting a sandbox.
    pub fn node_of(&self, id: &str) -> Option<String> {
        self.cache
            .lock()
            .unwrap()
            .get(id)
            .map(|p| p.sandbox.node_id.clone())
    }

    /// The id of the sandbox carrying this name, if one does.
    pub fn id_by_name(&self, name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        self.cache.lock().unwrap().by_name.get(name).cloned()
    }

    /// Writes off a node silent since before `before_ms`, for the leader of
    /// `epoch` only, settling every placement on it: returns what was
    /// dropped and what was kept unplaced, or `None` when the node was heard
    /// from since or another leader took over.
    ///
    /// A suspended sandbox whose state is in the object store does not need
    /// the node, so it is kept unplaced, with its name, for the next start to
    /// place on a node that can restore it. `info` is the dead node's, whose
    /// architecture and hypervisor version are stamped on a record that does
    /// not carry its own, and whose CPU, which wrote the saved memory, on
    /// every one. One holding public addresses is kept unplaced too, but only
    /// its own node can take it back: the addresses reach nowhere else.
    pub async fn write_off(
        &self,
        node_id: &str,
        info: &common::NodeInfo,
        before_ms: i64,
        epoch: i64,
    ) -> Result<Option<WrittenOff>, Status> {
        let lost = self
            .store
            .write_off_node(node_id, before_ms, epoch, |row| {
                let sandbox = decode(&row.record)?;
                kept_unplaced(sandbox, node_id, info).map(|kept| encode(&kept))
            })
            .await
            .map_err(unavailable)?;
        let Some(lost) = lost else {
            return Ok(None);
        };
        let mut out = WrittenOff::default();
        let mut cache = self.cache.lock().unwrap();
        for lost in lost {
            let kept = lost.unplaced.as_deref().and_then(decode);
            let entry = kept.clone().map(|sandbox| Placed {
                sandbox,
                generation: lost.row.generation,
            });
            self.cached(&mut cache, &lost.row.id, entry);
            match kept {
                Some(sandbox) => out.unplaced.push(sandbox),
                None => out.dropped.extend(decode(&lost.row.record)),
            }
        }
        Ok(Some(out))
    }

    /// Applies a node's heartbeat: its status and its complete listing,
    /// compared against the store in one transaction. See
    /// [`burrow_store::Store::reconcile_node`].
    ///
    /// A row the node leaves out of two consecutive listings is lost: kept
    /// unplaced if the object store can bring it back, unless the node's last
    /// word on it was that it destroyed it, and deleted otherwise.
    pub async fn reconcile(
        &self,
        node: burrow_store::NodeRow,
        info: &common::NodeInfo,
        seq: u64,
        reported: &[nodepb::SandboxStateReport],
        holdings: Holdings,
    ) -> Result<Reconciled, Status> {
        let Holdings {
            snapshots,
            swept_snapshots,
            volumes,
        } = holdings;
        let now = node.last_heartbeat_ms;
        let node_id = node.id.clone();
        let by_id: HashMap<&str, &nodepb::SandboxStateReport> = reported
            .iter()
            .map(|report| (report.sandbox_id.as_str(), report))
            .collect();
        let report = burrow_store::NodeReport {
            node,
            seq: seq as i64,
            sandboxes: reported
                .iter()
                .map(|report| burrow_store::ReportedSandbox {
                    id: report.sandbox_id.clone(),
                    generation: report.generation as i64,
                    hash: report_hash(report),
                    in_flight: i64::from(report.is_in_flight),
                })
                .collect(),
            pending_after_ms: now - PENDING_DEADLINE_MS,
            usage_before_ms: now - USAGE_WRITE_INTERVAL_MS,
            unanswered_before_ms: now - UNANSWERED_AFTER_MS,
            snapshots,
            swept_snapshots,
            volumes,
        };
        let restate = |row: &burrow_store::PlacementRow| {
            let report = by_id.get(row.id.as_str()).filter(|r| !r.is_in_flight)?;
            let sandbox = restated(decode(&row.record)?, report);
            Some((encode(&sandbox), report_hash(report)))
        };
        let lose = |row: &burrow_store::PlacementRow, last: Option<(i32, String)>| {
            let destroyed = last.as_ref().is_some_and(|(kind, detail)| {
                *kind == common::EventKind::Destroyed as i32 && detail.is_empty()
            });
            if destroyed {
                return None;
            }
            let mut sandbox = decode(&row.record)?;
            // Released to the object store for a move that never wrote the
            // row onto its target: its state is there, whatever the record
            // from before says.
            let released = last.is_some_and(|(kind, detail)| {
                kind == common::EventKind::Stopped as i32 && detail == RELEASED
            });
            if released {
                sandbox.state = common::SandboxState::Suspended as i32;
                sandbox.is_durable = true;
            }
            kept_unplaced(sandbox, &node_id, info).map(|kept| encode(&kept))
        };
        let outcome = self
            .store
            .reconcile_node(&report, restate, lose)
            .await
            .map_err(unavailable)?;
        let applied = match outcome {
            burrow_store::Reconciled::Unknown => return Ok(Reconciled::default()),
            burrow_store::Reconciled::Stale => {
                return Ok(Reconciled {
                    is_known: true,
                    ..Default::default()
                });
            }
            burrow_store::Reconciled::Applied(applied) => applied,
        };
        let mut cache = self.cache.lock().unwrap();
        for row in applied.replaced.iter().chain(&applied.restated) {
            let entry = placed(row);
            self.cached(&mut cache, &row.id, entry);
        }
        let mut lost = Vec::with_capacity(applied.lost.len());
        for gone in applied.lost {
            let entry = gone
                .unplaced
                .as_deref()
                .and_then(decode)
                .map(|sandbox| Placed {
                    sandbox,
                    generation: gone.row.generation,
                });
            self.cached(&mut cache, &gone.row.id, entry);
            lost.push(gone.row.id);
        }
        // Usage moves on every beat; the replica the node beats to answers
        // with the latest without writing it each time.
        for report in reported.iter().filter(|r| !r.is_in_flight) {
            if let Some(held) = cache.get_mut(&report.sandbox_id)
                && held.sandbox.node_id == node_id
                && held.generation == report.generation as i64
            {
                held.sandbox.cpu_usage_usec = report.cpu_usage_usec;
                held.sandbox.rx_bytes = report.rx_bytes;
                held.sandbox.tx_bytes = report.tx_bytes;
            }
        }
        Ok(Reconciled {
            is_applied: true,
            is_known: true,
            destroy: applied
                .destroy
                .into_iter()
                .map(|(sandbox_id, generation)| nodepb::SandboxGeneration {
                    sandbox_id,
                    generation: generation as u64,
                })
                .collect(),
            restated: applied.restated.len(),
            replaced: applied.replaced.into_iter().map(|row| row.id).collect(),
            lost,
            unanswered: applied.unanswered,
            destroy_snapshots: applied.destroy_snapshots,
            destroy_volumes: applied.destroy_volumes,
        })
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
        let cache = self.cache.lock().unwrap();
        networks
            .iter()
            .flat_map(|network| cache.members(network))
            // An unplaced member is not anywhere, so it pins nothing.
            .find(|p| !p.sandbox.node_id.is_empty())
            .map(|p| p.sandbox.node_id.clone())
    }

    /// Guest addresses on each private network that live on *other* nodes.
    ///
    /// A node already knows its own members; what it cannot know is which
    /// remote addresses share a network with them, which is exactly what its
    /// firewall needs in order to let mesh traffic through.
    pub fn network_members(&self, for_node: &str) -> Vec<nodepb::NetworkMembers> {
        let cache = self.cache.lock().unwrap();
        let mut out: Vec<_> = cache
            .by_network
            .keys()
            .filter_map(|network| {
                let members: Vec<_> = cache
                    .members(network)
                    .map(|p| &p.sandbox)
                    .filter(|sandbox| sandbox.node_id != for_node && !sandbox.guest_ip.is_empty())
                    .flat_map(|sandbox| {
                        sandbox
                            .policy
                            .iter()
                            .flat_map(|p| p.networks.iter())
                            .filter(|m| &m.network == network)
                            .map(|membership| nodepb::NetworkMember {
                                sandbox_id: sandbox.id.clone(),
                                alias: alias_of(membership, &sandbox.id),
                                guest_ip: sandbox.guest_ip.clone(),
                            })
                    })
                    .collect();
                (!members.is_empty()).then(|| nodepb::NetworkMembers {
                    network: network.clone(),
                    members,
                })
            })
            .collect();
        out.sort_by(|a, b| a.network.cmp(&b.network));
        out
    }

    /// Every sandbox, or only those carrying an exact `key=value` tag.
    pub fn list_tagged(&self, tag: Option<(&str, &str)>) -> Vec<common::Sandbox> {
        let mut out: Vec<_> = self
            .cache
            .lock()
            .unwrap()
            .values()
            .map(|p| &p.sandbox)
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

/// A create's claim on its name, and the row written ahead of it. Given
/// back unless the create made a sandbox or may have: a node that could not
/// be heard from may still be building it, and its heartbeat settles that.
pub struct Reservation {
    store: Arc<burrow_store::Store>,
    id: String,
    written_on: Option<String>,
    is_kept: bool,
}

impl Reservation {
    pub fn keep(mut self) {
        self.is_kept = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.is_kept {
            return;
        }
        let store = Arc::clone(&self.store);
        let id = std::mem::take(&mut self.id);
        let written_on = self.written_on.take();
        tokio::spawn(async move {
            let given_back = match written_on {
                Some(node) => store
                    .remove_placement_at(&id, &node, FIRST_GENERATION)
                    .await
                    .map(drop),
                None => store.release_claims(&id).await,
            };
            if let Err(err) = given_back {
                tracing::warn!(sandbox = id, %err, "could not give back a failed create's claims");
            }
        });
    }
}

/// A create's claim on its request id. Given back if the create made no
/// sandbox; otherwise kept in the store with the sandbox's other claims.
pub struct RequestClaim {
    store: Arc<burrow_store::Store>,
    key: String,
    id: String,
}

impl Drop for RequestClaim {
    fn drop(&mut self) {
        let store = Arc::clone(&self.store);
        let key = std::mem::take(&mut self.key);
        let id = std::mem::take(&mut self.id);
        tokio::spawn(async move {
            if matches!(store.get_placement(&id).await, Ok(None)) {
                let _ = store.release_claim(&key, &id).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(id: &str, node: &str) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: node.into(),
            state: common::SandboxState::Running as i32,
            ..Default::default()
        }
    }

    async fn with_node(registry: &SandboxRegistry, node: &str) {
        registry
            .store()
            .register_node(
                &burrow_store::NodeRow {
                    id: node.into(),
                    ..Default::default()
                },
                None,
                8,
            )
            .await
            .unwrap();
    }

    /// Creates `id` on `node` the way a create does: the row first, then the
    /// node's answer.
    async fn created(registry: &SandboxRegistry, id: &str, node: &str) {
        let mut reservation = registry.reserve(id, "").await.unwrap();
        registry
            .write_ahead(&mut reservation, sandbox(id, node))
            .await
            .unwrap();
        assert!(
            registry
                .settle(sandbox(id, node), FIRST_GENERATION)
                .await
                .unwrap()
        );
        reservation.keep();
    }

    fn listing(entries: &[(&str, i64)]) -> Vec<nodepb::SandboxStateReport> {
        entries
            .iter()
            .map(|(id, generation)| nodepb::SandboxStateReport {
                sandbox_id: id.to_string(),
                state: common::SandboxState::Running as i32,
                generation: *generation as u64,
                ..Default::default()
            })
            .collect()
    }

    async fn beat(
        registry: &SandboxRegistry,
        node: &str,
        seq: u64,
        entries: &[(&str, i64)],
    ) -> Reconciled {
        let row = burrow_store::NodeRow {
            id: node.into(),
            last_heartbeat_ms: burrow_common::unix_now_ms(),
            ..Default::default()
        };
        registry
            .reconcile(
                row,
                &common::NodeInfo::default(),
                seq,
                &listing(entries),
                Holdings::default(),
            )
            .await
            .unwrap()
    }

    fn destroyed(out: &Reconciled) -> Vec<(&str, u64)> {
        out.destroy
            .iter()
            .map(|d| (d.sandbox_id.as_str(), d.generation))
            .collect()
    }

    /// The row exists before the node is asked to build anything, and reads
    /// leave it out until the node answers.
    #[tokio::test]
    async fn a_create_is_written_ahead_and_shown_once_answered() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        let mut reservation = registry.reserve("sbx_a", "web").await.unwrap();
        assert!(registry.reserve("sbx_b", "web").await.is_err());
        registry
            .write_ahead(&mut reservation, sandbox("sbx_a", "n1"))
            .await
            .unwrap();
        let row = registry
            .store()
            .get_placement("sbx_a")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((row.node_id.as_str(), row.generation), ("n1", 1));
        assert!(row.pending_since_ms > 0);
        assert!(registry.get("sbx_a").is_none());
        registry.reload_since(Instant::now()).await.unwrap();
        assert!(registry.get("sbx_a").is_none());

        // The node's listing may already carry it: legitimate, not destroyed.
        let out = beat(&registry, "n1", 1, &[("sbx_a", 1)]).await;
        assert!(out.destroy.is_empty());

        assert!(registry.settle(sandbox("sbx_a", "n1"), 1).await.unwrap());
        reservation.keep();
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some("n1"));
    }

    /// A create the node refused gives back its row and its name.
    #[tokio::test]
    async fn a_failed_create_gives_back_its_row_and_name() {
        let registry = SandboxRegistry::in_memory().await;
        let mut reservation = registry.reserve("sbx_a", "web").await.unwrap();
        registry
            .write_ahead(&mut reservation, sandbox("sbx_a", "n1"))
            .await
            .unwrap();
        drop(reservation);
        for _ in 0..100 {
            if registry
                .store()
                .get_placement("sbx_a")
                .await
                .unwrap()
                .is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            registry
                .store()
                .get_placement("sbx_a")
                .await
                .unwrap()
                .is_none()
        );
        assert!(registry.reserve("sbx_b", "web").await.is_ok());
    }

    /// Delete always succeeds and needs no node. Whenever the node is heard
    /// from again, however long after, it is told to destroy its copy.
    #[tokio::test]
    async fn a_sandbox_deleted_while_its_node_was_away_is_destroyed_on_its_return() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        created(&registry, "sbx_a", "n1").await;
        let removed = registry.remove("sbx_a").await.unwrap().unwrap();
        assert_eq!(removed.node_id, "n1");
        assert!(registry.get("sbx_a").is_none());

        // No timer is involved, so "a long time" is any number of beats.
        let out = beat(&registry, "n1", 1_000_000, &[("sbx_a", 1)]).await;
        assert_eq!(destroyed(&out), [("sbx_a", 1)]);
        let again = beat(&registry, "n1", 1_000_001, &[("sbx_a", 1)]).await;
        assert_eq!(destroyed(&again), [("sbx_a", 1)]);
        assert!(
            registry
                .store()
                .get_placement("sbx_a")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A move raises the generation, so the node it left destroys whatever
    /// copy it comes back with, and the node it went to keeps its own.
    #[tokio::test]
    async fn the_node_a_sandbox_moved_off_destroys_its_copy() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        with_node(&registry, "n2").await;
        created(&registry, "sbx_a", "n1").await;
        let (current, generation) = registry.placed("sbx_a").await.unwrap();
        let next = registry
            .move_to(&current, "n1", generation, "n2")
            .await
            .unwrap();
        assert_eq!(next, 2);
        assert!(registry.settle(sandbox("sbx_a", "n2"), next).await.unwrap());

        let old = beat(&registry, "n1", 1, &[("sbx_a", 1)]).await;
        assert_eq!(destroyed(&old), [("sbx_a", 1)]);
        let new = beat(&registry, "n2", 1, &[("sbx_a", 2)]).await;
        assert!(new.destroy.is_empty());
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some("n2"));
    }

    /// A node SIGKILLed and restarted brings back from its own records a
    /// sandbox that was recovered on another node meanwhile. It used to adopt
    /// it back, so a later move to it failed with ALREADY_EXISTS. Its copy is
    /// at an old generation: it is destroyed, and a move back writes a newer
    /// one, which is the only copy the node may keep.
    #[tokio::test]
    async fn a_restarted_node_does_not_take_back_a_sandbox_recovered_elsewhere() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        with_node(&registry, "n2").await;
        let durable = common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..sandbox("sbx_a", "n1")
        };
        let mut reservation = registry.reserve("sbx_a", "").await.unwrap();
        registry
            .write_ahead(&mut reservation, durable.clone())
            .await
            .unwrap();
        registry.settle(durable.clone(), 1).await.unwrap();
        reservation.keep();

        // n1 is written off, and the sandbox recovered on n2.
        let epoch = registry.store().next_leader_epoch().await.unwrap();
        let written_off = registry
            .write_off("n1", &common::NodeInfo::default(), i64::MAX, epoch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written_off.unplaced.len(), 1);
        let (current, generation) = registry.placed("sbx_a").await.unwrap();
        assert_eq!(current.node_id, "");
        let on_n2 = registry
            .move_to(&current, "", generation, "n2")
            .await
            .unwrap();
        registry
            .settle(
                common::Sandbox {
                    node_id: "n2".into(),
                    ..durable.clone()
                },
                on_n2,
            )
            .await
            .unwrap();

        // n1 restarts and lists its copy from before.
        with_node(&registry, "n1").await;
        let out = beat(&registry, "n1", 1, &[("sbx_a", 1)]).await;
        assert_eq!(destroyed(&out), [("sbx_a", 1)]);
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some("n2"));

        // A move back gives n1 a newer generation than the copy it held.
        let (current, generation) = registry.placed("sbx_a").await.unwrap();
        let back = registry
            .move_to(&current, "n2", generation, "n1")
            .await
            .unwrap();
        assert!(back > 1);
        registry
            .settle(
                common::Sandbox {
                    node_id: "n1".into(),
                    ..durable
                },
                back,
            )
            .await
            .unwrap();
        let stale = beat(&registry, "n1", 2, &[("sbx_a", 1)]).await;
        assert_eq!(destroyed(&stale), [("sbx_a", 1)]);
        let fresh = beat(&registry, "n1", 3, &[("sbx_a", back)]).await;
        assert!(fresh.destroy.is_empty());
    }

    /// A node written off and back still holding a durable sandbox nobody
    /// has started since keeps it: its copy is the current one, and its
    /// state in the object store is its own.
    #[tokio::test]
    async fn a_written_off_node_back_with_an_unplaced_sandbox_keeps_it() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        let durable = common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..sandbox("sbx_a", "n1")
        };
        let mut reservation = registry.reserve("sbx_a", "").await.unwrap();
        registry
            .write_ahead(&mut reservation, durable.clone())
            .await
            .unwrap();
        registry.settle(durable, 1).await.unwrap();
        reservation.keep();
        let epoch = registry.store().next_leader_epoch().await.unwrap();
        registry
            .write_off("n1", &common::NodeInfo::default(), i64::MAX, epoch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some(""));

        with_node(&registry, "n1").await;
        let out = beat(&registry, "n1", 1, &[("sbx_a", 1)]).await;
        assert!(out.destroy.is_empty());
        assert_eq!(out.replaced, ["sbx_a"]);
        assert_eq!(registry.node_of("sbx_a").as_deref(), Some("n1"));
    }

    /// A create or adopt taking longer than the pending deadline is listed
    /// by its node as in flight, which keeps its row however long it takes,
    /// and leaves the record alone and unfetched until the node answers.
    #[tokio::test]
    async fn a_create_in_flight_past_its_deadline_keeps_its_row() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        let stub = common::Sandbox {
            state: common::SandboxState::Creating as i32,
            name: "slow".into(),
            ..sandbox("sbx_slow", "n1")
        };
        registry
            .store()
            .insert_placement(&burrow_store::PlacementRow {
                id: "sbx_slow".into(),
                node_id: "n1".into(),
                record: encode(&stub),
                generation: FIRST_GENERATION,
                pending_since_ms: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        let in_flight = vec![nodepb::SandboxStateReport {
            sandbox_id: "sbx_slow".into(),
            state: common::SandboxState::Creating as i32,
            generation: FIRST_GENERATION as u64,
            is_in_flight: true,
            ..Default::default()
        }];
        for seq in 1..5 {
            let row = burrow_store::NodeRow {
                id: "n1".into(),
                last_heartbeat_ms: burrow_common::unix_now_ms(),
                ..Default::default()
            };
            let out = registry
                .reconcile(
                    row,
                    &common::NodeInfo::default(),
                    seq,
                    &in_flight,
                    Holdings::default(),
                )
                .await
                .unwrap();
            assert!(out.lost.is_empty() && out.destroy.is_empty() && out.unanswered.is_empty());
        }
        let row = registry
            .store()
            .get_placement("sbx_slow")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode(&row.record).unwrap().name, "slow");
        // Not listed at all, the same row is lost.
        beat(&registry, "n1", 5, &[]).await;
        assert_eq!(beat(&registry, "n1", 6, &[]).await.lost, ["sbx_slow"]);
    }

    /// A report delayed in flight arrives after a newer one and is ignored,
    /// so it cannot restate a sandbox or count a miss.
    #[tokio::test]
    async fn a_delayed_heartbeat_changes_nothing() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        created(&registry, "sbx_a", "n1").await;
        assert!(beat(&registry, "n1", 10, &[("sbx_a", 1)]).await.is_applied);
        let late = beat(&registry, "n1", 9, &[]).await;
        assert!(!late.is_applied && late.is_known);
        let late = beat(&registry, "n1", 8, &[]).await;
        assert!(!late.is_applied);
        assert!(
            beat(&registry, "n1", 11, &[("sbx_a", 1)])
                .await
                .lost
                .is_empty()
        );
        assert!(registry.get("sbx_a").is_some());
        assert!(!beat(&registry, "nx", 1, &[]).await.is_known);
    }

    /// One listing that leaves a sandbox out loses nothing; two in a row do.
    /// What the object store can bring back is kept unplaced, unless the
    /// node's last word on it was that it destroyed it.
    #[tokio::test]
    async fn a_row_is_lost_only_after_two_listings_leave_it_out() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        created(&registry, "sbx_gone", "n1").await;
        let durable = common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..sandbox("sbx_durable", "n1")
        };
        let mut reservation = registry.reserve("sbx_durable", "").await.unwrap();
        registry
            .write_ahead(&mut reservation, durable.clone())
            .await
            .unwrap();
        registry.settle(durable, 1).await.unwrap();
        reservation.keep();

        assert!(beat(&registry, "n1", 1, &[]).await.lost.is_empty());
        let mut both = listing(&[("sbx_gone", 1), ("sbx_durable", 1)]);
        both[1].state = common::SandboxState::Suspended as i32;
        both[1].is_durable = true;
        let row = burrow_store::NodeRow {
            id: "n1".into(),
            last_heartbeat_ms: burrow_common::unix_now_ms(),
            ..Default::default()
        };
        let out = registry
            .reconcile(
                row,
                &common::NodeInfo::default(),
                2,
                &both,
                Holdings::default(),
            )
            .await
            .unwrap();
        assert!(out.lost.is_empty());
        assert!(beat(&registry, "n1", 3, &[]).await.lost.is_empty());
        let mut lost = beat(&registry, "n1", 4, &[]).await.lost;
        lost.sort();
        assert_eq!(lost, ["sbx_durable", "sbx_gone"]);
        assert!(registry.get("sbx_gone").is_none());
        assert_eq!(registry.node_of("sbx_durable").as_deref(), Some(""));
    }

    #[tokio::test]
    async fn a_sandbox_its_node_destroyed_is_not_kept_unplaced() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        let durable = common::Sandbox {
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..sandbox("sbx_a", "n1")
        };
        let mut reservation = registry.reserve("sbx_a", "").await.unwrap();
        registry
            .write_ahead(&mut reservation, durable.clone())
            .await
            .unwrap();
        registry.settle(durable, 1).await.unwrap();
        reservation.keep();
        registry
            .store()
            .append_event(&burrow_store::EventRow {
                node_id: "n1".into(),
                node_seq: 1,
                sandbox_id: "sbx_a".into(),
                kind: common::EventKind::Destroyed as i32,
                ..Default::default()
            })
            .await
            .unwrap();
        beat(&registry, "n1", 1, &[]).await;
        assert_eq!(beat(&registry, "n1", 2, &[]).await.lost, ["sbx_a"]);
        assert!(
            registry
                .store()
                .get_placement("sbx_a")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A move whose replica died between the source letting go and the row
    /// naming the target leaves the row on the source with the record from
    /// before, of a running sandbox no checkpoint covers. The source's last
    /// word, that it released it to the object store, keeps it unplaced
    /// rather than deleted, so a start brings it back.
    #[tokio::test]
    async fn a_sandbox_released_for_a_move_that_never_landed_is_kept() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        created(&registry, "sbx_a", "n1").await;
        registry
            .store()
            .append_event(&burrow_store::EventRow {
                node_id: "n1".into(),
                node_seq: 1,
                sandbox_id: "sbx_a".into(),
                kind: common::EventKind::Stopped as i32,
                detail: "released".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        beat(&registry, "n1", 1, &[]).await;
        assert_eq!(beat(&registry, "n1", 2, &[]).await.lost, ["sbx_a"]);
        let row = registry.store().get_placement("sbx_a").await.unwrap();
        assert_eq!(row.map(|row| row.node_id).as_deref(), Some(""));
    }

    /// The row of a sandbox being released for a move is pending, so the
    /// source's listings leaving it out while it uploads lose nothing, and
    /// says what the release leaves: suspended in the object store.
    #[tokio::test]
    async fn a_sandbox_being_released_is_pending_and_recoverable() {
        let registry = SandboxRegistry::in_memory().await;
        with_node(&registry, "n1").await;
        created(&registry, "sbx_a", "n1").await;
        registry
            .mark_releasing(&sandbox("sbx_a", "n1"), 1)
            .await
            .unwrap();
        let row = registry
            .store()
            .get_placement("sbx_a")
            .await
            .unwrap()
            .unwrap();
        assert!(row.pending_since_ms > 0);
        assert!(is_movable(&decode(&row.record).unwrap()));
        for seq in 1..5 {
            assert!(beat(&registry, "n1", seq, &[]).await.lost.is_empty());
        }
        assert!(
            registry
                .mark_releasing(&sandbox("sbx_a", "n1"), 2)
                .await
                .is_err()
        );
    }

    /// A node's own state changes are taken from its listing and reach every
    /// replica through the store.
    #[tokio::test]
    async fn a_node_initiated_suspension_reaches_the_other_replicas() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let first = SandboxRegistry::open(Arc::clone(&store)).await.unwrap();
        let second = SandboxRegistry::open(Arc::clone(&store)).await.unwrap();
        with_node(&first, "n1").await;
        created(&first, "sbx_a", "n1").await;
        let mut suspended = listing(&[("sbx_a", 1)]);
        suspended[0].state = common::SandboxState::Suspended as i32;
        let row = burrow_store::NodeRow {
            id: "n1".into(),
            last_heartbeat_ms: burrow_common::unix_now_ms(),
            ..Default::default()
        };
        let out = first
            .reconcile(
                row,
                &common::NodeInfo::default(),
                1,
                &suspended,
                Holdings::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.restated, 1);
        second.reload_since(Instant::now()).await.unwrap();
        assert_eq!(
            second.get("sbx_a").unwrap().state,
            common::SandboxState::Suspended as i32
        );
    }

    /// Two replicas: a delete through one, a heartbeat through the other.
    /// The second decides against the store, not its cache, so it tells the
    /// node to destroy the sandbox even before it has reloaded.
    #[tokio::test]
    async fn a_replica_that_has_not_reloaded_still_destroys_a_deleted_sandbox() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let first = SandboxRegistry::open(Arc::clone(&store)).await.unwrap();
        let second = SandboxRegistry::open(Arc::clone(&store)).await.unwrap();
        with_node(&first, "n1").await;
        created(&first, "sbx_a", "n1").await;
        second.reload_since(Instant::now()).await.unwrap();
        assert!(second.get("sbx_a").is_some());

        first.remove("sbx_a").await.unwrap();
        let out = beat(&second, "n1", 1, &[("sbx_a", 1)]).await;
        assert_eq!(destroyed(&out), [("sbx_a", 1)]);
        second.reload_since(Instant::now()).await.unwrap();
        assert!(second.get("sbx_a").is_none());
    }

    /// A reload that read the store before this replica wrote does not put
    /// the older row back in the cache.
    #[tokio::test]
    async fn a_reload_does_not_undo_a_write_made_while_it_read() {
        let registry = SandboxRegistry::in_memory().await;
        created(&registry, "sbx_a", "n1").await;
        let mark = registry.seq.load(Ordering::SeqCst);
        let rows = registry.store().list_placements().await.unwrap();
        registry.remove("sbx_a").await.unwrap();
        registry.reload(mark, rows);
        assert!(registry.get("sbx_a").is_none());
        let rows = registry.store().list_placements().await.unwrap();
        registry.reload(registry.seq.load(Ordering::SeqCst), rows);
        assert!(registry.written.lock().unwrap().is_empty());
    }

    /// The digest covers what a node reports about a sandbox, not its usage.
    #[test]
    fn a_report_digest_ignores_usage_and_matches_the_record() {
        let mut report = listing(&[("sbx_a", 1)]).remove(0);
        let before = report_hash(&report);
        report.cpu_usage_usec = 99;
        assert_eq!(report_hash(&report), before);
        report.state = common::SandboxState::Suspended as i32;
        assert_ne!(report_hash(&report), before);
        let record = restated(sandbox("sbx_a", "n1"), &report);
        assert_eq!(record_hash(&record), report_hash(&report));
    }

    #[tokio::test]
    async fn a_tag_filter_matches_the_whole_pair() {
        let registry = SandboxRegistry::in_memory().await;
        for (id, value) in [("a", "ml"), ("b", "mlops")] {
            let mut reservation = registry.reserve(id, "").await.unwrap();
            let tagged = common::Sandbox {
                tags: [("team".to_string(), value.to_string())].into(),
                ..sandbox(id, "n1")
            };
            registry
                .write_ahead(&mut reservation, tagged.clone())
                .await
                .unwrap();
            registry.settle(tagged, 1).await.unwrap();
            reservation.keep();
        }
        let ids: Vec<String> = registry
            .list_tagged(Some(("team", "ml")))
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(ids, ["a"]);
    }
}
