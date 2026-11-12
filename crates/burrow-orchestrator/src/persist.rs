//! Ordered, asynchronous writes from the registries to the store.
//!
//! The sandbox registry decides under its own lock, synchronously, and that
//! is where its ordering guarantees come from: a delete and an insert of one
//! id cannot interleave. The store is async. This bridges the two without
//! giving either up: the registry enqueues each write while it still holds
//! its lock, and one task applies them in that order.
//!
//! Every write carries a sequence number. A replica reloading its cache from
//! the store first waits for its own queue to drain up to a mark, and throws
//! the reload away if anything was enqueued after the mark, so a reload can
//! never replace a local change with the older row it superseded.
//!
//! Another replica's writes are not ordered with this one's, so a placement
//! is never written blind: each write reads the row, checks the row still
//! says what this replica's decision rested on, and writes over exactly the
//! version it read, reading again if another write got there first.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{mpsc, oneshot};

use burrow_proto::common::v1 as common;

/// What the stored placement must say for a write to go ahead.
#[derive(Debug, Clone)]
pub enum Guard {
    /// Whatever it says: the object store has already made the node the
    /// holder.
    Any,
    /// Nothing yet, or this node: a sandbox the node just built.
    Fresh(String),
    /// This node: the node answered as the sandbox's holder.
    On(String),
    /// Nothing, this node, or no node with nobody placing it: a node's own
    /// listing, which may predate a move off it.
    Adoptable(String),
}

pub enum Change {
    /// The whole record, as the node answered with it.
    Replace(Box<common::Sandbox>),
    /// Only what a node reports on a heartbeat, taken from this record.
    Restate(Box<common::Sandbox>),
    /// Off its node, stamped with where its state can restore. `cpu` is the
    /// node's that last held it, which wrote its saved memory.
    Unplace {
        arch: String,
        hypervisor_version: String,
        cpu: Option<common::CpuFingerprint>,
    },
}

pub enum Op {
    Update {
        id: String,
        guard: Guard,
        change: Change,
    },
    /// Removes the row while it names the node, or no node for `""`.
    DeletePlacementOn {
        sandbox_id: String,
        node_id: String,
    },
    /// For a node written off: unplaces the row if the object store can
    /// bring the sandbox back, and removes it otherwise.
    WriteOff {
        sandbox_id: String,
        node_id: String,
        arch: String,
        hypervisor_version: String,
        cpu: Option<common::CpuFingerprint>,
    },
    PutTombstone(burrow_store::TombstoneRow),
    DeleteTombstone(String),
    PruneTombstones(i64),
    /// A uniqueness claim for a sandbox adopted from a node rather than
    /// created here; created sandboxes claim before they exist.
    Claim {
        key: String,
        sandbox_id: String,
    },
    ReleaseClaims(String),
    /// `ReleaseClaims`, kept if the sandbox is now placed off this node.
    ReleaseClaimsUnlessMoved {
        sandbox_id: String,
        node_id: String,
    },
    /// One claim, given up by the holder that took it.
    ReleaseClaim {
        key: String,
        holder: String,
    },
}

enum Message {
    Op(u64, Op),
    Flush(oneshot::Sender<u64>),
}

#[derive(Clone)]
pub struct Writer {
    tx: mpsc::UnboundedSender<Message>,
    enqueued: Arc<AtomicU64>,
}

impl Writer {
    /// Starts the task that applies writes to `store`, in order.
    pub fn spawn(store: Arc<burrow_store::Store>) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut applied = 0u64;
            while let Some(message) = rx.recv().await {
                match message {
                    Message::Op(seq, op) => {
                        // Retried until it lands, in order: a write that is
                        // dropped leaves this replica's view and the store's
                        // apart for good, and the next write may depend on it.
                        let mut backoff = std::time::Duration::from_millis(100);
                        while let Err(err) = apply(&store, &op).await {
                            tracing::warn!(%err, what = describe(&op), "store write failed; retrying");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
                        }
                        applied = seq;
                    }
                    Message::Flush(reply) => {
                        let _ = reply.send(applied);
                    }
                }
            }
        });
        Self {
            tx,
            enqueued: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Queues a write. Never blocks, so it is safe under a std lock.
    pub fn send(&self, op: Op) {
        let seq = self.enqueued.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.tx.send(Message::Op(seq, op));
    }

    /// Waits until every write queued so far has been applied, returning the
    /// mark to compare against [`Self::enqueued`] later.
    pub async fn flush(&self) -> u64 {
        let (reply, done) = oneshot::channel();
        if self.tx.send(Message::Flush(reply)).is_err() {
            return self.enqueued();
        }
        done.await.unwrap_or_else(|_| self.enqueued())
    }

    /// Sequence number of the last write queued.
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::SeqCst)
    }
}

async fn apply(store: &burrow_store::Store, op: &Op) -> burrow_store::Result<()> {
    match op {
        Op::Update { id, guard, change } => update(store, id, guard, change).await,
        Op::DeletePlacementOn {
            sandbox_id,
            node_id,
        } => store.delete_placement_on(sandbox_id, node_id).await,
        Op::WriteOff {
            sandbox_id,
            node_id,
            arch,
            hypervisor_version,
            cpu,
        } => write_off(store, sandbox_id, node_id, arch, hypervisor_version, cpu).await,
        Op::PutTombstone(row) => store.put_tombstone(row).await,
        Op::DeleteTombstone(id) => store.delete_tombstone(id).await,
        Op::PruneTombstones(cutoff) => store.prune_tombstones(*cutoff).await.map(drop),
        Op::Claim { key, sandbox_id } => store
            .claim(key, sandbox_id, burrow_common::unix_now())
            .await
            .map(drop),
        Op::ReleaseClaims(id) => store.release_claims(id).await,
        Op::ReleaseClaimsUnlessMoved {
            sandbox_id,
            node_id,
        } => store.release_claims_unless_moved(sandbox_id, node_id).await,
        Op::ReleaseClaim { key, holder } => store.release_claim(key, holder).await,
    }
}

async fn admits(
    store: &burrow_store::Store,
    id: &str,
    guard: &Guard,
    row: Option<&burrow_store::PlacementRow>,
) -> burrow_store::Result<bool> {
    let node = row.map(|row| row.node_id.as_str());
    Ok(match guard {
        Guard::Any => true,
        Guard::Fresh(holder) => node.is_none_or(|node| node == holder),
        Guard::On(holder) => node == Some(holder.as_str()),
        Guard::Adoptable(holder) => match node {
            None => true,
            Some(node) if node == holder => true,
            Some("") => store.claim_holder(&adopt_key(id)).await?.is_none(),
            Some(_) => false,
        },
    })
}

fn changed(change: &Change, current: Option<common::Sandbox>) -> Option<common::Sandbox> {
    match change {
        Change::Replace(sandbox) => Some(sandbox.as_ref().clone()),
        Change::Restate(reported) => current.map(|mut sandbox| {
            sandbox.state = reported.state;
            sandbox.is_durable = reported.is_durable;
            sandbox.state_reason = reported.state_reason.clone();
            sandbox.checkpoint_at_unix_ms = reported.checkpoint_at_unix_ms;
            sandbox.checkpoint_kind = reported.checkpoint_kind;
            sandbox.is_agent_unconfirmed = reported.is_agent_unconfirmed;
            sandbox.cpu_usage_usec = reported.cpu_usage_usec;
            sandbox.rx_bytes = reported.rx_bytes;
            sandbox.tx_bytes = reported.tx_bytes;
            sandbox
        }),
        Change::Unplace {
            arch,
            hypervisor_version,
            cpu,
        } => current.map(|mut sandbox| {
            sandbox.node_id.clear();
            if sandbox.arch.is_empty() {
                sandbox.arch = arch.clone();
                sandbox.hypervisor_version = hypervisor_version.clone();
            }
            sandbox.cpu = cpu.clone();
            sandbox
        }),
    }
}

async fn update(
    store: &burrow_store::Store,
    id: &str,
    guard: &Guard,
    change: &Change,
) -> burrow_store::Result<()> {
    loop {
        let row = store.get_placement(id).await?;
        if !admits(store, id, guard, row.as_ref()).await? {
            tracing::info!(
                sandbox = id,
                ?guard,
                held = row.as_ref().map(|row| row.node_id.as_str()),
                "the stored placement moved on; not writing over it"
            );
            return Ok(());
        }
        let current = row
            .as_ref()
            .and_then(|row| crate::sandboxes::decode(&row.record));
        let Some(next) = changed(change, current) else {
            return Ok(());
        };
        let written = burrow_store::PlacementRow {
            id: id.to_string(),
            node_id: next.node_id.clone(),
            record: crate::sandboxes::encode(&next),
            version: 0,
        };
        if store
            .replace_placement(&written, row.map(|row| row.version))
            .await?
        {
            return Ok(());
        }
    }
}

async fn write_off(
    store: &burrow_store::Store,
    id: &str,
    node_id: &str,
    arch: &str,
    hypervisor_version: &str,
    cpu: &Option<common::CpuFingerprint>,
) -> burrow_store::Result<()> {
    loop {
        let Some(row) = store.get_placement(id).await? else {
            return Ok(());
        };
        if row.node_id != node_id {
            return Ok(());
        }
        let written = match crate::sandboxes::decode(&row.record)
            .filter(crate::sandboxes::is_movable)
            .and_then(|mut sandbox| {
                crate::sandboxes::lost_to_checkpoint(&mut sandbox, node_id);
                changed(
                    &Change::Unplace {
                        arch: arch.to_string(),
                        hypervisor_version: hypervisor_version.to_string(),
                        cpu: cpu.clone(),
                    },
                    Some(sandbox),
                )
            }) {
            Some(next) => {
                let written = burrow_store::PlacementRow {
                    id: id.to_string(),
                    node_id: String::new(),
                    record: crate::sandboxes::encode(&next),
                    version: 0,
                };
                store.replace_placement(&written, Some(row.version)).await?
            }
            None => store.delete_placement_if(id, row.version).await?,
        };
        if written {
            return Ok(());
        }
    }
}

fn describe(op: &Op) -> &'static str {
    match op {
        Op::Update { .. } => "persist a placement",
        Op::DeletePlacementOn { .. } => "remove a stored placement",
        Op::WriteOff { .. } => "write off a placement",
        Op::PutTombstone(_) => "persist a tombstone",
        Op::DeleteTombstone(_) => "remove a stored tombstone",
        Op::PruneTombstones(_) => "prune stored tombstones",
        Op::Claim { .. } => "record a name claim",
        Op::ReleaseClaims(_) | Op::ReleaseClaimsUnlessMoved { .. } => "release a sandbox's claims",
        Op::ReleaseClaim { .. } => "release a claim",
    }
}

/// The store keys a sandbox's uniqueness claims live under.
pub fn id_key(id: &str) -> String {
    format!("id:{id}")
}

pub fn name_key(name: &str) -> String {
    format!("name:{name}")
}

/// Held while a sandbox no node holds is being handed to one. The holder is
/// the attempt rather than the sandbox, so two replicas starting the same
/// sandbox cannot both win it, and an attempt whose replica died is swept
/// like an abandoned create.
pub fn request_key(request: &str) -> String {
    format!("request:{request}")
}

pub fn adopt_key(id: &str) -> String {
    format!("adopt:{id}")
}
