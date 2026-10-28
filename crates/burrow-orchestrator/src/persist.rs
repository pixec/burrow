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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{mpsc, oneshot};

pub enum Op {
    PutPlacement(burrow_store::PlacementRow),
    DeletePlacement(String),
    DeletePlacementsForNode(String),
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
        Op::PutPlacement(row) => store.put_placement(row).await,
        Op::DeletePlacement(id) => store.delete_placement(id).await,
        Op::DeletePlacementsForNode(node_id) => {
            store.delete_placements_for_node(node_id).await.map(drop)
        }
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

fn describe(op: &Op) -> &'static str {
    match op {
        Op::PutPlacement(_) => "persist a placement",
        Op::DeletePlacement(_) => "remove a stored placement",
        Op::DeletePlacementsForNode(_) => "clear stored placements for a node",
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
pub fn adopt_key(id: &str) -> String {
    format!("adopt:{id}")
}
