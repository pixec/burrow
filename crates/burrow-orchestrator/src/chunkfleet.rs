//! Whether nodes may delete what the object-store format before casync
//! chunks wrote: only once no node on a build that reads it has been heard
//! from for a day. Exists for the release that migrates stores, and goes
//! with the nodes' migration.
//!
//! Decided from the store, which every replica shares and which keeps the
//! last time such a node was heard from even after the node is written off
//! or forgotten, not from one replica's view of the fleet.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use burrow_proto::common::v1::NodeInfo;
use prost::Message as _;

use crate::OrchestratorState;
use crate::registry::NodeRegistry;

/// How long no node on an old build must have been heard from. A day, the
/// collector's grace, or the node expiry if longer: a node silent for less
/// may come back on the build it had.
const QUIET_FOR: Duration = Duration::from_secs(24 * 3600);
const REFRESH_EVERY: Duration = Duration::from_secs(30);

pub struct ChunkFleet {
    is_upgraded: AtomicBool,
    window_ms: i64,
    /// Without a store, when an old build was last heard from, starting at
    /// this process's start.
    seen_at_ms: AtomicI64,
}

impl ChunkFleet {
    pub fn new(node_expiry: Option<Duration>, now_ms: i64) -> Self {
        let window = node_expiry.map_or(QUIET_FOR, |expiry| expiry.max(QUIET_FOR));
        Self {
            is_upgraded: AtomicBool::new(false),
            window_ms: window.as_millis() as i64,
            seen_at_ms: AtomicI64::new(now_ms),
        }
    }

    pub fn is_upgraded(&self) -> bool {
        self.is_upgraded.load(Ordering::Relaxed)
    }

    /// Takes note of what a node says it is.
    pub async fn note(&self, store: Option<&burrow_store::Store>, info: &NodeInfo, now_ms: i64) {
        if info.is_casync_chunk_store {
            return;
        }
        self.is_upgraded.store(false, Ordering::Relaxed);
        self.seen_at_ms.fetch_max(now_ms, Ordering::Relaxed);
        if let Some(store) = store
            && let Err(err) = store.note_pre_casync_node(now_ms).await
        {
            tracing::warn!(%err, node_id = info.id, "could not record a node on a build before casync chunks");
        }
    }

    /// Decides again: no old build heard from for the window, and every
    /// node the fleet knows on a casync build.
    async fn refresh(
        &self,
        store: Option<&burrow_store::Store>,
        nodes: &NodeRegistry,
        now_ms: i64,
    ) {
        let decided = match store {
            Some(store) => match (store.pre_casync_seen_at().await, store.list_nodes().await) {
                (Ok(seen_at), Ok(rows)) => {
                    now_ms - seen_at >= self.window_ms
                        && rows.iter().all(|row| {
                            NodeInfo::decode(row.info.as_slice())
                                .is_ok_and(|info| info.is_casync_chunk_store)
                        })
                }
                _ => false,
            },
            None => {
                now_ms - self.seen_at_ms.load(Ordering::Relaxed) >= self.window_ms
                    && nodes.is_fleet_on_casync_chunks()
            }
        };
        if decided && !self.is_upgraded() {
            tracing::info!(
                "every node keeps chunks as casync does; nodes may delete the format before it"
            );
        }
        self.is_upgraded.store(decided, Ordering::Relaxed);
    }
}

pub async fn refresh_loop(state: std::sync::Arc<OrchestratorState>) {
    loop {
        state
            .chunk_fleet
            .refresh(
                state.store.as_deref(),
                &state.nodes,
                burrow_common::unix_now_ms(),
            )
            .await;
        tokio::time::sleep(REFRESH_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: &str, is_casync: bool) -> NodeInfo {
        NodeInfo {
            id: id.into(),
            is_casync_chunk_store: is_casync,
            ..Default::default()
        }
    }

    /// An old build heard from once holds the fleet back for the whole
    /// window, written off or not, and every node the store knows must be
    /// on a casync build.
    #[tokio::test]
    async fn the_fleet_is_upgraded_only_after_a_quiet_window() {
        let store = burrow_store::Store::open_in_memory().await.unwrap();
        let nodes = NodeRegistry::default();
        let fleet = ChunkFleet::new(Some(Duration::from_secs(60)), 0);
        let day = QUIET_FOR.as_millis() as i64;
        let seeded = store.pre_casync_seen_at().await.unwrap();
        let refresh = |now_ms| fleet.refresh(Some(&store), &nodes, now_ms);

        refresh(seeded + day - 1).await;
        assert!(!fleet.is_upgraded(), "an upgrade starts the window");
        refresh(seeded + day).await;
        assert!(fleet.is_upgraded());

        fleet
            .note(Some(&store), &info("old", false), seeded + day + 5)
            .await;
        assert!(!fleet.is_upgraded());
        refresh(seeded + 2 * day).await;
        assert!(!fleet.is_upgraded(), "heard from within the window");
        refresh(seeded + 2 * day + 5).await;
        assert!(
            fleet.is_upgraded(),
            "silent for the window, written off or not"
        );

        for (id, is_casync) in [("new", true), ("old", false)] {
            let row = crate::cluster::node_row(&info(id, is_casync), &Default::default(), "", "");
            store.register_node(&row, None, 16).await.unwrap();
        }
        refresh(seeded + 3 * day).await;
        assert!(
            !fleet.is_upgraded(),
            "the store knows a node on an old build"
        );
    }
}
