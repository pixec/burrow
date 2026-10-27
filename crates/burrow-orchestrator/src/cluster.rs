//! Keeping one replica's caches in step with the others.
//!
//! The registries answer reads from memory, which is what keeps routing a
//! call cheap. With several replicas each writes its own changes to the store
//! as it makes them, and this loop reads everyone's back once a second, so a
//! sandbox created through one replica is routable through another within
//! that second. Decisions two replicas could race on are not taken here: the
//! store settles those in the statement that makes them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use burrow_proto::common::v1 as common;
use prost::Message as _;

use crate::OrchestratorState;

const PERIOD: Duration = Duration::from_secs(1);

/// How often a replica re-reads each node's snapshots and volumes. They are
/// reported to whichever replica a node heartbeats to, so the others learn of
/// changes this late at worst; a create from a snapshot is still checked by
/// the node that restores it.
const INVENTORY_PERIOD: Duration = Duration::from_secs(30);

pub fn spawn(state: Arc<OrchestratorState>, store: Arc<burrow_store::Store>) {
    tokio::spawn(async move {
        let mut inventoried: HashMap<String, Instant> = HashMap::new();
        let mut ticker = tokio::time::interval(PERIOD);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = sync_once(&state, &store, &mut inventoried).await {
                tracing::warn!(%err, "could not catch up with the store");
            }
        }
    });
}

async fn sync_once(
    state: &Arc<OrchestratorState>,
    store: &burrow_store::Store,
    inventoried: &mut HashMap<String, Instant>,
) -> burrow_store::Result<()> {
    reload_nodes(state, store).await?;

    if let Some(writer) = state.sandboxes.writer() {
        let mark = writer.flush().await;
        let placements = store.list_placements().await?;
        let tombstones = store.list_tombstones().await?;
        state.sandboxes.reload(mark, placements, tombstones);
    }

    let known: HashSet<String> = state.nodes.healthy_ids();
    inventoried.retain(|id, _| known.contains(id));
    for node_id in known {
        if inventoried
            .get(&node_id)
            .is_some_and(|at| at.elapsed() < INVENTORY_PERIOD)
        {
            continue;
        }
        inventoried.insert(node_id.clone(), Instant::now());
        let state = Arc::clone(state);
        tokio::spawn(async move { crate::refresh_inventory(&state, &node_id).await });
    }
    Ok(())
}

/// Replaces the node cache with the store's view of the fleet.
pub async fn reload_nodes(
    state: &OrchestratorState,
    store: &burrow_store::Store,
) -> burrow_store::Result<()> {
    let rows = store.list_nodes().await?;
    let decoded = rows
        .into_iter()
        .filter_map(|row| {
            let info = common::NodeInfo::decode(row.info.as_slice()).ok()?;
            let status = common::NodeStatus::decode(row.status.as_slice()).unwrap_or_default();
            Some((info, status, row))
        })
        .collect();
    state.nodes.reload(decoded);
    Ok(())
}

/// A node as the store records it.
pub fn node_row(
    info: &common::NodeInfo,
    status: &common::NodeStatus,
    wireguard_public_key: &str,
    wireguard_endpoint: &str,
) -> burrow_store::NodeRow {
    burrow_store::NodeRow {
        id: info.id.clone(),
        index: 0,
        info: info.encode_to_vec(),
        status: status.encode_to_vec(),
        wireguard_public_key: wireguard_public_key.to_string(),
        wireguard_endpoint: wireguard_endpoint.to_string(),
        last_heartbeat_ms: crate::registry::unix_ms(),
        is_reported: false,
        total_vcpus: info.total_vcpus,
        committed_vcpus: status.committed_vcpus,
        free_mem_mib: status.free_mem_mib,
        reserved_vcpus: 0,
        reserved_mem_mib: 0,
    }
}
