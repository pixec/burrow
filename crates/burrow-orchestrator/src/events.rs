//! The fleet's event log.
//!
//! Every node keeps its own log of what it did to its sandboxes. The
//! orchestrator tails each node's log into one of its own, so a consumer reads
//! a single ordered stream and resumes from the last `seq` it saw, and so an
//! event survives the node that recorded it. Each copied row keeps its origin,
//! node id and node position, and an origin is never stored twice, which is
//! what makes reconnecting a tail safe.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use burrow_proto::common::v1 as common;
use burrow_proto::node::v1 as nodepb;
use tokio_stream::StreamExt as _;

use crate::OrchestratorState;

pub struct EventLog {
    store: Option<Arc<burrow_store::Store>>,
    live: tokio::sync::broadcast::Sender<common::Event>,
    /// Nodes with a tail task running, so a re-registration does not start a
    /// second one.
    tailing: Mutex<HashSet<String>>,
}

impl EventLog {
    pub fn new(store: Option<Arc<burrow_store::Store>>) -> Self {
        Self {
            store,
            live: tokio::sync::broadcast::channel(4096).0,
            tailing: Mutex::new(HashSet::new()),
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<common::Event> {
        self.live.subscribe()
    }

    /// Records an event a node reported, returning it with its position here,
    /// or `None` when this origin was already recorded.
    async fn ingest(&self, node_id: &str, mut event: common::Event) -> Option<common::Event> {
        let row = burrow_store::EventRow {
            seq: 0,
            node_id: node_id.to_string(),
            node_seq: event.seq,
            at_unix_ms: event.at_unix_ms,
            sandbox_id: event.sandbox_id.clone(),
            kind: event.r#type.clone(),
            state: event.state,
            detail: event.detail.clone(),
            template: event.template.clone(),
            metadata_json: serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".into()),
            cpu_usage_usec: event.cpu_usage_usec,
            rx_bytes: event.rx_bytes,
            tx_bytes: event.tx_bytes,
            vcpus: event.vcpus,
            mem_mib: event.mem_mib,
        };
        event.node_seq = event.seq;
        event.node_id = node_id.to_string();
        // Without a store the log is live only, and positions are the node's.
        if let Some(store) = &self.store {
            match store.append_event(&row).await {
                Ok(0) => return None,
                Ok(seq) => event.seq = seq,
                Err(err) => {
                    tracing::error!(node_id, %err, "could not record an event");
                    return None;
                }
            }
        }
        let _ = self.live.send(event.clone());
        Some(event)
    }

    pub async fn replay(
        &self,
        after_seq: u64,
        sandbox_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<common::Event>, burrow_store::StoreError> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        let rows = store.list_events(after_seq, sandbox_id, limit).await?;
        Ok(rows.into_iter().map(to_proto).collect())
    }

    async fn resume_from(&self, node_id: &str) -> u64 {
        match &self.store {
            Some(store) => store.last_event_seq_for_node(node_id).await.unwrap_or(0),
            None => 0,
        }
    }

    /// Whether events written by another replica can be read back from the
    /// store, which is what a follower serves its tails from.
    pub fn is_shared(&self) -> bool {
        self.store.as_ref().is_some_and(|store| store.is_postgres())
    }
}

pub fn to_proto(row: burrow_store::EventRow) -> common::Event {
    common::Event {
        seq: row.seq,
        node_id: row.node_id,
        node_seq: row.node_seq,
        at_unix_ms: row.at_unix_ms,
        sandbox_id: row.sandbox_id,
        r#type: row.kind,
        state: row.state,
        detail: row.detail,
        template: row.template,
        metadata: serde_json::from_str(&row.metadata_json).unwrap_or_default(),
        cpu_usage_usec: row.cpu_usage_usec,
        rx_bytes: row.rx_bytes,
        tx_bytes: row.tx_bytes,
        vcpus: row.vcpus,
        mem_mib: row.mem_mib,
    }
}

/// Starts tailing a node's log, once per node for as long as it is known.
pub fn ensure_tailing(state: Arc<OrchestratorState>, node_id: String) {
    if !state.events.tailing.lock().unwrap().insert(node_id.clone()) {
        return;
    }
    tokio::spawn(async move {
        tail_node(&state, &node_id).await;
        state.events.tailing.lock().unwrap().remove(&node_id);
    });
}

/// Follows one node's log, resuming after whatever was already copied, and
/// reconnecting while the node is still registered.
async fn tail_node(state: &Arc<OrchestratorState>, node_id: &str) {
    loop {
        let Some(endpoint) = state.nodes.endpoint_any(node_id) else {
            // Forgotten entirely; a re-registration starts a new tail.
            return;
        };
        // Only the leader copies node logs: every replica could, and the
        // origin index would keep it exact, but N copies of every event is
        // N times the writes for nothing.
        state.leader.wait().await;
        let after = state.events.resume_from(node_id).await;
        let connected = state
            .channels
            .get(&endpoint, state.node_token.as_deref())
            .await;
        let stream = match connected {
            Ok(mut client) => {
                client
                    .tail_events(nodepb::NodeTailEventsRequest {
                        after_seq: after,
                        is_follow: true,
                    })
                    .await
            }
            Err(err) => Err(tonic::Status::unavailable(err.to_string())),
        };
        match stream {
            Ok(stream) => {
                let mut stream = stream.into_inner();
                while let Some(event) = stream.next().await {
                    match event {
                        Ok(event) => {
                            state.events.ingest(node_id, event).await;
                            if !state.leader.is_leader() {
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::debug!(node_id, %err, "event tail ended");
                            break;
                        }
                    }
                }
            }
            Err(err) => tracing::debug!(node_id, %err, "event tail could not start"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
