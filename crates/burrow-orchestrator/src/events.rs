//! The fleet's event log.
//!
//! Every node keeps its own log of what it did to its sandboxes and pushes it
//! here, in order, before it lets the call that caused an event return. So a
//! consumer reads a single ordered stream and resumes from the last `seq` it
//! saw, and an event survives the node that recorded it. Each copied row keeps
//! its origin, node id and node position, and an origin is never stored twice,
//! which is what makes a retried push safe.

use std::sync::Arc;

use burrow_proto::common::v1 as common;

pub struct EventLog {
    store: Option<Arc<burrow_store::Store>>,
    live: tokio::sync::broadcast::Sender<common::Event>,
}

impl EventLog {
    pub fn new(store: Option<Arc<burrow_store::Store>>) -> Self {
        Self {
            store,
            live: tokio::sync::broadcast::channel(4096).0,
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<common::Event> {
        self.live.subscribe()
    }

    /// Commits a node's events in its order and returns the highest node
    /// position now recorded for it. An event already recorded is skipped,
    /// so a node retrying a push it never saw acknowledged stores nothing
    /// twice.
    pub async fn push(
        &self,
        node_id: &str,
        events: Vec<common::Event>,
    ) -> Result<u64, burrow_store::StoreError> {
        let mut last = 0;
        for event in events {
            last = event.seq;
            self.ingest(node_id, event).await?;
        }
        match &self.store {
            Some(store) => store.last_event_seq_for_node(node_id).await,
            None => Ok(last),
        }
    }

    async fn ingest(
        &self,
        node_id: &str,
        mut event: common::Event,
    ) -> Result<(), burrow_store::StoreError> {
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
            match store.append_event(&row).await? {
                0 => return Ok(()),
                seq => event.seq = seq,
            }
        }
        let _ = self.live.send(event);
        Ok(())
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
