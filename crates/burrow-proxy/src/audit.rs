//! Audit records for egress attempts.
//!
//! Every connection a sandbox opens produces exactly one record, whether it
//! was allowed or denied. Records are appended as JSON lines, which a log
//! shipper can tail without tooling.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEvent {
    pub at: String,
    pub sandbox_id: String,
    pub source_ip: String,
    /// Where the sandbox was trying to go, as it addressed it.
    pub destination: String,
    pub host: Option<String>,
    pub port: u16,
    pub allowed: bool,
    pub reason: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Buffered writer for audit events.
///
/// Writes happen on a dedicated task so a slow or full disk slows logging
/// rather than blocking the data path. If the queue fills, events are dropped
/// with a warning: losing an audit line is bad, but stalling every sandbox's
/// network because of the audit log is worse.
#[derive(Clone)]
pub struct AuditLog {
    tx: mpsc::Sender<EgressEvent>,
}

impl AuditLog {
    /// Writes to a JSON-lines file, and to a store when one is given.
    ///
    /// Both: the file is what a log shipper tails, the store is what
    /// `QueryAudit` reads. Neither is derivable from the other cheaply.
    pub fn new(path: PathBuf, store: Option<std::sync::Arc<burrow_store::Store>>) -> Self {
        let (tx, mut rx) = mpsc::channel::<EgressEvent>(1024);
        tokio::spawn(async move {
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let mut file = match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(file) => file,
                Err(err) => {
                    tracing::error!(path = %path.display(), %err, "cannot open audit log");
                    return;
                }
            };
            while let Some(event) = rx.recv().await {
                if let Some(store) = &store
                    && let Err(err) = store.insert_egress(&burrow_store::EgressRow {
                        at: event.at.clone(),
                        sandbox_id: event.sandbox_id.clone(),
                        source_ip: event.source_ip.clone(),
                        destination: event.destination.clone(),
                        host: event.host.clone().unwrap_or_default(),
                        port: event.port as u32,
                        allowed: event.allowed,
                        reason: event.reason.clone(),
                        bytes_sent: event.bytes_sent as i64,
                        bytes_received: event.bytes_received as i64,
                    })
                {
                    tracing::error!(%err, "failed to record audit row");
                }

                let Ok(mut line) = serde_json::to_vec(&event) else {
                    continue;
                };
                line.push(b'\n');
                if let Err(err) = file.write_all(&line).await {
                    tracing::error!(%err, "failed to write audit record");
                }
            }
        });
        Self { tx }
    }

    pub fn record(&self, event: EgressEvent) {
        tracing::info!(
            sandbox = event.sandbox_id,
            destination = event.destination,
            host = event.host.as_deref().unwrap_or("-"),
            allowed = event.allowed,
            reason = event.reason,
            "egress"
        );
        if self.tx.try_send(event).is_err() {
            tracing::warn!("audit queue full; dropped an egress record");
        }
    }
}
