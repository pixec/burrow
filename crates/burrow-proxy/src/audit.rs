//! Audit records for egress attempts.
//!
//! Every connection a sandbox opens produces exactly one record, whether it
//! was allowed or denied. Records are appended as JSON lines, which a log
//! shipper can tail without tooling.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    /// Records for this sandbox that the queue could not take since the last
    /// one that got through.
    ///
    /// A dropped record is a gap in the log, and a gap that is not marked is
    /// indistinguishable from a sandbox that was quiet. Carrying the count on
    /// the next record that does get through makes the gap visible to whatever
    /// reads the log, without a record of its own that would itself have to be
    /// queued. Omitted from the JSON when it is zero, which is the normal case.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped_records: u64,
}

fn is_zero(count: &u64) -> bool {
    *count == 0
}

/// Queue depth for refusals, and for records of traffic that was allowed.
///
/// Separate queues, because they are not equally valuable. A refusal is the
/// only trace that a sandbox tried to reach somewhere it may not; a record of
/// allowed traffic is one of many, and the connection itself left other marks.
/// Under load the allowed queue is what fills, and losing from it costs volume
/// rather than evidence. Sharing one queue meant a sandbox could bury its own
/// refusals simply by making enough permitted requests alongside them.
const REFUSAL_QUEUE: usize = 2048;
const ALLOWED_QUEUE: usize = 1024;

/// How long a refusal waits for room before it is given up on.
///
/// Short: the caller is on the data path, and holding a connection open for
/// the audit log is the failure this whole design avoids. Long enough that a
/// momentary stall on the writer, a slow `fsync` or a store insert, costs a
/// pause and not a record.
const REFUSAL_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// Refusals waiting for room at once.
///
/// The wait above happens on a task of its own, since `record` is called from
/// the data path and cannot await. That is a task per refusal the queue could
/// not take immediately, so it is bounded: past this, a refusal is dropped and
/// counted like any other, which is still better than a task per datagram from
/// a sandbox that is deliberately generating denials.
const REFUSAL_WAITERS: usize = 256;

/// Buffered writer for audit events.
///
/// Writes happen on a dedicated task so a slow or full disk slows logging
/// rather than blocking the data path. If the queue fills, events are dropped:
/// losing an audit line is bad, but stalling every sandbox's network because
/// of the audit log is worse. Which line is lost is not left to chance
/// (see [`REFUSAL_QUEUE`]), and a drop is counted per sandbox and carried on
/// that sandbox's next record rather than passing in silence.
#[derive(Clone)]
pub struct AuditLog {
    refusals: mpsc::Sender<EgressEvent>,
    allowed: mpsc::Sender<EgressEvent>,
    /// Records dropped since each sandbox's last successful one.
    dropped: Arc<Mutex<HashMap<String, u64>>>,
    waiters: Arc<tokio::sync::Semaphore>,
}

impl AuditLog {
    /// Writes to a JSON-lines file, and to a store when one is given.
    ///
    /// Both: the file is what a log shipper tails, the store is what
    /// `QueryAudit` reads. Neither is derivable from the other cheaply.
    pub fn new(path: PathBuf, store: Option<std::sync::Arc<burrow_store::Store>>) -> Self {
        let (refusals, mut refusal_rx) = mpsc::channel::<EgressEvent>(REFUSAL_QUEUE);
        let (allowed, mut allowed_rx) = mpsc::channel::<EgressEvent>(ALLOWED_QUEUE);
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
            loop {
                // Biased, so a backlog of allowed records never delays a
                // refusal that is already queued behind it.
                let event = tokio::select! {
                    biased;
                    event = refusal_rx.recv() => event,
                    event = allowed_rx.recv() => event,
                };
                let Some(event) = event else {
                    // Both senders are gone only when the last `AuditLog`
                    // clone is dropped; one closing alone yields `None`
                    // forever, so the loop ends when either does.
                    return;
                };
                write(&mut file, &store, event).await;
            }
        });
        Self {
            refusals,
            allowed,
            dropped: Arc::new(Mutex::new(HashMap::new())),
            waiters: Arc::new(tokio::sync::Semaphore::new(REFUSAL_WAITERS)),
        }
    }

    pub fn record(&self, mut event: EgressEvent) {
        tracing::info!(
            sandbox = event.sandbox_id,
            destination = event.destination,
            host = event.host.as_deref().unwrap_or("-"),
            allowed = event.allowed,
            reason = event.reason,
            "egress"
        );

        // Whatever this sandbox lost since its last record travels with this
        // one, so the gap is visible to whoever reads the log. Taken before
        // the send, and put back if this record is itself dropped.
        event.dropped_records = self.take_dropped(&event.sandbox_id);

        let queue = if event.allowed {
            &self.allowed
        } else {
            &self.refusals
        };
        let Err(err) = queue.try_send(event) else {
            return;
        };
        let event = match err {
            mpsc::error::TrySendError::Full(event) => event,
            // The writer task is gone; nothing will be recorded again.
            mpsc::error::TrySendError::Closed(event) => {
                self.count_drop(event);
                return;
            }
        };

        if event.allowed {
            // Volume, not evidence. Dropped rather than waited on, which is
            // what leaves room for the refusals.
            self.count_drop(event);
            return;
        }

        // A refusal is the only trace that a sandbox tried to go somewhere it
        // may not, so it gets a short wait for room. On a task of its own:
        // `record` is called from the data path, where blocking is the thing
        // this queue exists to avoid.
        let Ok(waiter) = Arc::clone(&self.waiters).try_acquire_owned() else {
            self.count_drop(event);
            return;
        };
        let refusals = self.refusals.clone();
        let dropped = Arc::clone(&self.dropped);
        tokio::spawn(async move {
            let _waiter = waiter;
            if let Err(err) = refusals.send_timeout(event, REFUSAL_WAIT).await {
                let event = match err {
                    mpsc::error::SendTimeoutError::Timeout(event) => event,
                    mpsc::error::SendTimeoutError::Closed(event) => event,
                };
                count_drop_in(&dropped, event);
            }
        });
    }

    /// The count of records lost for `sandbox_id`, cleared as it is read.
    fn take_dropped(&self, sandbox_id: &str) -> u64 {
        self.dropped
            .lock()
            .unwrap()
            .remove(sandbox_id)
            .unwrap_or_default()
    }

    fn count_drop(&self, event: EgressEvent) {
        count_drop_in(&self.dropped, event);
    }
}

/// Books a lost record against its sandbox.
///
/// The count the lost record was carrying goes back with it, so a run of drops
/// accumulates rather than each one forgetting the last.
fn count_drop_in(dropped: &Mutex<HashMap<String, u64>>, event: EgressEvent) {
    let mut dropped = dropped.lock().unwrap();
    let count = dropped.entry(event.sandbox_id.clone()).or_insert(0);
    *count += 1 + event.dropped_records;
    // Logged occasionally rather than per record: the queue is full precisely
    // when something is generating more records than can be written, and a
    // warning per drop would be part of that.
    if count.is_power_of_two() {
        tracing::warn!(
            sandbox = event.sandbox_id,
            dropped = *count,
            allowed = event.allowed,
            "audit queue full; dropped an egress record"
        );
    }
}

async fn write(
    file: &mut tokio::fs::File,
    store: &Option<std::sync::Arc<burrow_store::Store>>,
    event: EgressEvent,
) {
    if let Some(store) = store
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
        return;
    };
    line.push(b'\n');
    if let Err(err) = file.write_all(&line).await {
        tracing::error!(%err, "failed to write audit record");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(sandbox: &str, allowed: bool) -> EgressEvent {
        EgressEvent {
            at: "1970-01-01T00:00:00Z".into(),
            sandbox_id: sandbox.into(),
            source_ip: "10.99.0.6".into(),
            destination: "93.184.216.34:443".into(),
            host: Some("example.com".into()),
            port: 443,
            allowed,
            reason: if allowed { "allowed" } else { "denied" }.into(),
            bytes_sent: 0,
            bytes_received: 0,
            dropped_records: 0,
        }
    }

    /// An `AuditLog` whose queues nothing is draining, so the drop paths can
    /// be exercised without racing a writer.
    fn stalled() -> (
        AuditLog,
        mpsc::Receiver<EgressEvent>,
        mpsc::Receiver<EgressEvent>,
    ) {
        let (refusals, refusal_rx) = mpsc::channel(2);
        let (allowed, allowed_rx) = mpsc::channel(2);
        (
            AuditLog {
                refusals,
                allowed,
                dropped: Arc::new(Mutex::new(HashMap::new())),
                waiters: Arc::new(tokio::sync::Semaphore::new(REFUSAL_WAITERS)),
            },
            refusal_rx,
            allowed_rx,
        )
    }

    /// A sandbox could bury its own refusals by making enough permitted
    /// requests alongside them, which turns the audit log into something the
    /// audited party controls. Refusals have a queue of their own.
    #[tokio::test]
    async fn a_flood_of_allowed_records_cannot_evict_a_refusal() {
        let (log, mut refusals, _allowed) = stalled();
        // Fill the allowed queue and then overflow it many times over.
        for _ in 0..64 {
            log.record(event("sbx", true));
        }
        log.record(event("sbx", false));

        let received = refusals.try_recv().expect("the refusal must be queued");
        assert!(!received.allowed);
        assert_eq!(received.reason, "denied");
    }

    /// A dropped record is a gap in the log, and an unmarked gap reads as a
    /// quiet sandbox. The count travels on the next record that gets through.
    #[tokio::test]
    async fn drops_are_counted_and_carried_on_the_next_record() {
        let (log, _refusals, mut allowed) = stalled();
        for _ in 0..5 {
            log.record(event("sbx", true));
        }
        // Two made it into the queue; three did not.
        assert_eq!(allowed.recv().await.unwrap().dropped_records, 0);
        assert_eq!(allowed.recv().await.unwrap().dropped_records, 0);
        assert_eq!(*log.dropped.lock().unwrap().get("sbx").unwrap(), 3);

        // The next record that fits carries the gap, and clears it.
        log.record(event("sbx", true));
        assert_eq!(allowed.recv().await.unwrap().dropped_records, 3);
        assert!(log.dropped.lock().unwrap().is_empty());
    }

    /// One sandbox's losses are not another's: the count is what says which
    /// sandbox has a gap in its record.
    #[tokio::test]
    async fn a_drop_is_booked_against_the_sandbox_that_caused_it() {
        let (log, _refusals, mut allowed) = stalled();
        for _ in 0..4 {
            log.record(event("noisy", true));
        }
        let _ = allowed.recv().await;
        let _ = allowed.recv().await;

        log.record(event("quiet", true));
        assert_eq!(allowed.recv().await.unwrap().dropped_records, 0);
        assert_eq!(*log.dropped.lock().unwrap().get("noisy").unwrap(), 2);
        assert!(log.dropped.lock().unwrap().get("quiet").is_none());
    }

    /// A refusal that cannot be queued waits briefly rather than being thrown
    /// away at once, because it is the only trace of the attempt.
    #[tokio::test]
    async fn a_refusal_waits_for_room_before_it_is_given_up_on() {
        let (log, mut refusals, _allowed) = stalled();
        log.record(event("sbx", false));
        log.record(event("sbx", false));
        // The queue is full; this one is waiting on the spawned task.
        log.record(event("sbx", false));
        assert!(
            log.dropped.lock().unwrap().is_empty(),
            "a refusal must not be dropped before it has waited"
        );

        // Draining makes room, and the waiter gets in.
        for _ in 0..3 {
            let received = tokio::time::timeout(REFUSAL_WAIT * 4, refusals.recv())
                .await
                .expect("the waiting refusal must be delivered")
                .expect("the queue is open");
            assert!(!received.allowed);
        }
        assert!(log.dropped.lock().unwrap().is_empty());
    }

    /// The wait is finite: a writer that never drains must not leave the
    /// refusal queued forever, nor the drop uncounted.
    #[tokio::test]
    async fn a_refusal_that_never_gets_room_is_counted_as_dropped() {
        let (log, _refusals, _allowed) = stalled();
        for _ in 0..3 {
            log.record(event("sbx", false));
        }
        tokio::time::sleep(REFUSAL_WAIT * 3).await;
        assert_eq!(*log.dropped.lock().unwrap().get("sbx").unwrap(), 1);
    }

    /// Zero is the normal case, so the field is absent from an ordinary line.
    #[test]
    fn the_drop_count_is_absent_from_an_ordinary_record() {
        let line = serde_json::to_string(&event("sbx", true)).unwrap();
        assert!(!line.contains("dropped_records"), "{line}");

        let mut lossy = event("sbx", true);
        lossy.dropped_records = 7;
        let line = serde_json::to_string(&lossy).unwrap();
        assert!(line.contains("\"dropped_records\":7"), "{line}");

        // And a record written before the field existed still reads back.
        let old = r#"{"at":"t","sandbox_id":"s","source_ip":"1.2.3.4",
            "destination":"d","host":null,"port":443,"allowed":true,
            "reason":"allowed","bytes_sent":0,"bytes_received":0}"#;
        let parsed: EgressEvent = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.dropped_records, 0);
    }
}
