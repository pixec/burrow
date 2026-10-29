//! Delivery of this node's event log to the orchestrator.
//!
//! An event is written to the node's store first, then pushed, in order, and
//! the lifecycle call that caused it waits for the orchestrator to commit it.
//! While the control plane is unreachable events queue in the store and are
//! pushed from the oldest once it answers again; [`Policy`] decides whether
//! lifecycle calls go ahead meanwhile.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use burrow_proto::node::v1 as nodepb;
use tonic::Status;

/// How long a lifecycle call waits for its event to be acknowledged before
/// leaving it queued.
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// How often an idle connection is checked, so a control plane that went away
/// while nothing happened is noticed before the next call waits on it.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_secs(2);
const BATCH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Policy {
    /// Queue the events and let the call return.
    #[default]
    Proceed,
    /// Refuse lifecycle calls until the queue is delivered.
    Fail,
}

pub struct Delivery {
    policy: Policy,
    /// Highest node position the orchestrator has committed.
    acked: tokio::sync::watch::Sender<u64>,
    /// Whether the last exchange with the orchestrator succeeded and nothing
    /// is queued behind a failure.
    is_reachable: AtomicBool,
    /// Set as the node shuts down, when nothing waits on the control plane:
    /// what is not acknowledged by then is pushed on the next start.
    is_closing: AtomicBool,
    appended: tokio::sync::Notify,
}

impl Delivery {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            acked: tokio::sync::watch::channel(0).0,
            is_reachable: AtomicBool::new(false),
            is_closing: AtomicBool::new(false),
            appended: tokio::sync::Notify::new(),
        }
    }

    pub fn is_reachable(&self) -> bool {
        self.is_reachable.load(Ordering::Relaxed)
    }

    /// Refuses a lifecycle call under [`Policy::Fail`] while events cannot be
    /// delivered.
    #[allow(clippy::result_large_err)]
    pub fn admit(&self) -> Result<(), Status> {
        if self.policy == Policy::Fail && !self.is_reachable() {
            return Err(Status::unavailable(
                "the control plane is not acknowledging this node's events, and \
                 --event-delivery fail refuses lifecycle calls until it does",
            ));
        }
        Ok(())
    }

    /// Stops every later [`Self::wait`] from waiting, for a shutdown that has
    /// a deadline of its own.
    pub fn close(&self) {
        self.is_closing.store(true, Ordering::Relaxed);
        self.acked.send_modify(|_| {});
    }

    /// Waits for the event at `seq` to be committed, unless delivery is down
    /// or the node is shutting down, in which case it stays queued and the
    /// caller goes on.
    pub async fn wait(&self, seq: u64) {
        self.appended.notify_one();
        if !self.is_reachable() || self.is_closing.load(Ordering::Relaxed) {
            return;
        }
        let mut acked = self.acked.subscribe();
        let settled = acked.wait_for(|acked| {
            *acked >= seq || !self.is_reachable() || self.is_closing.load(Ordering::Relaxed)
        });
        match tokio::time::timeout(ACK_TIMEOUT, settled).await {
            Ok(_) if !self.is_reachable() => {
                tracing::warn!(seq, "control plane went away; the event stays queued")
            }
            Ok(_) => {}
            Err(_) => tracing::warn!(seq, "event not acknowledged in time; it stays queued"),
        }
    }

    /// Where the orchestrator's copy ends on a fresh connection. May move
    /// back, for an orchestrator whose store lost what it had, which is then
    /// pushed again from there.
    fn resume(&self, committed: u64) {
        self.is_reachable.store(true, Ordering::Relaxed);
        self.acked.send_replace(committed);
    }

    fn acknowledge(&self, committed: u64) {
        self.is_reachable.store(true, Ordering::Relaxed);
        self.acked.send_if_modified(|acked| {
            let moved = committed > *acked;
            *acked = (*acked).max(committed);
            moved
        });
    }

    fn lose(&self, err: impl std::fmt::Display) {
        if self.is_reachable.swap(false, Ordering::Relaxed) {
            tracing::warn!(%err, "cannot deliver events; queueing them in the node's store");
            // Wakes calls waiting on an acknowledgement that is not coming.
            self.acked.send_modify(|_| {});
        }
    }
}

/// Pushes the node's log to the orchestrator for as long as the node runs.
pub async fn run(
    delivery: Arc<Delivery>,
    store: Arc<burrow_store::Store>,
    endpoint: String,
    token: Option<String>,
    node_id: Arc<std::sync::Mutex<String>>,
) {
    loop {
        let id = node_id.lock().unwrap().clone();
        // The orchestrator names this node on registration.
        if id.is_empty() {
            tokio::time::sleep(RETRY).await;
            continue;
        }
        if let Err(err) = deliver(&delivery, &store, &endpoint, token.clone(), &id).await {
            delivery.lose(err);
        }
        tokio::time::sleep(RETRY).await;
    }
}

async fn deliver(
    delivery: &Delivery,
    store: &burrow_store::Store,
    endpoint: &str,
    token: Option<String>,
    node_id: &str,
) -> anyhow::Result<()> {
    let mut client = crate::serve::connect_orchestrator(endpoint, token).await?;
    let mut push = async |events| {
        let request = nodepb::PushEventsRequest {
            node_id: node_id.to_string(),
            events,
        };
        let resp = tokio::time::timeout(ACK_TIMEOUT, client.push_events(request)).await??;
        anyhow::Ok(resp.into_inner().committed_seq)
    };
    // Where the orchestrator's copy ends, which may be further than this
    // process last heard if an earlier push landed and its answer did not.
    delivery.resume(push(Vec::new()).await?);
    loop {
        let after = *delivery.acked.borrow();
        let rows = store.list_events(after, None, BATCH).await?;
        if rows.is_empty() {
            let _ = tokio::time::timeout(PROBE_INTERVAL, delivery.appended.notified()).await;
            if store.list_events(after, None, 1).await?.is_empty() {
                delivery.acknowledge(push(Vec::new()).await?);
            }
            continue;
        }
        let events = rows
            .into_iter()
            .map(crate::sandbox::event_to_proto)
            .collect();
        delivery.acknowledge(push(events).await?);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_call_waits_for_its_event_while_delivery_is_up() {
        let delivery = Arc::new(Delivery::new(Policy::Proceed));
        delivery.acknowledge(4);
        let waiting = tokio::spawn({
            let delivery = Arc::clone(&delivery);
            async move { delivery.wait(5).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        delivery.acknowledge(5);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_call_goes_on_while_delivery_is_down_unless_told_to_fail() {
        let proceed = Delivery::new(Policy::Proceed);
        tokio::time::timeout(Duration::from_millis(100), proceed.wait(1))
            .await
            .unwrap();
        assert!(proceed.admit().is_ok());

        let fail = Delivery::new(Policy::Fail);
        assert_eq!(fail.admit().unwrap_err().code(), tonic::Code::Unavailable);
        fail.acknowledge(0);
        assert!(fail.admit().is_ok());
        fail.lose("gone");
        assert!(fail.admit().is_err());
    }

    /// An orchestrator that keeps what is pushed to it, once per position.
    #[derive(Default, Clone)]
    struct Registry(Arc<std::sync::Mutex<Vec<u64>>>);

    #[tonic::async_trait]
    impl nodepb::node_registry_server::NodeRegistry for Registry {
        async fn register(
            &self,
            _: tonic::Request<nodepb::RegisterRequest>,
        ) -> Result<tonic::Response<nodepb::RegisterResponse>, Status> {
            Err(Status::unimplemented(""))
        }

        async fn heartbeat(
            &self,
            _: tonic::Request<nodepb::HeartbeatRequest>,
        ) -> Result<tonic::Response<nodepb::HeartbeatResponse>, Status> {
            Err(Status::unimplemented(""))
        }

        async fn push_events(
            &self,
            req: tonic::Request<nodepb::PushEventsRequest>,
        ) -> Result<tonic::Response<nodepb::PushEventsResponse>, Status> {
            let mut seen = self.0.lock().unwrap();
            for event in req.into_inner().events {
                if !seen.contains(&event.seq) {
                    seen.push(event.seq);
                }
            }
            Ok(tonic::Response::new(nodepb::PushEventsResponse {
                committed_seq: seen.iter().copied().max().unwrap_or(0),
            }))
        }
    }

    async fn append(store: &burrow_store::Store, kind: &str) -> u64 {
        store
            .append_event(&burrow_store::EventRow {
                sandbox_id: "sbx_1".into(),
                kind: kind.into(),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn events_queue_while_the_orchestrator_is_away_and_arrive_in_order() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let delivery = Arc::new(Delivery::new(Policy::Proceed));
        tokio::spawn(run(
            Arc::clone(&delivery),
            Arc::clone(&store),
            format!("http://{address}"),
            None,
            Arc::new(std::sync::Mutex::new("node_a".into())),
        ));
        for kind in ["created", "started", "stopped"] {
            let seq = append(&store, kind).await;
            tokio::time::timeout(Duration::from_millis(500), delivery.wait(seq))
                .await
                .expect("a call goes on while nothing is listening");
        }
        assert!(!delivery.is_reachable());

        let registry = Registry::default();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(nodepb::node_registry_server::NodeRegistryServer::new(
                    registry.clone(),
                ))
                .serve(address),
        );
        let mut acked = delivery.acked.subscribe();
        tokio::time::timeout(Duration::from_secs(10), acked.wait_for(|acked| *acked >= 3))
            .await
            .expect("the queue is delivered once the orchestrator answers")
            .unwrap();
        assert!(delivery.is_reachable());

        let seq = append(&store, "destroyed").await;
        tokio::time::timeout(Duration::from_secs(5), delivery.wait(seq))
            .await
            .unwrap();
        assert_eq!(*delivery.acked.borrow(), seq);
        assert_eq!(*registry.0.lock().unwrap(), [1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn a_waiting_call_goes_on_when_delivery_is_lost() {
        let delivery = Arc::new(Delivery::new(Policy::Proceed));
        delivery.acknowledge(1);
        let waiting = tokio::spawn({
            let delivery = Arc::clone(&delivery);
            async move { delivery.wait(2).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        delivery.lose("gone");
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
    }

    /// A shutdown suspending sandboxes has its own deadline, and an event
    /// waiting on an orchestrator that is not answering used to spend it.
    #[tokio::test]
    async fn a_closed_delivery_does_not_wait() {
        let delivery = Arc::new(Delivery::new(Policy::Proceed));
        delivery.acknowledge(1);
        let waiting = tokio::spawn({
            let delivery = Arc::clone(&delivery);
            async move { delivery.wait(2).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        delivery.close();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_millis(100), delivery.wait(3))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_acknowledgement_never_moves_back() {
        let delivery = Delivery::new(Policy::Proceed);
        delivery.acknowledge(7);
        delivery.acknowledge(3);
        assert_eq!(*delivery.acked.borrow(), 7);
    }
}
