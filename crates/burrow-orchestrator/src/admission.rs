//! How many creates and lifecycle calls one replica sends a node at once.
//!
//! A burst past what a node can work through queues here rather than on the
//! node, where every call in it would run slower, heartbeats among them, until
//! callers time out and the node looks unreachable. A call's deadline starts
//! once it is admitted, so time spent queued is not held against the node.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const DEFAULT_LIMIT: u32 = 16;

pub struct Admission {
    limit: usize,
    nodes: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl Default for Admission {
    fn default() -> Self {
        Self::new(DEFAULT_LIMIT)
    }
}

impl Admission {
    pub fn new(limit: u32) -> Self {
        Self {
            limit: limit as usize,
            nodes: Mutex::default(),
        }
    }

    /// Waits for one of `node_id`'s slots, held until the permit drops.
    pub async fn admit(&self, node_id: &str) -> OwnedSemaphorePermit {
        let slots = Arc::clone(
            self.nodes
                .lock()
                .unwrap()
                .entry(node_id.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.limit))),
        );
        slots
            .acquire_owned()
            .await
            .expect("an admission semaphore is never closed")
    }
}

#[cfg(test)]
mod tests {
    use super::Admission;

    #[tokio::test]
    async fn a_burst_past_the_limit_queues_per_node() {
        let admission = Admission::new(2);
        let first = admission.admit("a").await;
        let _second = admission.admit("a").await;
        let _other = admission.admit("b").await;
        let queued =
            tokio::time::timeout(std::time::Duration::from_millis(50), admission.admit("a"));
        assert!(queued.await.is_err());
        drop(first);
        let _admitted = admission.admit("a").await;
    }
}
