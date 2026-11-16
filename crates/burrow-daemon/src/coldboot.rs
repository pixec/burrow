//! How many sandboxes boot cold on this node at once.
//!
//! A cold boot runs a kernel, an init and an agent to readiness, which keeps
//! its vCPUs busy in a way a running sandbox mostly does not. Under
//! `--cpu-overcommit` a burst of them can take every host CPU at once, slowing
//! each boot and every running sandbox with it. Past the limit a boot waits
//! for a slot rather than failing. Warm restores take no slot.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The default: one boot per host CPU.
pub fn default_limit() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

pub struct ColdBoots {
    slots: Arc<Semaphore>,
    limit: usize,
    waiting: AtomicU64,
}

/// A cold boot's slot, held until its agent has answered or the boot failed.
pub struct ColdBoot {
    _permit: OwnedSemaphorePermit,
}

impl ColdBoots {
    /// 0 is unlimited.
    pub fn new(limit: usize) -> Self {
        let limit = match limit {
            0 => Semaphore::MAX_PERMITS,
            limit => limit,
        };
        Self {
            slots: Arc::new(Semaphore::new(limit)),
            limit,
            waiting: AtomicU64::new(0),
        }
    }

    /// Waits for a slot for `sandbox`'s boot.
    pub async fn admit(&self, sandbox: &str) -> ColdBoot {
        if let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() {
            return ColdBoot { _permit: permit };
        }
        let waiting = Waiting::enter(&self.waiting);
        tracing::info!(
            sandbox,
            waiting = waiting.depth,
            limit = self.limit,
            "cold boot queued: the node is booting as many as --cold-boots allows"
        );
        let began = std::time::Instant::now();
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("the cold boot semaphore is never closed");
        drop(waiting);
        tracing::info!(
            sandbox,
            waited_ms = began.elapsed().as_millis() as u64,
            "cold boot admitted"
        );
        ColdBoot { _permit: permit }
    }

    /// Boots waiting for a slot.
    pub fn waiting(&self) -> u64 {
        self.waiting.load(Ordering::Relaxed)
    }

    /// Boots holding a slot.
    pub fn running(&self) -> u64 {
        (self.limit - self.slots.available_permits()) as u64
    }
}

/// Counts a boot as waiting until it is admitted or its create is dropped.
struct Waiting<'a> {
    count: &'a AtomicU64,
    depth: u64,
}

impl<'a> Waiting<'a> {
    fn enter(count: &'a AtomicU64) -> Self {
        let depth = count.fetch_add(1, Ordering::Relaxed) + 1;
        Self { count, depth }
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn boots_past_the_limit_wait_for_a_slot() {
        let boots = Arc::new(ColdBoots::new(2));
        let first = boots.admit("sbx_1").await;
        let _second = boots.admit("sbx_2").await;
        assert_eq!((boots.running(), boots.waiting()), (2, 0));

        let queued = tokio::spawn({
            let boots = Arc::clone(&boots);
            async move { boots.admit("sbx_3").await }
        });
        while boots.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        assert!(!queued.is_finished());
        drop(first);
        let _third = queued.await.unwrap();
        assert_eq!((boots.running(), boots.waiting()), (2, 0));
    }

    #[tokio::test]
    async fn a_create_dropped_while_queued_leaves_the_queue() {
        let boots = ColdBoots::new(1);
        let _held = boots.admit("sbx_1").await;
        let gave_up =
            tokio::time::timeout(std::time::Duration::from_millis(20), boots.admit("sbx_2")).await;
        assert!(gave_up.is_err());
        assert_eq!(boots.waiting(), 0);
    }

    #[test]
    fn zero_is_unlimited() {
        let boots = ColdBoots::new(0);
        assert_eq!(boots.running(), 0);
        assert!(default_limit() >= 1);
    }
}
