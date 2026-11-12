//! Event and session writes, applied one at a time in the order they were
//! made.
//!
//! A create or a resume does not wait for its own: the caller has its sandbox
//! as soon as the VM is up, and the rows follow. Every other write waits, and
//! because the queue is one queue, waiting for a write is waiting for every
//! write made before it. A session closed right after a create still finds
//! the row its opening wrote, and a tail still sees `created` before
//! `stopped`.

use std::future::Future;
use std::pin::Pin;

use tokio::sync::{mpsc, oneshot};

type Write = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone)]
pub struct Journal {
    tx: mpsc::UnboundedSender<Write>,
}

impl Journal {
    pub fn spawn() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<Write>();
        tokio::spawn(async move {
            while let Some(write) = rx.recv().await {
                write.await;
            }
        });
        Self { tx }
    }

    /// Queues `write` behind every write already queued.
    pub fn queue(&self, write: impl Future<Output = ()> + Send + 'static) {
        let _ = self.tx.send(Box::pin(write));
    }

    /// Queues `write` and waits for it, and so for everything queued before
    /// it.
    pub async fn write<T: Send + 'static>(
        &self,
        write: impl Future<Output = T> + Send + 'static,
    ) -> T {
        let (done, applied) = oneshot::channel();
        self.queue(async move {
            let _ = done.send(write.await);
        });
        applied.await.expect("the journal outlives its writers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_write_waits_for_everything_queued_before_it() {
        let journal = Journal::spawn();
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        for n in 0..3 {
            let order = order.clone();
            journal.queue(async move {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                order.lock().unwrap().push(n);
            });
        }
        let seen = {
            let order = order.clone();
            journal
                .write(async move { order.lock().unwrap().clone() })
                .await
        };
        assert_eq!(seen, vec![0, 1, 2]);
    }
}
