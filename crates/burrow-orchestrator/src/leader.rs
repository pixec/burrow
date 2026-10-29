//! Which orchestrator replica runs the fleet's background work.
//!
//! Writing off dead nodes, ageing out tombstones and claims, and copying
//! every node's event log must each happen once, not once per replica. One
//! replica holds a Postgres advisory lock on a connection of its own and is
//! the leader for as long as that connection lives; if the replica dies, the
//! connection does and the lock with it, and another replica's next attempt
//! takes over. No other coordination service is involved.
//!
//! With SQLite there is one process, and it is always the leader.

use std::sync::Arc;
use std::time::Duration;

use burrow_store::sqlx::{self, Connection as _};
use tokio::sync::watch;

/// The advisory lock's key: "burrow" in ASCII, so it reads as what it is in
/// `pg_locks`.
const LOCK_KEY: i64 = 0x6275_7272_6f77;

/// How often a follower tries for the lock and a leader checks it still
/// holds its connection.
const PERIOD: Duration = Duration::from_secs(2);

pub struct Leader {
    state: watch::Sender<bool>,
}

impl Leader {
    pub fn spawn(store: Option<Arc<burrow_store::Store>>) -> Arc<Self> {
        let pool = store.as_ref().and_then(|s| s.postgres_pool().cloned());
        let leader = Arc::new(Self {
            state: watch::channel(pool.is_none()).0,
        });
        if let Some(pool) = pool {
            let task = Arc::clone(&leader);
            tokio::spawn(async move { task.contend(pool).await });
        }
        leader
    }

    pub fn is_leader(&self) -> bool {
        *self.state.borrow()
    }

    /// Resolves as this replica becomes leader, or at once if it is.
    pub async fn wait(&self) {
        let mut rx = self.state.subscribe();
        let _ = rx.wait_for(|leading| *leading).await;
    }

    async fn contend(&self, pool: sqlx::PgPool) {
        'session: loop {
            // Detached from the pool: the lock belongs to this session, and a
            // pooled connection could be handed to someone else and reset.
            let mut conn = match pool.acquire().await {
                Ok(conn) => conn.detach(),
                Err(err) => {
                    tracing::warn!(%err, "leader election: no database connection");
                    tokio::time::sleep(PERIOD).await;
                    continue;
                }
            };
            loop {
                let held: Result<(bool,), _> = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                    .bind(LOCK_KEY)
                    .fetch_one(&mut conn)
                    .await;
                match held {
                    Ok((true,)) => break,
                    Ok((false,)) => tokio::time::sleep(PERIOD).await,
                    // Not a lock this session holds: a ping that then
                    // succeeded would make it a leader without one.
                    Err(err) => {
                        tracing::warn!(%err, "leader election: lost the database connection");
                        let _ = conn.close().await;
                        tokio::time::sleep(PERIOD).await;
                        continue 'session;
                    }
                }
            }
            if conn.ping().await.is_err() {
                continue;
            }
            self.state.send_replace(true);
            tracing::info!("this replica is now the leader");
            // Held until the session is: a failed ping means the database may
            // already have released the lock to someone else.
            while conn.ping().await.is_ok() {
                tokio::time::sleep(PERIOD).await;
            }
            self.state.send_replace(false);
            tracing::warn!("this replica lost the leadership");
            let _ = conn.close().await;
        }
    }
}
