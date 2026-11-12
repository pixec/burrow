//! Which orchestrator replica runs the fleet's background work.
//!
//! Writing off dead nodes, ageing out tombstones and claims, and copying
//! every node's event log must each happen once, not once per replica. One
//! replica holds a Postgres advisory lock on a connection of its own and is
//! the leader for as long as that connection lives; if the replica dies, the
//! connection does and the lock with it, and another replica's next attempt
//! takes over. No other coordination service is involved.
//!
//! Each term is numbered in the store as it starts, and the leader's writes
//! are conditional on its number. A leader cut off from the database stops
//! within a period, but the database may have handed the lock on before it
//! notices; the number is what keeps its last writes from landing.
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
    /// The epoch of the term this replica holds, while it holds one.
    state: watch::Sender<Option<i64>>,
}

impl Leader {
    pub fn spawn(store: Option<Arc<burrow_store::Store>>) -> Arc<Self> {
        let pool = store.as_ref().and_then(|s| s.postgres_pool().cloned());
        let leader = Arc::new(Self {
            state: watch::channel(pool.is_none().then_some(0)).0,
        });
        if let (Some(pool), Some(store)) = (pool, store) {
            let task = Arc::clone(&leader);
            tokio::spawn(async move { task.contend(pool, store).await });
        }
        leader
    }

    #[cfg(test)]
    pub fn holding(epoch: Option<i64>) -> Arc<Self> {
        Arc::new(Self {
            state: watch::channel(epoch).0,
        })
    }

    pub fn is_leader(&self) -> bool {
        self.state.borrow().is_some()
    }

    /// The epoch of this replica's term, while it leads.
    pub fn epoch(&self) -> Option<i64> {
        *self.state.borrow()
    }

    /// Resolves as this replica becomes leader, or at once if it is.
    pub async fn wait(&self) {
        let mut rx = self.state.subscribe();
        let _ = rx.wait_for(Option::is_some).await;
    }

    async fn contend(&self, pool: sqlx::PgPool, store: Arc<burrow_store::Store>) {
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
                let held = tokio::time::timeout(
                    PERIOD,
                    sqlx::query_as::<_, (bool,)>("SELECT pg_try_advisory_lock($1)")
                        .bind(LOCK_KEY)
                        .fetch_one(&mut conn),
                )
                .await;
                match held {
                    Ok(Ok((true,))) => break,
                    Ok(Ok((false,))) => tokio::time::sleep(PERIOD).await,
                    // Not a lock this session holds: a ping that then
                    // succeeded would make it a leader without one.
                    Ok(Err(_)) | Err(_) => {
                        tracing::warn!("leader election: lost the database connection");
                        let _ = conn.close().await;
                        tokio::time::sleep(PERIOD).await;
                        continue 'session;
                    }
                }
            }
            let epoch = match tokio::time::timeout(PERIOD, store.next_leader_epoch()).await {
                Ok(Ok(epoch)) => epoch,
                _ => {
                    let _ = conn.close().await;
                    continue;
                }
            };
            self.state.send_replace(Some(epoch));
            tracing::info!(epoch, "this replica is now the leader");
            // Held until the session is. A ping that fails, or does not come
            // back within a period, means the database may already have
            // released the lock to someone else.
            while tokio::time::timeout(PERIOD, conn.ping())
                .await
                .is_ok_and(|pinged| pinged.is_ok())
            {
                tokio::time::sleep(PERIOD).await;
            }
            self.state.send_replace(None);
            tracing::warn!(epoch, "this replica lost the leadership");
            let _ = conn.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against a real PostgreSQL named by BURROW_TEST_DATABASE_URL: one of
    /// two replicas leads, and when its session is cut the old term ends and
    /// a later one starts.
    #[tokio::test]
    #[ignore]
    async fn one_replica_leads_and_a_cut_session_hands_over() {
        let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
        let store =
            || async { Arc::new(burrow_store::Store::connect_postgres(&url).await.unwrap()) };
        let (a, b) = (
            Leader::spawn(Some(store().await)),
            Leader::spawn(Some(store().await)),
        );
        let leading = |a: &Leader, b: &Leader| (a.epoch(), b.epoch());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !a.is_leader() && !b.is_leader() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(PERIOD * 2).await;
        let epoch = match leading(&a, &b) {
            (Some(epoch), None) | (None, Some(epoch)) => epoch,
            both => panic!("{both:?}"),
        };

        let admin = store().await;
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_locks
             WHERE locktype='advisory' AND objid=($1::bigint & 4294967295)::oid AND granted",
        )
        .bind(LOCK_KEY)
        .execute(admin.postgres_pool().unwrap())
        .await
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match leading(&a, &b) {
                (Some(next), None) | (None, Some(next)) if next > epoch => {
                    assert_eq!(admin.leader_epoch().await.unwrap(), next);
                    break;
                }
                _ => {}
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{:?}",
                leading(&a, &b)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
