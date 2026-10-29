//! The same store against a real PostgreSQL, named by
//! BURROW_TEST_DATABASE_URL. Ignored by default; every query in the crate is
//! written once for both backends, and this is what proves the Postgres half.

use burrow_store::{EventRow, PlacementRow, SessionRow, Store, TombstoneRow};

#[tokio::test]
#[ignore]
async fn the_control_tables_round_trip_on_postgres() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let store = Store::connect_postgres(&url).await.unwrap();
    let run = format!("t{}", std::process::id());
    let a = format!("{run}_a");
    let b = format!("{run}_b");

    for (id, node, record) in [
        (&a, "n1", vec![1, 2, 3]),
        (&b, "n2", vec![4]),
        (&a, "n1", vec![9]),
    ] {
        store
            .put_placement(&PlacementRow {
                id: id.clone(),
                node_id: node.into(),
                record,
            })
            .await
            .unwrap();
    }
    let rows: Vec<_> = store
        .list_placements()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.id.starts_with(&run))
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].record, vec![9]);
    assert_eq!(store.delete_placements_for_node("n2").await.unwrap(), 1);
    store.delete_placement(&a).await.unwrap();

    for (id, at) in [(&a, 100), (&b, 200)] {
        store
            .put_tombstone(&TombstoneRow {
                sandbox_id: id.clone(),
                node_id: "n1".into(),
                at,
            })
            .await
            .unwrap();
    }
    assert_eq!(store.prune_tombstones(150).await.unwrap(), 1);
    store.delete_tombstone(&b).await.unwrap();

    store.put_secret(&a, "sealed").await.unwrap();
    store.put_secret(&a, "sealed2").await.unwrap();
    assert_eq!(
        store.get_secret(&a).await.unwrap().as_deref(),
        Some("sealed2")
    );
    assert!(store.delete_secret(&a).await.unwrap());
    assert!(!store.delete_secret(&a).await.unwrap());

    let event = |node_seq: u64| EventRow {
        node_id: run.clone(),
        node_seq,
        at_unix_ms: 1,
        sandbox_id: a.clone(),
        kind: "created".into(),
        ..Default::default()
    };
    let first = store.append_event(&event(1)).await.unwrap();
    assert!(first > 0);
    assert_eq!(store.append_event(&event(1)).await.unwrap(), 0);
    assert!(store.append_event(&event(2)).await.unwrap() > first);
    assert_eq!(store.last_event_seq_for_node(&run).await.unwrap(), 2);
    assert_eq!(
        store
            .list_events(first - 1, Some(&a), 10)
            .await
            .unwrap()
            .len(),
        2
    );

    for (id, at) in [("s1", 100), ("s2", 100), ("s3", 100)] {
        store
            .put_session(&SessionRow {
                id: format!("{run}_{id}"),
                sandbox_id: a.clone(),
                started_at: at,
                ended_at: 0,
                started_by: "boot".into(),
                ended_by: String::new(),
            })
            .await
            .unwrap();
    }
    assert_eq!(store.retain_recent_sessions(&a, 2).await.unwrap(), 1);
    let kept = store.list_sessions(&a).await.unwrap();
    assert_eq!(kept[0].id, format!("{run}_s3"));
    store.delete_sessions(&a).await.unwrap();
}

/// Two orchestrator replicas racing for one name, or for the last capacity on
/// a node, must not both win. Each task here stands in for a replica with a
/// connection of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn racing_claims_and_reservations_have_one_winner() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let run = format!("r{}", std::process::id());
    let mut stores = Vec::new();
    for _ in 0..8 {
        stores.push(Store::connect_postgres(&url).await.unwrap());
    }

    let name = format!("name:{run}");
    let claims = futures::future::join_all(stores.iter().enumerate().map(|(i, store)| {
        let name = name.clone();
        let id = format!("{run}_{i}");
        async move { store.claim(&name, &id, 1).await.unwrap() }
    }))
    .await;
    assert_eq!(claims.iter().filter(|won| **won).count(), 1);

    let node = burrow_store::NodeRow {
        id: format!("{run}_node"),
        info: vec![1],
        status: vec![1],
        total_vcpus: 4,
        ..Default::default()
    };
    let index = stores[0]
        .register_node(&node, None, 4096)
        .await
        .unwrap()
        .unwrap();
    stores[0]
        .heartbeat_node(&burrow_store::NodeRow {
            total_vcpus: 4,
            committed_vcpus: 1,
            free_mem_mib: 2048,
            ..node.clone()
        })
        .await
        .unwrap();
    // Room for three 1-vcpu, 512 MiB sandboxes by cpu, four by memory.
    let reserved = futures::future::join_all(
        stores
            .iter()
            .map(|store| async { store.reserve_capacity(&node.id, 1, 512).await.unwrap() }),
    )
    .await;
    assert_eq!(reserved.iter().filter(|won| **won).count(), 3);

    // Two registrations at once never share an address slice.
    let rows: Vec<_> = (0..8)
        .map(|i| burrow_store::NodeRow {
            id: format!("{run}_n{i}"),
            info: vec![1],
            status: vec![1],
            ..Default::default()
        })
        .collect();
    let indexes = futures::future::join_all(stores.iter().zip(&rows).map(|(store, row)| async {
        store.register_node(row, None, 4096).await.unwrap().unwrap()
    }))
    .await;
    let mut unique = indexes.clone();
    unique.push(index);
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), indexes.len() + 1);

    for row in rows.iter().chain(std::iter::once(&node)) {
        stores[0].delete_node(&row.id).await.unwrap();
    }
    stores[0].release_claims(&format!("{run}_0")).await.ok();
    for i in 0..8 {
        stores[0]
            .release_claims(&format!("{run}_{i}"))
            .await
            .unwrap();
    }
}

/// The ledger's statements on Postgres: a step commits once, a stale one is
/// refused, heartbeats only move a reading forward, and rows committed from
/// several connections at once become visible in id order, so an export
/// paging by id never passes a row that commits after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn the_usage_ledger_commits_once_and_in_id_order_on_postgres() {
    use burrow_store::{OpenUsageChange, OpenUsageRow, UsageCommit, UsageFilter, UsageRow};
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let store = Store::connect_postgres(&url).await.unwrap();
    let run = format!("u{}", std::process::id());
    let node = format!("{run}_node");
    let sandbox = format!("{run}_sbx");

    let event = |node_seq: u64, vcpus: u32| EventRow {
        node_id: node.clone(),
        node_seq,
        at_unix_ms: node_seq as i64,
        sandbox_id: sandbox.clone(),
        kind: "started".into(),
        vcpus,
        mem_mib: vcpus * 512,
        ..Default::default()
    };
    for (seq, vcpus) in [(1, 0), (2, 0), (3, 2)] {
        store.append_event(&event(seq, vcpus)).await.unwrap();
    }
    assert_eq!(store.first_shaped_event(&node).await.unwrap(), Some(3));
    assert_eq!(
        store
            .last_event_of(&sandbox)
            .await
            .unwrap()
            .unwrap()
            .node_seq,
        3
    );

    let open = OpenUsageRow {
        sandbox_id: sandbox.clone(),
        node_id: node.clone(),
        state: "running".into(),
        vcpus: 2,
        mem_mib: 1024,
        started_at_ms: 1_000,
        seen_at_ms: 1_000,
        metadata_json: "{}".into(),
        ..Default::default()
    };
    let opened = UsageCommit {
        cursor: Some((node.clone(), 0, 3)),
        rows: Vec::new(),
        changes: vec![OpenUsageChange {
            sandbox_id: sandbox.clone(),
            expected: None,
            next: Some(open.clone()),
        }],
    };
    assert!(store.commit_usage(&opened).await.unwrap());
    assert!(!store.commit_usage(&opened).await.unwrap());

    let beat = |cpu| vec![(sandbox.clone(), cpu, 10u64, 5u64)];
    store.observe_usage(&node, 5_000, &beat(700)).await.unwrap();
    store.observe_usage(&node, 4_000, &beat(999)).await.unwrap();
    let seen = store.open_usage(&sandbox).await.unwrap().unwrap();
    assert_eq!((seen.seen_at_ms, seen.seen_cpu_usage_usec), (5_000, 700));

    let row = |i: i64| UsageRow {
        sandbox_id: sandbox.clone(),
        node_id: node.clone(),
        metadata_json: "{}".into(),
        state: "running".into(),
        started_at_ms: i,
        ended_at_ms: i + 1,
        closed_by: "checkpoint".into(),
        ..Default::default()
    };
    let mut stores = Vec::new();
    for _ in 0..8 {
        stores.push(Store::connect_postgres(&url).await.unwrap());
    }
    let commits = futures::future::join_all(stores.iter().enumerate().map(|(i, store)| {
        let commit = UsageCommit {
            cursor: None,
            rows: (0..20).map(|j| row(i as i64 * 100 + j)).collect(),
            changes: Vec::new(),
        };
        async move { store.commit_usage(&commit).await.unwrap() }
    }))
    .await;
    assert!(commits.into_iter().all(|done| done));
    let rows = store
        .list_usage(&UsageFilter {
            sandbox_id: Some(sandbox.clone()),
            limit: 1_000,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 160);
    // Each commit's rows are contiguous: no other commit's id fell inside.
    for chunk in rows.chunks(20) {
        let batch = chunk[0].started_at_ms / 100;
        assert!(chunk.iter().all(|row| row.started_at_ms / 100 == batch));
        assert_eq!(chunk[19].id - chunk[0].id, 19);
    }

    let closed = UsageCommit {
        cursor: None,
        rows: Vec::new(),
        changes: vec![OpenUsageChange {
            sandbox_id: sandbox.clone(),
            expected: Some(open.started_at_ms),
            next: None,
        }],
    };
    assert!(store.commit_usage(&closed).await.unwrap());
    assert!(store.open_usage(&sandbox).await.unwrap().is_none());
}
