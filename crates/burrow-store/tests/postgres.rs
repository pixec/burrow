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
