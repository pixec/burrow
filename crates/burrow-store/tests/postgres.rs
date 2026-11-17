//! The same store against a real PostgreSQL, named by
//! BURROW_TEST_DATABASE_URL. Ignored by default; every query in the crate is
//! written once for both backends, and this is what proves the Postgres half.

use burrow_store::{
    EventRow, NodeReport, NodeRow, PlacementRow, Reconciled, ReportedSandbox, SessionRow, Store,
};

#[tokio::test]
#[ignore]
async fn the_control_tables_round_trip_on_postgres() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let store = Store::connect_postgres(&url).await.unwrap();
    let run = format!("t{}", std::process::id());
    let a = format!("{run}_a");
    let b = format!("{run}_b");

    for (id, node, record) in [(&a, "n1", vec![1, 2, 3]), (&b, "n2", vec![4])] {
        assert!(
            store
                .insert_placement(&PlacementRow {
                    id: id.clone(),
                    node_id: node.into(),
                    record,
                    generation: 1,
                    ..Default::default()
                })
                .await
                .unwrap()
        );
    }
    let rows: Vec<_> = store
        .list_placements()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.id.starts_with(&run))
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].record, vec![1, 2, 3]);
    store.remove_placement(&a).await.unwrap().unwrap();
    store.remove_placement(&b).await.unwrap().unwrap();

    assert!(store.insert_snapshot(&a, 1).await.unwrap());
    assert!(!store.insert_snapshot(&a, 1).await.unwrap());
    assert!(store.insert_volume(&b, 1).await.unwrap());
    let node = format!("{run}_node");
    store
        .register_node(
            &NodeRow {
                id: node.clone(),
                ..Default::default()
            },
            None,
            4096,
        )
        .await
        .unwrap();
    let first = NodeReport {
        node: NodeRow {
            id: node.clone(),
            ..Default::default()
        },
        seq: 1,
        ..Default::default()
    };
    store
        .reconcile_node(&first, |_| None, |_, _| None)
        .await
        .unwrap();
    store.record_stored_inventory(&[], &[], 1).await.unwrap();
    let report = NodeReport {
        node: NodeRow {
            id: node.clone(),
            ..Default::default()
        },
        seq: 2,
        snapshots: vec![a.clone(), format!("{run}_gone")],
        volumes: vec![b.clone(), format!("{run}_gone")],
        ..Default::default()
    };
    let Reconciled::Applied(out) = store
        .reconcile_node(&report, |_| None, |_, _| None)
        .await
        .unwrap()
    else {
        panic!("not applied");
    };
    assert_eq!(out.destroy_snapshots, [format!("{run}_gone")]);
    assert_eq!(out.destroy_volumes, [format!("{run}_gone")]);
    assert!(store.remove_snapshot(&a).await.unwrap());
    assert!(store.remove_volume(&b).await.unwrap());
    let epoch = store.leader_epoch().await.unwrap();
    store
        .write_off_node(&node, i64::MAX, epoch, |_| None)
        .await
        .unwrap();

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
        kind: 1,
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
                started_at_ms: at,
                ended_at_ms: 0,
                started_by: 1,
                ended_by: 0,
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
        cpu_capacity_millis: 4000,
        ..Default::default()
    };
    let index = stores[0]
        .register_node(&node, None, 4096)
        .await
        .unwrap()
        .unwrap();
    let beat = NodeReport {
        node: NodeRow {
            cpu_capacity_millis: 4000,
            committed_cpu_millis: 1000,
            free_mem_mib: 2048,
            ..node.clone()
        },
        seq: 1,
        ..Default::default()
    };
    stores[0]
        .reconcile_node(&beat, |_| None, |_, _| None)
        .await
        .unwrap();
    // Room for three 1-vcpu, 512 MiB sandboxes by cpu, four by memory.
    let reserved = futures::future::join_all(
        stores
            .iter()
            .map(|store| async { store.reserve_capacity(&node.id, 1000, 512).await.unwrap() }),
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

    let epoch = stores[0].leader_epoch().await.unwrap();
    for row in rows.iter().chain(std::iter::once(&node)) {
        stores[0]
            .write_off_node(&row.id, i64::MAX, epoch, |_| None)
            .await
            .unwrap();
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
        kind: 2,
        vcpus,
        mem_mib: vcpus * 512,
        ..Default::default()
    };
    for (seq, vcpus) in [(1, 0), (2, 0), (3, 2)] {
        store.append_event(&event(seq, vcpus)).await.unwrap();
    }
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
        state: 1,
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
        state: 1,
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

#[tokio::test]
#[ignore]
async fn placements_and_write_offs_are_conditional_on_postgres() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let store = Store::connect_postgres(&url).await.unwrap();
    let id = format!("cas{}", std::process::id());
    let row = |node: &str| PlacementRow {
        id: id.clone(),
        node_id: node.into(),
        generation: 1,
        ..Default::default()
    };
    assert!(store.insert_placement(&row("cas-n1")).await.unwrap());
    assert!(!store.insert_placement(&row("cas-n2")).await.unwrap());
    assert_eq!(
        store
            .move_placement(&id, "cas-n1", 1, "cas-n2", &[], 5)
            .await
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        store
            .move_placement(&id, "cas-n1", 1, "cas-n3", &[], 5)
            .await
            .unwrap(),
        None
    );
    assert!(
        !store
            .update_placement(&row("cas-n2"), 0, true)
            .await
            .unwrap()
    );
    assert!(
        store
            .unplace_placement(&id, "cas-n2", 2, &[])
            .await
            .unwrap()
    );
    assert!(!store.remove_placement_at(&id, "cas-n2", 2).await.unwrap());
    assert!(store.remove_placement(&id).await.unwrap().is_some());

    let deposed = store.next_leader_epoch().await.unwrap();
    let current = store.next_leader_epoch().await.unwrap();
    assert_eq!(store.leader_epoch().await.unwrap(), current);
    let node = NodeRow {
        id: format!("writeoff{}", std::process::id()),
        last_heartbeat_ms: 1_000,
        ..Default::default()
    };
    store.register_node(&node, None, 4096).await.unwrap();
    let held = PlacementRow {
        id: format!("{id}_held"),
        node_id: node.id.clone(),
        generation: 1,
        ..Default::default()
    };
    store.insert_placement(&held).await.unwrap();
    let keep = |_: &PlacementRow| Some(vec![7]);
    assert!(
        store
            .write_off_node(&node.id, 2_000, deposed, keep)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .write_off_node(&node.id, 500, current, keep)
            .await
            .unwrap()
            .is_none()
    );
    let lost = store
        .write_off_node(&node.id, 2_000, current, keep)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lost.len(), 1);
    let kept = store.get_placement(&held.id).await.unwrap().unwrap();
    assert_eq!(
        (kept.node_id.as_str(), kept.record.as_slice()),
        ("", &[7][..])
    );
    store.remove_placement(&held.id).await.unwrap();
}

fn listing(entries: &[(&str, i64)]) -> Vec<ReportedSandbox> {
    entries
        .iter()
        .map(|(id, generation)| ReportedSandbox {
            id: id.to_string(),
            generation: *generation,
            hash: 0,
            in_flight: 0,
        })
        .collect()
}

fn beat(node: &str, seq: i64, entries: &[(&str, i64)]) -> NodeReport {
    NodeReport {
        node: NodeRow {
            id: node.into(),
            last_heartbeat_ms: 10_000 + seq,
            ..Default::default()
        },
        seq,
        sandboxes: listing(entries),
        pending_after_ms: 0,
        usage_before_ms: 0,
        unanswered_before_ms: 0,
        snapshots: Vec::new(),
        swept_snapshots: Vec::new(),
        volumes: Vec::new(),
    }
}

async fn reconcile(store: &Store, report: &NodeReport) -> Reconciled {
    store
        .reconcile_node(report, |_| None, |_, _| None)
        .await
        .unwrap()
}

/// Two orchestrator replicas, each with its own connections, the way the HA
/// deployment runs them. One takes a node's heartbeats while the other
/// deletes and moves its sandboxes, and both receive the same node's reports
/// out of order: every decision is the store's, so neither replica's view
/// can bring back what the other removed, and of two reports racing only
/// the newer one is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn two_replicas_reconcile_one_node_against_the_store() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let first = Store::connect_postgres(&url).await.unwrap();
    let second = Store::connect_postgres(&url).await.unwrap();
    let run = format!("ha{}", std::process::id());
    let node = format!("{run}_n1");
    let other = format!("{run}_n2");
    for id in [&node, &other] {
        first
            .register_node(
                &NodeRow {
                    id: id.clone(),
                    ..Default::default()
                },
                None,
                4096,
            )
            .await
            .unwrap();
    }
    let kept = format!("{run}_kept");
    let deleted = format!("{run}_deleted");
    let moved = format!("{run}_moved");
    for id in [&kept, &deleted, &moved] {
        first
            .insert_placement(&PlacementRow {
                id: id.clone(),
                node_id: node.clone(),
                generation: 1,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // The second replica deletes one and moves another; the first, which
    // has not heard of either, takes the node's next report.
    second.remove_placement(&deleted).await.unwrap().unwrap();
    assert_eq!(
        second
            .move_placement(&moved, &node, 1, &other, &[], 1)
            .await
            .unwrap(),
        Some(2)
    );
    let held = [
        (kept.as_str(), 1),
        (deleted.as_str(), 1),
        (moved.as_str(), 1),
    ];
    let Reconciled::Applied(out) = reconcile(&first, &beat(&node, 2, &held)).await else {
        panic!("not applied");
    };
    let mut destroyed: Vec<_> = out.destroy.iter().map(|(id, _)| id.clone()).collect();
    destroyed.sort();
    let mut expected = vec![deleted.clone(), moved.clone()];
    expected.sort();
    assert_eq!(destroyed, expected);

    // Reports 3 and 4 race through the two replicas. Whichever lands
    // second sees the other's number, so 3 is applied only if it lands
    // first, and 4 always is.
    let (report3, report4) = (beat(&node, 3, &held), beat(&node, 4, &held));
    let (three, four) = tokio::join!(reconcile(&first, &report3), reconcile(&second, &report4));
    assert!(matches!(four, Reconciled::Applied(_)));
    assert!(matches!(three, Reconciled::Applied(_) | Reconciled::Stale));
    assert!(matches!(
        reconcile(&first, &beat(&node, 3, &[])).await,
        Reconciled::Stale
    ));
    assert_eq!(first.node_report_seq(&node).await.unwrap(), 4);

    // Twenty listings racing through both replicas, each leaving `kept`
    // out, lose it only once two applied ones in a row have.
    let racing = (5..25).map(|seq| {
        let store = if seq % 2 == 0 { &first } else { &second };
        let report = beat(&node, seq, &[]);
        async move { reconcile(store, &report).await }
    });
    futures::future::join_all(racing).await;
    assert!(first.get_placement(&kept).await.unwrap().is_none());
    assert_eq!(
        first.get_placement(&moved).await.unwrap().unwrap().node_id,
        other
    );
    first.remove_placement(&moved).await.unwrap();
    let epoch = first.leader_epoch().await.unwrap();
    for id in [&node, &other] {
        first
            .write_off_node(id, i64::MAX, epoch, |_| None)
            .await
            .unwrap();
    }
}

/// A heartbeat's restate decided on a row read without a lock. An edit
/// another replica committed meanwhile, a tag change say, is kept: the
/// restate writes only over the version it read, and the next heartbeat
/// tries again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn a_restate_does_not_revert_a_concurrent_edit() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let first = Store::connect_postgres(&url).await.unwrap();
    let second = Store::connect_postgres(&url).await.unwrap();
    let run = format!("edit{}", std::process::id());
    let node = format!("{run}_n");
    first
        .register_node(
            &NodeRow {
                id: node.clone(),
                ..Default::default()
            },
            None,
            4096,
        )
        .await
        .unwrap();
    let id = format!("{run}_a");
    let row = |record: Vec<u8>| PlacementRow {
        id: id.clone(),
        node_id: node.clone(),
        record,
        generation: 1,
        ..Default::default()
    };
    first.insert_placement(&row(vec![1])).await.unwrap();
    let mut report = beat(&node, 1, &[(id.as_str(), 1)]);
    report.sandboxes[0].hash = 9;
    let (selected, mut read) = tokio::sync::mpsc::unbounded_channel();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let wait = std::sync::Mutex::new(wait);
    let restating = tokio::spawn(async move {
        first
            .reconcile_node(
                &report,
                move |_| {
                    selected.send(()).unwrap();
                    tokio::task::block_in_place(|| wait.lock().unwrap().recv().unwrap());
                    Some((vec![2], 9))
                },
                |_, _| None,
            )
            .await
            .unwrap()
    });
    read.recv().await.unwrap();
    assert!(
        second
            .update_placement(&row(vec![7]), 0, false)
            .await
            .unwrap()
    );
    go.send(()).unwrap();
    let Reconciled::Applied(out) = restating.await.unwrap() else {
        panic!("not applied");
    };
    assert!(out.restated.is_empty());
    let kept = second.get_placement(&id).await.unwrap().unwrap();
    assert_eq!(kept.record, vec![7]);
    second.remove_placement(&id).await.unwrap();
    let epoch = second.leader_epoch().await.unwrap();
    second
        .write_off_node(&node, i64::MAX, epoch, |_| None)
        .await
        .unwrap();
}

/// How long heartbeat reconciles take on Postgres for `BURROW_TEST_NODES`
/// nodes (4 by default) with `BURROW_TEST_SANDBOXES` sandboxes each (2000 by
/// default), every node reconciling at once as replicas would. Prints the
/// figures; asserts only that the answers are right.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn reconcile_time_at_scale_on_postgres() {
    let url = std::env::var("BURROW_TEST_DATABASE_URL").unwrap();
    let var = |name: &str, default: usize| -> usize {
        std::env::var(name)
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(default)
    };
    let (count, nodes) = (
        var("BURROW_TEST_SANDBOXES", 2000),
        var("BURROW_TEST_NODES", 4),
    );
    let store = Store::connect_postgres(&url).await.unwrap();
    let run = format!("scale{}", std::process::id());
    let mut reports = Vec::new();
    for n in 0..nodes {
        let node = format!("{run}_n{n}");
        store
            .register_node(
                &NodeRow {
                    id: node.clone(),
                    ..Default::default()
                },
                None,
                4096,
            )
            .await
            .unwrap();
        let ids: Vec<String> = (0..count).map(|i| format!("{node}_{i:05}")).collect();
        for chunk in ids.chunks(500) {
            let rows: Vec<PlacementRow> = chunk
                .iter()
                .map(|id| PlacementRow {
                    id: id.clone(),
                    node_id: node.clone(),
                    record: vec![0; 1500],
                    generation: 1,
                    ..Default::default()
                })
                .collect();
            futures::future::join_all(rows.iter().map(|row| store.insert_placement(row))).await;
        }
        let entries: Vec<(&str, i64)> = ids.iter().map(|id| (id.as_str(), 1)).collect();
        reports.push(beat(&node, 1, &entries));
    }
    let round = async |reports: &[NodeReport]| {
        let started = std::time::Instant::now();
        let each = futures::future::join_all(reports.iter().map(|report| async {
            let started = std::time::Instant::now();
            let out = store
                .reconcile_node(
                    report,
                    |row| Some((vec![0; 1500], row.generation)),
                    |_, _| None,
                )
                .await
                .unwrap();
            let Reconciled::Applied(out) = out else {
                panic!("not applied");
            };
            assert!(out.destroy.is_empty() && out.lost.is_empty());
            started.elapsed()
        }))
        .await;
        (started.elapsed(), each)
    };
    let mut steady = Vec::new();
    let mut restating = Vec::new();
    let mut walls = Vec::new();
    for seq in 2..14 {
        let restates = seq % 2 == 0;
        for report in reports.iter_mut() {
            report.seq = seq;
            for (i, sandbox) in report.sandboxes.iter_mut().enumerate() {
                // One in six due a write, as usage on a 30 s interval at
                // 5 s beats does.
                sandbox.hash = match restates && i % 6 == (seq as usize / 2) % 6 {
                    true => seq,
                    false => 1,
                };
            }
        }
        let (wall, each) = round(&reports).await;
        if seq > 3 {
            walls.push(wall);
            match restates {
                true => restating.extend(each),
                false => steady.extend(each),
            }
        }
    }
    let median = |mut timings: Vec<std::time::Duration>| {
        timings.sort();
        timings[timings.len() / 2]
    };
    let max_wall = walls.iter().max().copied().unwrap_or_default();
    println!(
        "{nodes} nodes x {count} sandboxes, reconciling together: one node's reconcile median \
         {:?} unchanged, {:?} with a sixth restated; a round of all {nodes} at most {max_wall:?}",
        median(steady),
        median(restating),
    );
    for report in &reports {
        for sandbox in &report.sandboxes {
            store.remove_placement(&sandbox.id).await.unwrap();
        }
    }
    let epoch = store.leader_epoch().await.unwrap();
    for report in &reports {
        store
            .write_off_node(&report.node.id, i64::MAX, epoch, |_| None)
            .await
            .unwrap();
    }
}
