//! The usage ledger.
//!
//! One writer, on the leader, consumes every node's event log in that node's
//! order and appends an interval each time a sandbox leaves a state or a
//! shape. The usage inside an interval is the difference of the totals on the
//! two readings that bound it, never a sum of samples, so a replayed event
//! changes nothing and a missing one moves a boundary without changing the
//! amount.
//!
//! Open intervals carry the latest totals a heartbeat reported. Those are
//! what an hourly checkpoint closes an interval with, so a long one is
//! visible before it ends, and what a node's write-off closes it with, so no
//! time after the node went silent is attributed to anyone.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use burrow_proto::api::v1 as api;
use burrow_proto::common::v1::SandboxState;
use burrow_store::{EventRow, OpenUsageChange, OpenUsageRow, Store, UsageCommit, UsageRow};

use crate::OrchestratorState;

pub const RUNNING: &str = "running";
pub const SUSPENDED: &str = "suspended";
pub const STOPPED: &str = "stopped";

pub const CLOSED_BY_CHECKPOINT: &str = "checkpoint";
pub const CLOSED_BY_WRITE_OFF: &str = "write_off";
pub const CLOSED_BY_VANISHED: &str = "vanished";

/// How long an open interval's sandbox may go unreported by any heartbeat,
/// and unplaced, before it is taken to be gone without a `destroyed`. A
/// backstop: a node logs `destroyed` for every sandbox it loses, so this only
/// closes what a lost event or a node's lost store left open.
const VANISHED_AFTER_MS: i64 = 120_000;

/// The detail of an event a node logs for a VM it found gone on restart. Its
/// totals are the last the node wrote down, which a heartbeat may have
/// passed, and the VM stopped somewhere after that heartbeat.
const DETAIL_LOST: &str = "lost";

const HOUR_MS: i64 = 3_600_000;
const BATCH: usize = 500;

/// What an event does to the state a sandbox is counted in.
enum Effect {
    Enter(&'static str),
    End,
    Keep,
}

fn counted(state: i32) -> Option<&'static str> {
    match SandboxState::try_from(state).unwrap_or_default() {
        SandboxState::Creating | SandboxState::Running => Some(RUNNING),
        SandboxState::Paused | SandboxState::Suspended => Some(SUSPENDED),
        // A failed sandbox is one a node kept on disk and could not run.
        SandboxState::Stopped | SandboxState::Failed => Some(STOPPED),
        _ => None,
    }
}

fn effect(event: &EventRow) -> Effect {
    match event.kind.as_str() {
        "created" | "started" | "agent_ready" => Effect::Enter(RUNNING),
        // The VM of a sandbox being deleted; `destroyed` follows at once.
        "stopped" if event.detail == "deleted" => Effect::Keep,
        "stopped" => Effect::Enter(match counted(event.state) {
            Some(SUSPENDED) => SUSPENDED,
            _ => STOPPED,
        }),
        "destroyed" => Effect::End,
        // A node's restart reporting each sandbox it holds, in the state it
        // found it.
        "recovered" => counted(event.state).map_or(Effect::Keep, Effect::Enter),
        _ => Effect::Keep,
    }
}

/// Only an event that puts a sandbox on a node can move it there: a node that
/// lets go of a sandbox another node adopted reports that after the adoption.
fn places(event: &EventRow) -> bool {
    matches!(event.kind.as_str(), "created" | "started" | "agent_ready")
}

fn open_at(event: &EventRow, state: &str) -> OpenUsageRow {
    OpenUsageRow {
        sandbox_id: event.sandbox_id.clone(),
        node_id: event.node_id.clone(),
        template: event.template.clone(),
        metadata_json: event.metadata_json.clone(),
        state: state.to_string(),
        vcpus: event.vcpus,
        mem_mib: event.mem_mib,
        started_at_ms: event.at_unix_ms,
        cpu_usage_usec: event.cpu_usage_usec,
        rx_bytes: event.rx_bytes,
        tx_bytes: event.tx_bytes,
        seen_at_ms: event.at_unix_ms,
        seen_cpu_usage_usec: event.cpu_usage_usec,
        seen_rx_bytes: event.rx_bytes,
        seen_tx_bytes: event.tx_bytes,
    }
}

/// Closes `open` at `at` with the totals read then.
fn close(open: &OpenUsageRow, at: i64, totals: (u64, u64, u64), closed_by: &str) -> UsageRow {
    UsageRow {
        id: 0,
        sandbox_id: open.sandbox_id.clone(),
        node_id: open.node_id.clone(),
        template: open.template.clone(),
        metadata_json: open.metadata_json.clone(),
        state: open.state.clone(),
        vcpus: open.vcpus,
        mem_mib: open.mem_mib,
        started_at_ms: open.started_at_ms,
        ended_at_ms: at.max(open.started_at_ms),
        cpu_usage_usec: totals.0.saturating_sub(open.cpu_usage_usec),
        rx_bytes: totals.1.saturating_sub(open.rx_bytes),
        tx_bytes: totals.2.saturating_sub(open.tx_bytes),
        closed_by: closed_by.to_string(),
    }
}

fn seen(open: &OpenUsageRow) -> (u64, u64, u64) {
    (
        open.seen_cpu_usage_usec,
        open.seen_rx_bytes,
        open.seen_tx_bytes,
    )
}

/// One event applied to a sandbox's open interval: the row it closed, if
/// any, and the open interval after it.
pub fn advance(
    open: Option<&OpenUsageRow>,
    event: &EventRow,
) -> (Option<UsageRow>, Option<OpenUsageRow>) {
    let effect = effect(event);
    let Some(open) = open else {
        let state = match effect {
            Effect::Enter(state) => Some(state),
            Effect::Keep => counted(event.state),
            Effect::End => None,
        };
        return (None, state.map(|state| open_at(event, state)));
    };
    // Older than the interval it would close, or from a node the sandbox has
    // left: a replay or a late report, which moves nothing.
    if event.at_unix_ms < open.started_at_ms || (event.node_id != open.node_id && !places(event)) {
        return (None, Some(open.clone()));
    }
    let next_state = match effect {
        Effect::Enter(state) => Some(state),
        Effect::Keep => Some(open.state.as_str()),
        Effect::End => None,
    };
    let unchanged = next_state == Some(open.state.as_str())
        && event.node_id == open.node_id
        && event.vcpus == open.vcpus
        && event.mem_mib == open.mem_mib;
    if unchanged {
        let mut open = open.clone();
        if event.at_unix_ms >= open.seen_at_ms {
            open.seen_at_ms = event.at_unix_ms;
            open.seen_cpu_usage_usec = event.cpu_usage_usec;
            open.seen_rx_bytes = event.rx_bytes;
            open.seen_tx_bytes = event.tx_bytes;
        }
        return (None, Some(open));
    }
    let (at, totals) = if event.detail == DETAIL_LOST {
        let seen = seen(open);
        (
            open.seen_at_ms,
            (
                event.cpu_usage_usec.max(seen.0),
                event.rx_bytes.max(seen.1),
                event.tx_bytes.max(seen.2),
            ),
        )
    } else {
        (
            event.at_unix_ms,
            (event.cpu_usage_usec, event.rx_bytes, event.tx_bytes),
        )
    };
    let row = close(open, at, totals, &event.kind);
    (Some(row), next_state.map(|state| open_at(event, state)))
}

/// Splits an open interval at its latest heartbeat once that heartbeat is in
/// a later hour than the interval began.
pub fn checkpoint(open: &OpenUsageRow) -> Option<(UsageRow, OpenUsageRow)> {
    if open.seen_at_ms.div_euclid(HOUR_MS) <= open.started_at_ms.div_euclid(HOUR_MS) {
        return None;
    }
    let row = close(open, open.seen_at_ms, seen(open), CLOSED_BY_CHECKPOINT);
    let next = OpenUsageRow {
        started_at_ms: open.seen_at_ms,
        cpu_usage_usec: open.seen_cpu_usage_usec,
        rx_bytes: open.seen_rx_bytes,
        tx_bytes: open.seen_tx_bytes,
        ..open.clone()
    };
    Some((row, next))
}

/// Closes an open interval at the last heartbeat that reported it.
pub fn write_off(open: &OpenUsageRow) -> UsageRow {
    close(open, open.seen_at_ms, seen(open), CLOSED_BY_WRITE_OFF)
}

/// Consumes one batch of a node's log after `after`, moving its cursor on
/// from `cursor`. Returns whether there may be more.
async fn drain_batch(
    store: &Store,
    node_id: &str,
    cursor: u64,
    after: u64,
) -> burrow_store::Result<bool> {
    let events = store.list_node_events(node_id, after, BATCH).await?;
    let Some(last) = events.last().map(|event| event.node_seq) else {
        return Ok(false);
    };
    // Each touched sandbox's interval as stored, and as this batch leaves it.
    let mut touched: HashMap<String, (Option<OpenUsageRow>, Option<OpenUsageRow>)> = HashMap::new();
    let mut rows = Vec::new();
    for event in &events {
        if !touched.contains_key(&event.sandbox_id) {
            let stored = store.open_usage(&event.sandbox_id).await?;
            touched.insert(event.sandbox_id.clone(), (stored.clone(), stored));
        }
        let (_, current) = touched.get_mut(&event.sandbox_id).expect("inserted above");
        let (row, next) = advance(current.as_ref(), event);
        rows.extend(row);
        *current = next;
    }
    let changes = touched
        .into_iter()
        .filter(|(_, (stored, current))| stored != current)
        .map(|(sandbox_id, (stored, next))| OpenUsageChange {
            sandbox_id,
            expected: stored.map(|open| open.started_at_ms),
            next,
        })
        .collect();
    let committed = store
        .commit_usage(&UsageCommit {
            cursor: Some((node_id.to_string(), cursor, last)),
            rows,
            changes,
        })
        .await?;
    if !committed {
        tracing::debug!(node_id, "another writer moved the ledger; re-reading");
    }
    Ok(true)
}

/// Consumes a node's log. The ledger of a node starts at its first event
/// with a shape: a node from before events carried one logged none, and
/// counting its history at zero vCPUs and memory would be wrong rather than
/// missing.
async fn drain(store: &Store, node_id: &str) -> burrow_store::Result<()> {
    loop {
        let cursor = store
            .usage_cursors()
            .await?
            .into_iter()
            .find(|(id, _)| id == node_id)
            .map(|(_, seq)| seq);
        let after = match cursor {
            Some(seq) => seq,
            None => match store.first_shaped_event(node_id).await? {
                Some(seq) => seq - 1,
                None => return Ok(()),
            },
        };
        if !drain_batch(store, node_id, cursor.unwrap_or(0), after).await? {
            return Ok(());
        }
    }
}

/// Every node the fleet knows, and every node the ledger ever read from,
/// which covers a node written off with events still unread.
async fn drain_all(store: &Store) -> burrow_store::Result<()> {
    let mut nodes: HashSet<String> = store
        .usage_cursors()
        .await?
        .into_iter()
        .map(|(node_id, _)| node_id)
        .collect();
    nodes.extend(store.list_nodes().await?.into_iter().map(|row| row.id));
    for node_id in nodes {
        drain(store, &node_id).await?;
    }
    Ok(())
}

/// Checkpoints long intervals and closes those whose sandbox is gone.
async fn sweep_open(
    state: &OrchestratorState,
    store: &Store,
) -> burrow_store::Result<(usize, usize)> {
    let (mut split, mut vanished) = (0, 0);
    let now = crate::registry::unix_ms();
    for open in store.list_open_usage(None).await? {
        let (row, next) = if let Some((row, next)) = checkpoint(&open) {
            (row, Some(next))
        } else if open.seen_at_ms < now - VANISHED_AFTER_MS
            && state.sandboxes.get(&open.sandbox_id).is_none()
            && store.get_placement(&open.sandbox_id).await?.is_none()
        {
            (
                close(&open, open.seen_at_ms, seen(&open), CLOSED_BY_VANISHED),
                None,
            )
        } else {
            continue;
        };
        let is_split = next.is_some();
        let committed = store
            .commit_usage(&UsageCommit {
                cursor: None,
                rows: vec![row],
                changes: vec![OpenUsageChange {
                    sandbox_id: open.sandbox_id.clone(),
                    expected: Some(open.started_at_ms),
                    next,
                }],
            })
            .await?;
        match (committed, is_split) {
            (true, true) => split += 1,
            (true, false) => vanished += 1,
            _ => {}
        }
    }
    Ok((split, vanished))
}

/// Closes every open interval on a node being written off, after consuming
/// whatever of its log is not in the ledger yet.
pub async fn write_off_node(state: &OrchestratorState, node_id: &str) {
    let Some(store) = &state.store else {
        return;
    };
    let result = async {
        drain(store, node_id).await?;
        let mut closed = 0;
        for open in store.list_open_usage(Some(node_id)).await? {
            closed += store
                .commit_usage(&UsageCommit {
                    cursor: None,
                    rows: vec![write_off(&open)],
                    changes: vec![OpenUsageChange {
                        sandbox_id: open.sandbox_id.clone(),
                        expected: Some(open.started_at_ms),
                        next: None,
                    }],
                })
                .await? as usize;
        }
        burrow_store::Result::Ok(closed)
    }
    .await;
    match result {
        Ok(0) => {}
        Ok(closed) => tracing::warn!(
            node_id,
            closed,
            "closed open usage intervals at the node's last heartbeat"
        ),
        Err(err) => tracing::error!(node_id, %err, "could not write off the node's usage"),
    }
}

/// Runs the ledger writer while this replica leads.
pub async fn run(state: Arc<OrchestratorState>) {
    let Some(store) = state.store.clone() else {
        return;
    };
    let mut events = state.events.subscribe();
    let mut last_checkpoint = tokio::time::Instant::now();
    loop {
        state.leader.wait().await;
        if let Err(err) = drain_all(&store).await {
            tracing::warn!(%err, "the usage ledger could not consume the event log");
        }
        if last_checkpoint.elapsed() >= Duration::from_secs(60) {
            last_checkpoint = tokio::time::Instant::now();
            match sweep_open(&state, &store).await {
                Ok((0, 0)) => {}
                Ok((split, vanished)) => {
                    tracing::info!(
                        split,
                        vanished,
                        "checkpointed or closed open usage intervals"
                    )
                }
                Err(err) => tracing::warn!(%err, "could not sweep open usage intervals"),
            }
        }
        // Woken by an event pushed here; events pushed to another replica
        // wait for the tick.
        let _ = tokio::time::timeout(Duration::from_secs(1), events.recv()).await;
    }
}

const PAGE: u32 = 5_000;

type Tags = HashMap<String, String>;

fn tags(metadata_json: &str) -> Tags {
    serde_json::from_str(metadata_json).unwrap_or_default()
}

/// The stretch since an open interval began, up to its last reading, as a
/// row of its own.
fn so_far(open: &OpenUsageRow) -> UsageRow {
    close(open, open.seen_at_ms, seen(open), "")
}

fn to_proto(row: UsageRow, is_open: bool) -> api::UsageInterval {
    api::UsageInterval {
        id: row.id,
        metadata: tags(&row.metadata_json),
        sandbox_id: row.sandbox_id,
        node_id: row.node_id,
        template: row.template,
        state: row.state,
        vcpus: row.vcpus,
        mem_mib: row.mem_mib,
        started_at_unix_ms: row.started_at_ms,
        ended_at_unix_ms: row.ended_at_ms,
        cpu_usage_usec: row.cpu_usage_usec,
        rx_bytes: row.rx_bytes,
        tx_bytes: row.tx_bytes,
        closed_by: row.closed_by,
        is_open,
    }
}

fn group_of(interval: &api::UsageInterval, group_by: &str) -> String {
    match group_by {
        "sandbox" => interval.sandbox_id.clone(),
        "template" => interval.template.clone(),
        "node" => interval.node_id.clone(),
        "state" => interval.state.clone(),
        tag => interval.metadata.get(tag).cloned().unwrap_or_default(),
    }
}

/// Answers `QueryUsage`. `sandbox` is already resolved to an id.
pub async fn query(
    store: &Store,
    req: &api::QueryUsageRequest,
    sandbox: Option<String>,
) -> burrow_store::Result<api::QueryUsageResponse> {
    let window = |at: i64| {
        (req.from_unix_ms == 0 || at >= req.from_unix_ms)
            && (req.to_unix_ms == 0 || at < req.to_unix_ms)
    };
    let tagged = |metadata: &Tags| req.tags.iter().all(|(k, v)| metadata.get(k) == Some(v));
    let mut filter = burrow_store::UsageFilter {
        from_ms: (req.from_unix_ms != 0).then_some(req.from_unix_ms),
        to_ms: (req.to_unix_ms != 0).then_some(req.to_unix_ms),
        sandbox_id: sandbox.clone(),
        after_id: req.after_id,
        limit: match req.limit {
            0 => 1_000,
            limit => limit.min(PAGE),
        },
    };
    let is_summed = !req.group_by.is_empty();
    if is_summed {
        filter.limit = PAGE;
    }
    // Summed page by page, so a month of a fleet is never held at once.
    let mut sums: std::collections::BTreeMap<(String, String), api::UsageSum> = Default::default();
    let mut add = |interval: &api::UsageInterval| {
        let key = (group_of(interval, &req.group_by), interval.state.clone());
        let sum = sums.entry(key.clone()).or_insert_with(|| api::UsageSum {
            group: key.0,
            state: key.1,
            ..Default::default()
        });
        let duration = (interval.ended_at_unix_ms - interval.started_at_unix_ms).max(0) as u64;
        sum.intervals += 1;
        sum.duration_ms += duration;
        sum.vcpu_ms += duration * interval.vcpus as u64;
        sum.mem_mib_ms += duration * interval.mem_mib as u64;
        sum.cpu_usage_usec += interval.cpu_usage_usec;
        sum.rx_bytes += interval.rx_bytes;
        sum.tx_bytes += interval.tx_bytes;
    };
    let mut intervals = Vec::new();
    let mut next_after_id = 0;
    loop {
        let page = store.list_usage(&filter).await?;
        let full = page.len() == filter.limit as usize;
        let last = page.last().map(|row| row.id);
        for interval in page.into_iter().map(|row| to_proto(row, false)) {
            if !tagged(&interval.metadata) {
                continue;
            }
            if is_summed {
                add(&interval);
            } else {
                intervals.push(interval);
            }
        }
        match last {
            Some(last) if full && is_summed => filter.after_id = last,
            Some(last) if full => {
                next_after_id = last;
                break;
            }
            _ => break,
        }
    }
    if req.is_open_included && req.after_id == 0 {
        for open in store.list_open_usage(None).await? {
            if sandbox.as_ref().is_some_and(|id| id != &open.sandbox_id)
                || !window(open.started_at_ms)
            {
                continue;
            }
            let interval = to_proto(so_far(&open), true);
            if !tagged(&interval.metadata) {
                continue;
            }
            if is_summed {
                add(&interval);
            } else {
                intervals.push(interval);
            }
        }
    }
    Ok(api::QueryUsageResponse {
        intervals,
        sums: sums.into_values().collect(),
        next_after_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, state: SandboxState, at: i64, cpu: u64, rx: u64) -> EventRow {
        EventRow {
            node_id: "node_a".into(),
            at_unix_ms: at,
            sandbox_id: "sbx_1".into(),
            kind: kind.into(),
            state: state as i32,
            template: "alpine".into(),
            metadata_json: r#"{"team":"search"}"#.into(),
            cpu_usage_usec: cpu,
            rx_bytes: rx,
            tx_bytes: rx / 2,
            vcpus: 2,
            mem_mib: 2048,
            ..Default::default()
        }
    }

    /// Feeds events through, returning the rows closed and what stays open.
    fn replay(events: &[EventRow]) -> (Vec<UsageRow>, Option<OpenUsageRow>) {
        let mut open = None;
        let mut rows = Vec::new();
        for event in events {
            let (row, next) = advance(open.as_ref(), event);
            rows.extend(row);
            open = next;
        }
        (rows, open)
    }

    fn life() -> Vec<EventRow> {
        use SandboxState::*;
        vec![
            event("created", Running, 1_000, 0, 0),
            event("started", Running, 1_010, 10, 0),
            event("agent_ready", Running, 1_200, 50, 100),
            event("stopped", Suspended, 60_000, 30_000_000, 5_000),
            event("started", Running, 120_000, 30_000_000, 5_000),
            EventRow {
                detail: "deleted".into(),
                ..event("stopped", Running, 150_000, 40_000_000, 9_000)
            },
            event("destroyed", Running, 150_005, 40_000_000, 9_000),
        ]
    }

    fn sums(rows: &[UsageRow]) -> (u64, u64, u64, i64) {
        rows.iter().fold((0, 0, 0, 0), |acc, row| {
            (
                acc.0 + row.cpu_usage_usec,
                acc.1 + row.rx_bytes,
                acc.2 + row.tx_bytes,
                acc.3 + (row.ended_at_ms - row.started_at_ms),
            )
        })
    }

    #[test]
    fn a_life_becomes_one_row_per_state() {
        let (rows, open) = replay(&life());
        assert!(open.is_none());
        let states: Vec<_> = rows.iter().map(|row| row.state.as_str()).collect();
        assert_eq!(states, [RUNNING, SUSPENDED, RUNNING]);
        assert_eq!(rows[0].started_at_ms, 1_000);
        assert_eq!(rows[0].ended_at_ms, 60_000);
        assert_eq!(rows[0].cpu_usage_usec, 30_000_000);
        assert_eq!(rows[1].cpu_usage_usec, 0);
        assert_eq!(rows[2].cpu_usage_usec, 10_000_000);
        assert_eq!(rows[2].closed_by, "destroyed");
        assert_eq!(rows[0].metadata_json, r#"{"team":"search"}"#);
        assert_eq!(sums(&rows), (40_000_000, 9_000, 4_500, 149_005));
    }

    #[test]
    fn a_replayed_event_changes_nothing() {
        let mut events = life();
        events.insert(4, events[2].clone());
        events.insert(6, events[3].clone());
        assert_eq!(replay(&events), replay(&life()));
    }

    #[test]
    fn a_missing_event_moves_a_boundary_and_not_the_amount() {
        let full = replay(&life()).0;
        let mut events = life();
        // The suspend never arrived: the first running interval runs on
        // through the resume, and the suspended one is gone.
        events.remove(3);
        let (rows, _) = replay(&events);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ended_at_ms, 150_005);
        let (cpu, rx, tx, duration) = sums(&rows);
        let (full_cpu, full_rx, full_tx, full_duration) = sums(&full);
        assert_eq!(
            (cpu, rx, tx, duration),
            (full_cpu, full_rx, full_tx, full_duration)
        );
    }

    #[test]
    fn a_late_report_from_a_node_the_sandbox_left_moves_nothing() {
        use SandboxState::*;
        let mut adopted = event("started", Running, 2_000, 500, 0);
        adopted.node_id = "node_b".into();
        let released = event("stopped", Suspended, 3_000, 400, 0);
        let (rows, open) = replay(&[
            event("stopped", Suspended, 1_000, 400, 0),
            adopted,
            released,
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, SUSPENDED);
        let open = open.unwrap();
        assert_eq!(
            (open.node_id.as_str(), open.state.as_str()),
            ("node_b", RUNNING)
        );
    }

    #[test]
    fn a_checkpoint_splits_at_the_heartbeat_without_changing_the_sum() {
        let start = 10 * HOUR_MS + 1_000;
        let (_, open) = replay(&[event("started", SandboxState::Running, start, 100, 10)]);
        let mut open = open.unwrap();
        open.seen_at_ms = start + 1_000;
        open.seen_cpu_usage_usec = 900;
        assert!(checkpoint(&open).is_none(), "same hour");
        open.seen_at_ms = 11 * HOUR_MS + 2_000;
        open.seen_cpu_usage_usec = 5_000;
        open.seen_rx_bytes = 70;
        let (row, next) = checkpoint(&open).unwrap();
        assert_eq!(row.closed_by, CLOSED_BY_CHECKPOINT);
        assert_eq!(
            (row.started_at_ms, row.ended_at_ms),
            (start, 11 * HOUR_MS + 2_000)
        );
        assert_eq!((row.cpu_usage_usec, row.rx_bytes), (4_900, 60));
        assert_eq!(next.started_at_ms, row.ended_at_ms);
        let (closed, _) = advance(
            Some(&next),
            &event("destroyed", SandboxState::Running, 12 * HOUR_MS, 8_000, 100),
        );
        let closed = closed.unwrap();
        assert_eq!((closed.cpu_usage_usec, closed.rx_bytes), (3_000, 30));
        assert_eq!(row.cpu_usage_usec + closed.cpu_usage_usec, 8_000 - 100);
    }

    #[test]
    fn a_write_off_closes_at_the_last_heartbeat() {
        let (_, open) = replay(&[event("started", SandboxState::Running, 1_000, 0, 0)]);
        let mut open = open.unwrap();
        open.seen_at_ms = 41_000;
        open.seen_cpu_usage_usec = 7_000_000;
        open.seen_rx_bytes = 300;
        let row = write_off(&open);
        assert_eq!(row.closed_by, CLOSED_BY_WRITE_OFF);
        assert_eq!((row.started_at_ms, row.ended_at_ms), (1_000, 41_000));
        assert_eq!((row.cpu_usage_usec, row.rx_bytes), (7_000_000, 300));
    }

    #[tokio::test]
    async fn the_writer_consumes_a_log_once_and_resumes() {
        let store = Store::open_in_memory().await.unwrap();
        for (i, event) in life().into_iter().enumerate() {
            let row = EventRow {
                node_seq: i as u64 + 1,
                ..event
            };
            store.append_event(&row).await.unwrap();
            if i == 3 {
                drain(&store, "node_a").await.unwrap();
                let open = store.open_usage("sbx_1").await.unwrap().unwrap();
                assert_eq!(open.state, SUSPENDED);
            }
        }
        drain(&store, "node_a").await.unwrap();
        drain(&store, "node_a").await.unwrap();
        let rows = store
            .list_usage(&burrow_store::UsageFilter {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        let expected = replay(&life()).0;
        assert_eq!(rows.len(), expected.len());
        assert_eq!(sums(&rows), sums(&expected));
        assert!(store.open_usage("sbx_1").await.unwrap().is_none());
        // A writer that read a stale cursor is refused rather than doubling.
        let stale = UsageCommit {
            cursor: Some(("node_a".into(), 3, 7)),
            rows: expected.clone(),
            changes: Vec::new(),
        };
        assert!(!store.commit_usage(&stale).await.unwrap());
    }

    /// A node that lost a VM on restart reports it from the totals it last
    /// wrote down, which heartbeats had passed, and long after it died.
    #[test]
    fn a_lost_vm_closes_at_its_last_heartbeat_with_what_that_heartbeat_saw() {
        let (_, open) = replay(&[event("started", SandboxState::Running, 1_000, 100, 0)]);
        let mut open = open.unwrap();
        open.seen_at_ms = 50_000;
        open.seen_cpu_usage_usec = 9_000;
        open.seen_rx_bytes = 70;
        let lost = EventRow {
            detail: DETAIL_LOST.into(),
            ..event("stopped", SandboxState::Stopped, 900_000, 100, 0)
        };
        let (row, next) = advance(Some(&open), &lost);
        let row = row.unwrap();
        assert_eq!((row.started_at_ms, row.ended_at_ms), (1_000, 50_000));
        assert_eq!((row.cpu_usage_usec, row.rx_bytes), (8_900, 70));
        let next = next.unwrap();
        assert_eq!(
            (next.state.as_str(), next.started_at_ms),
            (STOPPED, 900_000)
        );
        // The node's totals go on from what it wrote down.
        let (row, _) = advance(
            Some(&next),
            &event("started", SandboxState::Running, 950_000, 100, 0),
        );
        assert_eq!(row.unwrap().cpu_usage_usec, 0);
    }

    /// A sandbox suspended across an upgrade logged nothing with a shape
    /// until it was next used; a node's restart now reports it.
    #[test]
    fn a_recovered_event_opens_what_the_ledger_did_not_know_and_keeps_what_it_did() {
        let recovered = |state| event("recovered", state, 5_000, 300, 10);
        let (rows, open) = replay(&[recovered(SandboxState::Suspended)]);
        assert!(rows.is_empty());
        assert_eq!(open.unwrap().state, SUSPENDED);
        let (rows, open) = replay(&[
            event("stopped", SandboxState::Suspended, 1_000, 300, 10),
            recovered(SandboxState::Suspended),
        ]);
        assert!(rows.is_empty());
        assert_eq!(open.unwrap().started_at_ms, 1_000);
        // A failed sandbox holds its disk, as a stopped one does.
        let (rows, open) = replay(&[
            event("stopped", SandboxState::Suspended, 1_000, 300, 10),
            recovered(SandboxState::Failed),
        ]);
        assert_eq!(rows[0].state, SUSPENDED);
        assert_eq!(open.unwrap().state, STOPPED);
    }

    /// Events from before a node logged shapes are not turned into intervals
    /// at zero vCPUs and memory: that node's ledger starts at its first
    /// event with one.
    #[tokio::test]
    async fn a_nodes_ledger_starts_at_its_first_shaped_event() {
        let store = Store::open_in_memory().await.unwrap();
        let shapeless = |seq, kind, at| EventRow {
            node_seq: seq,
            vcpus: 0,
            mem_mib: 0,
            ..event(kind, SandboxState::Running, at, 0, 0)
        };
        for row in [
            shapeless(1, "created", 1_000),
            shapeless(2, "stopped", 2_000),
            shapeless(3, "started", 3_000),
        ] {
            store.append_event(&row).await.unwrap();
        }
        drain(&store, "node_a").await.unwrap();
        assert!(store.usage_cursors().await.unwrap().is_empty());
        assert!(store.open_usage("sbx_1").await.unwrap().is_none());

        for (seq, kind, state, at) in [
            (4, "recovered", SandboxState::Suspended, 4_000),
            (5, "started", SandboxState::Running, 5_000),
        ] {
            store
                .append_event(&EventRow {
                    node_seq: seq,
                    ..event(kind, state, at, 0, 0)
                })
                .await
                .unwrap();
        }
        drain(&store, "node_a").await.unwrap();
        let rows = store
            .list_usage(&burrow_store::UsageFilter {
                limit: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].state.as_str(), rows[0].started_at_ms, rows[0].vcpus),
            (SUSPENDED, 4_000, 2)
        );
        assert_eq!(
            store.usage_cursors().await.unwrap(),
            [("node_a".to_string(), 5)]
        );
    }

    #[tokio::test]
    async fn sums_cover_closed_and_open_intervals_of_the_tagged_sandboxes() {
        let store = Store::open_in_memory().await.unwrap();
        for (i, event) in life().into_iter().take(5).enumerate() {
            store
                .append_event(&EventRow {
                    node_seq: i as u64 + 1,
                    ..event
                })
                .await
                .unwrap();
        }
        drain(&store, "node_a").await.unwrap();
        let query = |is_open_included, tags: &[(&str, &str)]| api::QueryUsageRequest {
            group_by: "team".into(),
            is_open_included,
            tags: tags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..Default::default()
        };
        let sums = super::query(&store, &query(false, &[]), None)
            .await
            .unwrap()
            .sums;
        assert_eq!(sums.len(), 2);
        let running = sums.iter().find(|sum| sum.state == RUNNING).unwrap();
        assert_eq!(
            (
                running.group.as_str(),
                running.intervals,
                running.duration_ms
            ),
            ("search", 1, 59_000)
        );
        assert_eq!(running.vcpu_ms, 2 * 59_000);
        let with_open = super::query(&store, &query(true, &[("team", "search")]), None)
            .await
            .unwrap()
            .sums;
        let running = with_open.iter().find(|sum| sum.state == RUNNING).unwrap();
        assert_eq!(running.intervals, 2);
        let none = super::query(&store, &query(true, &[("team", "other")]), None)
            .await
            .unwrap();
        assert!(none.sums.is_empty());
    }

    #[tokio::test]
    async fn heartbeats_feed_the_write_off() {
        let store = Store::open_in_memory().await.unwrap();
        let started = EventRow {
            node_seq: 1,
            ..event("started", SandboxState::Running, 1_000, 100, 0)
        };
        store.append_event(&started).await.unwrap();
        drain(&store, "node_a").await.unwrap();
        let beat = |at, cpu| (at, vec![("sbx_1".to_string(), cpu, 50u64, 25u64)]);
        let (at, totals) = beat(6_000, 2_100);
        store.observe_usage("node_a", at, &totals).await.unwrap();
        // An older beat, or one about another node, does not move the reading.
        let (at, totals) = beat(5_000, 9_999);
        store.observe_usage("node_a", at, &totals).await.unwrap();
        store.observe_usage("node_b", 7_000, &totals).await.unwrap();
        let open = store.list_open_usage(Some("node_a")).await.unwrap();
        let row = write_off(&open[0]);
        assert_eq!(
            (row.ended_at_ms, row.cpu_usage_usec, row.rx_bytes),
            (6_000, 2_000, 50)
        );
    }
}
