//! Which node holds which snapshot.
//!
//! A snapshot encodes host cpu features and the exact Firecracker version, so
//! it can only be restored where it was taken. That makes it node-local like a
//! template, and makes this table the thing that decides where a create from a
//! snapshot is placed.
//!
//! In memory only, deliberately: a snapshot is a directory a node can list, and
//! every node lists its snapshots when it registers. The node is the authority,
//! so a restart re-learns rather than remembers.

use std::collections::HashMap;
use std::sync::Mutex;

use burrow_proto::common::v1 as common;

#[derive(Default)]
pub struct SnapshotRegistry {
    snapshots: Mutex<HashMap<String, common::Snapshot>>,
}

impl SnapshotRegistry {
    /// Records a snapshot a node reported, stamped with the node holding it.
    pub fn insert(&self, node_id: &str, mut snapshot: common::Snapshot) {
        // The node cannot know its own id in a record it built for itself.
        snapshot.node_id = node_id.to_string();
        self.snapshots
            .lock()
            .unwrap()
            .insert(snapshot.id.clone(), snapshot);
    }

    pub fn get(&self, id: &str) -> Option<common::Snapshot> {
        self.snapshots.lock().unwrap().get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> Option<common::Snapshot> {
        self.snapshots.lock().unwrap().remove(id)
    }

    /// Every snapshot, newest first, optionally only one sandbox's.
    pub fn list(&self, sandbox_id: Option<&str>) -> Vec<common::Snapshot> {
        let mut out: Vec<_> = self
            .snapshots
            .lock()
            .unwrap()
            .values()
            .filter(|snapshot| sandbox_id.is_none_or(|id| snapshot.sandbox_id == id))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
        out
    }

    /// Replaces everything recorded against a node with what it reports.
    ///
    /// Called when a node registers, for the same reason sandboxes are
    /// reconciled then: the node owns its snapshots, and this table is a cache
    /// that an orchestrator restart rebuilds from the fleet.
    pub fn reconcile_node(&self, node_id: &str, reported: Vec<common::Snapshot>) -> usize {
        let mut snapshots = self.snapshots.lock().unwrap();
        snapshots.retain(|_, snapshot| snapshot.node_id != node_id);
        for mut snapshot in reported {
            snapshot.node_id = node_id.to_string();
            snapshots.insert(snapshot.id.clone(), snapshot);
        }
        snapshots
            .values()
            .filter(|snapshot| snapshot.node_id == node_id)
            .count()
    }

    /// Forgets snapshots a node no longer lists, returning how many.
    ///
    /// Nodes sweep expired snapshots and evict old ones under retention without
    /// being asked, so a heartbeat is the only place the orchestrator learns
    /// that a snapshot it still lists no longer exists.
    ///
    /// An empty report is not read as an empty node: one that has just started
    /// may not have scanned its store yet.
    pub fn apply_report(&self, node_id: &str, reported: &[String]) -> usize {
        if reported.is_empty() {
            return 0;
        }
        let held: std::collections::HashSet<&str> = reported.iter().map(String::as_str).collect();
        let mut snapshots = self.snapshots.lock().unwrap();
        let before = snapshots.len();
        snapshots.retain(|id, snapshot| snapshot.node_id != node_id || held.contains(id.as_str()));
        before - snapshots.len()
    }

    /// Drops every snapshot recorded against a node written off entirely.
    pub fn forget_node(&self, node_id: &str) {
        self.snapshots
            .lock()
            .unwrap()
            .retain(|_, snapshot| snapshot.node_id != node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(id: &str, sandbox: &str, created_at: &str) -> common::Snapshot {
        common::Snapshot {
            id: id.into(),
            sandbox_id: sandbox.into(),
            template: "default".into(),
            created_at: created_at.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_snapshot_is_recorded_against_the_node_holding_it() {
        let registry = SnapshotRegistry::default();
        registry.insert("node1", snapshot("snap_a", "sbx_a", "2026-09-01T00:00:00Z"));
        assert_eq!(registry.get("snap_a").unwrap().node_id, "node1");
        assert!(registry.get("snap_missing").is_none());
    }

    #[test]
    fn listing_is_newest_first_and_filterable_by_sandbox() {
        let registry = SnapshotRegistry::default();
        registry.insert("node1", snapshot("snap_a", "sbx_a", "2026-09-01T00:00:00Z"));
        registry.insert("node1", snapshot("snap_b", "sbx_a", "2026-09-03T00:00:00Z"));
        registry.insert("node2", snapshot("snap_c", "sbx_b", "2026-09-02T00:00:00Z"));

        let ids: Vec<String> = registry.list(None).into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["snap_b", "snap_c", "snap_a"]);
        assert_eq!(registry.list(Some("sbx_a")).len(), 2);
        assert!(registry.list(Some("sbx_missing")).is_empty());
    }

    /// The node swept it; continuing to list it would offer a create a
    /// snapshot that is not there.
    #[test]
    fn a_snapshot_the_node_no_longer_holds_is_forgotten() {
        let registry = SnapshotRegistry::default();
        registry.insert(
            "node1",
            snapshot("snap_gone", "sbx_a", "2026-09-01T00:00:00Z"),
        );
        registry.insert(
            "node1",
            snapshot("snap_kept", "sbx_a", "2026-09-02T00:00:00Z"),
        );
        registry.insert(
            "node2",
            snapshot("snap_other", "sbx_b", "2026-09-02T00:00:00Z"),
        );

        assert_eq!(
            registry.apply_report("node1", &["snap_kept".to_string()]),
            1
        );
        assert!(registry.get("snap_gone").is_none());
        assert!(registry.get("snap_kept").is_some());
        assert!(
            registry.get("snap_other").is_some(),
            "one node's report says nothing about another's"
        );

        // A node that has not scanned its store yet reports nothing, which is
        // not the same claim as holding nothing.
        assert_eq!(registry.apply_report("node1", &[]), 0);
        assert!(registry.get("snap_kept").is_some());
    }

    #[test]
    fn reconciling_replaces_a_nodes_records() {
        let registry = SnapshotRegistry::default();
        registry.insert(
            "node1",
            snapshot("snap_stale", "sbx_a", "2026-09-01T00:00:00Z"),
        );
        registry.insert(
            "node2",
            snapshot("snap_other", "sbx_b", "2026-09-01T00:00:00Z"),
        );

        let adopted = registry.reconcile_node(
            "node1",
            vec![snapshot("snap_fresh", "sbx_a", "2026-09-04T00:00:00Z")],
        );
        assert_eq!(adopted, 1);
        assert!(registry.get("snap_stale").is_none());
        assert_eq!(registry.get("snap_fresh").unwrap().node_id, "node1");
        assert!(registry.get("snap_other").is_some());

        registry.forget_node("node2");
        assert!(registry.get("snap_other").is_none());
        assert!(registry.get("snap_fresh").is_some());
    }
}
