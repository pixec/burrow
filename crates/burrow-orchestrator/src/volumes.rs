//! Which node holds which volume.
//!
//! A volume is a disk image on one machine, attached to a guest as a block
//! device, so it never moves. That makes this table the thing that decides
//! where a sandbox mounting one is placed, exactly as the snapshot registry
//! decides where a create from a snapshot goes.
//!
//! In memory only, for the same reason as snapshots: a node can list its own
//! volumes, and does so on registration. The node is the authority and a
//! restart re-learns rather than remembers.

use std::collections::HashMap;
use std::sync::Mutex;

use burrow_proto::common::v1 as common;

#[derive(Default)]
pub struct VolumeRegistry {
    volumes: Mutex<HashMap<String, common::Volume>>,
}

impl VolumeRegistry {
    /// Records a volume a node reported, stamped with the node holding it.
    pub fn insert(&self, node_id: &str, mut volume: common::Volume) {
        // The node cannot know its own id in a record it built for itself.
        volume.node_id = node_id.to_string();
        self.volumes
            .lock()
            .unwrap()
            .insert(volume.name.clone(), volume);
    }

    pub fn get(&self, name: &str) -> Option<common::Volume> {
        self.volumes.lock().unwrap().get(name).cloned()
    }

    pub fn remove(&self, name: &str) -> Option<common::Volume> {
        self.volumes.lock().unwrap().remove(name)
    }

    /// Every volume by name, optionally only one node's.
    pub fn list(&self, node_id: Option<&str>) -> Vec<common::Volume> {
        let mut out: Vec<_> = self
            .volumes
            .lock()
            .unwrap()
            .values()
            .filter(|volume| node_id.is_none_or(|id| volume.node_id == id))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Replaces everything recorded against a node with what it reports.
    pub fn reconcile_node(&self, node_id: &str, reported: Vec<common::Volume>) -> usize {
        let mut volumes = self.volumes.lock().unwrap();
        volumes.retain(|_, volume| volume.node_id != node_id);
        for mut volume in reported {
            volume.node_id = node_id.to_string();
            volumes.insert(volume.name.clone(), volume);
        }
        volumes
            .values()
            .filter(|volume| volume.node_id == node_id)
            .count()
    }

    /// Drops every volume recorded against a node written off entirely.
    pub fn forget_node(&self, node_id: &str) {
        self.volumes
            .lock()
            .unwrap()
            .retain(|_, volume| volume.node_id != node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(name: &str) -> common::Volume {
        common::Volume {
            name: name.into(),
            size_mib: 1024,
            created_at: "2026-09-01T00:00:00Z".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_volume_is_recorded_against_the_node_holding_it() {
        let registry = VolumeRegistry::default();
        registry.insert("node1", volume("cache"));
        assert_eq!(registry.get("cache").unwrap().node_id, "node1");
        assert!(registry.get("missing").is_none());
    }

    #[test]
    fn listing_is_by_name_and_filterable_by_node() {
        let registry = VolumeRegistry::default();
        registry.insert("node1", volume("beta"));
        registry.insert("node1", volume("alpha"));
        registry.insert("node2", volume("gamma"));

        let names: Vec<String> = registry.list(None).into_iter().map(|v| v.name).collect();
        assert_eq!(names, ["alpha", "beta", "gamma"]);
        assert_eq!(registry.list(Some("node1")).len(), 2);
    }

    /// A volume name is unique across the fleet, so a node that reports one it
    /// no longer holds must not leave the old record pointing at it.
    #[test]
    fn reconciling_replaces_a_nodes_records() {
        let registry = VolumeRegistry::default();
        registry.insert("node1", volume("stale"));
        registry.insert("node2", volume("other"));

        assert_eq!(registry.reconcile_node("node1", vec![volume("fresh")]), 1);
        assert!(registry.get("stale").is_none());
        assert_eq!(registry.get("fresh").unwrap().node_id, "node1");
        assert!(
            registry.get("other").is_some(),
            "one node's report says nothing about another's"
        );

        registry.forget_node("node2");
        assert!(registry.get("other").is_none());
        assert!(registry.get("fresh").is_some());
    }
}
