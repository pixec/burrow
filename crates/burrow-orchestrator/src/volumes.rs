//! Which node holds which volume.
//!
//! A volume is a disk image on one machine, attached to a guest as a block
//! device, so this table is the thing that decides where a sandbox mounting
//! one is placed, exactly as the snapshot registry decides where a create
//! from a snapshot goes.
//!
//! In memory only, for the same reason as snapshots: a node can list its own
//! volumes, and does so on registration. The node is the authority and a
//! restart re-learns rather than remembers.
//!
//! A durable volume, one kept in the object store, survives its node here
//! with an empty `node_id`, along with the node it was taken from, which the
//! node adopting it names so the store's conditional write takes it from that
//! holder and no other. Nodes list what the store holds on registration, so a
//! restarted orchestrator re-learns those too.

use std::collections::HashMap;
use std::sync::Mutex;

use burrow_proto::common::v1 as common;

#[derive(Default)]
pub struct VolumeRegistry {
    volumes: Mutex<HashMap<String, common::Volume>>,
    /// The holder each unplaced volume was taken from: a written-off node,
    /// or empty for one released for a move.
    taken_from: Mutex<HashMap<String, String>>,
    /// Volumes released for a move, by the node that let go and when. A
    /// heartbeat that node sampled before it let go would otherwise put the
    /// volume back on it.
    released: Mutex<HashMap<String, (String, std::time::Instant)>>,
}

/// How long a node's reports of a volume it released are ignored.
const RELEASE_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

impl VolumeRegistry {
    /// Records a volume a node reported, stamped with the node holding it.
    pub fn insert(&self, node_id: &str, mut volume: common::Volume) {
        // The node cannot know its own id in a record it built for itself.
        volume.node_id = node_id.to_string();
        self.taken_from.lock().unwrap().remove(&volume.name);
        self.released.lock().unwrap().remove(&volume.name);
        self.volumes
            .lock()
            .unwrap()
            .insert(volume.name.clone(), volume);
    }

    pub fn get(&self, name: &str) -> Option<common::Volume> {
        self.volumes.lock().unwrap().get(name).cloned()
    }

    pub fn remove(&self, name: &str) -> Option<common::Volume> {
        self.taken_from.lock().unwrap().remove(name);
        self.released.lock().unwrap().remove(name);
        self.volumes.lock().unwrap().remove(name)
    }

    /// The holder an unplaced volume is to be taken from.
    pub fn taken_from(&self, name: &str) -> String {
        self.taken_from
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    /// Detaches a durable volume from the node that released it for a move.
    pub fn release(&self, name: &str) {
        if let Some(volume) = self.volumes.lock().unwrap().get_mut(name) {
            let node_id = std::mem::take(&mut volume.node_id);
            volume.attached_to.clear();
            self.taken_from
                .lock()
                .unwrap()
                .insert(name.to_string(), String::new());
            self.released
                .lock()
                .unwrap()
                .insert(name.to_string(), (node_id, std::time::Instant::now()));
        }
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
    ///
    /// A durable volume another node reports a newer upload of stays with
    /// that node: a node back from being written off lists its stale copy
    /// until it learns from the store that it lost it.
    pub fn reconcile_node(&self, node_id: &str, reported: Vec<common::Volume>) -> usize {
        let mut volumes = self.volumes.lock().unwrap();
        let mut taken_from = self.taken_from.lock().unwrap();
        let mut released = self.released.lock().unwrap();
        released.retain(|_, (_, at)| at.elapsed() < RELEASE_GRACE);
        volumes.retain(|_, volume| volume.node_id != node_id);
        for mut volume in reported {
            if let Some(held) = volumes.get(&volume.name)
                && !held.node_id.is_empty()
                && held.is_durable
                && held.uploaded_at_unix_ms > volume.uploaded_at_unix_ms
            {
                continue;
            }
            if released
                .get(&volume.name)
                .is_some_and(|(by, _)| by == node_id)
            {
                continue;
            }
            released.remove(&volume.name);
            volume.node_id = node_id.to_string();
            taken_from.remove(&volume.name);
            volumes.insert(volume.name.clone(), volume);
        }
        volumes
            .values()
            .filter(|volume| volume.node_id == node_id)
            .count()
    }

    /// Makes the unplaced volumes exactly those the object store lists that
    /// no known node holds, returning how many were adopted and forgotten.
    ///
    /// `listed` carries each volume's holder as its manifest names it, and
    /// `is_known` says whether the fleet still has that node: one it does
    /// not was written off, so its volumes wait here to be placed.
    pub fn reconcile_remote(
        &self,
        listed: Vec<common::Volume>,
        is_known: impl Fn(&str) -> bool,
    ) -> (usize, usize) {
        let mut volumes = self.volumes.lock().unwrap();
        let mut taken_from = self.taken_from.lock().unwrap();
        let names: std::collections::HashSet<String> =
            listed.iter().map(|volume| volume.name.clone()).collect();
        let before = volumes.len();
        volumes.retain(|name, volume| !volume.node_id.is_empty() || names.contains(name));
        taken_from.retain(|name, _| volumes.contains_key(name));
        let forgotten = before - volumes.len();
        let mut adopted = 0;
        for mut volume in listed {
            if volumes
                .get(&volume.name)
                .is_some_and(|held| !held.node_id.is_empty())
            {
                continue;
            }
            if !volume.node_id.is_empty() && is_known(&volume.node_id) {
                volumes.insert(volume.name.clone(), volume);
                continue;
            }
            taken_from.insert(volume.name.clone(), std::mem::take(&mut volume.node_id));
            if !volumes.contains_key(&volume.name) {
                adopted += 1;
            }
            volumes.insert(volume.name.clone(), volume);
        }
        (adopted, forgotten)
    }

    /// Forgets a node written off entirely. Its durable volumes stay,
    /// unplaced, to be taken from it by the next node to mount them.
    pub fn forget_node(&self, node_id: &str) -> usize {
        let mut volumes = self.volumes.lock().unwrap();
        let mut taken_from = self.taken_from.lock().unwrap();
        let mut kept = 0;
        volumes.retain(|name, volume| {
            if volume.node_id != node_id {
                return true;
            }
            if !volume.is_durable {
                return false;
            }
            volume.node_id.clear();
            volume.attached_to.clear();
            taken_from.insert(name.clone(), node_id.to_string());
            kept += 1;
            true
        });
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(name: &str) -> common::Volume {
        common::Volume {
            name: name.into(),
            size_mib: 1024,
            created_at_unix_ms: 1_787_000_000_000,
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

    fn durable(name: &str, uploaded_at: i64) -> common::Volume {
        common::Volume {
            is_durable: true,
            uploaded_at_unix_ms: uploaded_at,
            ..volume(name)
        }
    }

    /// A durable volume outlives its node, waiting to be taken from it, and
    /// is placed again once a node reports holding it.
    #[test]
    fn a_durable_volume_outlives_its_node() {
        let registry = VolumeRegistry::default();
        registry.insert("node1", durable("data", 10));
        registry.insert("node1", volume("local"));
        assert_eq!(registry.forget_node("node1"), 1);
        assert!(registry.get("local").is_none());
        let data = registry.get("data").unwrap();
        assert!(data.node_id.is_empty());
        assert_eq!(registry.taken_from("data"), "node1");

        registry.reconcile_node("node2", vec![durable("data", 10)]);
        assert_eq!(registry.get("data").unwrap().node_id, "node2");
        assert_eq!(registry.taken_from("data"), "");
    }

    /// A heartbeat the source sampled before it released a volume for a move
    /// does not put the volume back on it.
    #[test]
    fn a_released_volume_is_not_put_back_by_a_late_heartbeat() {
        let registry = VolumeRegistry::default();
        registry.insert("node1", durable("data", 10));
        registry.release("data");
        registry.reconcile_node("node1", vec![durable("data", 10)]);
        assert!(registry.get("data").unwrap().node_id.is_empty());
        registry.insert("node2", durable("data", 10));
        assert_eq!(registry.get("data").unwrap().node_id, "node2");
    }

    /// A node back from being written off still lists its stale copy until
    /// it learns otherwise; the newer upload keeps the volume.
    #[test]
    fn a_stale_copy_does_not_take_the_volume_back() {
        let registry = VolumeRegistry::default();
        registry.insert("node2", durable("data", 20));
        registry.reconcile_node("node1", vec![durable("data", 10)]);
        assert_eq!(registry.get("data").unwrap().node_id, "node2");
    }

    /// The store's listing fills in volumes whose node was written off while
    /// no replica was looking, and leaves those a known node holds there.
    #[test]
    fn the_store_listing_unplaces_only_volumes_of_unknown_nodes() {
        let registry = VolumeRegistry::default();
        let held = |name: &str, node: &str| common::Volume {
            node_id: node.into(),
            ..durable(name, 1)
        };
        let (adopted, forgotten) = registry.reconcile_remote(
            vec![
                held("orphan", "gone"),
                held("live", "node1"),
                held("moving", ""),
            ],
            |node| node == "node1",
        );
        assert_eq!((adopted, forgotten), (2, 0));
        assert!(registry.get("orphan").unwrap().node_id.is_empty());
        assert_eq!(registry.taken_from("orphan"), "gone");
        assert_eq!(registry.get("live").unwrap().node_id, "node1");
        assert_eq!(registry.taken_from("moving"), "");

        let (_, forgotten) = registry.reconcile_remote(vec![held("live", "node1")], |_| true);
        assert_eq!(forgotten, 2);
        assert!(registry.get("orphan").is_none());
    }
}
