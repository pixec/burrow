use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use burrow_core::NodeId;
use burrow_proto::common::v1::{NodeInfo, NodeStatus};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// A node missing this many intervals is reported unhealthy.
const STALE_AFTER: Duration = Duration::from_secs(15);

/// What a sandbox needs from the node it lands on.
#[derive(Debug, Clone, Default)]
pub struct Placement {
    pub template: String,
    /// Node that already hosts this sandbox's private-network peers.
    ///
    /// A preference when the mesh can carry traffic between nodes, and a hard
    /// requirement when it cannot: without one, being on the same node is the
    /// only way members reach each other.
    pub prefer_node: Option<String>,
    /// Whether peers can be reached from another node.
    pub mesh_available: bool,
    /// What the sandbox will consume, so a node is not handed work it cannot
    /// honour.
    pub vcpus: u32,
    pub mem_mib: u64,
    /// Consider nodes that do not hold the template yet, because the caller
    /// intends to copy it there first.
    pub allow_template_transfer: bool,
    /// Labels the node must carry, all of them, matched exactly.
    ///
    /// Burrow's stand-in for regions: operators label their nodes and a caller
    /// says which labels its workload needs. Hard, like the template, because a
    /// sandbox asked for on dedicated hardware and placed elsewhere is worse
    /// than one that was refused.
    pub node_labels: HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    #[error("no healthy node available")]
    NoHealthyNode,
    #[error("no node has room for {vcpus} vcpu / {mem_mib} MiB")]
    NoCapacity { vcpus: u32, mem_mib: u64 },
    #[error(
        "no node has template {0:?}; templates are node-local, so build or warm it on a node that can run it"
    )]
    TemplateNotOnAnyNode(String),
    #[error(
        "the private network's other members are on node {0}, which cannot take this sandbox; \
         cross-node private networks are not supported yet"
    )]
    PeersUnreachable(String),
    #[error(
        "no healthy node carries {0}; label nodes with `burrowd serve --label` and check \
         `burrow nodes ls`"
    )]
    NoNodeWithLabels(String),
}

/// Why a node could not be admitted to the fleet.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error(
        "the fleet is full: all {0} guest-address slices are held by registered nodes; \
         a slice frees when a departed node's record is reaped"
    )]
    NoAddressSlice(u32),
    #[error(
        "node claimed address slice {index}, but the guest address pool has only {max}; \
         the stored index is from a build with a different pool and has to be cleared"
    )]
    ClaimOutOfRange { index: u32, max: u32 },
}

/// Whether a node carries every label asked for.
fn labelled(entry: &NodeEntry, want: &HashMap<String, String>) -> bool {
    want.iter()
        .all(|(key, value)| entry.info.labels.get(key) == Some(value))
}

/// The wanted labels no live node satisfies, for an error a reader can act on.
///
/// The whole unsatisfied set rather than the first one: an operator fixing
/// labels one error at a time is an operator restarting nodes one at a time.
fn unsatisfied(live: &[&NodeEntry], want: &HashMap<String, String>) -> String {
    let mut missing: Vec<String> = want
        .iter()
        .filter(|(key, value)| {
            !live
                .iter()
                .any(|entry| entry.info.labels.get(*key) == Some(*value))
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    missing.sort();
    // Every pair exists somewhere but no single node has them all, which is a
    // different mistake and deserves to read as one.
    if missing.is_empty() {
        let mut all: Vec<String> = want.iter().map(|(k, v)| format!("{k}={v}")).collect();
        all.sort();
        return format!("all of {}", all.join(", "));
    }
    missing.join(", ")
}

pub struct NodeEntry {
    pub info: NodeInfo,
    pub status: NodeStatus,
    pub last_heartbeat: Instant,
    pub last_heartbeat_at: String,
    /// Slice of the sandbox address pool this node owns.
    pub index: u32,
    pub wireguard_public_key: String,
    pub wireguard_endpoint: String,
    /// Whether this node has sent a status since registering.
    ///
    /// Without it, "has no templates" and "has not said yet" are the same
    /// empty list, and a node that genuinely holds nothing looks like a
    /// candidate for every template on the fleet.
    pub reported: bool,
}

impl NodeEntry {
    pub fn healthy(&self) -> bool {
        self.last_heartbeat.elapsed() < STALE_AFTER
    }
}

/// In-memory node registry: nodes re-register after an orchestrator restart,
/// because Heartbeat answers `reregister` for an id it does not know.
#[derive(Default)]
pub struct NodeRegistry {
    nodes: Mutex<HashMap<String, NodeEntry>>,
    /// Capacity handed out since each node's last heartbeat. Cleared when a
    /// fresh status arrives, which already reflects it.
    pending: Mutex<HashMap<String, Reserved>>,
}

/// Capacity promised to sandboxes a node has not yet reported.
#[derive(Debug, Default, Clone, Copy)]
struct Reserved {
    vcpus: u32,
    mem_mib: u64,
}

/// Whether a node can take this sandbox without oversubscribing itself.
fn fits(entry: &NodeEntry, pending: &HashMap<String, Reserved>, want: &Placement) -> bool {
    let held = pending.get(&entry.info.id).copied().unwrap_or_default();
    let committed = entry.status.committed_vcpus as u64 + held.vcpus as u64 + want.vcpus as u64;
    // A node that has not reported its cpu count cannot be checked; trusting it
    // beats refusing to place anything on it.
    let cpu_ok = entry.info.total_vcpus == 0 || committed <= entry.info.total_vcpus as u64;
    let free = entry.status.free_mem_mib.saturating_sub(held.mem_mib);
    let mem_ok = free >= want.mem_mib;
    cpu_ok && mem_ok
}

/// Reported free memory, less anything placed since that report.
fn free_mem(entry: &NodeEntry, pending: &HashMap<String, Reserved>) -> u64 {
    let held = pending.get(&entry.info.id).copied().unwrap_or_default();
    entry.status.free_mem_mib.saturating_sub(held.mem_mib)
}

/// Free fraction of whichever resource this node is tightest on, 0.0 to 1.0.
///
/// Scoring on the minimum rather than on memory alone is the point: it is what
/// stops a node with plenty of free RAM and every core committed from looking
/// like the best place to put more work.
fn headroom(entry: &NodeEntry, pending: &HashMap<String, Reserved>) -> f64 {
    let held = pending.get(&entry.info.id).copied().unwrap_or_default();
    let cpu_free = if entry.info.total_vcpus == 0 {
        1.0
    } else {
        let committed = entry.status.committed_vcpus as f64 + held.vcpus as f64;
        1.0 - (committed / entry.info.total_vcpus as f64).clamp(0.0, 1.0)
    };
    let mem_free = if entry.info.total_mem_mib == 0 {
        1.0
    } else {
        (free_mem(entry, pending) as f64 / entry.info.total_mem_mib as f64).clamp(0.0, 1.0)
    };
    cpu_free.min(mem_free)
}

impl NodeRegistry {
    /// Registers a node, returning its id and address-pool index.
    ///
    /// A returning node keeps its index: its sandboxes' addresses derive from
    /// it, so reassigning would strand every address the node still holds.
    pub fn register(
        &self,
        mut info: NodeInfo,
        wireguard_public_key: String,
        wireguard_endpoint: String,
        claimed_index: Option<u32>,
    ) -> Result<(String, u32), RegisterError> {
        // A slice out of range is refused rather than reassigned. The node
        // already has sandboxes addressed from it, and handing it a different
        // slice would leave those addresses pointing into another node's range.
        if let Some(claimed) = claimed_index
            && claimed >= burrow_net::ipam::MAX_NODES
        {
            return Err(RegisterError::ClaimOutOfRange {
                index: claimed,
                max: burrow_net::ipam::MAX_NODES,
            });
        }
        let node_id = if info.id.is_empty() {
            NodeId::generate().to_string()
        } else {
            info.id.clone()
        };
        info.id = node_id.clone();

        let mut nodes = self.nodes.lock().unwrap();
        let taken: std::collections::HashSet<u32> = nodes
            .iter()
            .filter(|(id, _)| *id != &node_id)
            .map(|(_, e)| e.index)
            .collect();

        let index = match (nodes.get(&node_id), claimed_index) {
            // A node already using a slice keeps it: its sandboxes' addresses
            // are derived from it and cannot be moved.
            (_, Some(claimed)) if !taken.contains(&claimed) => claimed,
            (Some(existing), _) => existing.index,
            // A full fleet is refused rather than folded onto slice 0: two
            // nodes handing out the same guest addresses makes cross-node
            // routing ambiguous and lets one node's sandbox answer for
            // another's.
            (None, _) => (0..burrow_net::ipam::MAX_NODES)
                .find(|candidate| !taken.contains(candidate))
                .ok_or(RegisterError::NoAddressSlice(burrow_net::ipam::MAX_NODES))?,
        };
        if let Some(claimed) = claimed_index
            && claimed != index
        {
            tracing::error!(
                node_id,
                claimed,
                assigned = index,
                "node claimed an address slice another node holds; its existing \
                 sandboxes may have colliding addresses"
            );
        }

        nodes.insert(
            node_id.clone(),
            NodeEntry {
                info,
                status: NodeStatus::default(),
                last_heartbeat: Instant::now(),
                last_heartbeat_at: burrow_core::now_rfc3339(),
                index,
                wireguard_public_key,
                wireguard_endpoint,
                // A re-registering node re-reports on its next heartbeat; until
                // then its previous inventory is not carried over.
                reported: false,
            },
        );
        Ok((node_id, index))
    }

    /// Every healthy node except `exclude`, as mesh peers.
    ///
    /// A node with no key is omitted rather than listed unreachable: it cannot
    /// participate, and a peer entry without a key would be meaningless.
    pub fn mesh_peers(&self, exclude: &str) -> Vec<burrow_proto::node::v1::MeshPeer> {
        let nodes = self.nodes.lock().unwrap();
        nodes
            .values()
            .filter(|e| e.info.id != exclude && e.healthy() && !e.wireguard_public_key.is_empty())
            // `register` refuses an index the pool cannot hold, so this only
            // fails for a node registered by an older build; such a peer is
            // omitted rather than advertised with someone else's subnet.
            .filter_map(|e| {
                Some(burrow_proto::node::v1::MeshPeer {
                    node_id: e.info.id.clone(),
                    public_key: e.wireguard_public_key.clone(),
                    endpoint: e.wireguard_endpoint.clone(),
                    subnet: burrow_net::Ipam::for_node(e.index).ok()?.subnet(),
                })
            })
            .collect()
    }

    /// Whether any healthy node other than `exclude` can carry mesh traffic.
    pub fn mesh_is_available(&self, exclude: &str) -> bool {
        !self.mesh_peers(exclude).is_empty()
    }

    /// Records a heartbeat; returns false when the node is unknown and must
    /// re-register (e.g. after an orchestrator restart).
    ///
    /// `info` is what the node says it is right now; an absent one leaves the
    /// registered description alone. The id is never taken from it: the
    /// orchestrator assigned that, and a node repeating the empty id it started
    /// with would otherwise erase it.
    pub fn heartbeat(&self, node_id: &str, status: NodeStatus, info: Option<NodeInfo>) -> bool {
        let mut nodes = self.nodes.lock().unwrap();
        match nodes.get_mut(node_id) {
            Some(entry) => {
                if let Some(info) = info {
                    entry.info = NodeInfo {
                        id: entry.info.id.clone(),
                        ..info
                    };
                }
                entry.status = status;
                entry.reported = true;
                entry.last_heartbeat = Instant::now();
                entry.last_heartbeat_at = burrow_core::now_rfc3339();
                drop(nodes);
                self.clear_pending(node_id);
                true
            }
            None => false,
        }
    }

    /// The labels a node carries, empty for one the registry does not know.
    ///
    /// For the paths that cannot place, and so can only check: a fork is built
    /// where its source's state already is.
    pub fn labels(&self, node_id: &str) -> HashMap<String, String> {
        self.nodes
            .lock()
            .unwrap()
            .get(node_id)
            .map(|e| e.info.labels.clone())
            .unwrap_or_default()
    }

    /// Whether a node is known, and whether it is still heartbeating.
    ///
    /// `None` for a node the registry has never seen. The distinction matters
    /// on the delete path: a healthy node that merely refuses a connection is
    /// a transient failure, while a node that has stopped heartbeating may
    /// never come back, and only the second may be written off.
    pub fn health(&self, node_id: &str) -> Option<bool> {
        Some(self.nodes.lock().unwrap().get(node_id)?.healthy())
    }

    /// Ids of every node still heartbeating.
    ///
    /// Taken once so a whole list of sandboxes can be marked up without
    /// re-locking the registry per row.
    pub fn healthy_ids(&self) -> std::collections::HashSet<String> {
        self.nodes
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.healthy())
            .map(|e| e.info.id.clone())
            .collect()
    }

    /// Nodes whose last heartbeat is older than `expiry`.
    ///
    /// Well past unhealthy: this is the point at which a node is presumed gone
    /// for good rather than briefly unreachable.
    pub fn expired(&self, expiry: Duration) -> Vec<String> {
        self.nodes
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.last_heartbeat.elapsed() >= expiry)
            .map(|e| e.info.id.clone())
            .collect()
    }

    /// Drops a node entirely, along with anything charged against it.
    pub fn remove_node(&self, node_id: &str) {
        self.nodes.lock().unwrap().remove(node_id);
        self.pending.lock().unwrap().remove(node_id);
    }

    /// gRPC endpoint for a node, if it is known and healthy.
    pub fn endpoint(&self, node_id: &str) -> Option<String> {
        let nodes = self.nodes.lock().unwrap();
        let entry = nodes.get(node_id)?;
        if !entry.healthy() {
            return None;
        }
        Some(format!("http://{}", entry.info.address))
    }

    /// Picks a node for a new sandbox: healthy, not draining, most free memory.
    ///
    /// Prefer [`place_for`] when a template or private network is involved;
    /// this is the unconstrained case.
    pub fn place(&self) -> Option<String> {
        self.place_for(&Placement::default()).ok()
    }

    /// Picks a node that can actually run the sandbox being asked for.
    ///
    /// Two constraints are hard, because ignoring either produces a sandbox
    /// that looks fine and is not:
    ///
    /// - **The template must be present.** Images are node-local, so a node
    ///   without the template cannot boot it at all.
    /// - **Private-network peers must be co-located.** Membership is enforced
    ///   per node, so two members placed on different nodes would silently
    ///   fail to reach each other rather than erroring.
    ///
    /// Among eligible nodes, one already holding a warm snapshot wins (a ~300ms
    /// create against a ~1.5s one), and the least-loaded node breaks the
    /// remaining ties. "Least loaded" means the node whose *tightest* dimension
    /// has the most headroom: a memory-rich but cpu-saturated node would
    /// otherwise look like the best place for more work.
    pub fn place_for(&self, want: &Placement) -> Result<String, PlacementError> {
        let nodes = self.nodes.lock().unwrap();

        let live: Vec<_> = nodes
            .values()
            .filter(|e| e.healthy() && !e.status.draining)
            .collect();
        if live.is_empty() {
            return Err(PlacementError::NoHealthyNode);
        }

        // Applied before the template, so a caller who asked for hardware that
        // does not exist is told that, rather than being told about an image.
        let labelled_live: Vec<_> = live
            .iter()
            .copied()
            .filter(|e| labelled(e, &want.node_labels))
            .collect();
        if labelled_live.is_empty() {
            return Err(PlacementError::NoNodeWithLabels(unsatisfied(
                &live,
                &want.node_labels,
            )));
        }
        let live = labelled_live;

        let with_template: Vec<_> = live
            .iter()
            .filter(|e| {
                want.allow_template_transfer
                    || want.template.is_empty()
                    // A node that has not reported yet is given the benefit of
                    // the doubt; one that has is taken at its word.
                    || !e.reported
                    || e.status.templates.contains(&want.template)
            })
            .collect();
        if with_template.is_empty() {
            return Err(PlacementError::TemplateNotOnAnyNode(want.template.clone()));
        }

        // Without a mesh, peers on another node are simply unreachable, so
        // co-location is the only correct answer rather than the fast one.
        if let Some(node_id) = &want.prefer_node
            && !want.mesh_available
        {
            return with_template
                .iter()
                .find(|e| e.info.id == *node_id)
                .map(|e| e.info.id.clone())
                .ok_or_else(|| PlacementError::PeersUnreachable(node_id.clone()));
        }

        let pending = self.pending.lock().unwrap();
        let with_room: Vec<_> = with_template
            .into_iter()
            .filter(|e| fits(e, &pending, want))
            .collect();
        if with_room.is_empty() {
            return Err(PlacementError::NoCapacity {
                vcpus: want.vcpus,
                mem_mib: want.mem_mib,
            });
        }

        let chosen = with_room
            .into_iter()
            .max_by_key(|e| {
                (
                    // Same node as the peers: no encryption, no extra hop.
                    want.prefer_node.as_deref() == Some(e.info.id.as_str()),
                    e.status.warm_templates.contains_key(&want.template),
                    // Headroom on the tightest dimension, in thousandths so it
                    // orders as an integer.
                    (headroom(e, &pending) * 1000.0) as i64,
                    // Absolute free memory breaks the remaining ties, and
                    // decides entirely for a node that has not reported its
                    // capacity, where every fraction is 1.0.
                    free_mem(e, &pending),
                )
            })
            .map(|e| e.info.id.clone())
            .ok_or(PlacementError::NoHealthyNode)?;
        drop(pending);

        // Charged immediately rather than waiting for the node's next
        // heartbeat. Placements are far quicker than the heartbeat interval, so
        // without this a burst of concurrent creates all read the same stale
        // status and pile onto whichever node was least loaded a second ago.
        self.reserve(&chosen, want);
        Ok(chosen)
    }

    /// Charges a placement against a node until its next heartbeat reports it.
    fn reserve(&self, node_id: &str, want: &Placement) {
        let mut pending = self.pending.lock().unwrap();
        let entry = pending.entry(node_id.to_string()).or_default();
        entry.vcpus += want.vcpus;
        entry.mem_mib += want.mem_mib;
    }

    /// Gives back capacity reserved for a placement that no longer exists.
    ///
    /// A reservation covers the window between placing a sandbox and the node
    /// reporting it. If the sandbox is destroyed inside that window the charge
    /// has to be returned, or a burst of create-then-destroy exhausts a node
    /// that is in fact empty.
    pub fn release(&self, node_id: &str, vcpus: u32, mem_mib: u64) {
        let mut pending = self.pending.lock().unwrap();
        let Some(entry) = pending.get_mut(node_id) else {
            return;
        };
        entry.vcpus = entry.vcpus.saturating_sub(vcpus);
        entry.mem_mib = entry.mem_mib.saturating_sub(mem_mib);
        if entry.vcpus == 0 && entry.mem_mib == 0 {
            pending.remove(node_id);
        }
    }

    /// Drops a node's optimistic reservations.
    ///
    /// Called when a heartbeat arrives, because the status it carries already
    /// accounts for everything placed before it was sampled. Keeping the
    /// reservations on top of it would double-charge the node.
    fn clear_pending(&self, node_id: &str) {
        self.pending.lock().unwrap().remove(node_id);
    }

    /// The edge a node serves for its own sandboxes, if it serves one.
    ///
    /// The domain and the port it answers on, which is everything a URL for a
    /// published port there needs. Health is not consulted: a node whose
    /// heartbeat is late still holds its sandboxes, and its edge is still the
    /// address that avoids the detour through here.
    pub fn node_edge(&self, node_id: &str) -> Option<(String, u16)> {
        let nodes = self.nodes.lock().unwrap();
        let info = &nodes.get(node_id)?.info;
        if info.edge_domain.is_empty() || info.edge_port == 0 {
            return None;
        }
        Some((
            info.edge_domain.clone(),
            u16::try_from(info.edge_port).ok()?,
        ))
    }

    /// Every host in the fleet running an edge router.
    ///
    /// Handed to nodes so they can deny them to their sandboxes. The node's own
    /// API address rather than its edge domain: the domain is a wildcard that
    /// resolves per hostname, and what a firewall rule needs is the machine.
    /// Unhealthy nodes are included: a node that stopped beating has not
    /// stopped listening.
    pub fn edge_hosts(&self) -> Vec<String> {
        let nodes = self.nodes.lock().unwrap();
        let mut hosts: Vec<String> = nodes
            .values()
            .filter(|entry| !entry.info.edge_domain.is_empty())
            .map(|entry| entry.info.address.clone())
            .filter(|address| !address.is_empty())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    /// Whether a node already reports holding `template`.
    ///
    /// Read from the node's last heartbeat, so a template imported since then
    /// reads as absent and the transfer is a no-op the node resolves itself.
    pub fn has_template(&self, node_id: &str, template: &str) -> bool {
        self.nodes
            .lock()
            .unwrap()
            .get(node_id)
            .is_some_and(|e| e.status.templates.iter().any(|t| t == template))
    }

    /// A healthy node holding `template`, to copy it from.
    ///
    /// Any node with the artifacts will do: they are content-addressed, so
    /// every copy is the same copy. Draining nodes are eligible, since they
    /// refuse new sandboxes, not reads.
    pub fn source_for_template(&self, template: &str) -> Option<(String, String)> {
        let nodes = self.nodes.lock().unwrap();
        nodes
            .values()
            .find(|e| e.healthy() && e.status.templates.iter().any(|t| t == template))
            .map(|e| (e.info.id.clone(), e.info.address.clone()))
    }

    /// Records a drain decision immediately, rather than waiting for the
    /// node's next heartbeat to report it.
    pub fn set_draining(&self, node_id: &str, draining: bool) {
        if let Some(entry) = self.nodes.lock().unwrap().get_mut(node_id) {
            entry.status.draining = draining;
        }
    }

    pub fn snapshot(&self) -> Vec<burrow_proto::api::v1::Node> {
        let nodes = self.nodes.lock().unwrap();
        let mut out: Vec<_> = nodes
            .values()
            .map(|e| burrow_proto::api::v1::Node {
                info: Some(e.info.clone()),
                status: Some(e.status.clone()),
                healthy: e.healthy(),
                last_heartbeat_at: e.last_heartbeat_at.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            a.info
                .as_ref()
                .map(|i| i.id.clone())
                .cmp(&b.info.as_ref().map(|i| i.id.clone()))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burrow_proto::common::v1::{NodeInfo, NodeStatus};

    fn registry(nodes: &[(&str, NodeStatus)]) -> NodeRegistry {
        let registry = NodeRegistry::default();
        for (id, status) in nodes {
            let _ = registry.register(
                NodeInfo {
                    id: (*id).into(),
                    address: format!("{id}:7071"),
                    ..Default::default()
                },
                format!("{id}-pubkey"),
                format!("{id}:51820"),
                None,
            );
            registry.heartbeat(id, status.clone(), None);
        }
        registry
    }

    /// A node's edge is what it says it is on its own heartbeat, and a node
    /// without one has none to report.
    #[test]
    fn only_a_node_serving_an_edge_advertises_one() {
        let registry = registry(&[("node-a", NodeStatus::default())]);
        assert_eq!(registry.node_edge("node-a"), None);
        assert!(registry.edge_hosts().is_empty());

        registry.heartbeat(
            "node-a",
            NodeStatus::default(),
            Some(NodeInfo {
                id: "node-a".into(),
                address: "node-a:7071".into(),
                edge_domain: "node-a.example.com".into(),
                edge_port: 7081,
                ..Default::default()
            }),
        );
        assert_eq!(
            registry.node_edge("node-a"),
            Some(("node-a.example.com".into(), 7081))
        );
        // The machine, not the wildcard domain: a firewall rule needs an
        // address, and the domain resolves per hostname.
        assert_eq!(registry.edge_hosts(), ["node-a:7071"]);
    }

    /// Sets what an operator labelled a node with.
    fn label(registry: &NodeRegistry, id: &str, pairs: &[(&str, &str)]) {
        let mut nodes = registry.nodes.lock().unwrap();
        let entry = nodes.get_mut(id).expect("registered node");
        entry.info.labels = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
    }

    fn wants(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn status(templates: &[&str], warm: &[&str], free_mem_mib: u64) -> NodeStatus {
        NodeStatus {
            templates: templates.iter().map(|t| (*t).to_string()).collect(),
            warm_templates: warm.iter().map(|t| ((*t).to_string(), 1)).collect(),
            free_mem_mib,
            ..Default::default()
        }
    }

    #[test]
    fn every_node_gets_a_distinct_address_slice() {
        // Overlapping slices would make two nodes hand out the same guest
        // address, which cross-node routing could not disambiguate.
        let registry = registry(&[("a", status(&[], &[], 1)), ("b", status(&[], &[], 1))]);
        let nodes = registry.nodes.lock().unwrap();
        assert_ne!(nodes["a"].index, nodes["b"].index);
    }

    #[test]
    fn a_claimed_slice_is_honoured() {
        // The node is authoritative: its sandboxes already hold addresses
        // from the slice it claims.
        let registry = NodeRegistry::default();
        let (_, index) = registry
            .register(
                NodeInfo {
                    id: "a".into(),
                    address: "a:7071".into(),
                    ..Default::default()
                },
                String::new(),
                String::new(),
                Some(7),
            )
            .expect("slice 7 is free");
        assert_eq!(index, 7);
    }

    #[test]
    fn a_claim_on_a_taken_slice_is_refused() {
        let registry = registry(&[("a", status(&[], &[], 1))]);
        let held = registry.nodes.lock().unwrap()["a"].index;
        let (_, index) = registry
            .register(
                NodeInfo {
                    id: "b".into(),
                    address: "b:7071".into(),
                    ..Default::default()
                },
                String::new(),
                String::new(),
                Some(held),
            )
            .expect("another slice is free");
        assert_ne!(index, held, "two nodes must never share a slice");
    }

    /// Handing a new node slice 0 because nothing was free put it on the same
    /// guest addresses as whoever already held slice 0, with no way for
    /// cross-node routing to tell the two apart.
    #[test]
    fn a_full_fleet_refuses_a_new_node_rather_than_sharing_a_slice() {
        let registry = NodeRegistry::default();
        for index in 0..burrow_net::ipam::MAX_NODES {
            registry
                .register(
                    NodeInfo {
                        id: format!("node{index}"),
                        address: format!("node{index}:7071"),
                        ..Default::default()
                    },
                    String::new(),
                    String::new(),
                    Some(index),
                )
                .expect("every slice is claimed exactly once");
        }
        let err = registry
            .register(
                NodeInfo {
                    id: "one-too-many".into(),
                    address: "extra:7071".into(),
                    ..Default::default()
                },
                String::new(),
                String::new(),
                None,
            )
            .expect_err("the pool is exhausted");
        assert!(matches!(err, RegisterError::NoAddressSlice(_)), "{err:?}");
        // A node already in the fleet is still admitted: it keeps its own slice.
        assert!(
            registry
                .register(
                    NodeInfo {
                        id: "node0".into(),
                        address: "node0:7071".into(),
                        ..Default::default()
                    },
                    String::new(),
                    String::new(),
                    None,
                )
                .is_ok()
        );
    }

    /// A claim the pool cannot hold was once silently reassigned, which left
    /// the node's existing sandbox addresses inside another node's range.
    #[test]
    fn a_claim_past_the_pool_is_refused() {
        let registry = NodeRegistry::default();
        let err = registry
            .register(
                NodeInfo {
                    id: "a".into(),
                    address: "a:7071".into(),
                    ..Default::default()
                },
                String::new(),
                String::new(),
                Some(burrow_net::ipam::MAX_NODES),
            )
            .expect_err("the pool has no such slice");
        assert!(
            matches!(err, RegisterError::ClaimOutOfRange { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_returning_node_keeps_its_slice() {
        // Its sandboxes' addresses derive from the index; reassigning would
        // strand every address it still holds.
        let registry = registry(&[("a", status(&[], &[], 1))]);
        let before = registry.nodes.lock().unwrap()["a"].index;
        let (_, after) = registry
            .register(
                NodeInfo {
                    id: "a".into(),
                    address: "a:7071".into(),
                    ..Default::default()
                },
                "a-pubkey".into(),
                "a:51820".into(),
                None,
            )
            .expect("a returning node is always admitted");
        assert_eq!(before, after);
    }

    #[test]
    fn mesh_peers_exclude_the_asking_node() {
        let registry = registry(&[("a", status(&[], &[], 1)), ("b", status(&[], &[], 1))]);
        let peers = registry.mesh_peers("a");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, "b");
        // The peer's range is what makes it routable and is also what
        // WireGuard will accept traffic from.
        assert!(peers[0].subnet.ends_with("/22"));
    }

    #[test]
    fn a_node_without_a_key_is_not_a_mesh_peer() {
        let registry = NodeRegistry::default();
        let _ = registry.register(
            NodeInfo {
                id: "keyless".into(),
                address: "keyless:7071".into(),
                ..Default::default()
            },
            String::new(),
            String::new(),
            None,
        );
        registry.heartbeat("keyless", status(&[], &[], 1), None);
        assert!(registry.mesh_peers("other").is_empty());
        assert!(!registry.mesh_is_available("other"));
    }

    #[test]
    fn a_node_without_the_template_is_not_eligible() {
        // Images are node-local; placing here would fail at boot instead.
        let registry = registry(&[
            ("a", status(&["other"], &[], 9999)),
            ("b", status(&["wanted"], &[], 1)),
        ]);
        let placed = registry
            .place_for(&Placement {
                template: "wanted".into(),
                prefer_node: None,
                mesh_available: false,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            placed, "b",
            "free memory must not outweigh having the image"
        );
    }

    #[test]
    fn a_template_no_node_holds_is_an_error_not_a_guess() {
        let registry = registry(&[("a", status(&["other"], &[], 100))]);
        let err = registry
            .place_for(&Placement {
                template: "missing".into(),
                prefer_node: None,
                mesh_available: false,
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::TemplateNotOnAnyNode(_)));
    }

    #[test]
    fn a_warm_node_wins_over_a_roomier_cold_one() {
        let registry = registry(&[
            ("cold", status(&["t"], &[], 9999)),
            ("warm", status(&["t"], &["t"], 1)),
        ]);
        let placed = registry
            .place_for(&Placement {
                template: "t".into(),
                prefer_node: None,
                mesh_available: false,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(placed, "warm");
    }

    #[test]
    fn without_a_mesh_network_peers_must_be_co_located() {
        let registry = registry(&[
            ("a", status(&["t"], &[], 9999)),
            ("b", status(&["t"], &[], 1)),
        ]);
        let placed = registry
            .place_for(&Placement {
                template: "t".into(),
                prefer_node: Some("b".into()),
                mesh_available: false,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(placed, "b", "peers must be co-located, whatever the load");
    }

    #[test]
    fn without_a_mesh_unreachable_peers_fail_rather_than_split_the_network() {
        // Splitting members across nodes would leave them silently unable to
        // reach each other, which is worse than refusing.
        let registry = registry(&[("a", status(&["t"], &[], 100))]);
        let err = registry
            .place_for(&Placement {
                template: "t".into(),
                prefer_node: Some("gone".into()),
                mesh_available: false,
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::PeersUnreachable(_)));
    }

    #[test]
    fn with_a_mesh_co_location_is_a_preference_not_a_requirement() {
        let registry = registry(&[
            ("a", status(&["t"], &[], 9999)),
            ("b", status(&["t"], &[], 1)),
        ]);
        // Preferred while it can take the sandbox...
        assert_eq!(
            registry
                .place_for(&Placement {
                    template: "t".into(),
                    prefer_node: Some("b".into()),
                    mesh_available: true,
                    ..Default::default()
                })
                .unwrap(),
            "b"
        );
        // ...but a peer node that is gone no longer blocks placement, because
        // the mesh can carry the traffic.
        assert_eq!(
            registry
                .place_for(&Placement {
                    template: "t".into(),
                    prefer_node: Some("gone".into()),
                    mesh_available: true,
                    ..Default::default()
                })
                .unwrap(),
            "a"
        );
    }

    /// Burrow's stand-in for a region: the caller names labels, and only a node
    /// carrying every one of them is eligible.
    #[test]
    fn a_required_label_decides_the_node() {
        let registry = registry(&[
            ("roomy", status(&["t"], &[], 9999)),
            ("labelled", status(&["t"], &[], 1)),
        ]);
        label(&registry, "roomy", &[("rack", "a1")]);
        label(&registry, "labelled", &[("rack", "b7"), ("tenant", "acme")]);

        // Repeated, because a constraint that only usually holds is not one:
        // free memory would send every one of these to "roomy".
        for _ in 0..8 {
            let placed = registry
                .place_for(&Placement {
                    template: "t".into(),
                    node_labels: wants(&[("rack", "b7")]),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(placed, "labelled");
        }
    }

    /// A label nothing carries is refused by name. Placing anyway would put a
    /// tenant's workload on hardware they asked it to stay off.
    #[test]
    fn an_unsatisfiable_label_is_an_error_naming_it() {
        let registry = registry(&[("a", status(&["t"], &[], 100))]);
        label(&registry, "a", &[("rack", "a1")]);
        let err = registry
            .place_for(&Placement {
                template: "t".into(),
                node_labels: wants(&[("rack", "b7")]),
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoNodeWithLabels(_)), "{err}");
        assert!(err.to_string().contains("rack=b7"), "{err}");
    }

    /// A label is a pair: the same key with another value does not satisfy it.
    #[test]
    fn a_matching_key_with_another_value_is_not_a_match() {
        let registry = registry(&[("a", status(&["t"], &[], 100))]);
        label(&registry, "a", &[("tenant", "other")]);
        assert!(
            registry
                .place_for(&Placement {
                    template: "t".into(),
                    node_labels: wants(&[("tenant", "acme")]),
                    ..Default::default()
                })
                .is_err()
        );
    }

    /// Two nodes between them carrying the pairs is not one node carrying both,
    /// and the error says so rather than naming a pair that does exist.
    #[test]
    fn labels_are_required_together_on_one_node() {
        let registry = registry(&[
            ("a", status(&["t"], &[], 100)),
            ("b", status(&["t"], &[], 100)),
        ]);
        label(&registry, "a", &[("rack", "b7")]);
        label(&registry, "b", &[("tenant", "acme")]);
        let err = registry
            .place_for(&Placement {
                template: "t".into(),
                node_labels: wants(&[("rack", "b7"), ("tenant", "acme")]),
                ..Default::default()
            })
            .unwrap_err();
        assert!(err.to_string().contains("all of"), "{err}");
    }

    /// The label constraint is checked before the template, so a caller who
    /// asked for hardware that does not exist is told that.
    #[test]
    fn an_unsatisfiable_label_outranks_a_missing_template() {
        let registry = registry(&[("a", status(&["other"], &[], 100))]);
        let err = registry
            .place_for(&Placement {
                template: "missing".into(),
                node_labels: wants(&[("rack", "b7")]),
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoNodeWithLabels(_)), "{err}");
    }

    /// Extra labels on a node are not a mismatch: a constraint says what a node
    /// must carry, not everything it may.
    #[test]
    fn a_node_may_carry_labels_nobody_asked_for() {
        let registry = registry(&[("a", status(&["t"], &[], 100))]);
        label(&registry, "a", &[("rack", "b7"), ("gpu", "h100")]);
        assert_eq!(
            registry
                .place_for(&Placement {
                    template: "t".into(),
                    node_labels: wants(&[("rack", "b7")]),
                    ..Default::default()
                })
                .unwrap(),
            "a"
        );
    }

    /// An operator's relabel has to land without waiting for the node to
    /// re-register, or a relabelled fleet is one placement decision behind.
    #[test]
    fn a_heartbeat_carries_a_relabel() {
        let registry = registry(&[("a", status(&["t"], &[], 100))]);
        let want = Placement {
            template: "t".into(),
            node_labels: wants(&[("rack", "b7")]),
            ..Default::default()
        };
        assert!(registry.place_for(&want).is_err());

        registry.heartbeat(
            "a",
            status(&["t"], &[], 100),
            Some(NodeInfo {
                // The node repeats the id it was started with, which is not the
                // one the orchestrator assigned it.
                id: String::new(),
                address: "a:7071".into(),
                labels: wants(&[("rack", "b7")]),
                ..Default::default()
            }),
        );
        assert_eq!(registry.place_for(&want).unwrap(), "a");
        assert_eq!(registry.labels("a")["rack"], "b7");
        // The assigned id survives what the node said about itself.
        assert_eq!(registry.nodes.lock().unwrap()["a"].info.id, "a");
    }

    #[test]
    fn draining_nodes_are_skipped() {
        let mut draining = status(&["t"], &[], 9999);
        draining.draining = true;
        let registry = registry(&[("a", draining), ("b", status(&["t"], &[], 1))]);
        assert_eq!(
            registry
                .place_for(&Placement {
                    template: "t".into(),
                    prefer_node: None,
                    mesh_available: false,
                    ..Default::default()
                })
                .unwrap(),
            "b"
        );
    }

    /// Free memory alone is the wrong signal: a node can have plenty of it and
    /// no cores left, and placing there produces a sandbox that runs badly.
    #[test]
    fn a_cpu_saturated_node_loses_to_one_with_cores_free() {
        let registry = registry(&[
            (
                "roomy-memory",
                NodeStatus {
                    free_mem_mib: 60_000,
                    committed_vcpus: 16,
                    ..Default::default()
                },
            ),
            (
                "roomy-cpu",
                NodeStatus {
                    free_mem_mib: 8_000,
                    committed_vcpus: 1,
                    ..Default::default()
                },
            ),
        ]);
        set_capacity(&registry, "roomy-memory", 16, 64_000);
        set_capacity(&registry, "roomy-cpu", 16, 64_000);

        let chosen = registry
            .place_for(&Placement {
                vcpus: 1,
                mem_mib: 512,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(chosen, "roomy-cpu");
    }

    #[test]
    fn a_node_with_every_core_committed_is_not_offered_more() {
        let registry = registry(&[(
            "full",
            NodeStatus {
                free_mem_mib: 60_000,
                committed_vcpus: 8,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "full", 8, 64_000);

        let err = registry
            .place_for(&Placement {
                vcpus: 1,
                mem_mib: 512,
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoCapacity { .. }), "{err}");
    }

    /// Placements are far quicker than the heartbeat interval, so a burst of
    /// creates would otherwise all read the same stale status and land on one
    /// node.
    #[test]
    fn concurrent_placements_spread_before_the_next_heartbeat() {
        let registry = registry(&[
            (
                "a",
                NodeStatus {
                    free_mem_mib: 64_000,
                    ..Default::default()
                },
            ),
            (
                "b",
                NodeStatus {
                    free_mem_mib: 64_000,
                    ..Default::default()
                },
            ),
        ]);
        set_capacity(&registry, "a", 8, 64_000);
        set_capacity(&registry, "b", 8, 64_000);

        let want = Placement {
            vcpus: 4,
            mem_mib: 32_000,
            ..Default::default()
        };
        let first = registry.place_for(&want).unwrap();
        let second = registry.place_for(&want).unwrap();
        assert_ne!(
            first, second,
            "both placements went to {first} without a heartbeat in between"
        );
    }

    /// A heartbeat already accounts for what was placed before it; keeping the
    /// reservations on top would charge the node twice.
    #[test]
    fn a_heartbeat_clears_what_was_reserved_against_it() {
        let registry = registry(&[(
            "only",
            NodeStatus {
                free_mem_mib: 4_000,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "only", 8, 8_000);

        let want = Placement {
            vcpus: 1,
            mem_mib: 3_000,
            ..Default::default()
        };
        registry.place_for(&want).unwrap();
        // The reservation now covers most of the reported free memory.
        assert!(registry.place_for(&want).is_err());

        registry.heartbeat(
            "only",
            NodeStatus {
                free_mem_mib: 4_000,
                committed_vcpus: 1,
                ..Default::default()
            },
            None,
        );
        registry
            .place_for(&want)
            .expect("heartbeat should clear the reservation");
    }

    /// Capacity is reported by the node; a node that has not said how big it is
    /// should still be usable rather than excluded from every placement.
    #[test]
    fn a_node_that_reports_no_capacity_is_still_placeable() {
        let registry = registry(&[("unknown", NodeStatus::default())]);
        registry
            .place_for(&Placement {
                vcpus: 4,
                mem_mib: 0,
                ..Default::default()
            })
            .expect("an unsized node should not be excluded");
    }

    /// Sets what a node says it physically has, which registration carries.
    fn set_capacity(registry: &NodeRegistry, id: &str, vcpus: u32, mem_mib: u64) {
        let mut nodes = registry.nodes.lock().unwrap();
        let entry = nodes.get_mut(id).expect("registered node");
        entry.info.total_vcpus = vcpus;
        entry.info.total_mem_mib = mem_mib;
    }

    /// Capacity is only known once a node reports it. Until then the score
    /// must still prefer the emptier node rather than pick arbitrarily.
    #[test]
    fn without_reported_capacity_free_memory_still_decides() {
        let registry = registry(&[
            ("small", status(&["t"], &[], 1)),
            ("large", status(&["t"], &[], 9_999)),
        ]);
        for _ in 0..8 {
            let chosen = registry
                .place_for(&Placement {
                    template: "t".into(),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(chosen, "large");
        }
    }

    /// A node that has the template is not the only candidate: it can be
    /// copied to one that has room.
    #[test]
    fn a_template_holder_can_be_found_to_copy_from() {
        let registry = registry(&[
            ("holder", status(&["python"], &[], 100)),
            ("empty", status(&[], &[], 100)),
        ]);
        let (node_id, address) = registry.source_for_template("python").expect("a holder");
        assert_eq!(node_id, "holder");
        assert_eq!(address, "holder:7071");
        assert!(registry.source_for_template("nonexistent").is_none());
    }

    /// Relaxing the template constraint is what lets placement consider a node
    /// the template has not reached yet.
    #[test]
    fn allowing_a_transfer_widens_placement_to_nodes_without_the_template() {
        // Reports an inventory, and the wanted template is not in it. An
        // *empty* inventory means "has not reported yet" and is treated as
        // usable, which is a different case.
        let registry = registry(&[("other-images", status(&["node"], &[], 100))]);
        let want = Placement {
            template: "python".into(),
            ..Default::default()
        };
        assert!(matches!(
            registry.place_for(&want).unwrap_err(),
            PlacementError::TemplateNotOnAnyNode(_)
        ));
        assert_eq!(
            registry
                .place_for(&Placement {
                    allow_template_transfer: true,
                    ..want
                })
                .unwrap(),
            "other-images"
        );
    }

    /// "Holds no templates" and "has not said yet" are the same empty list on
    /// the wire, and confusing them sends sandboxes to a node that cannot run
    /// them.
    #[test]
    fn a_node_that_reports_an_empty_inventory_is_not_a_candidate() {
        let registry = NodeRegistry::default();
        let _ = registry.register(
            NodeInfo {
                id: "fresh".into(),
                address: "fresh:7071".into(),
                ..Default::default()
            },
            "key".into(),
            "fresh:51820".into(),
            None,
        );

        let want = Placement {
            template: "python".into(),
            ..Default::default()
        };
        // Before any heartbeat it gets the benefit of the doubt.
        assert_eq!(registry.place_for(&want).unwrap(), "fresh");

        // Having now said it holds nothing, it is taken at its word.
        registry.heartbeat("fresh", NodeStatus::default(), None);
        assert!(matches!(
            registry.place_for(&want).unwrap_err(),
            PlacementError::TemplateNotOnAnyNode(_)
        ));
    }

    /// A reservation covers the window before a node reports the sandbox. If
    /// the sandbox is destroyed inside that window the charge has to come
    /// back, or a burst of create-then-destroy exhausts an empty node.
    #[test]
    fn a_released_placement_gives_its_capacity_back() {
        let registry = registry(&[(
            "only",
            NodeStatus {
                free_mem_mib: 4_000,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "only", 2, 8_000);

        // Two of these fit in the reported 4,000 MiB; a third does not.
        let want = Placement {
            vcpus: 1,
            mem_mib: 1_500,
            ..Default::default()
        };
        registry.place_for(&want).unwrap();
        registry.place_for(&want).unwrap();
        assert!(registry.place_for(&want).is_err());

        registry.release("only", want.vcpus, want.mem_mib);
        registry
            .place_for(&want)
            .expect("releasing one placement should make room for another");
    }

    #[test]
    fn releasing_more_than_was_reserved_does_not_underflow() {
        let registry = registry(&[(
            "only",
            NodeStatus {
                free_mem_mib: 4_000,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "only", 8, 8_000);
        registry.release("only", 99, 99_999);
        registry.release("only", 1, 1);
        registry
            .place_for(&Placement {
                vcpus: 1,
                mem_mib: 100,
                ..Default::default()
            })
            .expect("an unknown release must not corrupt the ledger");
    }
}
