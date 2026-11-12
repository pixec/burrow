use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use burrow_common::NodeId;
use burrow_common::cpu::cpus_text;
use burrow_common::hypervisor::Hypervisor;
use burrow_proto::common::v1::{self as common, NodeInfo, NodeStatus};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// A node missing this many intervals is reported unhealthy.
const STALE_AFTER: Duration = Duration::from_secs(15);
/// A node unheard for this long is taken to be gone rather than slow: it is
/// no longer called, placed on, or given a delete before one is tombstoned.
/// Until then a node whose heartbeats arrive late, as they do from one busy
/// with a burst, is still called and placed on, after every punctual node.
pub const ABSENT_AFTER: Duration = Duration::from_secs(60);

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
    pub is_mesh_available: bool,
    /// What the sandbox will consume, so a node is not handed work it cannot
    /// honour. `vcpus` and `mem_mib` are the guest's; a node is charged
    /// [`cpu_charge_millis`](Self::cpu_charge_millis), which is
    /// `reserved_cpus` where the sandbox has a reservation and `cpus` where it
    /// is capped, and [`mem_charge_mib`](Self::mem_charge_mib).
    pub vcpus: u32,
    pub cpus: f64,
    pub reserved_cpus: f64,
    /// The host CPUs the sandbox is pinned to, which the node must have, and
    /// its IO weight, which needs the node's cgroup io.weight. Hard, because
    /// a node without them can only refuse the VM its cgroup.
    pub cpuset_cpus: String,
    pub blkio_weight: u32,
    pub mem_mib: u64,
    /// The disk it is promised, in bytes: its root disk. Checked against
    /// what the node reports with the node's own rule
    /// ([`burrow_common::disk`]), so a node is not chosen only to refuse.
    pub disk_bytes: u64,
    /// Consider nodes that do not hold the template yet, because the caller
    /// intends to copy it there first.
    pub is_template_transfer_allowed: bool,
    /// Labels the node must carry, all of them, matched exactly.
    ///
    /// Burrow's stand-in for regions: operators label their nodes and a caller
    /// says which labels its workload needs. Hard, like the template, because a
    /// sandbox asked for on dedicated hardware and placed elsewhere is worse
    /// than one that was refused.
    pub node_labels: HashMap<String, String>,
    /// What the node must be able to restore, when the sandbox starts from
    /// state written elsewhere. Empty means anything. Hard, because a
    /// snapshot restored under another Firecracker or on another architecture
    /// does not fail cleanly; it boots a guest whose memory lies about the
    /// machine.
    pub arch: String,
    pub hypervisor_version: String,
    /// The CPU saved memory was written on, when the sandbox restores some:
    /// a node must be [`cpu_mismatch`]-free with it.
    pub cpu: Option<common::CpuFingerprint>,
    /// The hypervisor the sandbox runs under: its template's, or its state's
    /// when it restores. Empty means any. Hard, because a node without it
    /// can only refuse the create.
    pub hypervisor: String,
    /// Policy features the node must enforce ([`policy_features`]). Hard,
    /// because a node without one drops that part of the policy silently.
    pub policy_features: Vec<&'static str>,
}

impl Placement {
    /// The host CPU a node is charged for the sandbox, in thousandths of a
    /// CPU.
    pub fn cpu_charge_millis(&self) -> u64 {
        cpu_charge_millis(self.vcpus, self.cpus, self.reserved_cpus)
    }

    /// The host memory the sandbox may hold on a node, which is what that
    /// node is charged.
    pub fn mem_charge_mib(&self, info: &NodeInfo, status: &NodeStatus) -> u64 {
        mem_charge_mib(info, status, &self.hypervisor, &self.template, self.mem_mib)
    }
}

/// The host CPU a sandbox of `vcpus` capped at `cpus` with `reserved_cpus`
/// reserved is charged, in thousandths of a CPU.
pub fn cpu_charge_millis(vcpus: u32, cpus: f64, reserved_cpus: f64) -> u64 {
    use burrow_common::cpu::{cap_millis, charge_millis};
    charge_millis(vcpus, cap_millis(cpus), cap_millis(reserved_cpus))
}

/// The host memory a guest of `mem_mib` may hold on a node: the cgroup
/// ceiling the node puts on it, with the VMM overhead it reports. An empty
/// `hypervisor` is the one the node runs `template` under, and a node that
/// does not hold `template` is charged the costliest hypervisor it offers.
pub fn mem_charge_mib(
    info: &NodeInfo,
    status: &NodeStatus,
    hypervisor: &str,
    template: &str,
    mem_mib: u64,
) -> u64 {
    use burrow_common::hypervisor::Hypervisor;
    if mem_mib == 0 {
        return 0;
    }
    let ceiling = |hypervisor: Hypervisor| {
        let overhead = info
            .vmm_memory_overhead_mib
            .get(hypervisor.as_str())
            .copied()
            .unwrap_or_else(|| hypervisor.default_vmm_overhead_mib());
        u64::from(hypervisor.memory_ceiling_mib(mem_mib as u32, overhead))
    };
    let hypervisor = match hypervisor {
        "" => status
            .template_hypervisors
            .get(template)
            .map_or("", String::as_str),
        named => named,
    };
    match hypervisor {
        "" => info
            .hypervisors
            .iter()
            .filter_map(|name| name.parse().ok())
            .map(ceiling)
            .max()
            .unwrap_or(mem_mib),
        named => named.parse().map_or(mem_mib, ceiling),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    #[error("no healthy node available")]
    NoHealthyNode,
    #[error("could not reserve capacity: {0}")]
    Store(String),
    #[error("no node can restore this snapshot: it needs {arch} and {hypervisor} {version}")]
    NoCompatibleNode {
        arch: String,
        hypervisor: String,
        version: String,
    },
    #[error("no node can restore this state on its CPU: {0}")]
    NoCompatibleCpu(String),
    #[error(
        "no healthy node offers {0}; start burrowd with --hypervisors including it on a node \
         that has its binary"
    )]
    NoNodeWithHypervisor(String),
    #[error(
        "no node has room for {cpus} CPU / {mem_mib} MiB of host memory / {disk_mib} MiB of \
         disk{disk_note}"
    )]
    NoCapacity {
        cpus: String,
        mem_mib: u64,
        disk_mib: u64,
        /// Which node came closest on disk and what it lacked, when disk is
        /// what ruled the nodes out.
        disk_note: String,
    },
    #[error(
        "no node has template {0:?}; templates are node-local, so build or warm it on a node that can run it"
    )]
    TemplateNotOnAnyNode(String),
    #[error(
        "the private network's other members are on node {0}, which cannot take this sandbox, \
         and no node mesh is configured to reach them from another node; start the nodes with \
         --mesh-endpoint"
    )]
    PeersUnreachable(String),
    #[error("no healthy node enforces {0}")]
    NoNodeWithPolicyFeatures(String),
    #[error("no healthy node can hold the sandbox's host limits: {0}")]
    NoNodeForHostLimits(String),
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

/// The version of `hypervisor` a node runs.
pub fn version_of<'a>(info: &'a NodeInfo, hypervisor: &str) -> &'a str {
    info.hypervisor_versions
        .get(hypervisor)
        .map_or("", String::as_str)
}

/// Whether a node can restore state written by `hypervisor` at `version` on
/// `arch`. Empty wants accept anything.
pub fn can_restore(info: &NodeInfo, arch: &str, hypervisor: &str, version: &str) -> bool {
    (arch.is_empty() || info.arch == arch)
        && (version.is_empty() || version_of(info, hypervisor) == version)
        && offers(info, hypervisor)
}

/// How `have`, a node's CPU, falls short of restoring memory `hypervisor`
/// saved on `want`, or `None` when it does not; see
/// [`common::CpuFingerprint`] for the rule.
pub fn cpu_mismatch(
    want: &common::CpuFingerprint,
    have: Option<&common::CpuFingerprint>,
    hypervisor: &str,
) -> Option<String> {
    let Some(have) = have else {
        return Some("reports no CPU fingerprint".into());
    };
    let mut differences = Vec::new();
    if have.vendor != want.vendor {
        differences.push(format!("has vendor {}, not {}", have.vendor, want.vendor));
    }
    if have.physical_address_bits != want.physical_address_bits {
        differences.push(format!(
            "has {}-bit physical addresses, not {}",
            have.physical_address_bits, want.physical_address_bits
        ));
    }
    let is_superset_enough =
        hypervisor == Hypervisor::CloudHypervisor.as_str() && !want.vendor.starts_with("0x");
    if !is_superset_enough && (have.family, have.model) != (want.family, want.model) {
        differences.push(format!(
            "is family {} model {}, not family {} model {}",
            have.family, have.model, want.family, want.model
        ));
    }
    let lacking: Vec<&str> = want
        .features
        .iter()
        .filter(|f| !have.features.contains(f))
        .map(String::as_str)
        .collect();
    if !lacking.is_empty() {
        differences.push(format!("lacks {}", lacking.join(" ")));
    }
    let adding: Vec<&str> = have
        .features
        .iter()
        .filter(|f| !want.features.contains(f))
        .map(String::as_str)
        .collect();
    if !is_superset_enough && !adding.is_empty() {
        differences.push(format!("adds {}", adding.join(" ")));
    }
    (!differences.is_empty()).then(|| differences.join(", "))
}

/// Whether a node can run sandboxes under `hypervisor`.
pub fn offers(info: &NodeInfo, hypervisor: &str) -> bool {
    info.hypervisors.iter().any(|offered| offered == hypervisor)
}

/// The policy features `network` uses, which a node has to name in
/// `NodeInfo.policy_features` to be given it.
pub fn policy_features(network: Option<&common::NetworkPolicy>) -> Vec<&'static str> {
    use burrow_common::features;
    let Some(network) = network else {
        return Vec::new();
    };
    let mut used = Vec::new();
    if !network.ingress.is_empty() {
        used.push(features::INGRESS);
    }
    used
}

/// The features in `wanted` a node does not enforce.
pub fn missing_features(info: &NodeInfo, wanted: &[&'static str]) -> Vec<&'static str> {
    wanted
        .iter()
        .copied()
        .filter(|feature| !info.policy_features.iter().any(|f| f == feature))
        .collect()
}

/// Why `info`'s node cannot hold the host limits `want` pins: a
/// `cpuset_cpus` naming a CPU it does not have, or a `blkio_weight` without
/// cgroup io.weight. A node that has not reported its CPU count is not ruled
/// out on its cpuset.
pub fn host_limits_gap(info: &NodeInfo, want: &Placement) -> Option<String> {
    if !want.cpuset_cpus.is_empty()
        && info.total_vcpus > 0
        && let Ok(set) = burrow_common::cpu::parse_cpuset(&want.cpuset_cpus)
        && let Some(&last) = set.last()
        && last >= info.total_vcpus
    {
        return Some(format!(
            "has CPUs 0-{}, and cpuset_cpus {:?} names CPU {last}",
            info.total_vcpus - 1,
            want.cpuset_cpus
        ));
    }
    if want.blkio_weight > 0 && !info.is_io_weight_supported {
        return Some(format!(
            "has no cgroup io.weight for blkio_weight {}",
            want.blkio_weight
        ));
    }
    None
}

/// Whether a node carries every label asked for.
fn is_labelled(entry: &NodeEntry, want: &HashMap<String, String>) -> bool {
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
    pub last_heartbeat_at_ms: i64,
    /// Slice of the sandbox address pool this node owns.
    pub index: u32,
    pub wireguard_public_key: String,
    pub wireguard_endpoint: String,
    /// Whether this node has sent a status since registering.
    ///
    /// Without it, "has no templates" and "has not said yet" are the same
    /// empty list, and a node that genuinely holds nothing looks like a
    /// candidate for every template on the fleet.
    pub is_reported: bool,
    /// Capacity other orchestrator replicas have promised on this node since
    /// its last heartbeat, as the store last said, less what they released.
    pub reserved_cpu_millis: i64,
    pub reserved_mem_mib: i64,
}

impl NodeEntry {
    pub fn is_healthy(&self) -> bool {
        self.last_heartbeat.elapsed() < STALE_AFTER
    }

    pub fn is_present(&self) -> bool {
        self.last_heartbeat.elapsed() < ABSENT_AFTER
    }
}

/// In-memory node registry: nodes re-register after an orchestrator restart,
/// because Heartbeat answers `is_reregistration_required` for an id it does not know.
#[derive(Default)]
pub struct NodeRegistry {
    nodes: Mutex<HashMap<String, NodeEntry>>,
    /// Capacity handed out since each node's last heartbeat. Cleared when a
    /// fresh status arrives, which already reflects it.
    pending: Mutex<HashMap<String, Reserved>>,
}

/// What placement charges a sandbox whose policy names no disk. The node
/// gives it the template's image plus 1 GiB, and the image's size is the
/// node's to know, so placement charges the 1 GiB; the node's own admission,
/// which charges the whole disk, is the gate.
pub const DEFAULT_DISK_MIB: u64 = 1024;

/// The disk a sandbox with these resources is provisioned, in bytes.
pub fn disk_bytes(resources: Option<&burrow_proto::common::v1::ResourcePolicy>) -> u64 {
    let mib = match resources.map(|r| r.disk_mib).unwrap_or(0) {
        0 => DEFAULT_DISK_MIB,
        mib => u64::from(mib),
    };
    mib * burrow_common::disk::MIB
}

/// Capacity promised to sandboxes a node has not yet reported, less what
/// sandboxes it did report have given back since: below zero when more was
/// released than placed.
#[derive(Debug, Default, Clone, Copy)]
struct Reserved {
    cpu_millis: i64,
    mem_mib: i64,
    disk_bytes: u64,
}

/// What is promised on a node beyond its last report: this replica's own
/// reservations, or the store's count of every replica's if that is larger.
/// The store's includes this replica's once it has been reloaded, so the two
/// are not added; the store's conditional reservation is the real gate, and
/// this only ranks.
fn held(entry: &NodeEntry, pending: &HashMap<String, Reserved>) -> Reserved {
    let local = pending.get(&entry.info.id).copied().unwrap_or_default();
    Reserved {
        cpu_millis: merged(local.cpu_millis, entry.reserved_cpu_millis),
        mem_mib: merged(local.mem_mib, entry.reserved_mem_mib),
        // The store does not carry disk reservations; the node's own
        // admission is the gate, and this only keeps a burst from piling on.
        disk_bytes: local.disk_bytes,
    }
}

/// The larger of this replica's count and the store's, except that a release
/// both have seen is credited in full: without a store, the store's count
/// stays at zero and would otherwise swallow every release.
fn merged(local: i64, stored: i64) -> i64 {
    if local < 0 && stored <= 0 {
        local.min(stored)
    } else {
        local.max(stored)
    }
}

/// A node's disk as its last heartbeat reported it.
pub fn disk_capacity(status: &NodeStatus) -> burrow_common::disk::DiskCapacity {
    let disk = status.disk.unwrap_or_default();
    burrow_common::disk::DiskCapacity {
        free_bytes: disk.free_bytes,
        total_bytes: disk.total_bytes,
        reserve_bytes: disk.reserve_bytes,
        provisioned_bytes: disk.provisioned_bytes,
        overcommit: disk.overcommit,
    }
}

/// Whether the node has room for the disk, with what is already placed on it
/// since its report. A node that does not report disk is not checked.
fn disk_fit(
    entry: &NodeEntry,
    held: Reserved,
    want: &Placement,
) -> Result<(), burrow_common::disk::Shortfall> {
    disk_capacity(&entry.status).admit(held.disk_bytes.saturating_add(want.disk_bytes))
}

/// Whether a node can take this sandbox without oversubscribing itself.
fn is_fit(entry: &NodeEntry, pending: &HashMap<String, Reserved>, want: &Placement) -> bool {
    let held = held(entry, pending);
    let committed =
        net(entry.status.committed_cpu_millis, held.cpu_millis) + want.cpu_charge_millis();
    // A node that has not reported its cpu count cannot be checked; trusting it
    // beats refusing to place anything on it.
    let cpu_ok =
        entry.info.total_vcpus == 0 || committed <= u64::from(entry.info.total_vcpus) * 1000;
    let mem_ok = free_mem(entry, pending) >= want.mem_charge_mib(&entry.info, &entry.status);
    cpu_ok && mem_ok && disk_fit(entry, held, want).is_ok()
}

/// Reported free memory, less anything placed since that report.
fn free_mem(entry: &NodeEntry, pending: &HashMap<String, Reserved>) -> u64 {
    let held = held(entry, pending);
    net(entry.status.free_mem_mib, -held.mem_mib)
}

/// A reported figure moved by what was reserved or released since.
fn net(reported: u64, held: i64) -> u64 {
    reported.saturating_add_signed(held)
}

/// Whether `entry` holds a warm snapshot of the template and machine `want`
/// asks for. A snapshot of another shape is no use to it: a restore cannot
/// change a guest's vCPUs or memory.
fn holds_warm(entry: &NodeEntry, want: &Placement) -> bool {
    let mem_mib = match want.mem_mib {
        0 => 512,
        mem => mem,
    };
    entry.status.warm_shapes.iter().any(|shape| {
        shape.template == want.template
            && shape.resources.as_ref().is_some_and(|resources| {
                resources.vcpus == want.vcpus.max(1) && u64::from(resources.mem_mib) == mem_mib
            })
    })
}

/// Free fraction of whichever resource this node is tightest on, 0.0 to 1.0.
///
/// Scoring on the minimum rather than on memory alone is the point: it is what
/// stops a node with plenty of free RAM and every core committed from looking
/// like the best place to put more work.
fn headroom(entry: &NodeEntry, pending: &HashMap<String, Reserved>) -> f64 {
    let held = held(entry, pending);
    let cpu_free = if entry.info.total_vcpus == 0 {
        1.0
    } else {
        let committed = net(entry.status.committed_cpu_millis, held.cpu_millis) as f64;
        1.0 - (committed / (f64::from(entry.info.total_vcpus) * 1000.0)).clamp(0.0, 1.0)
    };
    let mem_free = if entry.info.total_mem_mib == 0 {
        1.0
    } else {
        (free_mem(entry, pending) as f64 / entry.info.total_mem_mib as f64).clamp(0.0, 1.0)
    };
    let capacity = disk_capacity(&entry.status);
    let disk_free = burrow_common::disk::DiskCapacity {
        provisioned_bytes: capacity.provisioned_bytes.saturating_add(held.disk_bytes),
        ..capacity
    }
    .headroom();
    cpu_free.min(mem_free).min(disk_free)
}

/// When disk is what kept every candidate out: the one closest to fitting,
/// and what it ran into. Empty when some node had the disk.
fn disk_note(
    candidates: &[&NodeEntry],
    pending: &HashMap<String, Reserved>,
    want: &Placement,
) -> String {
    let mut closest: Option<(&NodeEntry, burrow_common::disk::Shortfall)> = None;
    for entry in candidates {
        match disk_fit(entry, held(entry, pending), want) {
            Ok(()) => return String::new(),
            Err(short) => {
                if closest.is_none_or(|(_, best)| short.bytes < best.bytes) {
                    closest = Some((entry, short));
                }
            }
        }
    }
    match closest {
        Some((entry, short)) => match short.limit {
            burrow_common::disk::Limit::Capacity => format!(
                "; node {} is the closest on disk, short by {} MiB of what it may provision",
                entry.info.id,
                short.mib()
            ),
            burrow_common::disk::Limit::Reserve => format!(
                "; node {} is the closest on disk, {} MiB below its free-disk reserve",
                entry.info.id,
                short.mib()
            ),
        },
        None => String::new(),
    }
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
                last_heartbeat_at_ms: burrow_common::unix_now_ms(),
                index,
                wireguard_public_key,
                wireguard_endpoint,
                // A re-registering node re-reports on its next heartbeat; until
                // then its previous inventory is not carried over.
                is_reported: false,
                reserved_cpu_millis: 0,
                reserved_mem_mib: 0,
            },
        );
        Ok((node_id, index))
    }

    /// Records a registration whose address slice the store already chose.
    ///
    /// With several orchestrator replicas the slice cannot be chosen from one
    /// replica's view of the fleet, so the store decides and this only keeps
    /// the cache in step.
    pub fn register_at(
        &self,
        info: NodeInfo,
        wireguard_public_key: String,
        wireguard_endpoint: String,
        index: u32,
    ) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.retain(|id, entry| id == &info.id || entry.index != index);
        nodes.insert(
            info.id.clone(),
            NodeEntry {
                info,
                status: NodeStatus::default(),
                last_heartbeat: Instant::now(),
                last_heartbeat_at_ms: burrow_common::unix_now_ms(),
                index,
                wireguard_public_key,
                wireguard_endpoint,
                is_reported: false,
                reserved_cpu_millis: 0,
                reserved_mem_mib: 0,
            },
        );
    }

    /// Replaces the cache with the fleet as the store records it, for a
    /// replica catching up with registrations and heartbeats that reached
    /// other replicas.
    ///
    /// A heartbeat is wall-clock milliseconds in the store and an instant
    /// here; a node this replica heard from more recently than the store
    /// says keeps the newer one. A node whose heartbeat moved on has its local
    /// reservations dropped, as a heartbeat arriving here would.
    pub fn reload(&self, rows: Vec<(NodeInfo, NodeStatus, burrow_store::NodeRow)>) {
        let now_ms = burrow_common::unix_now_ms();
        let mut nodes = self.nodes.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();
        let mut fresh = HashMap::new();
        for (info, status, row) in rows {
            let age =
                Duration::from_millis(now_ms.saturating_sub(row.last_heartbeat_ms).max(0) as u64);
            let stored = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
            let previous = nodes.remove(&row.id);
            let last_heartbeat = match &previous {
                Some(held) if held.last_heartbeat > stored => held.last_heartbeat,
                _ => {
                    if previous.is_some() {
                        pending.remove(&row.id);
                    }
                    stored
                }
            };
            let (status, is_reported) = match previous {
                Some(held) if held.last_heartbeat > stored => (held.status, held.is_reported),
                _ => (status, row.is_reported),
            };
            fresh.insert(
                row.id.clone(),
                NodeEntry {
                    info,
                    status,
                    last_heartbeat,
                    last_heartbeat_at_ms: row.last_heartbeat_ms,
                    index: row.index,
                    wireguard_public_key: row.wireguard_public_key,
                    wireguard_endpoint: row.wireguard_endpoint,
                    is_reported,
                    reserved_cpu_millis: row.reserved_cpu_millis,
                    reserved_mem_mib: row.reserved_mem_mib,
                },
            );
        }
        pending.retain(|id, _| fresh.contains_key(id));
        *nodes = fresh;
    }

    /// Whether this replica's cache holds a node, for a heartbeat that may
    /// have registered through another replica.
    pub fn knows(&self, node_id: &str) -> bool {
        self.nodes.lock().unwrap().contains_key(node_id)
    }

    /// Every healthy node except `exclude`, as mesh peers.
    ///
    /// A node with no key is omitted rather than listed unreachable: it cannot
    /// participate, and a peer entry without a key would be meaningless.
    pub fn mesh_peers(&self, exclude: &str) -> Vec<burrow_proto::node::v1::MeshPeer> {
        let nodes = self.nodes.lock().unwrap();
        nodes
            .values()
            .filter(|e| {
                e.info.id != exclude && e.is_healthy() && !e.wireguard_public_key.is_empty()
            })
            .map(|e| burrow_proto::node::v1::MeshPeer {
                node_id: e.info.id.clone(),
                public_key: e.wireguard_public_key.clone(),
                endpoint: e.wireguard_endpoint.clone(),
                subnet: burrow_net::Ipam::for_node(e.index)
                    .expect("register admits only an index the pool holds")
                    .subnet(),
            })
            .collect()
    }

    /// Whether any healthy node other than `exclude` can carry mesh traffic.
    pub fn is_mesh_available(&self, exclude: &str) -> bool {
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
                entry.is_reported = true;
                entry.reserved_cpu_millis = 0;
                entry.reserved_mem_mib = 0;
                entry.last_heartbeat = Instant::now();
                entry.last_heartbeat_at_ms = burrow_common::unix_now_ms();
                drop(nodes);
                self.clear_pending(node_id);
                true
            }
            None => false,
        }
    }

    /// Records that a node was heard from, ahead of the store write that
    /// queues behind a burst's on the pool.
    pub fn touch(&self, node_id: &str) {
        if let Some(entry) = self.nodes.lock().unwrap().get_mut(node_id) {
            entry.last_heartbeat = Instant::now();
            entry.last_heartbeat_at_ms = burrow_common::unix_now_ms();
        }
    }

    /// Moves a node's last heartbeat `by` into the past.
    #[cfg(test)]
    pub fn age(&self, node_id: &str, by: Duration) {
        let mut nodes = self.nodes.lock().unwrap();
        let entry = nodes.get_mut(node_id).unwrap();
        entry.last_heartbeat = Instant::now() - by;
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
        Some(self.nodes.lock().unwrap().get(node_id)?.is_healthy())
    }

    /// Whether a node is unknown or has gone [`ABSENT_AFTER`] without a
    /// heartbeat, as opposed to merely slow.
    pub fn is_absent(&self, node_id: &str) -> bool {
        !self
            .nodes
            .lock()
            .unwrap()
            .get(node_id)
            .is_some_and(NodeEntry::is_present)
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
            .filter(|e| e.is_healthy())
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

    /// What a node said about itself, healthy or not.
    pub fn info(&self, node_id: &str) -> Option<NodeInfo> {
        self.nodes
            .lock()
            .unwrap()
            .get(node_id)
            .map(|e| e.info.clone())
    }

    /// Drops a node entirely, along with anything charged against it.
    pub fn remove_node(&self, node_id: &str) {
        self.nodes.lock().unwrap().remove(node_id);
        self.pending.lock().unwrap().remove(node_id);
    }

    /// A registered node's endpoint whether or not it is answering, for
    /// callers that keep trying until the node is forgotten.
    pub fn endpoint_any(&self, node_id: &str) -> Option<String> {
        let nodes = self.nodes.lock().unwrap();
        Some(format!("http://{}", nodes.get(node_id)?.info.address))
    }

    /// gRPC endpoint for a node, if it is known and not absent.
    pub fn endpoint(&self, node_id: &str) -> Option<String> {
        let nodes = self.nodes.lock().unwrap();
        let entry = nodes.get(node_id)?;
        if !entry.is_present() {
            return None;
        }
        Some(format!("http://{}", entry.info.address))
    }

    /// Picks a node for a new sandbox: not absent, not draining, most free memory.
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
    /// Among eligible nodes, one already holding a warm snapshot of the
    /// template at the shape asked for wins (a ~300ms
    /// create against a ~1.5s one), and the least-loaded node breaks the
    /// remaining ties. "Least loaded" means the node whose *tightest* dimension
    /// has the most headroom: a memory-rich but cpu-saturated node would
    /// otherwise look like the best place for more work.
    pub fn place_for(&self, want: &Placement) -> Result<String, PlacementError> {
        self.place_excluding(want, &std::collections::HashSet::new())
    }

    /// [`place_for`](Self::place_for), passing over `excluded`: nodes another
    /// replica filled between this one's view of them and its reservation.
    pub fn place_excluding(
        &self,
        want: &Placement,
        excluded: &std::collections::HashSet<String>,
    ) -> Result<String, PlacementError> {
        let nodes = self.nodes.lock().unwrap();

        let live: Vec<_> = nodes
            .values()
            .filter(|e| e.is_present() && !e.status.is_draining && !excluded.contains(&e.info.id))
            .collect();
        if live.is_empty() {
            return Err(PlacementError::NoHealthyNode);
        }

        // Applied before the template, so a caller who asked for hardware that
        // does not exist is told that, rather than being told about an image.
        let labelled_live: Vec<_> = live
            .iter()
            .copied()
            .filter(|e| is_labelled(e, &want.node_labels))
            .collect();
        if labelled_live.is_empty() {
            return Err(PlacementError::NoNodeWithLabels(unsatisfied(
                &live,
                &want.node_labels,
            )));
        }
        let live = labelled_live;

        let compatible: Vec<_> = live
            .iter()
            .copied()
            .filter(|e| {
                (want.arch.is_empty() || e.info.arch == want.arch)
                    && (want.hypervisor_version.is_empty()
                        || version_of(&e.info, &want.hypervisor) == want.hypervisor_version)
            })
            .collect();
        if compatible.is_empty() {
            return Err(PlacementError::NoCompatibleNode {
                arch: want.arch.clone(),
                hypervisor: want.hypervisor.clone(),
                version: want.hypervisor_version.clone(),
            });
        }
        let mut live = compatible;

        if let Some(cpu) = &want.cpu {
            let mismatches: Vec<_> = live
                .iter()
                .map(|e| cpu_mismatch(cpu, e.info.cpu.as_ref(), &want.hypervisor))
                .collect();
            if mismatches.iter().all(Option::is_some) {
                let why = live
                    .iter()
                    .zip(mismatches)
                    .map(|(e, why)| format!("node {} {}", e.info.id, why.unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(PlacementError::NoCompatibleCpu(why));
            }
            live = live
                .into_iter()
                .zip(mismatches)
                .filter_map(|(e, why)| why.is_none().then_some(e))
                .collect();
        }

        let offering: Vec<_> = live
            .iter()
            .copied()
            .filter(|e| want.hypervisor.is_empty() || offers(&e.info, &want.hypervisor))
            .collect();
        if offering.is_empty() {
            return Err(PlacementError::NoNodeWithHypervisor(
                want.hypervisor.clone(),
            ));
        }
        let live = offering;

        let enforcing: Vec<_> = live
            .iter()
            .copied()
            .filter(|e| missing_features(&e.info, &want.policy_features).is_empty())
            .collect();
        if enforcing.is_empty() {
            return Err(PlacementError::NoNodeWithPolicyFeatures(
                want.policy_features.join(", "),
            ));
        }
        let live = enforcing;

        let holding: Vec<_> = live
            .iter()
            .copied()
            .filter(|e| host_limits_gap(&e.info, want).is_none())
            .collect();
        if holding.is_empty() {
            return Err(PlacementError::NoNodeForHostLimits(
                live.iter()
                    .filter_map(|e| {
                        Some(format!("{} {}", e.info.id, host_limits_gap(&e.info, want)?))
                    })
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        let live = holding;

        let with_template: Vec<_> = live
            .iter()
            .filter(|e| {
                want.is_template_transfer_allowed
                    || want.template.is_empty()
                    // A node that has not reported yet is given the benefit of
                    // the doubt; one that has is taken at its word.
                    || !e.is_reported
                    || e.status.templates.contains(&want.template)
            })
            .collect();
        if with_template.is_empty() {
            return Err(PlacementError::TemplateNotOnAnyNode(want.template.clone()));
        }

        // Without a mesh, peers on another node are simply unreachable, so
        // co-location is the only correct answer rather than the fast one.
        if let Some(node_id) = &want.prefer_node
            && !want.is_mesh_available
        {
            return with_template
                .iter()
                .find(|e| e.info.id == *node_id)
                .map(|e| e.info.id.clone())
                .ok_or_else(|| PlacementError::PeersUnreachable(node_id.clone()));
        }

        let pending = self.pending.lock().unwrap();
        let candidates: Vec<&NodeEntry> = with_template.iter().map(|e| **e).collect();
        let with_room: Vec<_> = with_template
            .into_iter()
            .filter(|e| is_fit(e, &pending, want))
            .collect();
        if with_room.is_empty() {
            return Err(PlacementError::NoCapacity {
                cpus: cpus_text(want.cpu_charge_millis()),
                mem_mib: candidates
                    .iter()
                    .map(|e| want.mem_charge_mib(&e.info, &e.status))
                    .min()
                    .unwrap_or(want.mem_mib),
                disk_mib: want.disk_bytes.div_ceil(burrow_common::disk::MIB),
                disk_note: disk_note(&candidates, &pending, want),
            });
        }

        let chosen = with_room
            .into_iter()
            .max_by_key(|e| {
                (
                    // A node whose heartbeats are late is busy, so it only
                    // takes what no punctual node can.
                    e.is_healthy(),
                    // Same node as the peers: no encryption, no extra hop.
                    want.prefer_node.as_deref() == Some(e.info.id.as_str()),
                    holds_warm(e, want),
                    // Headroom on the tightest dimension, in thousandths so it
                    // orders as an integer.
                    (headroom(e, &pending) * 1000.0) as i64,
                    // Absolute free memory breaks the remaining ties, and
                    // decides entirely for a node that has not reported its
                    // capacity, where every fraction is 1.0.
                    free_mem(e, &pending),
                )
            })
            .map(|e| (e.info.id.clone(), want.mem_charge_mib(&e.info, &e.status)))
            .ok_or(PlacementError::NoHealthyNode)?;
        drop(pending);

        // Charged immediately rather than waiting for the node's next
        // heartbeat. Placements are far quicker than the heartbeat interval, so
        // without this a burst of concurrent creates all read the same stale
        // status and pile onto whichever node was least loaded a second ago.
        let (chosen, mem_mib) = chosen;
        self.reserve(&chosen, want, mem_mib);
        Ok(chosen)
    }

    /// Charges a placement against a node until its next heartbeat reports it.
    fn reserve(&self, node_id: &str, want: &Placement, mem_mib: u64) {
        let mut pending = self.pending.lock().unwrap();
        let entry = pending.entry(node_id.to_string()).or_default();
        entry.cpu_millis += want.cpu_charge_millis() as i64;
        entry.mem_mib += mem_mib as i64;
        entry.disk_bytes += want.disk_bytes;
    }

    /// What `node_id` is charged for a guest of `mem_mib` from `template`
    /// under `hypervisor`, as [`mem_charge_mib`] reads them.
    pub fn mem_charge_mib(
        &self,
        node_id: &str,
        hypervisor: &str,
        template: &str,
        mem_mib: u64,
    ) -> u64 {
        let nodes = self.nodes.lock().unwrap();
        match nodes.get(node_id) {
            Some(entry) => {
                mem_charge_mib(&entry.info, &entry.status, hypervisor, template, mem_mib)
            }
            None => mem_charge_mib(
                &NodeInfo::default(),
                &NodeStatus::default(),
                hypervisor,
                template,
                mem_mib,
            ),
        }
    }

    /// Charges a node for host CPU a sandbox on it was just given, until its
    /// next heartbeat reports it. The node admitted it already.
    pub fn charge_cpu(&self, node_id: &str, cpu_millis: u64) {
        self.pending
            .lock()
            .unwrap()
            .entry(node_id.to_string())
            .or_default()
            .cpu_millis += cpu_millis as i64;
    }

    /// Charges a node for memory a sandbox on it is about to be given, if the
    /// node has the room a create of that much would need.
    pub fn reserve_growth(&self, node_id: &str, mem_mib: u64) -> bool {
        let nodes = self.nodes.lock().unwrap();
        let Some(entry) = nodes.get(node_id) else {
            return false;
        };
        let mut pending = self.pending.lock().unwrap();
        if free_mem(entry, &pending) < mem_mib {
            return false;
        }
        pending.entry(node_id.to_string()).or_default().mem_mib += mem_mib as i64;
        true
    }

    /// Gives back capacity a sandbox no longer holds, until the node's next
    /// heartbeat reports it gone.
    ///
    /// One placed since that heartbeat takes its reservation back. One the
    /// heartbeat reported is credited instead, so a node is not held full by
    /// a sandbox already deleted or shrunk: a burst of create-then-destroy
    /// would otherwise exhaust a node that is in fact empty.
    pub fn release(&self, node_id: &str, cpu_millis: u64, mem_mib: u64, disk_bytes: u64) {
        let mut pending = self.pending.lock().unwrap();
        let entry = pending.entry(node_id.to_string()).or_default();
        entry.cpu_millis -= cpu_millis as i64;
        entry.mem_mib -= mem_mib as i64;
        entry.disk_bytes = entry.disk_bytes.saturating_sub(disk_bytes);
    }

    /// Moves this replica's copy of the store's reservations by what is
    /// being released there, ahead of the next reload saying so.
    pub fn release_stored(&self, node_id: &str, cpu_millis: u64, mem_mib: u64) {
        if let Some(entry) = self.nodes.lock().unwrap().get_mut(node_id) {
            entry.reserved_cpu_millis -= cpu_millis as i64;
            entry.reserved_mem_mib -= mem_mib as i64;
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

    /// Every node's API address and Access endpoint, for nodes to deny to
    /// their sandboxes. The Access endpoint is listed as well as the address
    /// because it may be another host altogether, a public name in front of a
    /// private one. Unhealthy nodes are included, as for edges.
    pub fn node_hosts(&self) -> Vec<String> {
        let nodes = self.nodes.lock().unwrap();
        let mut hosts: Vec<String> = nodes
            .values()
            .flat_map(|entry| {
                [
                    entry.info.address.clone(),
                    entry.info.access_endpoint.clone(),
                ]
            })
            .filter(|host| !host.is_empty())
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

    /// Whether a node reports `template` as imported from Kits.
    pub fn is_kit_template(&self, node_id: &str, template: &str) -> bool {
        self.nodes
            .lock()
            .unwrap()
            .get(node_id)
            .is_some_and(|e| e.status.kit_templates.iter().any(|t| t == template))
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
            .find(|e| e.is_healthy() && e.status.templates.iter().any(|t| t == template))
            .map(|e| (e.info.id.clone(), e.info.address.clone()))
    }

    /// Records a drain decision immediately, rather than waiting for the
    /// node's next heartbeat to report it.
    pub fn set_draining(&self, node_id: &str, draining: bool) {
        if let Some(entry) = self.nodes.lock().unwrap().get_mut(node_id) {
            entry.status.is_draining = draining;
        }
    }

    /// Whether every healthy node offers the same hypervisors, in which case
    /// one holding a template can run it and placement need not ask which.
    pub fn is_uniform_in_hypervisors(&self) -> bool {
        let nodes = self.nodes.lock().unwrap();
        let mut offered = nodes.values().filter(|e| e.is_healthy()).map(|e| {
            let mut list = e.info.hypervisors.clone();
            list.sort();
            list
        });
        let Some(first) = offered.next() else {
            return true;
        };
        offered.all(|list| list == first)
    }

    pub fn snapshot(&self) -> Vec<burrow_proto::api::v1::Node> {
        let nodes = self.nodes.lock().unwrap();
        let mut out: Vec<_> = nodes
            .values()
            .map(|e| burrow_proto::api::v1::Node {
                info: Some(e.info.clone()),
                status: Some(e.status.clone()),
                is_healthy: e.is_healthy(),
                last_heartbeat_at_unix_ms: e.last_heartbeat_at_ms,
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
                    hypervisors: vec!["firecracker".into()],
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

    /// A node's Access endpoint is denied to sandboxes whether or not it runs
    /// an edge, and so is its API address.
    #[test]
    fn every_node_s_api_and_access_endpoint_are_listed() {
        let registry = registry(&[("node-a", NodeStatus::default())]);
        registry.heartbeat(
            "node-a",
            NodeStatus::default(),
            Some(NodeInfo {
                id: "node-a".into(),
                address: "10.0.0.5:7071".into(),
                access_endpoint: "https://node-a.example.com:7073".into(),
                ..Default::default()
            }),
        );
        assert_eq!(
            registry.node_hosts(),
            ["10.0.0.5:7071", "https://node-a.example.com:7073"]
        );
        assert!(registry.edge_hosts().is_empty());
    }

    /// A node whose heartbeats arrive late is busy, not gone: it is still
    /// called and placed on, after every punctual node, until it has been
    /// silent long enough to be absent.
    #[test]
    fn a_late_node_is_placed_on_after_punctual_ones_until_it_is_absent() {
        let registry = registry(&[
            ("node-a", NodeStatus::default()),
            ("node-b", NodeStatus::default()),
        ]);
        label(&registry, "node-a", &[("cpu", "modern")]);
        label(&registry, "node-b", &[("cpu", "modern")]);
        let late = STALE_AFTER + Duration::from_secs(5);
        registry.age("node-a", late);
        assert_eq!(registry.health("node-a"), Some(false));
        assert!(!registry.is_absent("node-a"));
        assert!(registry.endpoint("node-a").is_some());

        let want = Placement {
            node_labels: wants(&[("cpu", "modern")]),
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "node-b");
        registry.age("node-b", late);
        label(&registry, "node-b", &[("cpu", "legacy")]);
        assert_eq!(registry.place_for(&want).unwrap(), "node-a");

        registry.age("node-a", ABSENT_AFTER);
        assert!(registry.is_absent("node-a"));
        assert!(registry.endpoint("node-a").is_none());
        let err = registry.place_for(&want).unwrap_err();
        assert!(matches!(err, PlacementError::NoNodeWithLabels(_)), "{err}");
        assert!(registry.is_absent("node-c"));
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
            warm_shapes: warm
                .iter()
                .map(|t| burrow_proto::common::v1::WarmShape {
                    template: (*t).to_string(),
                    resources: Some(burrow_proto::common::v1::ResourcePolicy {
                        vcpus: 1,
                        mem_mib: 512,
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
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
        assert!(!registry.is_mesh_available("other"));
    }

    /// A snapshot fetched from the object store only restores under the
    /// Firecracker and architecture that wrote it, so placement of one is
    /// limited to nodes that match, whatever their capacity.
    #[test]
    fn a_snapshot_is_placed_only_on_a_node_that_can_restore_it() {
        let registry = registry(&[("a", status(&[], &[], 9999)), ("b", status(&[], &[], 1000))]);
        for (id, version) in [("a", "v1.15.0"), ("b", "v1.16.1")] {
            registry.heartbeat(
                id,
                status(&[], &[], if id == "a" { 9999 } else { 1000 }),
                Some(NodeInfo {
                    id: id.into(),
                    address: format!("{id}:7071"),
                    arch: "aarch64".into(),
                    hypervisors: vec!["firecracker".into()],
                    hypervisor_versions: [("firecracker".to_string(), version.to_string())].into(),
                    ..Default::default()
                }),
            );
        }
        let want = Placement {
            arch: "aarch64".into(),
            hypervisor: "firecracker".into(),
            hypervisor_version: "v1.16.1".into(),
            vcpus: 1,
            mem_mib: 1,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "b");
        let none = registry.place_for(&Placement {
            hypervisor_version: "v2.0.0".into(),
            ..want
        });
        assert!(matches!(none, Err(PlacementError::NoCompatibleNode { .. })));
    }

    fn cpu(features: &[&str], address_bits: u32) -> common::CpuFingerprint {
        common::CpuFingerprint {
            vendor: "GenuineIntel".into(),
            family: 6,
            model: 0x55,
            features: features.iter().map(|f| f.to_string()).collect(),
            physical_address_bits: address_bits,
        }
    }

    /// Cloud Hypervisor restores where every feature the guest may use is
    /// offered, and checks so itself; Firecracker does not check, so it is
    /// held to the same CPU. Device memory is laid out under the address
    /// width, so neither restores at another.
    #[test]
    fn saved_memory_restores_only_on_a_compatible_cpu() {
        let ch = "cloud-hypervisor";
        let fc = "firecracker";
        let modern = cpu(&["avx", "avx2", "avx512f"], 46);
        let legacy = cpu(&["avx"], 46);
        assert_eq!(cpu_mismatch(&legacy, Some(&modern), ch), None);
        assert_eq!(
            cpu_mismatch(&modern, Some(&legacy), ch).as_deref(),
            Some("lacks avx2 avx512f")
        );
        assert_eq!(
            cpu_mismatch(&legacy, Some(&modern), fc).as_deref(),
            Some("adds avx2 avx512f")
        );
        assert_eq!(cpu_mismatch(&modern, Some(&modern), fc), None);
        assert_eq!(
            cpu_mismatch(&cpu(&["avx"], 44), Some(&legacy), ch).as_deref(),
            Some("has 46-bit physical addresses, not 44")
        );
        let amd = common::CpuFingerprint {
            vendor: "AuthenticAMD".into(),
            ..modern.clone()
        };
        assert!(
            cpu_mismatch(&legacy, Some(&amd), ch)
                .unwrap()
                .contains("vendor")
        );
        let arm = common::CpuFingerprint {
            vendor: "0x41".into(),
            ..legacy.clone()
        };
        let newer_arm = common::CpuFingerprint {
            model: 0xd40,
            ..arm.clone()
        };
        assert!(
            cpu_mismatch(&arm, Some(&newer_arm), ch)
                .unwrap()
                .contains("model")
        );
        assert_eq!(
            cpu_mismatch(&legacy, None, ch).as_deref(),
            Some("reports no CPU fingerprint")
        );
    }

    #[test]
    fn a_memory_restore_is_placed_only_on_a_compatible_cpu() {
        let registry = registry(&[("a", status(&[], &[], 9999)), ("b", status(&[], &[], 1000))]);
        for (id, fingerprint) in [("a", cpu(&["avx"], 44)), ("b", cpu(&["avx", "avx2"], 46))] {
            registry.heartbeat(
                id,
                status(&[], &[], if id == "a" { 9999 } else { 1000 }),
                Some(NodeInfo {
                    id: id.into(),
                    address: format!("{id}:7071"),
                    hypervisors: vec!["cloud-hypervisor".into()],
                    cpu: Some(fingerprint),
                    ..Default::default()
                }),
            );
        }
        let want = Placement {
            hypervisor: "cloud-hypervisor".into(),
            cpu: Some(cpu(&["avx"], 46)),
            vcpus: 1,
            mem_mib: 1,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "b");
        let err = registry
            .place_for(&Placement {
                cpu: Some(cpu(&["avx", "avx512f"], 46)),
                ..want.clone()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoCompatibleCpu(_)), "{err}");
        assert!(err.to_string().contains("node b lacks avx512f"), "{err}");
        assert!(
            err.to_string()
                .contains("node a has 44-bit physical addresses, not 46"),
            "{err}"
        );
        // A disk boot asks for no CPU.
        assert_eq!(
            registry
                .place_for(&Placement { cpu: None, ..want })
                .unwrap(),
            "a"
        );
    }

    /// Cloud Hypervisor state names Cloud Hypervisor's version. Compared with
    /// the node's Firecracker version instead, it matched nothing, and a move
    /// to a node running the same Cloud Hypervisor was refused.
    #[test]
    fn state_is_matched_against_the_version_of_its_own_hypervisor() {
        let registry = registry(&[("a", status(&[], &[], 9999))]);
        registry.heartbeat(
            "a",
            status(&[], &[], 9999),
            Some(NodeInfo {
                id: "a".into(),
                address: "a:7071".into(),
                arch: "aarch64".into(),
                hypervisors: vec!["firecracker".into(), "cloud-hypervisor".into()],
                hypervisor_versions: [
                    ("firecracker".to_string(), "v1.16.1".to_string()),
                    ("cloud-hypervisor".to_string(), "v54.0".to_string()),
                ]
                .into(),
                ..Default::default()
            }),
        );
        let want = Placement {
            arch: "aarch64".into(),
            hypervisor: "cloud-hypervisor".into(),
            hypervisor_version: "v54.0".into(),
            vcpus: 1,
            mem_mib: 1,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "a");
        let newer = registry.place_for(&Placement {
            hypervisor_version: "v55.0".into(),
            ..want
        });
        assert!(matches!(
            newer,
            Err(PlacementError::NoCompatibleNode { .. })
        ));
    }

    fn offering(registry: &NodeRegistry, id: &str, hypervisors: &[&str]) {
        registry.heartbeat(
            id,
            status(&["t"], &[], 9999),
            Some(NodeInfo {
                id: id.into(),
                address: format!("{id}:7071"),
                hypervisors: hypervisors.iter().map(|h| (*h).to_string()).collect(),
                ..Default::default()
            }),
        );
    }

    /// A template's hypervisor is as hard a requirement as its presence: a
    /// node without it could only refuse the create.
    #[test]
    fn a_sandbox_is_placed_only_where_its_hypervisor_is_offered() {
        let registry = registry(&[
            ("a", status(&["t"], &[], 9999)),
            ("b", status(&["t"], &[], 1)),
        ]);
        offering(&registry, "a", &["firecracker"]);
        offering(&registry, "b", &["firecracker", "cloud-hypervisor"]);
        let want = Placement {
            template: "t".into(),
            hypervisor: "cloud-hypervisor".into(),
            vcpus: 1,
            mem_mib: 1,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "b");
        assert!(!registry.is_uniform_in_hypervisors());

        let none = registry.place_for(&Placement {
            hypervisor: "kvmtool".into(),
            ..want
        });
        assert!(matches!(none, Err(PlacementError::NoNodeWithHypervisor(_))));
    }

    /// A policy using a field an old node would drop is placed only on a node
    /// that names it, and one using none of them anywhere.
    #[test]
    fn a_policy_is_placed_only_where_its_fields_are_enforced() {
        use burrow_common::features;
        let registry = registry(&[
            ("old", status(&["t"], &[], 9999)),
            ("new", status(&["t"], &[], 1000)),
        ]);
        registry.heartbeat(
            "new",
            status(&["t"], &[], 1000),
            Some(NodeInfo {
                id: "new".into(),
                address: "new:7071".into(),
                policy_features: features::ALL.iter().map(|f| f.to_string()).collect(),
                ..Default::default()
            }),
        );
        let network = common::NetworkPolicy {
            mode: common::NetworkMode::Open as i32,
            is_tls_inspected: true,
            deny_ports: vec![common::PortRule {
                port: 25,
                ..Default::default()
            }],
            is_ipv6_denied: true,
            ingress: vec![common::IngressRule::default()],
            ..Default::default()
        };
        let used = policy_features(Some(&network));
        assert_eq!(used, [features::INGRESS]);
        let want = Placement {
            template: "t".into(),
            vcpus: 1,
            mem_mib: 1,
            policy_features: used,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "new");
        assert_eq!(
            registry
                .place_for(&Placement {
                    policy_features: Vec::new(),
                    ..want.clone()
                })
                .unwrap(),
            "old"
        );

        registry.heartbeat(
            "new",
            status(&["t"], &[], 1),
            Some(NodeInfo {
                id: "new".into(),
                address: "new:7071".into(),
                ..Default::default()
            }),
        );
        assert!(matches!(
            registry.place_for(&want),
            Err(PlacementError::NoNodeWithPolicyFeatures(_))
        ));
        assert!(policy_features(Some(&common::NetworkPolicy::default())).is_empty());
    }

    #[test]
    fn a_node_reporting_no_hypervisors_runs_none() {
        let none = NodeInfo::default();
        assert!(!offers(&none, "firecracker"));
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
                is_mesh_available: false,
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
                is_mesh_available: false,
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
                is_mesh_available: false,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(placed, "warm");
    }

    /// A snapshot of the template at another shape cannot be restored for
    /// this create, so it is no reason to prefer the node.
    #[test]
    fn a_node_warm_at_another_shape_does_not_win() {
        let registry = registry(&[
            ("cold", status(&["t"], &[], 9999)),
            ("warm", status(&["t"], &["t"], 1)),
        ]);
        let placed = registry
            .place_for(&Placement {
                template: "t".into(),
                vcpus: 2,
                mem_mib: 2048,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(placed, "cold");
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
                is_mesh_available: false,
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
                is_mesh_available: false,
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
                    is_mesh_available: true,
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
                    is_mesh_available: true,
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
        draining.is_draining = true;
        let registry = registry(&[("a", draining), ("b", status(&["t"], &[], 1))]);
        assert_eq!(
            registry
                .place_for(&Placement {
                    template: "t".into(),
                    prefer_node: None,
                    is_mesh_available: false,
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
                    committed_cpu_millis: 16_000,
                    ..Default::default()
                },
            ),
            (
                "roomy-cpu",
                NodeStatus {
                    free_mem_mib: 8_000,
                    committed_cpu_millis: 1000,
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
                committed_cpu_millis: 8000,
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
                committed_cpu_millis: 1000,
                ..Default::default()
            },
            None,
        );
        registry
            .place_for(&want)
            .expect("heartbeat should clear the reservation");
    }

    /// A sandbox the last heartbeat reported frees its share once it is
    /// deleted or shrunk, not once the next heartbeat says so.
    #[test]
    fn a_release_after_a_heartbeat_frees_the_node_at_once() {
        let registry = registry(&[(
            "only",
            NodeStatus {
                free_mem_mib: 1_000,
                committed_cpu_millis: 7_000,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "only", 8, 8_000);
        let want = Placement {
            vcpus: 2,
            mem_mib: 1_500,
            ..Default::default()
        };
        let charge = registry.mem_charge_mib("only", "", "", 1_500);
        assert!(registry.place_for(&want).is_err());

        registry.release("only", 2_000, charge, 0);
        registry
            .place_for(&want)
            .expect("the release should free the node");
        assert!(registry.place_for(&want).is_err());

        registry.heartbeat(
            "only",
            NodeStatus {
                free_mem_mib: 1_000,
                committed_cpu_millis: 7_000,
                ..Default::default()
            },
            None,
        );
        assert!(
            registry.place_for(&want).is_err(),
            "a heartbeat ends the credit"
        );
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
                    is_template_transfer_allowed: true,
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

    /// A node is charged a guest's whole cgroup ceiling, with the VMM
    /// overhead that node reports, so the books match the cap it enforces.
    #[test]
    fn a_guest_is_charged_its_memory_ceiling() {
        let registry = registry(&[("only", status(&[], &[], 600))]);
        let want = Placement {
            vcpus: 1,
            mem_mib: 512,
            ..Default::default()
        };
        assert_eq!(registry.mem_charge_mib("only", "", "", 512), 512 + 64 + 4);
        assert_eq!(registry.place_for(&want).unwrap(), "only");
        registry.release("only", want.cpu_charge_millis(), 580, 0);

        registry.heartbeat(
            "only",
            status(&[], &[], 600),
            Some(NodeInfo {
                id: "only".into(),
                address: "only:7071".into(),
                hypervisors: vec!["firecracker".into()],
                vmm_memory_overhead_mib: [("firecracker".to_string(), 128)].into(),
                ..Default::default()
            }),
        );
        assert_eq!(registry.mem_charge_mib("only", "", "", 512), 512 + 128 + 4);
        assert!(registry.place_for(&want).is_err());
    }

    /// A create that names no hypervisor, as every create does on a fleet
    /// offering the same ones, is charged the ceiling of the hypervisor the
    /// node runs its template under, and a node without the template the
    /// costliest it offers.
    #[test]
    fn a_template_is_charged_the_ceiling_of_its_own_hypervisor() {
        use burrow_common::hypervisor::Hypervisor;
        let both = |id: &str| NodeInfo {
            id: id.into(),
            address: format!("{id}:7071"),
            hypervisors: vec!["firecracker".into(), "cloud-hypervisor".into()],
            ..Default::default()
        };
        let holding = NodeStatus {
            template_hypervisors: [("alpine-ch".to_string(), "cloud-hypervisor".to_string())]
                .into(),
            ..status(&["alpine-ch"], &[], 64_000)
        };
        let registry = registry(&[("holder", holding.clone())]);
        registry.heartbeat("holder", holding, Some(both("holder")));
        let ceiling = |hypervisor: Hypervisor| {
            u64::from(hypervisor.memory_ceiling_mib(512, hypervisor.default_vmm_overhead_mib()))
        };
        let want = Placement {
            template: "alpine-ch".into(),
            vcpus: 1,
            mem_mib: 512,
            ..Default::default()
        };
        assert_eq!(
            registry.mem_charge_mib("holder", "", "alpine-ch", 512),
            ceiling(Hypervisor::CloudHypervisor)
        );
        assert_eq!(registry.place_for(&want).unwrap(), "holder");
        let info = both("other");
        assert_eq!(
            want.mem_charge_mib(&info, &status(&[], &[], 64_000)),
            ceiling(Hypervisor::CloudHypervisor).max(ceiling(Hypervisor::Firecracker))
        );
    }

    /// A sandbox pinned to host CPUs goes only where every one exists, and
    /// one with an IO weight only where cgroup io.weight does; with neither
    /// anywhere, the refusal names each node and what it lacks.
    #[test]
    fn host_limits_rule_out_nodes_that_cannot_hold_them() {
        let registry = registry(&[
            ("small", status(&["t"], &[], 64_000)),
            ("large", status(&["t"], &[], 1_000)),
        ]);
        set_capacity(&registry, "small", 2, 64_000);
        set_capacity(&registry, "large", 8, 64_000);
        registry
            .nodes
            .lock()
            .unwrap()
            .get_mut("small")
            .unwrap()
            .info
            .is_io_weight_supported = true;
        let pinned = Placement {
            template: "t".into(),
            cpuset_cpus: "4-5".into(),
            ..Default::default()
        };
        assert_eq!(registry.place_for(&pinned).unwrap(), "large");
        let weighted = Placement {
            template: "t".into(),
            blkio_weight: 500,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&weighted).unwrap(), "small");

        let neither = Placement {
            template: "t".into(),
            cpuset_cpus: "4-5".into(),
            blkio_weight: 500,
            ..Default::default()
        };
        let err = registry.place_for(&neither).unwrap_err();
        assert!(
            matches!(err, PlacementError::NoNodeForHostLimits(_)),
            "{err}"
        );
        let text = err.to_string();
        assert!(text.contains("small has CPUs 0-1"), "{text}");
        assert!(text.contains("large has no cgroup io.weight"), "{text}");
    }

    /// A sandbox with a reservation is charged it, not its vCPUs or its cap:
    /// two 8-vCPU sandboxes reserving 4 CPUs each fill an 8-CPU node.
    #[test]
    fn a_reserved_sandbox_is_charged_its_reservation() {
        let registry = registry(&[(
            "xxl",
            NodeStatus {
                free_mem_mib: 64_000,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "xxl", 8, 64_000);
        let want = Placement {
            vcpus: 8,
            reserved_cpus: 4.0,
            mem_mib: 512,
            ..Default::default()
        };
        assert_eq!(want.cpu_charge_millis(), 4000);
        for _ in 0..2 {
            assert_eq!(registry.place_for(&want).unwrap(), "xxl");
        }
        assert!(registry.place_for(&want).is_err());
    }

    /// A sandbox capped below its vCPUs is charged its cap: four 2-vCPU
    /// sandboxes at half a CPU each fit a 2-CPU node, and a fifth does not.
    /// Committed CPU a node reports counts the same way.
    #[test]
    fn a_capped_sandbox_is_charged_its_cap() {
        let registry = registry(&[(
            "small",
            NodeStatus {
                free_mem_mib: 64_000,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "small", 2, 64_000);
        let want = Placement {
            vcpus: 2,
            cpus: 0.5,
            mem_mib: 512,
            ..Default::default()
        };
        assert_eq!(want.cpu_charge_millis(), 500);
        for _ in 0..4 {
            assert_eq!(registry.place_for(&want).unwrap(), "small");
        }
        let err = registry.place_for(&want).unwrap_err();
        assert!(err.to_string().contains("0.5 CPU"), "{err}");

        registry.heartbeat(
            "small",
            NodeStatus {
                free_mem_mib: 64_000,
                committed_cpu_millis: 1_500,
                ..Default::default()
            },
            None,
        );
        assert!(registry.place_for(&want).is_ok());
        let uncapped = Placement {
            vcpus: 2,
            mem_mib: 512,
            ..Default::default()
        };
        assert!(registry.place_for(&uncapped).is_err());
    }

    /// Memory a running sandbox grows by is charged like a create, so a node
    /// short of it is refused and a concurrent create sees what it took.
    #[test]
    fn growth_is_charged_against_free_memory() {
        let registry = registry(&[("only", status(&[], &[], 4_000))]);
        assert!(registry.reserve_growth("only", 3_000));
        assert!(!registry.reserve_growth("only", 2_000));
        let want = Placement {
            vcpus: 1,
            mem_mib: 1_500,
            ..Default::default()
        };
        assert!(registry.place_for(&want).is_err());
        registry.release("only", 0, 3_000, 0);
        assert_eq!(registry.place_for(&want).unwrap(), "only");
        assert!(!registry.reserve_growth("missing", 1));
    }

    /// A reservation covers the window before a node reports the sandbox. If
    /// the sandbox is destroyed inside that window the charge has to come
    /// back, or a burst of create-then-destroy exhausts an empty node.
    #[test]
    fn a_released_placement_gives_its_capacity_back() {
        let registry = registry(&[(
            "only",
            NodeStatus {
                free_mem_mib: 3_500,
                ..Default::default()
            },
        )]);
        set_capacity(&registry, "only", 2, 8_000);

        // Two of these, at 1,572 MiB each with the VMM and page tables, fit in
        // the reported 3,500 MiB; a third does not.
        let want = Placement {
            vcpus: 1,
            mem_mib: 1_500,
            ..Default::default()
        };
        registry.place_for(&want).unwrap();
        registry.place_for(&want).unwrap();
        assert!(registry.place_for(&want).is_err());

        let charged =
            registry.mem_charge_mib("only", &want.hypervisor, &want.template, want.mem_mib);
        registry.release("only", want.cpu_charge_millis(), charged, want.disk_bytes);
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
        registry.release("only", 99, 99_999, u64::MAX);
        registry.release("only", 1, 1, 1);
        registry
            .place_for(&Placement {
                vcpus: 1,
                mem_mib: 100,
                ..Default::default()
            })
            .expect("an unknown release must not corrupt the ledger");
    }

    const GIB: u64 = 1 << 30;

    fn disk(free_gib: u64, provisioned_gib: u64, overcommit: f64) -> NodeStatus {
        NodeStatus {
            free_mem_mib: 64_000,
            disk: Some(burrow_proto::common::v1::DiskCapacity {
                free_bytes: free_gib * GIB,
                total_bytes: 100 * GIB,
                reserve_bytes: 5 * GIB,
                provisioned_bytes: provisioned_gib * GIB,
                overcommit,
            }),
            ..Default::default()
        }
    }

    /// A disk within what a node may provision is placed there.
    #[test]
    fn a_disk_that_fits_is_placed() {
        let registry = registry(&[("a", disk(50, 20, 1.0))]);
        let want = Placement {
            disk_bytes: 25 * GIB,
            ..Default::default()
        };
        assert_eq!(registry.place_for(&want).unwrap(), "a");
    }

    /// One past what every node may provision is refused as a capacity
    /// problem, naming the node that came closest and what it lacked.
    #[test]
    fn a_disk_that_fits_nowhere_is_refused_with_the_shortfall() {
        let registry = registry(&[("a", disk(50, 70, 1.0)), ("b", disk(90, 71, 1.0))]);
        let err = registry
            .place_for(&Placement {
                disk_bytes: 26 * GIB,
                ..Default::default()
            })
            .unwrap_err();
        assert!(matches!(err, PlacementError::NoCapacity { .. }), "{err}");
        let message = err.to_string();
        assert!(message.contains("26624 MiB of disk"), "{message}");
        assert!(
            message.contains("node a is the closest on disk"),
            "{message}"
        );
        assert!(message.contains("short by 1024 MiB"), "{message}");
        // A node under its reserve says that instead.
        let low = self::registry(&[("c", disk(4, 0, 1.0))])
            .place_for(&Placement {
                disk_bytes: GIB,
                ..Default::default()
            })
            .unwrap_err()
            .to_string();
        assert!(low.contains("below its free-disk reserve"), "{low}");
        // As the API answers it.
        assert_eq!(
            crate::api::placement_status(err).code(),
            tonic::Code::ResourceExhausted
        );
    }

    /// The node's overcommit is honoured, as the node itself applies it.
    #[test]
    fn a_nodes_disk_overcommit_lets_it_take_more() {
        let want = Placement {
            disk_bytes: 60 * GIB,
            ..Default::default()
        };
        assert!(
            registry(&[("a", disk(50, 40, 1.0))])
                .place_for(&want)
                .is_err()
        );
        assert_eq!(
            registry(&[("a", disk(50, 40, 2.0))])
                .place_for(&want)
                .unwrap(),
            "a"
        );
    }

    /// Placements since the last heartbeat count against the disk too, or a
    /// burst of creates all fits into the same room.
    #[test]
    fn disk_placed_since_the_last_heartbeat_is_counted() {
        let registry = registry(&[("a", disk(30, 66, 1.0))]);
        let want = Placement {
            disk_bytes: 10 * GIB,
            ..Default::default()
        };
        registry.place_for(&want).unwrap();
        registry.place_for(&want).unwrap();
        assert!(registry.place_for(&want).is_err());
        let charged = registry.mem_charge_mib("a", &want.hypervisor, &want.template, want.mem_mib);
        registry.release("a", want.cpu_charge_millis(), charged, want.disk_bytes);
        assert_eq!(registry.place_for(&want).unwrap(), "a");
    }

    /// A node with more disk headroom wins when everything else is equal.
    #[test]
    fn the_node_with_less_provisioned_disk_is_preferred() {
        let registry = registry(&[("full", disk(90, 80, 1.0)), ("empty", disk(90, 0, 1.0))]);
        assert_eq!(
            registry
                .place_for(&Placement {
                    disk_bytes: GIB,
                    ..Default::default()
                })
                .unwrap(),
            "empty"
        );
    }

    /// A node that does not report disk, one that cannot measure it, is not
    /// checked.
    #[test]
    fn a_node_that_does_not_report_disk_is_trusted() {
        let registry = registry(&[("old", status(&[], &[], 64_000))]);
        assert_eq!(
            registry
                .place_for(&Placement {
                    disk_bytes: 1 << 50,
                    ..Default::default()
                })
                .unwrap(),
            "old"
        );
    }

    #[test]
    fn a_sandbox_without_a_disk_size_is_charged_the_default() {
        assert_eq!(disk_bytes(None), 1024 * burrow_common::disk::MIB);
        assert_eq!(
            disk_bytes(Some(&burrow_proto::common::v1::ResourcePolicy {
                disk_mib: 4096,
                ..Default::default()
            })),
            4096 * burrow_common::disk::MIB
        );
    }
}
