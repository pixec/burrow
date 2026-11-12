//! Node-local sandbox lifecycle.
//!
//! Owns the microVMs running on this node: creating their working directories,
//! booting them, holding the agent connection, and tearing them down.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::{Status, transport::Channel};

use burrow_common::cpu::cpus_text;
use burrow_net::{Ipam, Lease, firewall, tap};
use burrow_proto::common::v1 as common;
use burrow_proto::guest::v1::guest_client::GuestClient;
use burrow_vmm::{DriveSpec, GuestAddr, Hypervisor, HypervisorExt, Layout, NetSpec, Vm, VmSpec};

use crate::guestconn;
use crate::rootdisk::IMAGE as TEMPLATE_ROOTFS;
use burrow_proto::api::v1::{LimitsOutcome, ResourceChange, ResourceOutcome};

/// Conventional filenames inside a template directory.
const TEMPLATE_KERNEL: &str = "vmlinux";

/// A volume's image, hard-linked into the sandbox's working directory.
///
/// Linked rather than referenced in place because firecracker takes drive
/// paths relative to the VM's working directory, which under the jailer is the
/// chroot: a path outside it does not exist as far as the VMM is concerned.
/// The link shares the inode, so the volume's bytes are not copied and
/// removing the sandbox's directory does not remove the volume.
fn volume_image(index: usize) -> String {
    match cfg!(target_os = "macos") {
        true => format!("volume{index}.img"),
        false => format!("volume{index}.ext4"),
    }
}

/// Has the guest write what it holds in memory back to its disks, so a VMM
/// killed next leaves them as the guest last saw them. Best effort: a guest
/// that has stopped answering is stopped all the same.
async fn flush_guest(sandbox: &RunningSandbox) {
    let cmd: &[&str] = match burrow_vmm::GuestOs::from_record(&sandbox.record().guest_os) {
        Some(burrow_vmm::GuestOs::Windows) => &[
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Volume | Where-Object FileSystem -eq NTFS | Write-VolumeCache -ErrorAction SilentlyContinue",
        ],
        _ => &["sync"],
    };
    let start = burrow_proto::guest::v1::ExecStart {
        cmd: cmd.iter().map(|arg| arg.to_string()).collect(),
        ..Default::default()
    };
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        guestconn::run_to_completion(sandbox, start),
    )
    .await;
}

/// Runs `capture` with the guest's filesystems at `paths` frozen through its
/// agent: synced, clean and still until the thaw. A guest that cannot freeze
/// them is synced instead, and the capture is what a power cut would leave.
/// Returns what `capture` did, how long the guest's writes were held, and
/// whether they were frozen.
async fn with_frozen<T>(
    sandbox: &RunningSandbox,
    paths: Vec<String>,
    capture: impl std::future::Future<Output = T>,
) -> (T, std::time::Duration, bool) {
    use burrow_proto::guest::v1::{RootDiskRequest, root_disk_request::Op};
    let request = |op: Op| RootDiskRequest {
        op: op as i32,
        paths: paths.clone(),
        ..Default::default()
    };
    let started = std::time::Instant::now();
    let frozen = match sandbox.agent().await {
        Ok(mut agent) => matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                agent.root_disk(request(Op::Freeze)),
            )
            .await,
            Ok(Ok(_))
        ),
        Err(_) => false,
    };
    if !frozen {
        flush_guest(sandbox).await;
    }
    let held = std::time::Instant::now();
    let out = capture.await;
    if frozen {
        let mut thawed = false;
        for _ in 0..5 {
            if let Ok(mut agent) = sandbox.agent().await
                && agent.root_disk(request(Op::Thaw)).await.is_ok()
            {
                thawed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        if !thawed {
            tracing::error!(
                sandbox = sandbox.id(),
                ?paths,
                "could not thaw the guest's filesystems after a capture; writes to them block \
                 until it is restarted"
            );
        }
    }
    let took = match frozen {
        true => started.elapsed(),
        false => held.elapsed(),
    };
    (out, took, frozen)
}

/// Range the node draws from when a caller does not request a specific host
/// port. Deliberately above the ephemeral range used for outbound sockets so
/// published ports cannot collide with the host's own connections.
const HOST_PORT_RANGE: std::ops::Range<u16> = 20000..30000;

#[derive(Clone)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub firecracker_bin: PathBuf,
    /// Appended to every guest kernel command line.
    pub extra_boot_args: String,
    /// Boots every guest with a verbose console, as a create can ask for one.
    pub is_console_verbose: bool,
    pub agent_timeout: std::time::Duration,
    /// How a command's log rotates when its exec does not say.
    pub command_log_rotation: burrow_common::cmdlog::Rotation,
    /// cgroup2 mount point; `None` disables resource limits entirely.
    pub cgroup_root: Option<PathBuf>,
    pub is_resource_limits_required: bool,
    /// Serve restored guest memory on demand rather than paging the whole
    /// snapshot in. What a sandbox never touches then costs nothing, and
    /// sandboxes restored from one template share the backing page cache.
    pub is_memory_lazy: bool,
    /// Confines each VMM to a chroot under an unprivileged uid, for the
    /// hypervisors that can be jailed. `None` runs every VMM as root with the
    /// whole host visible.
    pub jail: Option<burrow_vmm::Jail>,
    /// How Cloud Hypervisor runs here, whether or not it is enabled: a
    /// sandbox recovered from a run that had it still needs a backend to
    /// describe its VM with, even if all it can then do is fail to resume.
    pub cloud_hypervisor: burrow_vmm::CloudHypervisorConfig,
    /// The hypervisors this node offers, as it advertises them. A template or
    /// sandbox needing another is refused.
    pub hypervisors: Vec<Hypervisor>,
    /// Whether a guest here can be given nested virtualization: a hypervisor
    /// that can show it the extensions, on a KVM with nesting on.
    pub is_nested_virt_supported: bool,
    /// Host memory each hypervisor's VMM is allowed beyond its guest
    /// (`--vmm-memory-overhead-mib`); one not named gets its default.
    pub vmm_memory_overhead_mib: HashMap<Hypervisor, u32>,
    /// How long a build layer and an unreferenced blob are kept.
    ///
    /// Neither has an owner that could delete it: a cached layer outlives the
    /// build that produced it (that is the point of it), and a blob outlives
    /// the template it was stored for. Zero disables collection, which lets a
    /// node keep every artifact it has ever built at the cost of a directory
    /// that only grows.
    pub artifact_retention: std::time::Duration,
    /// Where this node's orchestrator answers, denied to every sandbox.
    ///
    /// The control plane is the fleet's: its API creates and destroys
    /// sandboxes, and routes exec and logs into them. A sandbox that reaches it
    /// has reached every other sandbox, without a packet ever crossing a rule
    /// about them.
    pub control_plane: Vec<std::net::IpAddr>,
    /// Whether and through which relay sandboxes here can be shared.
    pub share: crate::share::ShareOptions,
    /// Where snapshots are copied so they outlive this node. `None` keeps
    /// them node-local.
    pub object_store: Option<crate::objstore::ObjectStore>,
    /// Seals the brokered credentials of a sandbox stored in `object_store`,
    /// shared by every node so whichever adopts it can open them.
    pub store_vault: Option<Arc<burrow_common::vault::Vault>>,
    /// What `firecracker_bin` reports, recorded on every snapshot: guest state
    /// only restores under the Firecracker that wrote it.
    pub firecracker_version: String,
    /// What the Cloud Hypervisor binary reports, for the same reason.
    pub cloud_hypervisor_version: String,
    /// The agent this node ships. A guest found running another build on
    /// handshake is upgraded to it in place.
    pub guest_upgrade: Option<Arc<guestconn::GuestUpgrade>>,
    /// What lifecycle calls do while the orchestrator cannot acknowledge
    /// events.
    pub event_delivery: crate::delivery::Policy,
    /// How much disk this node promises its sandboxes, and what it keeps free.
    pub disk: crate::diskcap::DiskPolicy,
    /// Public addresses: the uplink and ingress limits.
    pub public: crate::publicip::PublicConfig,
    /// Which shapes are warmed, and how many snapshots are kept.
    pub warm: crate::warm::WarmPolicy,
    /// The shortest interval a sandbox's checkpoints are taken at, whatever
    /// its policy asks, so no tenant can hammer the object store.
    pub checkpoint_min_secs: u64,
}

impl NodeConfig {
    pub(crate) fn templates_dir(&self) -> PathBuf {
        self.data_dir.join("images")
    }

    pub(crate) fn vmm_overhead_mib(&self, hypervisor: Hypervisor) -> u32 {
        self.vmm_memory_overhead_mib
            .get(&hypervisor)
            .copied()
            .unwrap_or_else(|| hypervisor.default_vmm_overhead_mib())
    }

    /// The cgroup memory ceiling of a guest of `guest_mib` under `hypervisor`.
    pub(crate) fn memory_ceiling_mib(&self, hypervisor: Hypervisor, guest_mib: u32) -> u32 {
        hypervisor.memory_ceiling_mib(guest_mib, self.vmm_overhead_mib(hypervisor))
    }

    /// How a VM under `hypervisor` is run here.
    pub(crate) fn backend(&self, hypervisor: Hypervisor) -> burrow_vmm::Backend {
        match hypervisor {
            Hypervisor::Firecracker => {
                burrow_vmm::Backend::Firecracker(burrow_vmm::FirecrackerConfig {
                    bin: self.firecracker_bin.clone(),
                    jail: self.jail_for(hypervisor).cloned(),
                })
            }
            Hypervisor::CloudHypervisor => {
                burrow_vmm::Backend::CloudHypervisor(self.cloud_hypervisor.clone())
            }
            // A template's machine was provisioned and given its agent when
            // it was built, so a sandbox's clone boots straight to it.
            #[cfg(target_os = "macos")]
            Hypervisor::Vz => burrow_vmm::Backend::Vz(burrow_vmm::VzConfig::default()),
            // Never offered here, so never asked for: serve refuses vz off a Mac.
            #[cfg(not(target_os = "macos"))]
            Hypervisor::Vz => unreachable!("vz is offered on macOS only"),
        }
    }

    /// The jail a VM under `hypervisor` runs in, where it can run in one.
    pub(crate) fn jail_for(&self, hypervisor: Hypervisor) -> Option<&burrow_vmm::Jail> {
        // Cloud Hypervisor's own confinement is off only where the operator
        // turned it off: see `--unjailed-cloud-hypervisor`.
        let is_jailed = match hypervisor {
            Hypervisor::Firecracker => true,
            Hypervisor::CloudHypervisor => self.cloud_hypervisor.jail.is_some(),
            Hypervisor::Vz => false,
        };
        self.jail
            .as_ref()
            .filter(|_| hypervisor.capabilities().is_jailable && is_jailed)
    }

    /// What `hypervisor` reports itself as, recorded on the state it writes.
    pub(crate) fn version(&self, hypervisor: Hypervisor) -> &str {
        match hypervisor {
            Hypervisor::Firecracker => &self.firecracker_version,
            Hypervisor::CloudHypervisor => &self.cloud_hypervisor_version,
            // Never offered: serve refuses vz until a macOS node exists.
            Hypervisor::Vz => "",
        }
    }

    /// Where a sandbox's files live.
    ///
    /// Under the jailer this *is* the chroot the VMM is pivoted into, because
    /// everything firecracker touches has to be inside it and every path
    /// burrow hands the API is already relative.
    fn sandbox_dir(&self, id: &str, hypervisor: Hypervisor) -> PathBuf {
        match self.jail_for(hypervisor) {
            Some(jail) => jail.chroot_for(hypervisor, id),
            None => self.data_dir.join("sandboxes").join(id),
        }
    }

    /// Removes a VM's working directory, and under the jail the directory
    /// the chroot sits in.
    pub(crate) async fn remove_workdir(&self, workdir: &Path) -> std::io::Result<()> {
        let tree = match &self.jail {
            Some(jail) => jail.tree_of(workdir),
            None => workdir,
        };
        tokio::fs::remove_dir_all(tree).await
    }

    /// The directory whose filesystem holds sandboxes' disks, which is the
    /// one disk admission measures: the jail's base when there is a jail, the
    /// data directory otherwise.
    pub(crate) fn disk_dir(&self) -> PathBuf {
        match &self.jail {
            Some(jail) if jail.chroot_base.exists() => jail.chroot_base.clone(),
            _ => self.data_dir.clone(),
        }
    }

    /// Where a sandbox's command output is kept: beside its directory rather
    /// than in it, since under the jailer that is the VMM's own root.
    fn command_logs_dir(&self, id: &str) -> PathBuf {
        self.data_dir.join("command-logs").join(id)
    }
}

/// Longest chain of memory layers a restore will consult.
///
/// Every layer is another lookup on the path of a page fault, and diffs
/// accumulate one per suspend. Past this a full snapshot is taken instead,
/// which costs one slow pause and resets the chain.
const MAX_MEMORY_CHAIN: usize = 4;

/// Longest chain a restored sandbox is left with.
///
/// A fork copies its source's chain whole, so a fork of a fork restores
/// through three layers and every page fault consults each of them. Past this
/// the child's chain is flattened behind the create, which is sequential file
/// work the running guest never notices, rather than on the fork's critical
/// path. Lower than [`MAX_MEMORY_CHAIN`] because a fork's chain only grows from
/// here, and a flatten now is cheaper than one under a later suspend.
const MAX_RESTORED_CHAIN: usize = 2;

/// Rebuilds a sandbox's memory chain from the files in its working directory.
///
/// Used on recovery: a node restart has no in-memory chain, and the files are
/// the authority anyway.
///
/// The directory is enumerated rather than probed up to [`MAX_MEMORY_CHAIN`].
/// That cap is a policy about when to flatten, not a fact about what is on
/// disk: flattening happens *after* the diff that exceeds it is written, and a
/// crash or a failed compaction in that window leaves a chain longer than the
/// cap. Probing to the cap would silently truncate it here and restore the
/// guest from a prefix of its own memory, which is worse than a long chain.
/// What a suspend syncs, in order: the state, the memory it wrote (a diff, or
/// the full image), then the writable disks. The directory follows them.
fn suspend_sync_order(layout: Layout, memory: Option<&str>, drives: Vec<String>) -> Vec<String> {
    std::iter::once(layout.state.to_string())
        .chain(memory.map(str::to_string))
        .chain(drives)
        .collect()
}

async fn discover_memory_chain(workdir: &std::path::Path, layout: Layout) -> Vec<String> {
    let Some(memory) = layout.memory else {
        return Vec::new();
    };
    if !tokio::fs::try_exists(workdir.join(memory))
        .await
        .unwrap_or(false)
    {
        return Vec::new();
    }
    let mut chain = vec![memory.to_string()];

    let Ok(mut entries) = tokio::fs::read_dir(workdir).await else {
        return chain;
    };
    let mut diffs: Vec<usize> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(index) = Layout::diff_index(&entry.file_name().to_string_lossy()) {
            diffs.push(index);
        }
    }
    // Numerically, not by filename: `diff10` sorts before `diff9` as text, and
    // a chain applied out of order restores pages from the wrong generation.
    diffs.sort_unstable();

    // Diffs are numbered by the chain length at the time they were written, so
    // a complete chain is 1, 2, 3… without gaps. A gap means a diff is missing,
    // and the ones past it describe memory that no longer exists on disk;
    // stopping there restores from the last consistent point.
    for (expected, index) in (1..).zip(diffs) {
        if index != expected {
            tracing::warn!(
                workdir = %workdir.display(),
                missing = expected,
                "memory chain has a gap; restoring from what precedes it"
            );
            break;
        }
        chain.push(Layout::diff(index));
    }
    chain
}

/// Sessions kept per sandbox before the oldest are evicted.
///
/// The same bound the guest agent puts on its command history, and for the same
/// reason: a sandbox that is suspended and resumed on a loop would otherwise
/// grow a table for as long as it lives.
const MAX_SESSIONS: usize = 64;

/// How a VM started, as recorded on the session it opens.
const STARTED_BOOT: common::SessionStart = common::SessionStart::Boot;
const STARTED_RESTORE: common::SessionStart = common::SessionStart::Restore;
const STARTED_RESUME: common::SessionStart = common::SessionStart::Resume;
/// How one stopped.
const ENDED_SUSPENDED: common::SessionEnd = common::SessionEnd::Suspended;
const ENDED_DELETED: common::SessionEnd = common::SessionEnd::Deleted;
const ENDED_FAILED: common::SessionEnd = common::SessionEnd::Failed;
const ENDED_STOPPED: common::SessionEnd = common::SessionEnd::Stopped;
/// A session that was still open when the node died. Nothing observed when its
/// VM stopped, so its end time stays unset rather than being invented.
const ENDED_UNKNOWN: common::SessionEnd = common::SessionEnd::Unknown;

/// Event kinds, as the log records them. A sandbox's life reads
/// created, started, agent_ready, then stopped and started per suspend and
/// resume, then destroyed; snapshot_created sits wherever a commit happened,
/// and recovered wherever the node restarted.
const EVENT_CREATED: common::EventKind = common::EventKind::Created;
const EVENT_STARTED: common::EventKind = common::EventKind::Started;
const EVENT_AGENT_READY: common::EventKind = common::EventKind::AgentReady;
const EVENT_STOPPED: common::EventKind = common::EventKind::Stopped;
const EVENT_DESTROYED: common::EventKind = common::EventKind::Destroyed;
const EVENT_SNAPSHOT_CREATED: common::EventKind = common::EventKind::SnapshotCreated;
/// Logged on a node's start for each sandbox it holds, in the state it found
/// it in.
const EVENT_RECOVERED: common::EventKind = common::EventKind::Recovered;
const EVENT_IP_ATTACHED: common::EventKind = common::EventKind::IpAttached;
const EVENT_IP_DETACHED: common::EventKind = common::EventKind::IpDetached;
/// The detail of an event recovery logs for a VM that was gone when it
/// looked: its figures are the last the node recorded, not a reading.
const DETAIL_LOST: &str = "lost";
const REASON_LOST: &str = "the node stopped without suspending its VM, so its memory is lost; \
                           its disk is kept, and `burrow boot` starts it again";
const REASON_VMM_EXITED: &str = "its VMM exited while it was running, so its memory is lost; \
                                 its disk is kept, and `burrow boot` starts it again";
const REASON_MEMORY_DISCARDED: &str = "stopped while suspended, and the guest could not be resumed \
                                       to shut down cleanly, so its memory was discarded and what \
                                       it had not written to its disk is lost";

/// Guest memory when the policy names none.
const DEFAULT_MEM_MIB: u32 = 512;

/// `burrowd --memory-hotplug-max-mib`: the most a sandbox's memory grows to
/// by default, and the most it may ask to.
static MEMORY_HOTPLUG_MAX_MIB: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(DEFAULT_MEMORY_HOTPLUG_MAX_MIB);
pub(crate) const DEFAULT_MEMORY_HOTPLUG_MAX_MIB: u32 = 16_384;
/// How many times its boot memory a sandbox grows to by default. Memory
/// plugged into ZONE_MOVABLE has its page structures, 1/64 of it, allocated
/// from boot memory, so at 16 times a guest spends a quarter of its boot
/// memory describing what was plugged.
const DEFAULT_MEMORY_GROWTH: u32 = 16;

pub fn set_memory_hotplug_max(mib: u32) {
    MEMORY_HOTPLUG_MAX_MIB.store(mib, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn memory_hotplug_max() -> u32 {
    MEMORY_HOTPLUG_MAX_MIB.load(std::sync::atomic::Ordering::Relaxed)
}

/// How far a sandbox of `mem_mib` grows while it runs, `requested` being
/// what its policy asked for and 0 the node's default.
pub(crate) fn max_mem_mib(mem_mib: u32, requested: u32) -> u32 {
    match requested {
        0 => mem_mib
            .saturating_mul(DEFAULT_MEMORY_GROWTH)
            .min(memory_hotplug_max())
            .max(mem_mib),
        n => n.max(mem_mib),
    }
}

/// Whether a guest's memory can change while it runs. Windows has no
/// virtio-mem driver burrow installs.
fn can_plug_memory(hypervisor: Hypervisor, guest_os: burrow_vmm::GuestOs) -> bool {
    hypervisor.capabilities().is_memory_hotplug_supported && guest_os == burrow_vmm::GuestOs::Linux
}

/// The virtio-mem region a VM booting with `boot_mib` gets to grow to
/// `max_mib`: none where its memory cannot change while it runs, and
/// otherwise rounded up to what both backends size a region in.
pub(crate) fn hotplug_region(
    hypervisor: Hypervisor,
    guest_os: burrow_vmm::GuestOs,
    boot_mib: u32,
    max_mib: u32,
) -> u32 {
    if !can_plug_memory(hypervisor, guest_os) {
        return 0;
    }
    max_mib
        .saturating_sub(boot_mib)
        .next_multiple_of(burrow_vmm::MEMORY_REGION_ALIGN_MIB)
}

/// Fixes the memory of a VM about to boot, or to restore a warm snapshot
/// taken at boot: all of it is boot memory, and it can grow as far as the
/// policy asks or the node's default, where anything can plug it. A limit
/// left below the memory by a change made while shut down rises to it.
#[allow(clippy::result_large_err)]
fn pin_boot_memory(
    resources: &mut common::ResourcePolicy,
    hypervisor: Hypervisor,
    guest_os: burrow_vmm::GuestOs,
) -> Result<(), Status> {
    if resources.mem_mib == 0 {
        resources.mem_mib = DEFAULT_MEM_MIB;
    }
    let mem = resources.mem_mib;
    let requested = resources.max_mem_mib;
    resources.max_mem_mib = match can_plug_memory(hypervisor, guest_os) {
        false if requested > mem => {
            return Err(Status::invalid_argument(format!(
                "max_mem_mib {requested} is more than mem_mib {mem}, and a {guest_os} guest \
                 under {hypervisor} cannot be given memory while it runs"
            )));
        }
        false => mem,
        true => max_mem_mib(mem, requested),
    };
    resources.boot_mem_mib = mem;
    Ok(())
}

/// How long a macOS guest gets to resize its APFS container, which takes
/// minutes on a busy Mac; the sandbox's own client gives up after the agent
/// timeout.
const CONTAINER_RESIZE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

async fn container_agent(guest: GuestAddr) -> Result<GuestClient<Channel>, Status> {
    guestconn::connect(guest, CONTAINER_RESIZE_TIMEOUT)
        .await
        .map_err(|err| Status::internal(format!("reaching the agent: {err}")))
}

/// The file a sandbox's writable disk is, which is all a stopped sandbox is.
fn disk_file(guest_os: burrow_vmm::GuestOs) -> &'static str {
    crate::macnode::disk_file(guest_os).unwrap_or(crate::rootdisk::ROOT_DISK)
}

/// A disk's size in MiB, as a record states it.
fn size_mib(path: &Path) -> u32 {
    u32::try_from(crate::rootdisk::provisioned_bytes(path).div_ceil(burrow_common::disk::MIB))
        .unwrap_or(u32::MAX)
}

/// The clocks an `UpdateLifetime` moves; `None` leaves one as it is.
#[derive(Default)]
pub struct Lifetimes {
    pub max_lifetime_secs: Option<u64>,
    pub idle_suspend_secs: Option<u64>,
    pub suspended_ttl_secs: Option<u64>,
    pub snapshot_expiration_secs: Option<u64>,
    pub snapshot_keep_last: Option<u32>,
    pub is_evicted_snapshot_kept: Option<bool>,
    pub checkpoint_secs: Option<u64>,
    pub is_memory_checkpointed: Option<bool>,
}

/// What became of each field of a resources update, `None` for a field not
/// asked for.
#[derive(Debug, Default)]
pub struct ResourcesUpdated {
    pub vcpus: Option<ResourceOutcome>,
    pub mem_mib: Option<ResourceOutcome>,
    pub disk_mib: Option<ResourceOutcome>,
    /// The root filesystem's size as the guest reported it after a disk
    /// change, or 0 when no guest has seen the disk yet.
    pub filesystem_bytes: u64,
    pub limits: Option<LimitsOutcome>,
}

/// The host limits a resources update asks for; `None` leaves one as it is.
#[derive(Default)]
pub struct LimitsUpdate {
    pub cpus: Option<f64>,
    pub reserved_cpus: Option<f64>,
    pub cpu_shares: Option<u32>,
    pub cpuset_cpus: Option<String>,
    pub blkio_weight: Option<u32>,
}

impl LimitsUpdate {
    pub fn is_empty(&self) -> bool {
        self.cpus.is_none()
            && self.reserved_cpus.is_none()
            && self.cpu_shares.is_none()
            && self.cpuset_cpus.is_none()
            && self.blkio_weight.is_none()
    }

    fn apply(self, resources: &mut common::ResourcePolicy) {
        if let Some(cpus) = self.cpus {
            resources.cpus = cpus;
        }
        if let Some(reserved) = self.reserved_cpus {
            resources.reserved_cpus = reserved;
        }
        if let Some(shares) = self.cpu_shares {
            resources.cpu_shares = shares;
        }
        if let Some(cpuset) = self.cpuset_cpus {
            resources.cpuset_cpus = cpuset;
        }
        if let Some(weight) = self.blkio_weight {
            resources.blkio_weight = weight;
        }
    }
}

/// The host CPUs this node has.
pub(crate) fn node_cpus() -> u32 {
    std::thread::available_parallelism().map_or(0, |n| n.get() as u32)
}

/// The cgroup limits a sandbox's resources ask for, under a memory ceiling.
pub(crate) fn cgroup_limits(
    resources: &common::ResourcePolicy,
    memory_mib: u32,
) -> burrow_vmm::Limits {
    use burrow_common::cpu;
    let cap = cpu::cap_millis(resources.cpus);
    let reserve = cpu::cap_millis(resources.reserved_cpus);
    let charge = cpu::charge_millis(resources.vcpus, cap, reserve);
    burrow_vmm::Limits {
        cpu_max_millis: cap,
        cpu_reserve_millis: reserve,
        cpu_weight: cpu::shares_to_weight(cpu::shares(resources.cpu_shares, charge)),
        cpuset_cpus: resources.cpuset_cpus.clone(),
        io_weight: match resources.blkio_weight {
            0 => 0,
            weight => cpu::blkio_to_io_weight(weight),
        },
        memory_mib,
        pids_max: 0,
    }
}

/// Starts a sandbox's `cpus` cap on a VMM whose guest has answered. A VMM
/// boots and restores without it, since a cap below its vCPUs can stall a
/// kernel boot past the agent's deadline.
fn start_cpu_cap(vm: &Vm, limits: &burrow_vmm::Limits, sandbox: &str) {
    if limits.cpu_max_millis == 0 {
        return;
    }
    if let Err(err) = vm.set_limits(limits) {
        tracing::error!(sandbox, %err, "the sandbox's host cpu cap was NOT applied");
    }
}

/// Whether a policy names a host CPU or IO limit, which a Mac node has no
/// cgroup to enforce.
fn has_host_limits(resources: &common::ResourcePolicy) -> bool {
    resources.cpus > 0.0
        || resources.reserved_cpus > 0.0
        || resources.cpu_shares > 0
        || !resources.cpuset_cpus.is_empty()
        || resources.blkio_weight > 0
}

fn outcome(change: ResourceChange, previous: u32, value: u32) -> ResourceOutcome {
    ResourceOutcome {
        change: change as i32,
        previous,
        value,
        reason: String::new(),
    }
}

/// A field that could not be applied, reported rather than failing the call:
/// what the sandbox's state or hypervisor rules out, or what the node has no
/// room for. Anything else is an error.
#[allow(clippy::result_large_err)]
fn refused(err: Status, previous: u32) -> Result<ResourceOutcome, Status> {
    match err.code() {
        tonic::Code::FailedPrecondition | tonic::Code::ResourceExhausted => Ok(ResourceOutcome {
            change: ResourceChange::Refused as i32,
            previous,
            value: previous,
            reason: err.message().to_string(),
        }),
        _ => Err(err),
    }
}

/// `record` with its totals replaced by `usage`, if given.
fn with_totals(mut record: common::Sandbox, usage: Option<Usage>) -> common::Sandbox {
    if let Some(usage) = usage {
        record.cpu_usage_usec = usage.cpu_usec;
        record.rx_bytes = usage.rx_bytes;
        record.tx_bytes = usage.tx_bytes;
    }
    record
}

/// What a sandbox has consumed, and the raw readings the totals came from.
///
/// The totals span every VM the sandbox has run; the readings do not, because
/// a resume builds a fresh cgroup and a firewall re-render rebuilds the byte
/// counters. Keeping both is what turns a series of counters that restart at
/// zero into one figure that only goes up.
#[derive(Debug, Clone, Copy, Default)]
struct Usage {
    cpu_usec: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    last_cpu: u64,
    last_rx: u64,
    last_tx: u64,
}

impl Usage {
    /// Folds a set of raw readings into the running totals.
    ///
    /// A reading below the last one came from a counter that was replaced
    /// rather than rewound (a resume builds a new cgroup, a re-render rebuilds
    /// the byte counters), so the whole of it is new.
    fn advance(&mut self, cpu: Option<u64>, traffic: Option<firewall::Traffic>) {
        fn delta(raw: u64, last: u64) -> u64 {
            if raw >= last { raw - last } else { raw }
        }
        if let Some(raw) = cpu {
            self.cpu_usec = self.cpu_usec.saturating_add(delta(raw, self.last_cpu));
            self.last_cpu = raw;
        }
        if let Some(raw) = traffic {
            self.rx_bytes = self
                .rx_bytes
                .saturating_add(delta(raw.rx_bytes, self.last_rx));
            self.last_rx = raw.rx_bytes;
            self.tx_bytes = self
                .tx_bytes
                .saturating_add(delta(raw.tx_bytes, self.last_tx));
            self.last_tx = raw.tx_bytes;
        }
    }

    /// Takes a reading as the new baseline without counting it: bytes that
    /// reached a sandbox with no VM to deliver them to.
    fn rebase(&mut self, traffic: firewall::Traffic) {
        self.last_rx = traffic.rx_bytes;
        self.last_tx = traffic.tx_bytes;
    }
}

/// How far this VM's agent handshake has got.
///
/// A warm create does not wait for it, so it is a piece of state a sandbox can
/// be observed in rather than a step inside a function.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Handshake {
    /// The VM is up and the guest has not answered yet.
    Pending,
    /// The guest answered: its address, entropy and clock are its own.
    Done,
    /// It never answered, and this is what that looked like. Terminal for this
    /// VM: only a resume, which handshakes for itself, clears it.
    Failed(String),
}

const CLOCK_SYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
const CLOCK_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// How far the node's wall clock may move against its monotonic one between
/// checks before guests are synced at once.
const CLOCK_JUMP: std::time::Duration = std::time::Duration::from_secs(1);

/// Whether guest clocks are due a sync, given the node's monotonic and wall
/// clocks at the last one and now.
fn clocks_due(
    last: (std::time::Instant, std::time::SystemTime),
    now: (std::time::Instant, std::time::SystemTime),
) -> bool {
    let steady = now.0.duration_since(last.0);
    if steady >= CLOCK_SYNC_INTERVAL {
        return true;
    }
    match now.1.duration_since(last.1) {
        Ok(wall) => wall.abs_diff(steady) > CLOCK_JUMP,
        Err(_) => true,
    }
}

/// A handshake that has already happened, for every path that waits for one.
fn settled() -> Arc<tokio::sync::watch::Sender<Handshake>> {
    Arc::new(tokio::sync::watch::channel(Handshake::Done).0)
}

/// Everything a half-provisioned sandbox is holding, given back unless the
/// create reaches the end.
///
/// A create takes an address lease, volume claims, a working directory, a tap
/// and finally a VMM, and every failure between the first of those and the
/// record being handed back has to undo all of them. Written out per error
/// path, that is five copies of the same five lines, and the one that gets
/// forgotten leaks an address and an interface for the life of the node.
///
/// So the guard owns the cleanup and the success path is what has to say
/// something, by calling [`Self::keep`]. Release is deliberately explicit
/// rather than done from `Drop`: the ordering matters (the VMM must die before
/// its tap goes, and the workdir must not be removed while firecracker is
/// still in it), and a create that returns before its directory is gone can be
/// retried straight into the middle of its own cleanup. `Drop` is left as the
/// backstop that says loudly when a path forgot.
struct Provisioning<'a> {
    manager: &'a SandboxManager,
    id: String,
    workdir: PathBuf,
    /// `None` until the tap is up; taken back out once the sandbox owns it.
    tap: Option<String>,
    /// `None` until the VM boots or restores.
    vm: Option<Vm>,
    is_kept: bool,
}

impl<'a> Provisioning<'a> {
    /// Starts guarding a create that has already taken its lease and claims.
    fn new(manager: &'a SandboxManager, id: &str, workdir: &Path) -> Self {
        Self {
            manager,
            id: id.to_string(),
            workdir: workdir.to_path_buf(),
            tap: None,
            vm: None,
            is_kept: false,
        }
    }

    /// The VM this create started, which it has by the time anything asks.
    fn vm(&self) -> &Vm {
        self.vm
            .as_ref()
            .expect("the vm is recorded before anything uses it")
    }

    fn vm_mut(&mut self) -> &mut Vm {
        self.vm
            .as_mut()
            .expect("the vm is recorded before anything uses it")
    }

    /// Gives everything back and turns `err` into the create's answer.
    ///
    /// Every failure path goes through here, so the order below is the only
    /// order teardown happens in.
    async fn fail(mut self, err: Status) -> Status {
        if let Some(vm) = self.vm.take() {
            let _ = vm.kill().await;
        }
        if let Some(tap) = self.tap.take() {
            tap::delete(&tap).await;
        }
        self.manager.release_lease(&self.id).await;
        self.manager.volumes.release_all(&self.id);
        let _ = self.manager.config.remove_workdir(&self.workdir).await;
        let _ = tokio::fs::remove_dir_all(self.manager.config.command_logs_dir(&self.id)).await;
        self.is_kept = true;
        err
    }

    /// The create succeeded: the sandbox owns all of this now.
    fn keep(mut self) -> Option<Vm> {
        self.is_kept = true;
        self.vm.take()
    }
}

impl Drop for Provisioning<'_> {
    fn drop(&mut self) {
        if self.is_kept {
            return;
        }
        // Reached only if a path added later returns without going through
        // `fail`. Cleaning up from here cannot be awaited, so it is spawned
        // and the node is told: a leaked lease and tap is a bug worth a log
        // line even when the spawn puts them back.
        tracing::error!(
            sandbox = self.id,
            "a create returned without releasing what it had provisioned"
        );
        let (manager, id, tap, workdir) = (
            self.manager.clone(),
            self.id.clone(),
            self.tap.take(),
            self.workdir.clone(),
        );
        let vm = self.vm.take();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Some(vm) = vm {
                    let _ = vm.kill().await;
                }
                if let Some(tap) = tap {
                    tap::delete(&tap).await;
                }
                manager.release_lease(&id).await;
                manager.volumes.release_all(&id);
                let _ = manager.config.remove_workdir(&workdir).await;
            });
        }
    }
}

/// Runs a warm create's handshake behind the create that started it.
///
/// The guest is still told its address, given fresh entropy and set to the
/// host's clock before anything can run inside it, because
/// [`RunningSandbox::agent`] waits for this to settle. Only the waiting moves:
/// the caller gets its record as soon as the VM is up.
///
/// Bounded as a whole, because the watch this settles is what everything else
/// waits on: a guest that hangs half way through a handshake must become an
/// error on the next call rather than a call that never returns.
///
/// `grow_to` is the size of a root disk grown under the guest before it
/// handshook, whose filesystem it grows to fill before the sandbox is ready.
fn spawn_handshake(
    manager: &SandboxManager,
    sandbox: &Arc<RunningSandbox>,
    request: burrow_proto::guest::v1::HandshakeRequest,
    grow_to: Option<u64>,
    timeout: std::time::Duration,
) {
    let id = sandbox.id.clone();
    let guest = GuestAddr::in_workdir(&sandbox.workdir);
    let signal = sandbox.handshake.clone();
    let manager = manager.clone();
    // Weak: a sandbox deleted while its guest is still waking must not be kept
    // alive by the task that was going to talk to it.
    let weak = Arc::downgrade(sandbox);
    tokio::spawn(async move {
        let began = std::time::Instant::now();
        let upgrade = manager.config.guest_upgrade.clone();
        // Which step the deadline caught, so a guest that never came up says
        // whether its vsock never accepted or its agent never answered.
        let step = std::sync::Mutex::new("waiting for the guest's vsock to accept");
        // An upgrade has its own bound on top, for the new agent's first
        // launch.
        let outcome = match tokio::time::timeout(timeout + guestconn::UPGRADE_TIMEOUT, async {
            let (agent, _) = guestconn::connect_when_ready(guest.clone(), timeout).await?;
            *step.lock().unwrap() = "waiting for the agent to answer the handshake";
            let (mut agent, _) =
                guestconn::handshake_upgrading(agent, guest, request, upgrade.as_deref(), timeout)
                    .await?;
            if let Some(size_bytes) = grow_to {
                *step.lock().unwrap() = "waiting for the guest to grow its filesystem";
                agent
                    .root_disk(burrow_proto::guest::v1::RootDiskRequest {
                        op: burrow_proto::guest::v1::root_disk_request::Op::Grow as i32,
                        size_bytes,
                        ..Default::default()
                    })
                    .await?;
            }
            Ok::<_, anyhow::Error>(agent)
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(anyhow::anyhow!(
                "stalled {} after {timeout:?}",
                step.lock().unwrap()
            )),
        };

        let (state, agent) = match outcome {
            Ok(agent) => (Handshake::Done, Some(agent)),
            Err(err) => (Handshake::Failed(error_chain(&*err)), None),
        };
        // The sandbox may have been resumed under this task, and a resume
        // handshakes for itself, so a verdict on the VM this task was watching
        // is only recorded while that VM's handshake is still the open one.
        // Checked and written together, or the resume's verdict could be
        // overwritten by this one.
        let recorded = signal.send_if_modified(|current| {
            if *current != Handshake::Pending {
                return false;
            }
            *current = state.clone();
            true
        });

        let Some(sandbox) = weak.upgrade() else {
            return;
        };
        match state {
            Handshake::Done if recorded => {
                if let Some(vm) = &*sandbox.vm.lock().await {
                    let limits = sandbox.spec.lock().unwrap().limits.clone();
                    start_cpu_cap(vm, &limits, &id);
                }
                // The channel this was made on is the one the first exec would
                // otherwise have to dial for itself.
                *sandbox.agent_channel.lock().await = Some(agent.expect("done means connected"));
                manager.emit(&sandbox, EVENT_AGENT_READY, "").await;
                tracing::debug!(
                    sandbox = id,
                    took_ms = began.elapsed().as_millis() as u64,
                    "deferred handshake complete"
                );
            }
            Handshake::Failed(err) if recorded => {
                // Loud, and with the console, because nothing else will report
                // it: the create it belonged to has already returned.
                let reason = match &mut *sandbox.vm.lock().await {
                    Some(vm) => no_agent_reason(vm, NoAgent::Stalled(err)).await,
                    None => err,
                };
                tracing::error!(
                    sandbox = id,
                    reason,
                    "the guest agent never came up; reclaiming the sandbox"
                );
                // This task is the one place that knows the guest has been
                // given up on, so it is the one that gives back what the
                // sandbox is holding: nothing else is waiting to fail the
                // create, which returned as soon as the VM was up.
                //
                // Released first: the teardown can only stop the VMM while it
                // holds the sandbox alone, and this task's own reference would
                // otherwise be the one keeping it shared.
                drop(sandbox);
                manager.reclaim_unconfirmed(&id).await;
            }
            _ => {}
        }
    });
}

/// What a guest agent able to take public addresses names among its features.
const PUBLIC_ADDRESSES: &str = "public-addresses";

/// What the guest calls the feed of command output it keeps for the host.
pub const OUTPUT_FEED: &str = "output-feed";

/// Writes the guest's command output to the node's logs as it arrives,
/// confirming each frame so the guest can let go of it. Holds the sandbox only
/// long enough to reach its agent, so a deleted one is not kept alive.
async fn feed(
    sandbox: std::sync::Weak<RunningSandbox>,
    logs: &crate::cmdlogs::CommandLogs,
) -> Result<(), Status> {
    let mut agent = {
        let Some(sandbox) = sandbox.upgrade() else {
            return Ok(());
        };
        if !sandbox.agent_has(OUTPUT_FEED).await? {
            return Ok(());
        }
        sandbox.reach_agent().await?
    };
    let (acks, inbound) = tokio::sync::mpsc::channel(64);
    let _ = acks
        .send(burrow_proto::guest::v1::FeedAck {
            seq: 0,
            positions: logs.positions(),
        })
        .await;
    let mut frames = agent
        .feed(tokio_stream::wrappers::ReceiverStream::new(inbound))
        .await?
        .into_inner();
    while let Some(frame) = frames.message().await? {
        let seq = frame.seq;
        logs.append(frame);
        // Acks are cumulative, so one dropped for want of room is covered by
        // the next.
        let _ = acks.try_send(burrow_proto::guest::v1::FeedAck {
            seq,
            positions: Vec::new(),
        });
    }
    Ok(())
}

pub struct RunningSandbox {
    /// Fixed for the sandbox's life, and held outside the record because the
    /// record is rebuilt from policy while these two never change.
    id: String,
    template: String,
    /// Its template's, and fixed for its life the same way: every VM it ever
    /// runs, and every snapshot it leaves, is this hypervisor's.
    hypervisor: Hypervisor,
    /// Everything else about the sandbox. Mutable because a pre-provisioned
    /// sandbox is stamped with the requesting caller's policy and tags
    /// when it is handed out.
    base_record: std::sync::Mutex<common::Sandbox>,
    state: std::sync::atomic::AtomicI32,
    /// `None` while suspended: the VMM process is gone and the sandbox lives
    /// only as a snapshot on disk.
    vm: Mutex<Option<Vm>>,
    /// Kept so a suspended sandbox can be restored with byte-identical
    /// resource paths, which a restore requires. Replaced by a boot from a
    /// stop, which describes the drives afresh.
    spec: std::sync::Mutex<VmSpec>,
    /// A live channel to this sandbox's agent.
    ///
    /// Reused across calls: a vsock connect plus an HTTP/2 handshake into a
    /// 1-vCPU guest is a real cost to pay on every exec. Dropped whenever the
    /// VM goes away, because a channel does not survive a pause.
    agent_channel: Mutex<Option<GuestClient<Channel>>>,
    /// What the agent behind `agent_channel` says it supports, asked once per
    /// channel and dropped with it: an upgrade can change the answer.
    agent_features: Mutex<Option<Vec<String>>>,
    /// Where this VM's handshake with the guest has got to.
    ///
    /// A warm create returns before the guest has answered, so its address,
    /// entropy and clock land after the caller already holds a record.
    /// Everything that reaches the guest goes through [`Self::agent`], which
    /// waits here first, so nothing ever runs inside a guest that has not been
    /// fixed up. Behind an `Arc` because the task doing the handshake outlives
    /// the call that started it.
    handshake: Arc<tokio::sync::watch::Sender<Handshake>>,
    /// Memory files to restore from, oldest first. Empty until the sandbox has
    /// a snapshot at all; `[snapshot.mem]` after a full one, with a diff
    /// appended per suspend after that.
    memory_chain: Mutex<Vec<String>>,
    /// Where the sandbox stands with the object store.
    durable: crate::durable::Durability,
    /// Unix seconds of the last thing anyone asked this sandbox to do.
    ///
    /// Idle suspension is measured from here rather than from the VM's own
    /// activity: a sandbox running a background job nobody is watching is
    /// exactly what the policy is meant to reclaim.
    last_activity: std::sync::atomic::AtomicI64,
    /// Unix seconds this sandbox entered `Suspended`; 0 while it is running.
    ///
    /// Separate from `last_activity`, which a resume refreshes: retention is
    /// about how long the snapshot has been sitting on disk, not about how
    /// recently anyone touched the guest before it was parked.
    suspended_at: std::sync::atomic::AtomicI64,
    /// What every VM this sandbox has run has cost, carried on the record so it
    /// survives a suspend, a resume and a restart of the daemon.
    usage: std::sync::Mutex<Usage>,
    /// The session opened by the VM currently running, if any.
    session: std::sync::Mutex<Option<String>>,
    workdir: PathBuf,
    /// Every command's output, as the guest feeds it.
    pub logs: Arc<crate::cmdlogs::CommandLogs>,
    /// Deadline every unary call to this sandbox's agent runs under.
    ///
    /// Carried on the sandbox rather than passed in because [`Self::agent`] is
    /// what every exec, transfer and watch goes through, and most of its
    /// callers hold nothing else from the node's configuration. Streaming
    /// calls are deliberately not bounded by it; see [`crate::guestconn`].
    agent_timeout: std::time::Duration,
    pub lease: Lease,
    pub tap: String,
}

impl RunningSandbox {
    pub fn record(&self) -> common::Sandbox {
        let mut record = self.base_record.lock().unwrap().clone();
        record.state = self.state.load(std::sync::atomic::Ordering::Relaxed);
        // Read rather than stored, for the same reason `state` is: it belongs
        // to the VM running now, and a create returns while it is still true.
        record.is_agent_unconfirmed = *self.handshake.borrow() != Handshake::Done;
        let usage = *self.usage.lock().unwrap();
        record.cpu_usage_usec = usage.cpu_usec;
        record.rx_bytes = usage.rx_bytes;
        record.tx_bytes = usage.tx_bytes;
        record.is_durable = self.durable.is_current();
        record.checkpoint_at_unix_ms = 0;
        record.checkpoint_kind = common::CheckpointKind::Unspecified as i32;
        record.cpu = None;
        if let Some(stored) = self.durable.stored.lock().unwrap().as_ref() {
            let cpu = stored.manifest.cpu.fingerprint();
            if record.is_durable {
                record.arch = stored.manifest.arch.clone();
                record.hypervisor_version = stored.manifest.hypervisor_version.clone();
                record.cpu = cpu.clone();
            }
            let kind = match stored.manifest.checkpoint.as_str() {
                crate::durable::CHECKPOINT_DISK => common::CheckpointKind::Disk,
                crate::durable::CHECKPOINT_MEMORY => common::CheckpointKind::Memory,
                _ => common::CheckpointKind::Unspecified,
            };
            if stored.is_published
                && kind != common::CheckpointKind::Unspecified
                && record.state != common::SandboxState::Suspended as i32
            {
                record.checkpoint_at_unix_ms = stored.manifest.checkpoint_at_ms;
                record.checkpoint_kind = kind as i32;
                record.arch = stored.manifest.arch.clone();
                record.hypervisor_version = stored.manifest.hypervisor_version.clone();
                record.cpu = cpu;
            }
        }
        record
    }

    /// Folds this VM's cgroup reading into the sandbox's CPU total.
    ///
    /// Called on every sample and once more before a VM is killed, because the
    /// cgroup is removed with it: whatever the guest did since the last sample
    /// is only readable while the VMM is still there.
    fn absorb_cpu(&self, vm: &Vm) {
        self.usage
            .lock()
            .unwrap()
            .advance(vm.cpu_usage_usec(), None);
    }

    /// The last [`Self::absorb_cpu`] of a VM about to be killed. The next VM's
    /// counter (a new cgroup, a new vz service process) starts at zero, so it
    /// is counted from zero rather than from this one's last reading.
    fn retire_cpu(&self, vm: &Vm) {
        let mut usage = self.usage.lock().unwrap();
        usage.advance(vm.cpu_usage_usec(), None);
        usage.last_cpu = 0;
    }

    /// Folds a reading of this sandbox's byte counters into its totals.
    fn absorb_traffic(&self, traffic: firewall::Traffic) {
        self.usage.lock().unwrap().advance(None, Some(traffic));
    }

    fn rebase_traffic(&self, traffic: firewall::Traffic) {
        self.usage.lock().unwrap().rebase(traffic);
    }

    /// The totals as they stand, for an event that has to be bounded by a
    /// reading taken before the VM it reports on started.
    fn totals(&self) -> Usage {
        *self.usage.lock().unwrap()
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The policy this sandbox runs under.
    ///
    /// Separate from `record()` because the exec and fs sections are consulted
    /// on the hot path of every pass-through call, and the caller there wants
    /// the policy rather than a whole record with a freshly loaded state.
    pub fn policy(&self) -> common::Policy {
        self.base_record
            .lock()
            .unwrap()
            .policy
            .clone()
            .unwrap_or_default()
    }

    /// The disk this sandbox's guest writes: its root disk or a macOS
    /// guest's disk image.
    pub fn disk_path(&self) -> PathBuf {
        self.workdir.join(disk_file(self.guest_os()))
    }

    fn guest_os(&self) -> burrow_vmm::GuestOs {
        burrow_vmm::GuestOs::from_record(&self.base_record.lock().unwrap().guest_os)
            .unwrap_or_default()
    }

    /// The size of this sandbox's disk in MiB. A macOS guest's is the size
    /// recorded for it, which a shrink records before its next boot cuts the
    /// image to it.
    fn disk_mib(&self) -> u32 {
        let recorded = self
            .base_record
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.as_ref())
            .map_or(0, |resources| resources.disk_mib);
        match crate::macnode::is_macos(self.guest_os()) && recorded != 0 {
            true => recorded,
            false => size_mib(&self.disk_path()),
        }
    }

    /// The template this sandbox was created from.
    pub fn template(&self) -> &str {
        &self.template
    }

    fn layout(&self) -> Layout {
        self.hypervisor.layout()
    }

    /// The files a suspend has to get onto the disk before it is reported:
    /// the state, the memory file it just wrote, and every disk the guest can
    /// write. In that order, which is the order they are synced in.
    fn snapshot_files(&self, memory: Option<&str>) -> Vec<String> {
        let spec = self.spec.lock().unwrap();
        let drives: Vec<String> = spec
            .drives
            .iter()
            .filter(|drive| !drive.is_read_only)
            .map(|drive| drive.path.clone())
            .chain(aux_storage(&spec.boot))
            .collect();
        suspend_sync_order(self.layout(), memory, drives)
    }

    /// The disk files this sandbox's guest writes, volumes aside, which
    /// admission charges at their size. A volume is counted as the volume.
    fn disk_files(&self) -> Vec<PathBuf> {
        self.spec
            .lock()
            .unwrap()
            .drives
            .iter()
            .filter(|drive| !drive.is_read_only && !crate::volume::is_volume_drive(&drive.id))
            .map(|drive| self.workdir.join(&drive.path))
            .collect()
    }

    /// Syncs what a suspend wrote, then the working directory. A suspend is
    /// not reported until this returns: without it the memory file, the
    /// vmstate and the guest's disk may still be only in the host page cache,
    /// and a power cut leaves a torn state that restores into a corrupt guest.
    async fn sync_snapshot(&self, memory: Option<&str>) -> Result<(), Status> {
        crate::fsync::files_then_dir(&self.workdir, self.snapshot_files(memory))
            .await
            .map_err(|err| Status::internal(format!("syncing the snapshot to disk: {err}")))
    }

    /// vCPUs this sandbox is promised, whether or not its VMM is running.
    pub fn vcpus(&self) -> u32 {
        self.spec.lock().unwrap().vcpus
    }

    /// Host CPU this node is charged for the sandbox, in thousandths of a
    /// CPU: its cap where it has one, otherwise its vCPUs.
    pub fn cpu_charge_millis(&self) -> u64 {
        let spec = self.spec.lock().unwrap();
        burrow_common::cpu::charge_millis(
            spec.vcpus,
            spec.limits.cpu_max_millis,
            spec.limits.cpu_reserve_millis,
        )
    }

    /// The memory the VM is given, the node's default or a macOS guest's
    /// minimum included, where the policy may say 0: what it booted with and
    /// what has been plugged since.
    pub fn mem_mib(&self) -> u32 {
        let spec = self.spec.lock().unwrap();
        spec.mem_mib + spec.mem_plugged_mib
    }

    /// What the VM booted with, the floor a running guest's memory shrinks
    /// to.
    pub fn boot_mem_mib(&self) -> u32 {
        self.spec.lock().unwrap().mem_mib
    }

    /// What the memory may grow to while the VM runs.
    pub fn max_mem_mib(&self) -> u32 {
        let max = self
            .base_record
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.as_ref())
            .map_or(0, |resources| resources.max_mem_mib);
        max.max(self.mem_mib())
    }

    /// Whether the guest was shown the host's virtualization extensions,
    /// which its snapshots keep.
    pub fn is_nested_virt_enabled(&self) -> bool {
        self.base_record
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.as_ref())
            .is_some_and(|resources| resources.is_nested_virt_enabled)
    }

    /// Marks the sandbox as used, deferring idle suspension.
    pub fn touch(&self) {
        self.last_activity.store(
            burrow_common::unix_now(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn idle_secs(&self) -> i64 {
        burrow_common::unix_now()
            - self
                .last_activity
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn lifetime(&self) -> common::LifetimePolicy {
        self.base_record
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .and_then(|policy| policy.lifetime)
            .unwrap_or_default()
    }

    fn snapshot_policy(&self) -> common::SnapshotPolicy {
        self.base_record
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .and_then(|policy| policy.snapshots)
            .unwrap_or_default()
    }

    /// Seconds since creation.
    fn age_secs(&self) -> i64 {
        let created = self.base_record.lock().unwrap().created_at_unix_ms;
        (burrow_common::unix_now_ms() - created) / 1000
    }

    fn set_state(&self, state: common::SandboxState) {
        self.state
            .store(state as i32, std::sync::atomic::Ordering::Relaxed);
        if state == common::SandboxState::Running {
            self.base_record.lock().unwrap().state_reason.clear();
        }
    }

    /// Whether the sandbox has no VM by design: whatever its counters see
    /// now never reached a guest.
    fn is_parked(&self) -> bool {
        let state = self.state.load(std::sync::atomic::Ordering::Relaxed);
        state == common::SandboxState::Suspended as i32
            || state == common::SandboxState::Stopped as i32
    }

    /// Marks the sandbox suspended and starts its retention clock.
    fn enter_suspended(&self) {
        self.suspended_at.store(
            burrow_common::unix_now(),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.set_state(common::SandboxState::Suspended);
    }

    /// Seconds spent suspended, or 0 for a sandbox that is not.
    fn suspended_secs(&self) -> i64 {
        match self.suspended_at.load(std::sync::atomic::Ordering::Relaxed) {
            0 => 0,
            at => burrow_common::unix_now() - at,
        }
    }

    fn suspended_at(&self) -> i64 {
        self.suspended_at.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn is_running(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Relaxed)
            == common::SandboxState::Running as i32
    }

    fn is_suspended(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Relaxed)
            == common::SandboxState::Suspended as i32
    }

    pub async fn agent(&self) -> Result<GuestClient<Channel>, Status> {
        // Every exec, file transfer and watch reaches the guest through here,
        // which makes it the honest definition of "in use". It excludes the
        // orchestrator's own bookkeeping, which must not keep an otherwise
        // idle sandbox alive.
        self.touch();
        self.reach_agent().await
    }

    /// [`Self::agent`] without counting as use, for the node's own traffic.
    async fn reach_agent(&self) -> Result<GuestClient<Channel>, Status> {
        if !self.is_running() {
            return Err(Status::failed_precondition(
                "sandbox is suspended; resume it first",
            ));
        }
        // A warm create hands back a record before the guest has answered, so
        // this is where that debt is paid: the first caller that actually needs
        // the guest waits for it, and hears about it if it never came.
        self.await_handshake().await?;

        let mut cached = self.agent_channel.lock().await;
        if let Some(client) = cached.as_ref() {
            // Cloning a tonic client shares the channel rather than dialling
            // again, which is the whole point.
            return Ok(client.clone());
        }
        let client = guestconn::connect(GuestAddr::in_workdir(&self.workdir), self.agent_timeout)
            .await
            .map_err(|err| {
                Status::unavailable(format!("agent unreachable: {}", error_chain(&*err)))
            })?;
        *cached = Some(client.clone());
        Ok(client)
    }

    /// Waits for this VM's handshake to settle, if it has not already.
    ///
    /// No timeout of its own: the task that drives the handshake runs under
    /// one, so the watch always settles, and a second deadline here would only
    /// give up on a guest that was still within the first.
    async fn await_handshake(&self) -> Result<(), Status> {
        let mut settled = self.handshake.subscribe();
        loop {
            match &*settled.borrow_and_update() {
                Handshake::Done => return Ok(()),
                // Named, and named as the agent rather than the network, because
                // the alternative is a caller reading "connection refused" and
                // going looking at its own side.
                Handshake::Failed(err) => {
                    return Err(Status::internal(format!(
                        "sandbox {}: its guest agent never came up: {err}",
                        self.id
                    )));
                }
                Handshake::Pending => {}
            }
            if settled.changed().await.is_err() {
                return Err(Status::internal(format!(
                    "sandbox {}: its guest agent never came up",
                    self.id
                )));
            }
        }
    }

    /// Drops the cached channel.
    ///
    /// Called whenever the VM behind it goes away. A channel kept across a
    /// pause points at a vsock that no longer exists, and fails in ways that
    /// look like the guest is broken rather than the connection.
    async fn forget_agent(&self) {
        *self.agent_channel.lock().await = None;
        *self.agent_features.lock().await = None;
        self.logs.stop_feed();
    }

    /// Whether the agent says it supports `feature`. One it does not name
    /// reads as no.
    pub async fn agent_has(&self, feature: &str) -> Result<bool, Status> {
        let mut agent = self.reach_agent().await?;
        let mut features = self.agent_features.lock().await;
        if features.is_none() {
            let health = agent
                .health(burrow_proto::guest::v1::GuestHealthRequest {})
                .await?
                .into_inner();
            *features = Some(health.features);
        }
        Ok(features
            .as_ref()
            .is_some_and(|held| held.iter().any(|f| f == feature)))
    }

    /// Steps the guest's clock to the node's if the two have drifted apart.
    /// Not use. A guest still handshaking is left to its handshake, which
    /// sets the clock itself.
    async fn sync_clock(&self) -> Result<(), Status> {
        if *self.handshake.borrow() != Handshake::Done {
            return Ok(());
        }
        let mut agent = self.reach_agent().await?;
        let synced = agent
            .sync_clock(guestconn::clock_request())
            .await?
            .into_inner();
        if synced.is_stepped {
            tracing::info!(
                sandbox = self.id(),
                offset_ms = synced.offset_nanos / 1_000_000,
                is_disciplined = synced.is_disciplined,
                "guest clock had drifted from the node's; stepped it"
            );
        }
        Ok(())
    }

    /// Starts draining the guest's output feed into this sandbox's logs, if
    /// nothing is yet. Ends with the VM; the next call starts it again.
    pub fn ensure_feed(self: &Arc<Self>) {
        if !self.is_running() {
            return;
        }
        let weak = Arc::downgrade(self);
        let logs = Arc::clone(&self.logs);
        self.logs.feed_with(|| async move {
            if let Err(err) = feed(weak, &logs).await {
                tracing::debug!(%err, "command output feed ended");
            }
        });
    }

    /// Snapshots to disk and stops the VMM. The sandbox keeps its address,
    /// tap device, and disks, so resuming restores it exactly.
    #[tracing::instrument(skip_all, fields(sandbox = %self.id(), diff))]
    async fn suspend(&self) -> Result<(), Status> {
        // A warm create or an adopt returns before its handshake lands. A
        // snapshot taken under it captures a guest half reconfigured, and the
        // task driving it outlives the VM, retrying the vsock path until its
        // deadline: the next VM at that path, a resume or an adopt back onto
        // this node, would be handshaken twice at once.
        self.await_handshake().await?;
        self.sync_guest().await;
        self.forget_agent().await;
        let mut slot = self.vm.lock().await;
        let Some(vm) = slot.take() else {
            let state = self.state.load(std::sync::atomic::Ordering::Relaxed);
            return Err(Status::failed_precondition(
                match common::SandboxState::try_from(state) {
                    Ok(common::SandboxState::Suspended) => "sandbox is already suspended",
                    Ok(common::SandboxState::Stopped) => "sandbox is stopped",
                    _ => "sandbox is marked running but has no VMM",
                },
            ));
        };

        // A diff records only the pages touched since the snapshot this VM was
        // restored from, which is nearly always a small fraction of the guest.
        // It is only possible when there is something to diff *against*, under
        // a hypervisor that can take one, and when the pages it holds can be
        // known exactly.
        let chain = self.memory_chain.lock().await.clone();
        let diff =
            !chain.is_empty() && vm.capabilities().is_diff_snapshot_supported && vm.can_map_diff();
        tracing::Span::current().record("diff", diff);

        let next = Layout::diff(chain.len());
        let result = async {
            vm.pause().await?;
            if diff {
                vm.snapshot_diff(&next).await
            } else {
                vm.snapshot().await
            }
        }
        .await;

        if let Err(err) = result {
            // The snapshot failed but the VM is still paused and usable;
            // resume it rather than stranding the sandbox.
            let _ = vm.resume().await;
            *slot = Some(vm);
            return Err(Status::internal(format!("snapshot failed: {err}")));
        }
        self.logs.clear_checkpoint();

        // On the disk before anything says suspended. The guest is still
        // paused, so its disks are not moving under the sync, and a sync that
        // fails leaves a VM that can simply carry on.
        let written = if diff {
            Some(next.as_str())
        } else {
            self.layout().memory
        };
        if let Err(err) = self.sync_snapshot(written).await {
            let _ = vm.resume().await;
            *slot = Some(vm);
            return Err(err);
        }

        // Recorded only after the snapshot succeeded: a chain naming a file
        // that was never written would fail every later restore. But recorded
        // *before* the kill, because what reached disk is the truth: a kill
        // that fails must not leave the sandbox marked Running with no VM and
        // a chain missing the diff that was just written, which a later resume
        // would restore around.
        let flattened = {
            let mut current = self.memory_chain.lock().await;
            if diff {
                current.push(next);
            } else {
                // A full snapshot supersedes everything before it.
                *current = self.layout().memory.map(String::from).into_iter().collect();
                Self::remove_stale_diffs(&self.workdir).await;
            }
            current.len() > MAX_MEMORY_CHAIN
        };
        self.enter_suspended();

        // The cgroup goes with the VMM, so this is the last chance to read what
        // it spent.
        self.retire_cpu(&vm);

        // A VMM that will not die is a leak, not a lost snapshot: the sandbox
        // is suspended either way, and the state above already says so.
        if let Err(err) = vm.kill().await {
            tracing::error!(sandbox = self.id(), %err, "vmm did not stop after snapshotting");
        }

        // Flattened here rather than by taking a full snapshot: the VM is gone,
        // so this is sequential file work instead of faulting the whole guest
        // back through the page-fault handler.
        if flattened {
            self.compact_memory_chain().await;
        }

        Ok(())
    }

    /// Has the guest write back what its page cache holds before its memory
    /// is captured, so the snapshot is not the only copy of writes it has
    /// acknowledged: a snapshot lost while suspended, or one a stop has to
    /// discard, still leaves them on the disk. An agent that cannot sync
    /// through RootDisk runs `sync` instead.
    async fn sync_guest(&self) {
        use burrow_proto::guest::v1::{RootDiskRequest, root_disk_request::Op};
        let synced = async {
            self.reach_agent()
                .await?
                .root_disk(RootDiskRequest {
                    op: Op::Sync as i32,
                    ..Default::default()
                })
                .await
        };
        match tokio::time::timeout(std::time::Duration::from_secs(5), synced).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.code() == tonic::Code::Unimplemented => flush_guest(self).await,
            Ok(Err(err)) => {
                tracing::warn!(
                    sandbox = self.id(),
                    err = err.message(),
                    "could not sync the guest before capturing its memory"
                )
            }
            Err(_) => {
                tracing::warn!(
                    sandbox = self.id(),
                    "the guest did not sync within 5s of a capture"
                )
            }
        }
    }

    /// Merges the memory chain back down to a single base file.
    async fn compact_memory_chain(&self) {
        self.durable.settle_memory().await;
        let mut chain = self.memory_chain.lock().await;
        let paths: Vec<std::path::PathBuf> =
            chain.iter().map(|name| self.workdir.join(name)).collect();
        // A chain only grows over a memory file, so a layout without one
        // never has anything to compact.
        let Some(memory) = self.layout().memory else {
            return;
        };
        let target = self.workdir.join(memory);
        let started = std::time::Instant::now();

        let merged = tokio::task::spawn_blocking({
            let paths = paths.clone();
            let target = target.clone();
            move || burrow_vmm::merge_chain(&paths, &target)
        })
        .await;

        // The diffs go only once the merged base is on the disk: until then
        // the base may hold a partial merge, which is harmless only while the
        // diffs layered over it are still there to restore through.
        let merged = match merged {
            Ok(Ok(())) => Ok(crate::fsync::file(&target).await.map_err(|err| {
                std::io::Error::new(err.kind(), format!("syncing the merged memory file: {err}"))
            })),
            other => other,
        };
        match merged {
            Ok(Ok(())) => {
                *chain = vec![memory.to_string()];
                drop(chain);
                Self::remove_stale_diffs(&self.workdir).await;
                if let Err(err) = crate::fsync::dir(&self.workdir).await {
                    tracing::warn!(sandbox = self.id(), %err, "could not sync the working directory after flattening");
                }
                tracing::info!(
                    sandbox = self.id(),
                    layers = paths.len(),
                    took_ms = started.elapsed().as_millis() as u64,
                    "flattened the memory chain"
                );
            }
            // The chain is still valid and still restorable; it just stays
            // long, which costs lookups rather than correctness.
            Ok(Err(err)) => {
                tracing::warn!(sandbox = self.id(), %err, "could not flatten the memory chain")
            }
            Err(err) => {
                tracing::warn!(sandbox = self.id(), %err, "chain flattening did not run")
            }
        }
    }

    /// Deletes diff files a full snapshot has made irrelevant.
    async fn remove_stale_diffs(workdir: &Path) {
        let Ok(mut entries) = tokio::fs::read_dir(workdir).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            if Layout::diff_index(&name.to_string_lossy()).is_some() {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
    }

    /// Restores from the on-disk snapshot and re-handshakes with the agent.
    #[tracing::instrument(skip_all, fields(sandbox = %self.id()))]
    async fn resume(
        &self,
        request: burrow_proto::guest::v1::HandshakeRequest,
        agent_timeout: std::time::Duration,
        upgrade: Option<&guestconn::GuestUpgrade>,
        is_stored: bool,
    ) -> Result<(), Status> {
        self.forget_agent().await;
        let mut slot = self.vm.lock().await;
        if slot.is_some() {
            return Err(Status::failed_precondition("sandbox is already running"));
        }

        let mut spec = self.spec.lock().unwrap().clone();
        spec.memory_chain = self.memory_chain.lock().await.clone();
        // Without the page-fault handler a base still arriving cannot be
        // served as the guest asks for it, so it has to be all here first.
        if !self.hypervisor.capabilities().is_lazy_memory_supported {
            self.durable.settle_memory().await;
        }
        spec.memory_source = self.durable.arriving().map(|h| burrow_vmm::MemorySource(h));
        record_working_set(&mut spec, is_stored);
        let limits = spec.limits.clone();
        let mut vm = Vm::restore(spec, true)
            .await
            .map_err(|err| Status::internal(format!("restore failed: {err}")))?;
        // Retried to the deadline, as a warm create's handshake is, and the
        // connection that succeeds is the one kept. Probing first and then
        // dialling again failed a resume outright whenever the second dial was
        // cut off, which a guest still waking does now and then.
        let guest = vm.guest();
        // `restored: true` is what tells the guest to reseed its RNG and reset
        // its clock, which it cannot know on its own.
        let handshook = match guestconn::connect_when_ready(guest.clone(), agent_timeout).await {
            Ok((agent, _)) => {
                guestconn::handshake_upgrading(agent, guest, request, upgrade, agent_timeout)
                    .await
                    .map(drop)
                    .map_err(|err| NoAgent::Handshake(err.message().to_string()))
            }
            Err(err) => Err(NoAgent::Unreachable(agent_timeout, error_chain(&*err))),
        };
        if let Err(failure) = handshook {
            let reason = no_agent_reason(&mut vm, failure).await;
            let _ = vm.kill().await;
            return Err(Status::internal(format!(
                "the guest did not come back: {reason}"
            )));
        }
        start_cpu_cap(&vm, &limits, self.id());
        // This VM handshook synchronously, whatever the last one did. A failure
        // recorded there was a verdict on a VM that no longer exists.
        self.handshake.send_replace(Handshake::Done);

        self.touch();
        tracing::info!(
            sandbox = self.id(),
            restore_ms = vm.boot_latency().as_millis() as u64,
            "sandbox resumed"
        );
        *slot = Some(vm);
        self.suspended_at
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.set_state(common::SandboxState::Running);
        Ok(())
    }

    /// Kills the VM without snapshotting it. The sandbox keeps its address,
    /// tap and disks; what it loses is its memory, so a later boot starts the
    /// image's init over the same writable disk rather than resuming.
    #[tracing::instrument(skip_all, fields(sandbox = %self.id()))]
    async fn shutdown(&self) -> Result<(), Status> {
        self.forget_agent().await;
        let mut slot = self.vm.lock().await;
        if let Some(vm) = slot.take() {
            self.retire_cpu(&vm);
            if let Err(err) = vm.kill().await {
                tracing::error!(sandbox = self.id(), %err, "vmm did not stop");
            }
        } else if !self.is_running() && !self.is_suspended() {
            // A running sandbox with no VM lost its VMM, and is stopped here.
            return Err(Status::failed_precondition("sandbox is already stopped"));
        }
        self.discard_memory().await;
        Ok(())
    }

    /// Stops a running sandbox whose VMM is gone, its slot emptied or its
    /// process exited on its own, keeping its disk. False while it has a live
    /// VMM, or a lifecycle call holds the slot and settles it itself.
    async fn retire_lost_vmm(&self) -> bool {
        let Ok(mut slot) = self.vm.try_lock() else {
            return false;
        };
        if !self.is_running() || slot.as_mut().is_some_and(|vm| !vm.has_exited()) {
            return false;
        }
        if let Some(vm) = slot.take() {
            self.retire_cpu(&vm);
            // Reaps the exited process and removes its cgroup.
            let _ = vm.kill().await;
        }
        self.discard_memory().await;
        self.base_record.lock().unwrap().state_reason = REASON_VMM_EXITED.to_string();
        drop(slot);
        self.forget_agent().await;
        true
    }

    /// Drops the memory a stopped sandbox no longer has. A suspended
    /// sandbox's is on disk and goes too, since a boot must not come back to
    /// a snapshot a later resume would restore around.
    async fn discard_memory(&self) {
        self.memory_chain.lock().await.clear();
        let layout = self.layout();
        for file in layout.files() {
            let _ = tokio::fs::remove_file(self.workdir.join(file)).await;
        }
        if let (Some(hydrator), Some(memory)) =
            (self.durable.hydration.lock().unwrap().take(), layout.memory)
        {
            hydrator.detach(&self.workdir.join(memory));
        }
        Self::remove_stale_diffs(&self.workdir).await;
        self.suspended_at
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.set_state(common::SandboxState::Stopped);
    }

    /// Cold-boots a stopped sandbox on its existing disks and handshakes.
    /// `hotplugged` are volumes attached once the agent is up rather than at
    /// boot, as a create on a root disk attaches them.
    #[tracing::instrument(skip_all, fields(sandbox = %self.id()))]
    async fn boot(
        &self,
        spec: VmSpec,
        request: burrow_proto::guest::v1::HandshakeRequest,
        agent_timeout: std::time::Duration,
        upgrade: Option<&guestconn::GuestUpgrade>,
        hotplugged: &[common::VolumeMount],
    ) -> Result<(), Status> {
        self.forget_agent().await;
        let mut slot = self.vm.lock().await;
        if slot.is_some() {
            return Err(Status::failed_precondition("sandbox is already running"));
        }
        if self.state.load(std::sync::atomic::Ordering::Relaxed)
            != common::SandboxState::Stopped as i32
        {
            return Err(Status::failed_precondition(
                "sandbox is not stopped; resume a suspended one instead",
            ));
        }
        // The guest starts its command ids over.
        self.logs.clear();
        let is_macos = crate::macnode::is_macos(spec.guest_os);
        if is_macos {
            self.cut_mac_disk().await;
            crate::macnode::seed(&spec.workdir, &request.inspection_ca_pem).await;
        }
        let mut vm = Vm::boot(spec.clone())
            .await
            .map_err(|err| Status::internal(format!("boot failed: {err}")))?;
        let (agent, _) = match guestconn::connect_when_ready(vm.guest(), agent_timeout).await {
            Ok(ready) => ready,
            Err(err) => {
                let failure = NoAgent::Unreachable(agent_timeout, error_chain(&*err));
                let reason = no_agent_reason(&mut vm, failure).await;
                let _ = vm.kill().await;
                return Err(Status::internal(reason));
            }
        };
        if let Err(err) = attach_volumes(&vm, hotplugged, spec.guest_os).await {
            let _ = vm.kill().await;
            return Err(err);
        }
        if let Err(err) =
            guestconn::handshake_upgrading(agent, vm.guest(), request, upgrade, agent_timeout).await
        {
            let failure = NoAgent::Handshake(err.message().to_string());
            let reason = no_agent_reason(&mut vm, failure).await;
            let _ = vm.kill().await;
            return Err(Status::internal(reason));
        }
        start_cpu_cap(&vm, &spec.limits, self.id());
        self.handshake.send_replace(Handshake::Done);
        self.touch();
        tracing::info!(
            sandbox = self.id(),
            boot_ms = vm.boot_latency().as_millis() as u64,
            "sandbox booted"
        );
        *slot = Some(vm);
        *self.spec.lock().unwrap() = spec;
        self.set_state(common::SandboxState::Running);
        let guest = slot.as_ref().map(Vm::guest);
        drop(slot);
        if let Some(guest) = guest.filter(|_| is_macos) {
            self.fill_mac_disk(guest).await;
        }
        Ok(())
    }

    /// Cuts a macOS guest's disk image to the size a shrink recorded, its
    /// container having been shrunk while it ran. A failure leaves the disk
    /// as big as it was, which the guest boots on as before.
    async fn cut_mac_disk(&self) {
        let (recorded, actual) = (self.disk_mib(), size_mib(&self.disk_path()));
        if recorded >= actual {
            return;
        }
        match crate::macnode::resize_disk(&self.workdir, recorded).await {
            Ok(()) => tracing::info!(
                sandbox = self.id(),
                from_mib = actual,
                disk_mib = recorded,
                "cut a macOS sandbox's disk to its shrunk container"
            ),
            Err(err) => tracing::warn!(
                sandbox = self.id(),
                err = err.message(),
                "could not cut a macOS sandbox's disk; it boots at {actual} MiB"
            ),
        }
    }

    /// Has the guest's container take the space a grow added while it was
    /// shut down, on the first boot after the grow and on no other. The
    /// request stays until the guest has done it.
    async fn fill_mac_disk(&self, guest: GuestAddr) {
        if !crate::macnode::is_fill_requested(&self.workdir).await {
            return;
        }
        let filled = async {
            container_agent(guest)
                .await?
                .root_disk(burrow_proto::guest::v1::RootDiskRequest {
                    op: burrow_proto::guest::v1::root_disk_request::Op::Grow as i32,
                    ..Default::default()
                })
                .await
                .map(tonic::Response::into_inner)
        }
        .await;
        match filled {
            Ok(filled) => {
                crate::macnode::clear_fill(&self.workdir).await;
                tracing::info!(
                    sandbox = self.id(),
                    container_mib = filled.size_bytes / burrow_common::disk::MIB,
                    "a macOS guest's container took its grown disk"
                );
            }
            Err(err) => tracing::warn!(
                sandbox = self.id(),
                err = err.message(),
                "a macOS guest's container did not take its grown disk; it tries again on its \
                 next boot"
            ),
        }
    }

    /// Writes the same snapshot a suspend would and leaves the guest running.
    ///
    /// The chain is extended exactly as [`Self::suspend`] extends it, in the
    /// same order and for the same reason: what reached disk is the truth, so
    /// the chain names the new layer before the guest is allowed to dirty
    /// another page. Only the end differs, the VM being resumed rather than
    /// killed.
    ///
    /// Failure never leaves the sandbox between states. A snapshot that fails
    /// wrote nothing and the guest goes back to running; a resume that fails
    /// after a snapshot that succeeded leaves a sandbox that *is* its snapshot,
    /// so it is suspended cleanly and `resume` brings it back.
    ///
    /// `capture`, when given, is where the guest's disk is cloned to while it
    /// is paused, so the disk a fork or a snapshot takes is the one the memory
    /// just written describes rather than one the guest has written to since.
    #[tracing::instrument(skip_all, fields(sandbox = %self.id(), diff))]
    /// Also clones each `(image, dest)` in `also` while the guest is paused,
    /// so volumes are captured at the instant its memory is. Returns how long
    /// the guest was paused.
    async fn checkpoint(
        &self,
        capture: Option<&Path>,
        also: &[(PathBuf, PathBuf)],
    ) -> Result<std::time::Duration, Status> {
        // As in a suspend: a fork restores whatever the snapshot caught.
        self.await_handshake().await?;
        self.sync_guest().await;
        let mut slot = self.vm.lock().await;
        let Some(vm) = slot.as_ref() else {
            return Err(Status::failed_precondition(
                "sandbox is suspended; resume it first",
            ));
        };

        let chain = self.memory_chain.lock().await.clone();
        let diff =
            !chain.is_empty() && vm.capabilities().is_diff_snapshot_supported && vm.can_map_diff();
        tracing::Span::current().record("diff", diff);
        let next = Layout::diff(chain.len());

        let paused = std::time::Instant::now();
        let result = async {
            vm.pause().await?;
            if diff {
                vm.snapshot_diff(&next).await
            } else {
                vm.snapshot().await
            }
        }
        .await;

        if let Err(err) = result {
            // Nothing usable was written; the VM is only paused.
            let _ = vm.resume().await;
            return Err(Status::internal(format!("snapshot failed: {err}")));
        }
        if let Some(capture) = capture
            && let Err(err) = crate::rootdisk::clone(&self.disk_path(), capture).await
        {
            let _ = vm.resume().await;
            return Err(Status::internal(format!("capturing the disk: {err}")));
        }
        for (image, dest) in also {
            if let Err(err) = crate::rootdisk::clone(image, dest).await {
                let _ = vm.resume().await;
                return Err(Status::internal(format!("capturing a volume: {err}")));
            }
        }
        // While the guest is still paused, so the mark holds no output the
        // snapshot does not.
        self.logs.mark_checkpoint();

        let flattened = {
            let mut current = self.memory_chain.lock().await;
            if diff {
                current.push(next);
            } else {
                *current = self.layout().memory.map(String::from).into_iter().collect();
                Self::remove_stale_diffs(&self.workdir).await;
            }
            current.len() > MAX_MEMORY_CHAIN
        };

        let resumed = vm.resume().await;
        let paused_for = paused.elapsed();
        if let Err(err) = resumed {
            let vm = slot.take().expect("the vm was present a moment ago");
            self.forget_agent().await;
            self.enter_suspended();
            self.retire_cpu(&vm);
            if let Err(err) = vm.kill().await {
                tracing::error!(sandbox = self.id(), %err, "vmm did not stop after a failed resume");
            }
            return Err(Status::internal(format!(
                "checkpoint written but the guest could not be resumed; \
                 the sandbox is suspended and can be resumed: {err}"
            )));
        }

        // The pause severed the guest's vsock, so the cached channel now points
        // at a connection that no longer exists. Dropping it here is what stops
        // the next exec failing as though the guest itself were broken.
        self.forget_agent().await;

        // Safe with the guest running: `merge_chain` renames a new file over
        // the base and the diffs are only unlinked, so the page-fault handler
        // keeps serving the inodes it already holds open.
        if flattened {
            drop(slot);
            self.compact_memory_chain().await;
        }
        Ok(paused_for)
    }

    /// Copies everything a fork needs into `dest`, and the command logs into
    /// `logs`, returning the child's memory chain. `capture` is the disk a
    /// checkpoint cloned while the guest was paused, moved in as the child's;
    /// without one the source is not running and its disk is cloned as is.
    ///
    /// The VM slot is held throughout, so a suspend, resume or checkpoint
    /// cannot add a layer to the chain half way through copying it.
    ///
    /// The chain is copied whole rather than flattened: the restore path
    /// already reads a chain, being how every suspended sandbox comes back, and
    /// flattening here would put an extra full-image rewrite on the fork's
    /// critical path for a cost the child pays lazily anyway.
    async fn stage_fork(
        &self,
        dest: &Path,
        logs: Option<&Path>,
        capture: Option<&Path>,
    ) -> Result<Vec<String>, Status> {
        self.durable.settle_memory().await;
        let _slot = self.vm.lock().await;
        let chain = self.memory_chain.lock().await.clone();
        if chain.is_empty() {
            return Err(Status::failed_precondition(
                "sandbox has no snapshot to fork from",
            ));
        }

        let io =
            |what: &str, err: std::io::Error| Status::internal(format!("forking {what}: {err}"));

        // Read-only for the guest's whole life, and already links to the
        // template; another link costs nothing and shares the same pages.
        for file in [TEMPLATE_KERNEL, TEMPLATE_ROOTFS] {
            tokio::fs::hard_link(self.workdir.join(file), dest.join(file))
                .await
                .map_err(|err| io(file, err))?;
        }
        // Small, and the child writes its own over it on its first suspend.
        let state = self.layout().state;
        tokio::fs::copy(self.workdir.join(state), dest.join(state))
            .await
            .map_err(|err| io(state, err))?;

        // The chain is linked, not copied. A layer is never written again
        // once it exists: a suspend writes a new diff, and a flatten renames
        // a merged base into place and unlinks the old names, so the child's
        // links keep serving the bytes the source had at the fork. The base
        // is already a link to the template's warm image for the same reason.
        for file in &chain {
            tokio::fs::hard_link(self.workdir.join(file), dest.join(file))
                .await
                .map_err(|err| io(file, err))?;
        }
        // The one file both sides write: a clone, which shares its blocks
        // where the filesystem can.
        let disk = crate::rootdisk::ROOT_DISK;
        match capture {
            Some(capture) => {
                if tokio::fs::rename(capture, dest.join(disk)).await.is_err() {
                    crate::rootdisk::clone(capture, &dest.join(disk))
                        .await
                        .map_err(|err| io(disk, err))?;
                    let _ = tokio::fs::remove_file(capture).await;
                }
            }
            None => {
                crate::rootdisk::clone(&self.workdir.join(disk), &dest.join(disk))
                    .await
                    .map_err(|err| io(disk, err))?;
            }
        }
        // The child's guest holds the same command table, so it needs the
        // output too: without it, a command that finished before the fork
        // replays nothing.
        if let Some(logs) = logs {
            let (source, logs) = (Arc::clone(&self.logs), logs.to_path_buf());
            tokio::task::spawn_blocking(move || source.copy_to(&logs))
                .await
                .map_err(|err| Status::internal(format!("forking command logs: {err}")))?
                .map_err(|err| io("command logs", err))?;
        }
        Ok(chain)
    }

    /// Copies everything a snapshot object needs into `dest`.
    ///
    /// The same files a fork stages, plus the shape they were taken with:
    /// Firecracker restores a machine configuration from the snapshot rather
    /// than from what a later caller asks for, and a snapshot that outlives its
    /// sandbox has nothing else left to read it from.
    async fn stage_snapshot(
        &self,
        dest: &Path,
        capture: Option<&Path>,
    ) -> Result<crate::snapshot::Staged, Status> {
        let chain = self
            .stage_fork(
                dest,
                Some(&dest.join(crate::snapshot::COMMAND_LOGS)),
                capture,
            )
            .await?;
        Ok(crate::snapshot::Staged {
            sandbox_id: self.id.clone(),
            template: self.template.clone(),
            hypervisor: self.hypervisor,
            vcpus: self.vcpus(),
            mem_mib: self.mem_mib(),
            boot_mem_mib: self.boot_mem_mib(),
            max_mem_mib: self.max_mem_mib(),
            is_nested_virt_enabled: self.is_nested_virt_enabled(),
            disk_mib: size_mib(&dest.join(crate::rootdisk::ROOT_DISK)),
            chain,
            inspection_root: self
                .base_record
                .lock()
                .unwrap()
                .inspection_root_fingerprint
                .clone(),
        })
    }
}

/// Where the state a new sandbox restores from comes from.
///
/// A live sandbox and a snapshot object hold the same files under the same
/// names, which is what makes both restorable, so they differ only in the copy.
/// What a macOS agent reports in Health when its Security framework trusts
/// the inspection root it was given.
const FEATURE_ROOT_TRUSTED: &str = "inspection-root-trusted";

/// The certificate inspected guests trust and its fingerprint.
#[derive(Clone)]
struct InspectionRoot {
    pem: String,
    fingerprint: String,
}

enum RestoreSource<'a> {
    /// A live sandbox, and the disk a checkpoint captured of it if it runs.
    Sandbox(&'a Arc<RunningSandbox>, Option<PathBuf>),
    Snapshot {
        id: &'a str,
        template: String,
        hypervisor: Hypervisor,
        disk_mib: u32,
    },
    /// A sandbox's own state in the object store, being adopted here.
    Stored {
        store: &'a crate::objstore::ObjectStore,
        manifest: &'a crate::durable::Manifest,
    },
}

impl RestoreSource<'_> {
    /// Stages the state, returning the memory chain and, when the base is
    /// still arriving, what it is arriving from.
    async fn stage_into(
        &self,
        snapshots: &crate::snapshot::SnapshotStore,
        dest: &Path,
        logs_dir: &Path,
    ) -> Result<(Vec<String>, Option<Arc<crate::chunks::Hydrator>>), Status> {
        match self {
            Self::Sandbox(source, capture) => Ok((
                source
                    .stage_fork(dest, Some(logs_dir), capture.as_deref())
                    .await?,
                None,
            )),
            Self::Snapshot { id, .. } => snapshots.stage_into(id, dest, logs_dir).await,
            Self::Stored { store, manifest } => {
                crate::durable::stage(store, snapshots, manifest, dest, logs_dir).await
            }
        }
    }

    fn template(&self) -> String {
        match self {
            Self::Sandbox(source, _) => source.template().to_string(),
            Self::Snapshot { template, .. } => template.clone(),
            Self::Stored { manifest, .. } => manifest.template.clone(),
        }
    }

    /// The hypervisor the state was written by, which is the only one that
    /// can restore it.
    #[allow(clippy::result_large_err)]
    fn hypervisor(&self) -> Result<Hypervisor, Status> {
        match self {
            Self::Sandbox(source, _) => Ok(source.hypervisor),
            Self::Snapshot { hypervisor, .. } => Ok(*hypervisor),
            Self::Stored { manifest, .. } => manifest.hypervisor(),
        }
    }

    /// The size of the disk the restored sandbox gets, in MiB.
    fn disk_mib(&self) -> u32 {
        match self {
            Self::Sandbox(source, _) => size_mib(&source.disk_path()),
            Self::Snapshot { disk_mib, .. } => *disk_mib,
            Self::Stored { manifest, .. } => manifest.disk_mib,
        }
    }
}

/// How a VM failed to give its sandbox a guest agent.
enum NoAgent {
    /// No vsock connection reached the agent before the deadline.
    Unreachable(std::time::Duration, String),
    /// The agent connected, and its handshake failed.
    Handshake(String),
    /// A deferred handshake gave up, at the step named.
    Stalled(String),
}

/// Lines of the guest's console a failure carries.
const CONSOLE_LINES: usize = 30;

/// Why a VM's guest agent never answered, as an operator debugging a
/// template needs it: the guest kernel's panic, the VMM's exit and what it
/// last printed, or which step ran out of time, then the console's last
/// lines.
async fn no_agent_reason(vm: &mut Vm, failure: NoAgent) -> String {
    let console = vm.console_tail(usize::MAX).await;
    let lines: Vec<&str> = console.lines().collect();
    let tail = lines[lines.len().saturating_sub(CONSOLE_LINES)..].join("\n");
    let why = if let Some(panic) = burrow_vmm::console::kernel_panic(&console) {
        format!("the guest kernel panicked: {panic}")
    } else if let Some(status) = vm.exit_status() {
        let output = vm.vmm_log_tail(20).await;
        if output == tail {
            return format!(
                "the VMM exited ({status}) before the guest agent connected; its last output \
                 and the guest's console:\n{tail}"
            );
        }
        format!(
            "the VMM exited ({status}) before the guest agent connected; it last printed:\n{output}"
        )
    } else {
        match failure {
            NoAgent::Unreachable(timeout, err) => {
                format!("the guest agent made no vsock connection within {timeout:?}: {err}")
            }
            NoAgent::Handshake(err) => {
                format!("the guest agent connected, and its handshake failed: {err}")
            }
            NoAgent::Stalled(err) => format!("the guest agent never came up: {err}"),
        }
    };
    match tail.is_empty() {
        true => format!("{why}\nthe guest wrote nothing to its console"),
        false => format!("{why}\nconsole, last {CONSOLE_LINES} lines:\n{tail}"),
    }
}

/// Flattens an error and its sources. tonic wraps connector failures in an
/// opaque "transport error", so the useful cause is always further down.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(err) = source {
        parts.push(err.to_string());
        source = err.source();
    }
    parts.join(": ")
}

#[derive(Clone)]
pub struct SandboxManager {
    /// Seals the secrets a persisted record carries: brokered header values,
    /// forward tokens and Kit credentials. The record in memory stays plain,
    /// since the proxy injects from it.
    vault: Arc<burrow_common::vault::Vault>,
    config: NodeConfig,
    sandboxes: Arc<Mutex<HashMap<String, Arc<RunningSandbox>>>>,
    /// Disk promised to creates still building, and the lock that makes
    /// measuring and promising one step.
    disk_admissions: Arc<crate::diskcap::Admissions>,
    /// Root disks made ahead of creates, where the filesystem cannot clone.
    spares: crate::rootdisk::Spares,
    resizer: Arc<crate::resizer::Resizer>,
    /// Ids claimed by a create that has not finished provisioning. Held so a
    /// duplicate create is refused during the seconds a VM takes to build,
    /// rather than only before and after.
    creating: Arc<Mutex<std::collections::HashSet<String>>>,
    ipam: Arc<Mutex<Arc<Ipam>>>,
    /// sandbox id -> published ports.
    ports: Arc<Mutex<HashMap<String, Vec<firewall::PortMap>>>>,
    /// The userspace network stacks of sandboxes without a tap, which the
    /// firewall sync drives instead of nftables.
    usernets: crate::macnode::UserNets,
    /// The macOS guests starting on this Mac, held against Apple's limit.
    mac_slots: crate::macnode::Slots,
    /// Tailcat servers for the sandboxes shared here.
    shares: Arc<crate::share::Shares>,
    /// Source-address -> egress policy, consulted by the proxy.
    proxy_policies: Arc<burrow_proxy::PolicyTable>,
    /// DNS pins, pruned alongside the policy table so a recycled address never
    /// inherits the previous sandbox's resolutions.
    resolutions: Arc<burrow_proxy::Resolutions>,
    /// What the proxy refuses to dial on any sandbox's behalf.
    ///
    /// The same set [`Self::denied_addresses`] renders into the ruleset, and
    /// written from the same place: the proxy runs on the host, outside the
    /// chain that denies these, so a rule the proxy did not hear about is a
    /// rule a sandbox can walk around.
    denied: Arc<burrow_proxy::DeniedAddresses>,
    /// Reported in heartbeats; the orchestrator stops placing here when set.
    draining: Arc<std::sync::atomic::AtomicBool>,
    /// Guest addresses on other nodes that share a private network with a
    /// sandbox here. Refreshed from the orchestrator on every heartbeat.
    remote_members: Arc<Mutex<HashMap<String, Vec<burrow_proto::node::v1::NetworkMember>>>>,
    /// Private-network names, served by this node's resolver. Rebuilt from the
    /// same membership the firewall is rendered from, so what resolves and what
    /// is reachable cannot drift apart.
    directory: Arc<burrow_proxy::directory::Directory>,
    /// Durable mirror of the registry, so a restart can pick sandboxes back up.
    store: Arc<burrow_store::Store>,
    /// Snapshot objects this node holds. Outside the sandbox map deliberately:
    /// a snapshot outlives the sandbox it was taken from.
    snapshots: Arc<crate::snapshot::SnapshotStore>,
    /// Live copy of the event log, for tails that are following it. The log
    /// itself is the `events` table; this only carries what is appended.
    events: tokio::sync::broadcast::Sender<common::Event>,
    /// Pushes the log to the orchestrator and tells a lifecycle call when its
    /// event is committed there.
    delivery: Arc<crate::delivery::Delivery>,
    /// Every sandbox's totals as of the last reaper tick, for the exporter.
    metrics: crate::metrics::SandboxMetrics,
    volumes: Arc<crate::volume::VolumeStore>,
    /// Woken when this node has something the orchestrator should hear about
    /// before the next scheduled heartbeat.
    announce: Arc<tokio::sync::Notify>,
    /// Addresses of the fleet's edge routers, denied to every sandbox
    /// alongside the control plane.
    ///
    /// Learned on the heartbeat rather than configured: an edge is opt-in per
    /// node, so this node cannot know from its own flags which of its peers
    /// serves one. Its own is in here too.
    edge_addresses: Arc<std::sync::Mutex<Vec<std::net::IpAddr>>>,
    /// Sandboxes provisioned ahead of demand, ready to be handed out.
    ///
    /// A create otherwise spends its whole time restoring a VM, waiting for its
    /// agent to accept and handshaking. Doing it in advance turns a create into
    /// bookkeeping.
    /// The root handed to sandboxes that opted in to TLS inspection. Set once
    /// at startup, read on every create.
    inspection_ca: Arc<std::sync::Mutex<Option<InspectionRoot>>>,
    /// Where node-side policy events, a request rule expiring among them, are
    /// recorded beside the proxy's. Set once at startup.
    audit: Arc<std::sync::Mutex<Option<burrow_proxy::AuditLog>>>,
    /// Request rules already seen to have expired, by sandbox, position,
    /// domain and expiry, so each expiry is recorded and re-rendered once.
    expired_rules: Arc<std::sync::Mutex<std::collections::HashSet<ExpiredRule>>>,
    /// Serialises the whole of [`SandboxManager::sync_firewall`].
    ///
    /// The render is taken from a snapshot of the sandbox map, but applying it
    /// touches nftables, the proxy's policy table and the resolver's pins, none
    /// of which are under that lock. Two syncs that overlapped could therefore
    /// apply in the opposite order to the one they rendered in, leaving the
    /// node enforcing an older ruleset than it believes, including one that
    /// still names a sandbox that has been deleted. Held across snapshot,
    /// render and apply, so the last render to start is the last to land.
    firewall: Arc<tokio::sync::Mutex<()>>,
    /// What each template has been asked for, and what has been warmed.
    ///
    /// Both halves are bounded per template. The shapes come from create
    /// requests, so a caller choosing a fresh vcpu/memory pair every time would
    /// otherwise grow this for the life of the node *and* queue a full warm
    /// build, costing a boot, a snapshot and the node's one warm build lock,
    /// for every novel one.
    warm_shapes: Arc<std::sync::Mutex<HashMap<String, WarmShapes>>>,
    /// Held by an automatic warm build from its admission checks to its
    /// finish, so they run one after another with the checks made against
    /// the node as it is when each starts.
    warm_queue: Arc<tokio::sync::Mutex<()>>,
    /// How long this node may go on resuming durable sandboxes without
    /// hearing from the orchestrator.
    lease: Arc<std::sync::Mutex<NodeLease>>,
    /// Sandboxes moved off this node whose teardown is still running, each
    /// gate held until it finishes. A move straight back waits on it, or the
    /// teardown would take the returning sandbox's directory and lease too.
    releasing: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Sandboxes recovery kept but could not put back in service.
    held: Arc<std::sync::Mutex<HashMap<String, Held>>>,
    /// The routes bringing public addresses to their taps, synced with every
    /// ruleset.
    host_routes: Arc<burrow_net::public::HostRoutes>,
    /// Which sandbox holds each public address, for waking and auditing.
    public_index: Arc<crate::publicip::PublicIndex>,
}

/// The public addresses one tapped sandbox holds, taken with the ruleset.
struct Publics {
    sandbox_id: String,
    ips: Vec<common::PublicIp>,
}

/// A sandbox recovery found on disk and could not bring back: its record,
/// failed and with the reason, and what of this node it still holds.
struct Held {
    record: common::Sandbox,
    workdir: Option<PathBuf>,
    is_leased: bool,
}

enum Recovery {
    Restored,
    Held,
    Gone,
}

/// Renewed by every heartbeat the orchestrator answers. Once it runs out the
/// orchestrator may write this node off and let another adopt its durable
/// sandboxes, so from then on this node resumes none of them on its own say.
#[derive(Default)]
struct NodeLease {
    renewed: Option<std::time::Instant>,
    length: std::time::Duration,
}

/// Distinct shapes of one template whose demand is counted, and whose build
/// attempts are remembered.
///
/// Only a tally, so it is cheap, but it is keyed by numbers a caller chooses
/// and therefore has to be bounded like everything else. The least-requested
/// entry makes way, which keeps the shapes that recur and drops the one-offs.
const MAX_TRACKED_SHAPES: usize = 16;

/// How long an automatic warm build waits for the node to have no create in
/// flight before giving the slot up.
const WARM_IDLE_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// The pause after an automatic warm build before the next may start, so a
/// burst of new shapes does not keep the node booting warm VMs back to back.
const WARM_BUILD_GAP: std::time::Duration = std::time::Duration::from_secs(2);

/// One template's warm bookkeeping.
#[derive(Default)]
struct WarmShapes {
    /// Creates seen per shape, capped at [`MAX_TRACKED_SHAPES`].
    demand: Vec<(ShapeKey, u32)>,
    /// Shapes a build has been started for, oldest first, capped at
    /// [`MAX_TRACKED_SHAPES`].
    ///
    /// One attempt per shape while it is remembered: a build holds the node's
    /// warm build lock, and one that failed usually fails again for the same
    /// reason. A shape is forgotten when its snapshot is evicted, so asking
    /// for it again builds it again.
    attempted: Vec<ShapeKey>,
}

impl WarmShapes {
    /// Counts one create of `key` and says whether it now deserves a snapshot.
    fn record_demand(&mut self, key: &ShapeKey, policy: &crate::warm::WarmPolicy) -> bool {
        // Pinned shapes, the one a create with no resource policy asks for
        // among them, are warmed on sight rather than on repetition.
        if policy.is_pinned(key.shape()) {
            return true;
        }
        if let Some(entry) = self.demand.iter_mut().find(|(shape, _)| shape == key) {
            entry.1 = entry.1.saturating_add(1);
            return entry.1 >= policy.demand;
        }
        if self.demand.len() >= MAX_TRACKED_SHAPES {
            // The least-requested entry, which is the one a burst of novel
            // shapes would otherwise be able to push the recurring ones out with.
            let (weakest, _) = self
                .demand
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, count))| *count)
                .map(|(index, entry)| (index, entry.1))
                .expect("the tally is not empty here");
            self.demand.swap_remove(weakest);
        }
        self.demand.push((key.clone(), 1));
        policy.demand <= 1
    }

    /// Claims the one attempt this shape gets, or says it is already taken.
    fn claim_attempt(&mut self, key: &ShapeKey) -> bool {
        if self.attempted.iter().any(|shape| shape == key) {
            return false;
        }
        self.attempted.push(key.clone());
        // Oldest first, so the cap forgets the shape that has gone longest
        // without being asked for rather than refusing the new one.
        if self.attempted.len() > MAX_TRACKED_SHAPES {
            self.attempted.remove(0);
        }
        true
    }

    /// Gives an attempt back, for a build the node declined to start or a
    /// snapshot it evicted.
    fn forget(&mut self, key: &ShapeKey) {
        self.attempted.retain(|shape| shape != key);
    }
}

/// The machine a warm snapshot is taken as, which is what a create has to
/// match to restore it.
///
/// Both are fixed when the VM is built and cannot be changed by a restore.
/// The disk is not part of it: a create asking for more than the snapshot's
/// restores it and grows the disk, and every snapshot is built at its
/// template's default disk.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ShapeKey {
    template: String,
    vcpus: u32,
    mem_mib: u32,
    max_mem_mib: u32,
}

impl ShapeKey {
    fn of(template: &str, resources: &common::ResourcePolicy) -> Self {
        let shape = crate::warm::Shape::wanted(resources);
        Self {
            template: template.to_string(),
            vcpus: shape.vcpus,
            mem_mib: shape.mem_mib,
            max_mem_mib: shape.max_mem_mib,
        }
    }

    fn shape(&self) -> crate::warm::Shape {
        crate::warm::Shape {
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
            disk_mib: 0,
            max_mem_mib: self.max_mem_mib,
        }
    }
}

impl SandboxManager {
    pub fn new(
        config: NodeConfig,
        proxy_policies: Arc<burrow_proxy::PolicyTable>,
        resolutions: Arc<burrow_proxy::Resolutions>,
        denied: Arc<burrow_proxy::DeniedAddresses>,
        directory: Arc<burrow_proxy::directory::Directory>,
        store: Arc<burrow_store::Store>,
        vault: burrow_common::vault::Vault,
    ) -> Self {
        Self {
            vault: Arc::new(vault),
            inspection_ca: Arc::new(std::sync::Mutex::new(None)),
            audit: Arc::new(std::sync::Mutex::new(None)),
            expired_rules: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            warm_shapes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            warm_queue: Arc::new(tokio::sync::Mutex::new(())),
            firewall: Arc::new(tokio::sync::Mutex::new(())),
            snapshots: Arc::new(crate::snapshot::SnapshotStore::new(
                &config.data_dir,
                config.object_store.clone(),
                Hypervisor::ALL
                    .into_iter()
                    .map(|h| (h, config.version(h).to_string()))
                    .collect(),
            )),
            volumes: Arc::new(
                crate::volume::VolumeStore::new(&config.data_dir)
                    .with_object_store(config.object_store.clone()),
            ),
            events: tokio::sync::broadcast::channel(1024).0,
            delivery: Arc::new(crate::delivery::Delivery::new(config.event_delivery)),
            metrics: Default::default(),
            shares: Arc::new(crate::share::Shares::new(
                config.share.clone(),
                &config.data_dir,
            )),
            spares: crate::rootdisk::Spares::new(config.data_dir.join("spares")),
            resizer: Default::default(),
            config,
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            disk_admissions: Default::default(),
            creating: Arc::new(Mutex::new(std::collections::HashSet::new())),
            // Replaced once the orchestrator assigns this node its slice.
            // Node 0 is the first slice of the pool and always in range, so
            // the only way this fails is a pool with no slices at all.
            ipam: Arc::new(Mutex::new(Arc::new(
                Ipam::for_node(0).expect("node 0 is always inside the address pool"),
            ))),
            ports: Arc::new(Mutex::new(HashMap::new())),
            usernets: Default::default(),
            mac_slots: Default::default(),
            proxy_policies,
            resolutions,
            denied,
            directory,
            store,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            remote_members: Arc::new(Mutex::new(HashMap::new())),
            announce: Arc::new(tokio::sync::Notify::new()),
            edge_addresses: Arc::new(std::sync::Mutex::new(Vec::new())),
            lease: Default::default(),
            releasing: Default::default(),
            held: Default::default(),
            host_routes: Default::default(),
            public_index: Default::default(),
        }
    }

    /// Denies the fleet's edge routers to every sandbox on this node.
    ///
    /// An edge proxies into a published port addressed by sandbox id, so a
    /// sandbox that can reach one has reached every sandbox that edge serves,
    /// without a packet crossing a rule about private networks. Every node's
    /// edge is in here, this node's own included.
    pub async fn set_edge_addresses(&self, addresses: Vec<std::net::IpAddr>) -> Result<(), Status> {
        *self.edge_addresses.lock().unwrap() = addresses;
        self.sync_firewall().await
    }

    /// Records who owns each writable volume image before the jail is handed
    /// it, so the grant can be taken back when the sandbox lets go.
    ///
    /// Only the writable ones: a read-only mount is left in `shared` and never
    /// chowned at all.
    async fn remember_volume_owners(&self, mounts: &[common::VolumeMount]) {
        for mount in mounts
            .iter()
            .filter(|mount| !mount.is_tmpfs && !mount.is_read_only)
        {
            self.volumes.remember_owner(&mount.volume).await;
        }
    }

    /// Every address a sandbox is denied outright, whatever its policy says.
    fn denied_addresses(&self) -> Vec<std::net::IpAddr> {
        let mut denied = self.config.control_plane.clone();
        denied.extend(self.edge_addresses.lock().unwrap().iter().copied());
        denied.sort();
        denied.dedup();
        denied
    }

    /// Confines address allocation to this node's slice of the pool.
    ///
    /// Applied before recovery, so sandboxes reload into the same range they
    /// were created in. Changing it once sandboxes exist would strand their
    /// addresses, so that case is refused loudly rather than silently
    /// producing a node whose sandboxes span two slices.
    pub async fn set_node_index(&self, index: u32) {
        if self.ipam.lock().await.node_index() == index {
            return;
        }
        if !self.sandboxes.lock().await.is_empty() {
            tracing::error!(
                current = self.ipam.lock().await.node_index(),
                assigned = index,
                "cannot move address slice while sandboxes exist; their addresses \
                 would be stranded and may collide with another node's"
            );
            return;
        }
        let mut ipam = self.ipam.lock().await;
        if ipam.node_index() == index {
            return;
        }
        // An index past the end of the pool is the orchestrator's mistake, not
        // this node's: keep the slice already in use and say so, rather than
        // taking the node down over an assignment it did not choose.
        let assigned = match Ipam::for_node(index) {
            Ok(ipam) => ipam,
            Err(err) => {
                tracing::error!(
                    index, %err,
                    "refusing an address slice this node cannot allocate from; \
                     keeping the current one"
                );
                return;
            }
        };
        *ipam = Arc::new(assigned);
        tracing::info!(index, subnet = %ipam.subnet(), "address pool assigned");
    }

    pub async fn node_index(&self) -> u32 {
        self.ipam.lock().await.node_index()
    }

    pub async fn subnet(&self) -> String {
        self.ipam.lock().await.subnet()
    }

    /// Moves a sandbox's files into its jail when a run with `--jailer` off
    /// left them outside it. Without this the sandbox would be found with no
    /// snapshot and discarded.
    async fn move_into_jail(&self, id: &str, hypervisor: Hypervisor, workdir: &Path) {
        let Some(jail) = self.config.jail_for(hypervisor) else {
            return;
        };
        if tokio::fs::try_exists(workdir).await.unwrap_or(true) {
            return;
        }
        let found = self.config.data_dir.join("sandboxes").join(id);
        if found == workdir || !tokio::fs::try_exists(&found).await.unwrap_or(false) {
            return;
        }
        let moved = async {
            if let Some(parent) = workdir.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::rename(&found, workdir).await?;
            let shared = [TEMPLATE_KERNEL.to_string(), TEMPLATE_ROOTFS.to_string()].into();
            grant_to_jail(workdir, jail, &shared).await
        };
        match moved.await {
            Ok(()) => {
                tracing::info!(sandbox = id, %hypervisor, "moved the sandbox's files into its jail")
            }
            Err(err) => {
                tracing::error!(sandbox = id, %err, "could not move the sandbox's files into its jail")
            }
        }
    }

    /// Records which remote addresses share a private network with sandboxes
    /// here, then re-renders so mesh traffic is permitted.
    pub async fn set_remote_members(
        &self,
        members: HashMap<String, Vec<burrow_proto::node::v1::NetworkMember>>,
    ) {
        {
            let mut current = self.remote_members.lock().await;
            if *current == members {
                // Heartbeats arrive constantly; only re-render on a change.
                return;
            }
            *current = members;
        }
        if let Err(err) = self.sync_firewall().await {
            tracing::error!(%err, "could not re-render for remote membership");
        }
    }

    /// Asks the heartbeat loop to report now rather than on its own schedule.
    ///
    /// Placement is driven by the inventory a node last reported, so until the
    /// next heartbeat lands a template built or imported a moment ago is
    /// invisible and a create naming it fails.
    pub fn announce_now(&self) {
        self.announce.notify_one();
    }

    /// Waits for either the heartbeat interval or something worth announcing.
    pub async fn wait_to_report(&self, interval: std::time::Duration) {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = self.announce.notified() => {}
        }
    }

    /// Refuses work needing a hypervisor this node does not offer.
    #[allow(clippy::result_large_err)]
    pub fn require_hypervisor(&self, hypervisor: Hypervisor) -> Result<(), Status> {
        if self.config.hypervisors.contains(&hypervisor) {
            return Ok(());
        }
        Err(Status::failed_precondition(format!(
            "this node does not run {hypervisor}; start burrowd with --hypervisors including it"
        )))
    }

    /// Refuses nested virtualization where the guest could not be given it:
    /// under a hypervisor that masks the extensions, or on a node whose KVM
    /// has nesting off.
    #[allow(clippy::result_large_err)]
    fn require_nested_virt(
        &self,
        hypervisor: Hypervisor,
        resources: &common::ResourcePolicy,
    ) -> Result<(), Status> {
        if !resources.is_nested_virt_enabled {
            return Ok(());
        }
        if !hypervisor.capabilities().is_nested_virt_supported {
            return Err(Status::failed_precondition(format!(
                "{hypervisor} on {} cannot give a guest nested virtualization; it needs Cloud \
                 Hypervisor on x86_64",
                std::env::consts::ARCH
            )));
        }
        if !self.config.is_nested_virt_supported {
            return Err(Status::failed_precondition(
                "this node cannot give a guest nested virtualization: its KVM has nesting off \
                 (kvm_amd or kvm_intel nested=1) or it runs no Cloud Hypervisor",
            ));
        }
        Ok(())
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Marks the node as draining, optionally suspending what it runs.
    ///
    /// Draining only stops *new* placement; existing sandboxes keep working
    /// unless suspended, so a drain can be used to quiesce a host before
    /// maintenance without interrupting anyone mid-command.
    pub async fn set_drain(&self, drain: bool, suspend: bool) -> u32 {
        self.draining
            .store(drain, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(drain, suspend, "drain state changed");
        if !(drain && suspend) {
            return 0;
        }

        let sandboxes: Vec<_> = self.sandboxes.lock().await.values().cloned().collect();
        let mut suspended = 0;
        for sandbox in sandboxes {
            if !sandbox.is_running() {
                continue;
            }
            match sandbox.suspend().await {
                Ok(()) => {
                    self.resync_public(&sandbox).await;
                    self.volumes.release_all(sandbox.id());
                    self.sample_last(&sandbox).await;
                    self.persist(&sandbox).await;
                    self.close_session(&sandbox, ENDED_SUSPENDED).await;
                    self.spawn_upload(&sandbox);
                    suspended += 1;
                }
                Err(err) => {
                    tracing::error!(sandbox = sandbox.id(), %err, "could not suspend while draining")
                }
            }
        }
        suspended
    }

    /// Writes a sandbox's current shape to the store.
    async fn persist(&self, sandbox: &RunningSandbox) {
        let record = sandbox.record();
        let ports = self
            .ports
            .lock()
            .await
            .get(sandbox.id())
            .cloned()
            .unwrap_or_default();
        let mut sealed = record.clone();
        if let Err(err) = seal_secrets(&self.vault, &mut sealed) {
            tracing::error!(sandbox = record.id, %err, "could not seal the record's secrets; not persisting it");
            return;
        }
        let row = burrow_store::SandboxRow {
            id: record.id.clone(),
            template: record.template.clone(),
            record: prost::Message::encode_to_vec(&sealed),
            state: record.state,
            lease_block: sandbox.lease.block,
            tap: sandbox.tap.clone(),
            ports: ports
                .iter()
                .map(|p| burrow_store::PortRow {
                    host_port: p.host_port,
                    guest_port: p.guest_port,
                    is_udp: p.protocol == firewall::Protocol::Udp,
                })
                .collect(),
            share: self.shares.spec(sandbox.id()).await,
            suspended_at: sandbox.suspended_at(),
        };
        if let Err(err) = self.store.put_sandbox(&row).await {
            tracing::error!(sandbox = record.id, %err, "failed to persist sandbox");
        }
    }

    /// Appends to the event log, hands the event to anyone following it, and
    /// waits for the orchestrator to commit it.
    ///
    /// Written before it is broadcast, and with the position the store gave
    /// it, so a tail that replays and then follows sees every event exactly
    /// once. The usage figures are the sandbox's totals at this instant.
    async fn emit(&self, sandbox: &RunningSandbox, kind: common::EventKind, detail: &str) {
        let shape = (sandbox.vcpus(), sandbox.mem_mib());
        self.log_event(&sandbox.record(), shape, kind, detail).await;
    }

    /// [`Self::emit`] for a record, with the vcpus and memory its VM had.
    async fn log_event(
        &self,
        record: &common::Sandbox,
        (vcpus, mem_mib): (u32, u32),
        kind: common::EventKind,
        detail: &str,
    ) {
        let row = burrow_store::EventRow {
            seq: 0,
            node_id: String::new(),
            node_seq: 0,
            at_unix_ms: burrow_common::unix_now_ms(),
            sandbox_id: record.id.clone(),
            kind: kind as i32,
            state: record.state,
            detail: detail.to_string(),
            template: record.template.clone(),
            metadata_json: serde_json::to_string(&record.tags).unwrap_or_else(|_| "{}".into()),
            cpu_usage_usec: record.cpu_usage_usec,
            rx_bytes: record.rx_bytes,
            tx_bytes: record.tx_bytes,
            vcpus,
            mem_mib,
        };
        let seq = match self.store.append_event(&row).await {
            Ok(seq) => seq,
            Err(err) => {
                tracing::error!(sandbox = record.id, kind = kind.label(), %err, "could not record an event");
                return;
            }
        };
        let _ = self
            .events
            .send(common::Event::from(burrow_store::EventRow { seq, ..row }));
        self.delivery.wait(seq).await;
    }

    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<common::Event> {
        self.events.subscribe()
    }

    pub fn delivery(&self) -> Arc<crate::delivery::Delivery> {
        Arc::clone(&self.delivery)
    }

    pub fn metrics(&self) -> &crate::metrics::SandboxMetrics {
        &self.metrics
    }

    /// Refuses a lifecycle call while its events could not be delivered, if
    /// the node was told to.
    #[allow(clippy::result_large_err)]
    pub fn admit(&self) -> Result<(), Status> {
        self.delivery.admit()
    }

    /// Runs a lifecycle call to its end on a task of its own, so a caller that
    /// gives up, a cancelled RPC among them, cannot leave it half done.
    pub fn detached<T, Fut>(
        &self,
        call: impl FnOnce(Self) -> Fut,
    ) -> impl std::future::Future<Output = Result<T, Status>>
    where
        T: Send + 'static,
        Fut: std::future::Future<Output = Result<T, Status>> + Send + 'static,
    {
        use tracing::Instrument as _;
        let task = tokio::spawn(call(self.clone()).in_current_span());
        async move {
            task.await.map_err(|err| {
                Status::internal(format!("the lifecycle call did not finish: {err}"))
            })?
        }
    }

    /// Stops a running sandbox whose VMM is gone and records why, returning
    /// whether it was one.
    async fn retire_lost_vmm(&self, sandbox: &Arc<RunningSandbox>) -> bool {
        if !sandbox.retire_lost_vmm().await {
            return false;
        }
        tracing::error!(
            sandbox = sandbox.id(),
            "the sandbox's VMM exited while it was running; keeping it stopped on its disk"
        );
        self.resync_public(sandbox).await;
        self.forget_stored(sandbox).await;
        self.volumes.release_all(sandbox.id());
        self.persist(sandbox).await;
        self.close_session(sandbox, ENDED_FAILED).await;
        self.announce_now();
        true
    }

    /// Refuses a call that needs the sandbox's VMM when it has lost it,
    /// stopping the sandbox first.
    async fn require_vmm(&self, sandbox: &Arc<RunningSandbox>) -> Result<(), Status> {
        match self.retire_lost_vmm(sandbox).await {
            true => Err(Status::failed_precondition(format!(
                "sandbox {}: {REASON_VMM_EXITED}",
                sandbox.id()
            ))),
            false => Ok(()),
        }
    }

    /// Records that a VM has started for this sandbox.
    ///
    /// Every way a sandbox gets a VM comes through here (a cold or warm boot, a
    /// restore from a fork or a snapshot, a resume), so the list is the whole
    /// history rather than the subset one code path remembered to write.
    ///
    /// `from` is the sandbox's totals from before its VM started, for a VM
    /// that came back from a suspend or a stop: restoring or booting it is
    /// work of the interval it starts, not of the one it ends.
    async fn open_session(
        &self,
        sandbox: &RunningSandbox,
        started_by: common::SessionStart,
        from: Option<Usage>,
    ) {
        let row = burrow_store::SessionRow {
            id: burrow_common::SessionId::generate().to_string(),
            sandbox_id: sandbox.id().to_string(),
            started_at_ms: burrow_common::unix_now_ms(),
            ended_at_ms: 0,
            started_by: started_by as i32,
            ended_by: 0,
        };
        if let Err(err) = self.store.put_session(&row).await {
            tracing::error!(sandbox = sandbox.id(), %err, "could not record a session");
            return;
        }
        *sandbox.session.lock().unwrap() = Some(row.id);
        let record = with_totals(sandbox.record(), from);
        let shape = (sandbox.vcpus(), sandbox.mem_mib());
        self.log_event(&record, shape, EVENT_STARTED, started_by.label())
            .await;
        // Applied as a session lands, which is the one moment the count grows.
        if let Err(err) = self
            .store
            .retain_recent_sessions(sandbox.id(), MAX_SESSIONS)
            .await
        {
            tracing::warn!(sandbox = sandbox.id(), %err, "could not bound the session list");
        }
    }

    /// Records that this sandbox's VM has stopped. A no-op when none is open.
    async fn close_session(&self, sandbox: &RunningSandbox, ended_by: common::SessionEnd) {
        let Some(id) = sandbox.session.lock().unwrap().take() else {
            return;
        };
        self.sample_last(sandbox).await;
        if let Err(err) = self
            .store
            .end_session(&id, burrow_common::unix_now_ms(), ended_by as i32)
            .await
        {
            tracing::error!(sandbox = sandbox.id(), %err, "could not close a session");
        }
        self.emit(sandbox, EVENT_STOPPED, ended_by.label()).await;
    }

    /// Every VM a sandbox has run, newest first.
    /// The end of a sandbox's console log, `tail_bytes` of it or 64 KiB.
    pub async fn console(
        &self,
        id: &str,
        tail_bytes: u32,
    ) -> Result<burrow_proto::api::v1::ConsoleLog, Status> {
        let sandbox = self.get(id).await?;
        let max_bytes = match u64::from(tail_bytes) {
            0 => 64 * 1024,
            bytes => bytes.min(2 * burrow_vmm::console::MAX_BYTES),
        };
        let (text, is_truncated) =
            burrow_vmm::console::tail_bytes(&sandbox.workdir, max_bytes).await;
        Ok(burrow_proto::api::v1::ConsoleLog { text, is_truncated })
    }

    pub async fn list_sessions(&self, id: &str) -> Result<Vec<common::Session>, Status> {
        // Checked first, so an unknown sandbox is a not-found rather than an
        // empty list that reads as "it never ran".
        self.get(id).await?;
        let rows = self
            .store
            .list_sessions(id)
            .await
            .map_err(|err| Status::internal(format!("reading sessions: {err}")))?;
        Ok(rows
            .into_iter()
            .map(|row| common::Session {
                id: row.id,
                sandbox_id: row.sandbox_id,
                started_at_unix_ms: row.started_at_ms,
                ended_at_unix_ms: row.ended_at_ms,
                started_by: row.started_by,
                ended_by: row.ended_by,
            })
            .collect())
    }

    /// Reads every sandbox's cgroup and byte counters into its running totals.
    ///
    /// Run on the reaper's tick, and again before any ruleset is applied: the
    /// render flushes the counter table, so a sample taken afterwards would
    /// have lost whatever was counted since the last one.
    pub async fn sample_usage(&self) {
        let traffic = match firewall::counters().await {
            Ok(traffic) => traffic,
            Err(err) => {
                tracing::debug!(%err, "could not read the byte counters");
                Default::default()
            }
        };

        let sandboxes: Vec<_> = self.sandboxes.lock().await.values().cloned().collect();
        for sandbox in sandboxes {
            self.absorb_traffic(&sandbox, &traffic, !sandbox.is_parked());
            // `try_lock`, because a suspend or a restore holds this slot for as
            // long as it takes to write a memory image. A sample skipped is
            // taken on the next tick; one that waited would stall the reaper.
            if let Ok(slot) = sandbox.vm.try_lock()
                && let Some(vm) = slot.as_ref()
            {
                sandbox.absorb_cpu(vm);
            }
            sandbox.ensure_feed();
        }
    }

    /// Folds a sandbox's byte counters into its totals, or, while it has no
    /// VM, only into its baseline: what arrives for a suspended or stopped
    /// sandbox is dropped at its tap and reaches no guest.
    fn absorb_traffic(
        &self,
        sandbox: &RunningSandbox,
        traffic: &HashMap<std::net::Ipv4Addr, firewall::Traffic>,
        is_counted: bool,
    ) {
        // A sandbox on a userspace stack is counted there, not by nftables.
        let Some(counted) = self
            .usernets
            .traffic(sandbox.id())
            .or_else(|| traffic.get(&sandbox.lease.guest_ip).copied())
        else {
            return;
        };
        if is_counted {
            sandbox.absorb_traffic(counted);
        } else {
            sandbox.rebase_traffic(counted);
        }
    }

    /// The totals a VM about to start is counted from, with the byte
    /// baseline moved up to now so nothing that arrived while it had none is
    /// counted once it does.
    async fn boundary(&self, sandbox: &RunningSandbox) -> Usage {
        let traffic = firewall::counters().await.unwrap_or_default();
        self.absorb_traffic(sandbox, &traffic, false);
        sandbox.totals()
    }

    /// One sandbox's readings, taken as its VM stops, so the totals the
    /// `stopped` event carries end that interval. A VM already gone had its
    /// cpu read as it was killed.
    async fn sample_last(&self, sandbox: &RunningSandbox) {
        let traffic = firewall::counters().await.unwrap_or_default();
        self.absorb_traffic(sandbox, &traffic, true);
        if let Ok(slot) = sandbox.vm.try_lock()
            && let Some(vm) = slot.as_ref()
        {
            sandbox.absorb_cpu(vm);
        }
    }

    /// Reattaches to sandboxes recorded by a previous run of this daemon.
    ///
    /// A VMM does not survive its parent, so nothing is running at this point.
    /// Sandboxes that were snapshotted (paused explicitly, or suspended during
    /// a graceful shutdown) are restored to `SUSPENDED`, and stopped ones to
    /// `STOPPED`. One that was running when the daemon died has lost its
    /// memory but not its disk, so it comes back stopped with the reason on
    /// its record. One that cannot be put back in service keeps its row and
    /// its files and is reported failed. Only a sandbox with nothing left on
    /// disk is dropped, and its `destroyed` event says so.
    pub async fn recover(&self) {
        let rows = match self.store.list_sandboxes().await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::error!(%err, "cannot read sandbox store; starting empty");
                return;
            }
        };
        // A VMM does not survive its parent, so every session still open
        // belongs to a VM that is already gone. Closed here rather than left
        // open forever, and without an end time: nothing observed when those
        // VMs stopped.
        match self.store.close_open_sessions(ENDED_UNKNOWN as i32).await {
            Ok(0) => {}
            Ok(closed) => tracing::info!(closed, "closed sessions left open by the previous run"),
            Err(err) => tracing::error!(%err, "could not close open sessions"),
        }

        // Not returned early when there are no rows: a node that crashed
        // mid-create has nothing recorded and everything to clean up.
        let (mut restored, mut held, mut discarded) = (0, 0, 0);
        for row in rows {
            match self.recover_one(row).await {
                Recovery::Restored => restored += 1,
                Recovery::Held => held += 1,
                Recovery::Gone => discarded += 1,
            }
        }

        self.collect_orphan_workdirs().await;
        tracing::info!(restored, held, discarded, "sandbox recovery complete");
        if self.config.object_store.is_some() {
            let (blobs, templates) = (
                crate::blobs::BlobStore::new(&self.config.data_dir),
                self.config.templates_dir(),
            );
            tokio::spawn(async move { crate::rootdisk::index_templates(&blobs, &templates).await });
        }
        if let Err(err) = self.sync_firewall().await {
            tracing::error!(%err, "recovered sandboxes have no firewall rules");
        }
    }

    async fn recover_one(&self, mut row: burrow_store::SandboxRow) -> Recovery {
        // Read before anything else, because it decides where the sandbox's
        // files are. Secrets are sealed field by field, so the record decodes
        // without them.
        let mut stored = match <common::Sandbox as prost::Message>::decode(&row.record[..]) {
            Ok(stored) => stored,
            Err(err) => {
                let stored = common::Sandbox {
                    template: row.template.clone(),
                    ..Default::default()
                };
                let reason = format!("its stored record does not decode: {err}");
                return self.hold(&row, stored, None, false, reason).await;
            }
        };
        // A hypervisor this build does not know (a newer build's, say) puts
        // the files somewhere this one cannot look, and not finding a
        // snapshot there is no reason to destroy the sandbox.
        let Some(hypervisor) = Hypervisor::from_record(&stored.hypervisor) else {
            let reason = format!(
                "it runs under {}, a hypervisor this build does not know",
                stored.hypervisor
            );
            return self.hold(&row, stored, None, false, reason).await;
        };
        let workdir = self.config.sandbox_dir(&row.id, hypervisor);
        self.move_into_jail(&row.id, hypervisor, &workdir).await;
        let layout = hypervisor.layout();
        let guest_os = burrow_vmm::GuestOs::from_record(&stored.guest_os).unwrap_or_default();
        let exists = async |file: &str| {
            tokio::fs::try_exists(workdir.join(file))
                .await
                .unwrap_or(false)
        };
        let is_resumable =
            row.state == common::SandboxState::Suspended as i32 && exists(layout.state).await;

        if !exists(disk_file(guest_os)).await {
            tracing::warn!(
                sandbox = row.id,
                "nothing of the sandbox is left on disk; recording it destroyed"
            );
            stored.id = row.id.clone();
            self.log_recorded(&stored, EVENT_DESTROYED, DETAIL_LOST)
                .await;
            tap::delete(&row.tap).await;
            let _ = self.config.remove_workdir(&workdir).await;
            let _ = tokio::fs::remove_dir_all(self.config.command_logs_dir(&row.id)).await;
            let _ = self.store.delete_sandbox(&row.id).await;
            // Sessions describe a sandbox's VMs and have no owner once it is
            // gone.
            let _ = self.store.delete_sessions(&row.id).await;
            return Recovery::Gone;
        }
        if !is_resumable && row.state != common::SandboxState::Stopped as i32 {
            // Its VM died with the daemon, so the memory is gone and the
            // disk is what is left, which is what a stop leaves too. An older
            // snapshot goes with it: a boot must not come back to one.
            tracing::warn!(
                sandbox = row.id,
                "the VM did not survive the daemon; keeping the sandbox stopped on its disk"
            );
            for file in layout.files() {
                let _ = tokio::fs::remove_file(workdir.join(file)).await;
            }
            RunningSandbox::remove_stale_diffs(&workdir).await;
            row.state = common::SandboxState::Stopped as i32;
            row.suspended_at = 0;
            stored.id = row.id.clone();
            stored.state = row.state;
            stored.state_reason = REASON_LOST.to_string();
            row.record = prost::Message::encode_to_vec(&stored);
            if let Err(err) = self.store.put_sandbox(&row).await {
                tracing::error!(sandbox = row.id, %err, "could not record the sandbox as stopped");
            }
            self.log_recorded(&stored, EVENT_STOPPED, DETAIL_LOST).await;
        }

        let mut record = stored.clone();
        if let Err(err) = open_secrets(&self.vault, &mut record) {
            let reason = format!("its stored secrets do not open: {err}");
            return self.hold(&row, stored, Some(workdir), false, reason).await;
        }
        // Hold the recorded lease before anything else can be allocated, so a
        // recovered sandbox keeps the address baked into its snapshot. A
        // duplicate lease may name a tap the accepted sandbox owns; the orphan
        // sweep removes only taps no sandbox kept.
        if let Err(err) = self.ipam.lock().await.reserve(&row.id, row.lease_block) {
            let reason = format!(
                "its address block {} cannot be reserved: {err}",
                row.lease_block
            );
            return self.hold(&row, stored, Some(workdir), false, reason).await;
        }
        let Some(lease) = self.ipam.lock().await.get(&row.id) else {
            self.ipam.lock().await.release(&row.id);
            let reason = format!("its address block {} has no lease", row.lease_block);
            return self.hold(&row, stored, Some(workdir), false, reason).await;
        };
        if hypervisor.capabilities().is_tap_networked
            && let Err(err) = tap::create(&lease).await
        {
            let reason = format!("its tap {} cannot be created: {err}", row.tap);
            return self.hold(&row, stored, Some(workdir), true, reason).await;
        }

        let stored_policy = record.policy.clone().unwrap_or_default();
        let resources = stored_policy.resources.unwrap_or_default();
        // Recovery has to describe the VM exactly as it was, volumes
        // included, or a restore is refused for a drive set that does not
        // match the snapshot.
        let volumes = stored_policy.volumes.clone();
        let usage = Usage {
            cpu_usec: record.cpu_usage_usec,
            rx_bytes: record.rx_bytes,
            tx_bytes: record.tx_bytes,
            ..Default::default()
        };
        let is_systemd =
            crate::oci::sandbox_environment(&self.config.data_dir, &workdir, &record.template)
                .await
                .systemd;
        let spec = self.build_spec(
            &row.id,
            &workdir,
            hypervisor,
            guest_os,
            &resources,
            &lease,
            &row.tap,
            &volumes,
            is_systemd,
            stored_policy.is_console_verbose,
        );

        let sandbox = Arc::new(RunningSandbox {
            id: record.id.clone(),
            template: record.template.clone(),
            hypervisor,
            base_record: std::sync::Mutex::new(record),
            state: std::sync::atomic::AtomicI32::new(row.state),
            vm: Mutex::new(None),
            spec: std::sync::Mutex::new(spec),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            // A sandbox that was running when the node went down never
            // recorded a suspension, so its row says 0, which read
            // literally is 1970 and would put it instantly past its
            // retention. Its suspension starts now, at recovery.
            suspended_at: std::sync::atomic::AtomicI64::new(match row.suspended_at {
                0 => burrow_common::unix_now(),
                at => at,
            }),
            agent_channel: Mutex::new(None),
            agent_features: Mutex::new(None),
            agent_timeout: self.config.agent_timeout,
            // A recovered sandbox is suspended: it has no VM, so there is
            // no handshake in flight. The resume that starts one does its
            // own, synchronously.
            handshake: settled(),
            // Rebuilt from disk rather than persisted: the files are the
            // record, and a chain that disagreed with them would fail
            // every restore.
            memory_chain: Mutex::new(discover_memory_chain(&workdir, hypervisor.layout()).await),
            // Carried forward from the stored record: what the sandbox
            // spent before the daemon restarted is still what it spent.
            // The raw readings are not restored, because the counters they
            // came from are gone.
            usage: std::sync::Mutex::new(usage),
            session: std::sync::Mutex::new(None),
            durable: Default::default(),
            logs: Arc::new(crate::cmdlogs::CommandLogs::new(
                &self.config.command_logs_dir(&row.id),
                self.config.command_log_rotation,
            )),
            workdir,
            lease,
            tap: row.tap.clone(),
        });
        self.recover_durability(&sandbox).await;
        if !row.ports.is_empty() {
            self.ports.lock().await.insert(
                row.id.clone(),
                row.ports
                    .iter()
                    .map(|p| firewall::PortMap {
                        host_port: p.host_port,
                        guest_port: p.guest_port,
                        protocol: if p.is_udp {
                            firewall::Protocol::Udp
                        } else {
                            firewall::Protocol::Tcp
                        },
                    })
                    .collect(),
            );
        }
        self.emit(&sandbox, EVENT_RECOVERED, "").await;
        self.sandboxes.lock().await.insert(row.id.clone(), sandbox);
        // Restarted from its stored keys, so the address clients hold is
        // still the one that works. A relay that is unreachable right now
        // is not a reason to lose the share: the server keeps trying.
        if let Some(share) = row.share
            && let Err(err) = self.shares.start(self, &row.id, share).await
        {
            tracing::error!(sandbox = row.id, %err, "could not restart the sandbox's share");
        }
        Recovery::Restored
    }

    /// Keeps a sandbox recovery could not put back in service. Its row and
    /// its files stay, so the next restart tries again; until then it is
    /// listed as failed with the reason, and a delete removes it.
    async fn hold(
        &self,
        row: &burrow_store::SandboxRow,
        mut record: common::Sandbox,
        workdir: Option<PathBuf>,
        is_leased: bool,
        reason: String,
    ) -> Recovery {
        tracing::error!(
            sandbox = row.id,
            reason,
            "sandbox left out of service; its files are kept"
        );
        self.volumes.release_all(&row.id);
        record.id = row.id.clone();
        record.state = common::SandboxState::Failed as i32;
        record.state_reason = reason;
        self.log_recorded(&record, EVENT_RECOVERED, "").await;
        self.held.lock().unwrap().insert(
            row.id.clone(),
            Held {
                record,
                workdir,
                is_leased,
            },
        );
        Recovery::Held
    }

    /// Logs an event for a sandbox recovery has only the record of. The
    /// record is written on lifecycle calls only, so the figures of the last
    /// event the sandbox logged are taken where they are further on, and its
    /// shape with them.
    async fn log_recorded(&self, record: &common::Sandbox, kind: common::EventKind, detail: &str) {
        let mut record = record.clone();
        let resources = record
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.clone())
            .unwrap_or_default();
        let mut shape = (
            resources.vcpus.max(1),
            match resources.mem_mib {
                0 => DEFAULT_MEM_MIB,
                mem_mib => mem_mib,
            },
        );
        if let Ok(Some(last)) = self.store.last_event_of(&record.id).await {
            record.cpu_usage_usec = record.cpu_usage_usec.max(last.cpu_usage_usec);
            record.rx_bytes = record.rx_bytes.max(last.rx_bytes);
            record.tx_bytes = record.tx_bytes.max(last.tx_bytes);
            if last.vcpus > 0 {
                shape = (last.vcpus, last.mem_mib);
            }
        }
        self.log_event(&record, shape, kind, detail).await;
    }

    /// Removes a sandbox recovery left out of service.
    async fn remove_held(&self, held: Held) {
        let id = held.record.id.clone();
        self.log_recorded(&held.record, EVENT_DESTROYED, "").await;
        if let Err(err) = self.store.delete_sandbox(&id).await {
            tracing::error!(sandbox = id, %err, "failed to remove sandbox from store");
        }
        if let Err(err) = self.store.delete_sessions(&id).await {
            tracing::error!(sandbox = id, %err, "failed to remove sessions from store");
        }
        if held.is_leased {
            self.release_lease(&id).await;
        }
        if let Some(workdir) = &held.workdir
            && let Err(err) = self.config.remove_workdir(workdir).await
        {
            tracing::warn!(sandbox = id, %err, "failed to remove sandbox directory");
        }
        let _ = tokio::fs::remove_dir_all(self.config.command_logs_dir(&id)).await;
        tracing::info!(
            sandbox = id,
            "removed a sandbox recovery had left out of service"
        );
    }

    /// Removes sandbox directories with no corresponding record.
    ///
    /// These accumulate from crashes. Each holds a root disk and possibly
    /// a memory snapshot, so left alone they quietly consume the node's disk.
    async fn collect_orphan_workdirs(&self) {
        // An import stages under build/ and removes its directory when it is
        // done; one that died mid-unpack, out of disk say, left gigabytes
        // nothing will read.
        let build = self.config.data_dir.join("build");
        if let Ok(mut entries) = tokio::fs::read_dir(&build).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if entry.file_name().to_string_lossy().starts_with("import-") {
                    let _ = tokio::fs::remove_dir_all(entry.path()).await;
                }
            }
        }
        crate::staged::Cache::new(&self.config.data_dir).prune();
        crate::template::sweep_pending(&self.config.data_dir).await;
        let mut known: std::collections::HashSet<String> =
            self.sandboxes.lock().await.keys().cloned().collect();
        known.extend(self.held.lock().unwrap().keys().cloned());

        // Both roots are scanned, not one: with `--jail` a sandbox's workdir
        // is its chroot under the jailer's base, so scanning only
        // `data_dir/sandboxes` would leave every jailed sandbox's directory
        // behind forever.
        //
        // Each root carries the *paths* its known sandboxes occupy rather than
        // their ids. The jailer names a chroot after its own sanitised id, so
        // matching directory names against ids there finds nothing and reads
        // every live sandbox as an orphan.
        let sandboxes_root = self.config.data_dir.join("sandboxes");
        let mut roots = vec![(
            sandboxes_root.clone(),
            known
                .iter()
                .map(|id| sandboxes_root.join(id))
                .collect::<std::collections::HashSet<_>>(),
        )];
        if let Some(jail) = &self.config.jail {
            for hypervisor in Hypervisor::ALL {
                roots.push((
                    jail.hypervisor_dir(hypervisor),
                    known
                        .iter()
                        .map(|id| jail.dir_for(hypervisor, id))
                        .collect(),
                ));
            }
        }
        let logs_root = self.config.data_dir.join("command-logs");
        roots.push((
            logs_root.clone(),
            known.iter().map(|id| logs_root.join(id)).collect(),
        ));

        let mut removed = 0;
        for (root, live) in roots {
            let Ok(mut entries) = tokio::fs::read_dir(&root).await else {
                continue;
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                if live.contains(&entry.path()) {
                    continue;
                }
                if tokio::fs::remove_dir_all(entry.path()).await.is_ok() {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            tracing::info!(removed, "removed orphaned sandbox directories");
        }
        self.collect_orphan_taps(&known).await;
    }

    /// Removes tap devices belonging to no recovered sandbox.
    ///
    /// A tap is programmed before its sandbox is recorded, so a crash in that
    /// window leaves one with no store row to reclaim it by. The host's own
    /// interface list is the only record left, so it is what recovery
    /// reconciles against.
    async fn collect_orphan_taps(&self, known: &std::collections::HashSet<String>) {
        let live: std::collections::HashSet<String> = {
            let sandboxes = self.sandboxes.lock().await;
            known
                .iter()
                .filter_map(|id| sandboxes.get(id).map(|sandbox| sandbox.tap.clone()))
                .collect()
        };

        let Ok(output) = tokio::process::Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .await
        else {
            return;
        };
        if !output.status.success() {
            return;
        }

        let mut removed = 0;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            // `1: lo: <LOOPBACK…`: the name is the second field, and may carry
            // an `@parent` suffix for stacked devices.
            let Some(name) = line
                .split_whitespace()
                .nth(1)
                .map(|field| field.trim_end_matches(':'))
                .map(|field| field.split('@').next().unwrap_or(field))
            else {
                continue;
            };
            // Only burrow's own taps, which are named `bt<block>`.
            if !name.starts_with("bt")
                || name.len() == 2
                || !name[2..].bytes().all(|b| b.is_ascii_digit())
            {
                continue;
            }
            if live.contains(name) {
                continue;
            }
            tap::delete(name).await;
            removed += 1;
        }
        if removed > 0 {
            tracing::info!(removed, "removed tap devices belonging to no sandbox");
        }
    }

    /// Snapshots every running sandbox so a restart can resume them.
    ///
    /// Called on shutdown. Without it, stopping the daemon destroys every
    /// sandbox on the node; with it, a restart is a pause and a resume.
    pub async fn suspend_all(&self) {
        let sandboxes: Vec<_> = self.sandboxes.lock().await.values().cloned().collect();
        let mut suspended = 0;
        for sandbox in sandboxes {
            if !sandbox.is_running() {
                continue;
            }
            match sandbox.suspend().await {
                // Persisted before the event is sent: a stop that runs out of
                // time waiting on the control plane must not leave the store
                // saying `Running` over a snapshot that is on disk.
                Ok(()) => {
                    self.volumes.release_all(sandbox.id());
                    self.sample_last(&sandbox).await;
                    self.persist(&sandbox).await;
                    self.close_session(&sandbox, ENDED_SUSPENDED).await;
                    suspended += 1;
                }
                Err(err) => {
                    tracing::error!(sandbox = sandbox.id(), %err, "could not suspend for shutdown")
                }
            }
        }
        tracing::info!(suspended, "suspended sandboxes for shutdown");
    }

    /// Publishes a guest port on the node's address.
    pub async fn expose_port(
        &self,
        sandbox_id: &str,
        guest_port: u16,
        requested_host_port: u16,
        protocol: firewall::Protocol,
    ) -> Result<firewall::PortMap, Status> {
        if guest_port == 0 {
            return Err(Status::invalid_argument("guest_port is required"));
        }
        // Confirms the sandbox exists before any allocation happens.
        self.get(sandbox_id).await?;

        let mut ports = self.ports.lock().await;
        let taken: std::collections::HashSet<u16> =
            ports.values().flatten().map(|p| p.host_port).collect();

        let host_port = if requested_host_port != 0 {
            // A caller who names their own host port is still confined to the
            // publishing range. Without this a tenant could ask for 22, or the
            // daemon's own gRPC port, and have the node DNAT it into their
            // guest, taking over a service they do not own.
            if !HOST_PORT_RANGE.contains(&requested_host_port) {
                return Err(Status::invalid_argument(format!(
                    "host port {requested_host_port} is outside the publishable range {}-{}",
                    HOST_PORT_RANGE.start,
                    HOST_PORT_RANGE.end - 1
                )));
            }
            if taken.contains(&requested_host_port) {
                return Err(Status::already_exists(format!(
                    "host port {requested_host_port} is already published"
                )));
            }
            requested_host_port
        } else {
            HOST_PORT_RANGE
                .clone()
                .find(|p| !taken.contains(p))
                .ok_or_else(|| Status::resource_exhausted("no free host ports"))?
        };

        ports
            .entry(sandbox_id.to_string())
            .or_default()
            .push(firewall::PortMap {
                host_port,
                guest_port,
                protocol,
            });
        drop(ports);

        self.sync_firewall().await?;
        tracing::info!(
            sandbox = sandbox_id,
            host_port,
            guest_port,
            protocol = protocol.keyword(),
            "port published"
        );
        Ok(firewall::PortMap {
            host_port,
            guest_port,
            protocol,
        })
    }

    pub async fn list_ports(&self, sandbox_id: &str) -> Vec<firewall::PortMap> {
        self.ports
            .lock()
            .await
            .get(sandbox_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn close_port(&self, sandbox_id: &str, host_port: u16) -> Result<(), Status> {
        {
            let mut ports = self.ports.lock().await;
            let entry = ports
                .get_mut(sandbox_id)
                .ok_or_else(|| Status::not_found("sandbox has no published ports"))?;
            let before = entry.len();
            entry.retain(|p| p.host_port != host_port);
            if entry.len() == before {
                return Err(Status::not_found(format!(
                    "host port {host_port} is not published for this sandbox"
                )));
            }
        }
        self.sync_firewall().await?;
        Ok(())
    }

    /// Shares a sandbox through a tailcat address, or reshapes an existing
    /// share. The keys, and so the address, are kept unless `rotate` asks for
    /// new ones.
    pub async fn share(
        &self,
        sandbox_id: &str,
        shape: crate::share::ShareShape,
        rotate: bool,
    ) -> Result<crate::share::ShareInfo, Status> {
        for key in &shape.allowed_clients {
            key.parse::<tailcat_rs::NodePublic>()
                .map_err(|_| Status::invalid_argument(format!("invalid client key {key:?}")))?;
        }
        let sandbox = self.get(sandbox_id).await?;
        let spec = match self.shares.spec(sandbox_id).await {
            Some(existing) if !rotate => shape.onto(existing),
            _ => crate::share::Shares::new_spec(shape),
        };
        let info = self.shares.start(self, sandbox_id, spec).await?;
        self.persist(&sandbox).await;
        Ok(info)
    }

    pub async fn get_share(&self, sandbox_id: &str) -> Result<crate::share::ShareInfo, Status> {
        self.get(sandbox_id).await?;
        self.shares
            .get(sandbox_id)
            .await
            .ok_or_else(|| Status::not_found("sandbox is not shared"))
    }

    pub async fn unshare(&self, sandbox_id: &str) -> Result<(), Status> {
        let sandbox = self.get(sandbox_id).await?;
        if !self.shares.stop(sandbox_id).await {
            return Err(Status::not_found("sandbox is not shared"));
        }
        self.persist(&sandbox).await;
        tracing::info!(sandbox = sandbox_id, "share revoked");
        Ok(())
    }

    /// Gives a sandbox's address block back to the pool and forgets every
    /// connection conntrack still associates with it.
    ///
    /// The ruleset stops new packets, but conntrack keeps an established
    /// flow's NAT binding for days, and the block is reissued to the very
    /// next create. Without the flush, a tenant that inherits the address
    /// also inherits the previous sandbox's live connections, whatever its
    /// own policy says.
    async fn release_lease(&self, id: &str) {
        let guest_ip = {
            let ipam = self.ipam.lock().await;
            let lease = ipam.get(id);
            ipam.release(id);
            lease.map(|lease| (lease.guest_ip, lease.guest_ip6()))
        };
        if let Some((guest_ip, guest_ip6)) = guest_ip {
            firewall::flush_conntrack(guest_ip, guest_ip6).await;
        }
    }

    /// Rebuilds the entire nftables ruleset from the currently running
    /// sandboxes. Called after any change to the set or to a policy; a full
    /// render can never drift from what the daemon believes is running.
    ///
    /// A failure to apply is returned rather than only logged: a sandbox whose
    /// rules never landed is a sandbox whose network policy is not being
    /// enforced, and whoever asked for it has to hear about that.
    async fn sync_firewall(&self) -> Result<(), Status> {
        // Held snapshot through apply: see the field's own comment for what
        // overlapping syncs would otherwise leave the node enforcing.
        let _ordered = self.firewall.lock().await;
        self.render_firewall(None).await
    }

    /// Puts a provisioned sandbox in the map with its rules already in force.
    ///
    /// Rendered with the sandbox and applied before it is inserted, under the
    /// one firewall lock, so no other render can land in between and leave it
    /// out. A failure registers nothing: the caller still holds the only
    /// handle and tears the sandbox down, so the error it returns is true.
    /// The guest may be running already, but a tap the ruleset does not name
    /// has every packet dropped by the anti-spoofing chain, so it has had no
    /// network until now.
    async fn register(&self, sandbox: &Arc<RunningSandbox>) -> Result<(), Status> {
        let _ordered = self.firewall.lock().await;
        self.render_firewall(Some(sandbox)).await?;
        self.sandboxes
            .lock()
            .await
            .insert(sandbox.id().to_string(), Arc::clone(sandbox));
        Ok(())
    }

    /// [`Self::register`], tearing the sandbox down when it fails.
    async fn register_or_discard(&self, sandbox: &Arc<RunningSandbox>) -> Result<(), Status> {
        let Err(err) = self.register(sandbox).await else {
            return Ok(());
        };
        if let Err(teardown) = self.tear_down(Arc::clone(sandbox)).await {
            tracing::warn!(sandbox = sandbox.id(), err = %teardown, "could not release a sandbox whose rules did not apply");
        }
        Err(err)
    }

    /// Renders and applies the ruleset for every sandbox in the map, plus
    /// `pending`. The caller holds the firewall lock.
    async fn render_firewall(&self, pending: Option<&Arc<RunningSandbox>>) -> Result<(), Status> {
        // The render below flushes the counter table, so what it has counted
        // has to be banked before it is rebuilt.
        self.sample_usage().await;

        let sandboxes = self.sandboxes.lock().await;
        let all: Vec<&Arc<RunningSandbox>> = sandboxes.values().chain(pending).collect();
        // nftables is Linux's. A node elsewhere renders the same policies for
        // its sandboxes' userspace stacks and needs no ruleset so long as none
        // of them has a tap.
        let is_ruleset_needed = cfg!(target_os = "linux")
            || all
                .iter()
                .any(|sandbox| sandbox.hypervisor.capabilities().is_tap_networked);
        let untapped: std::collections::HashSet<String> = all
            .iter()
            .filter(|sandbox| !sandbox.hypervisor.capabilities().is_tap_networked)
            .map(|sandbox| sandbox.id().to_string())
            .collect();
        let ports = self.ports.lock().await;

        // Private-network membership: sandboxes that share a named network may
        // address each other. Membership is symmetric, so each side gets a
        // rule permitting the other.
        // Keyed by owned names: the record they come from is a snapshot taken
        // under a lock, not something to borrow from.
        let mut members: HashMap<String, Vec<std::net::Ipv4Addr>> = HashMap::new();
        for sandbox in &all {
            for network in networks_of(&sandbox.record()) {
                members
                    .entry(network.to_string())
                    .or_default()
                    .push(sandbox.lease.guest_ip);
            }
        }

        let remote = self.remote_members.lock().await;

        // The directory is built from the same membership as the rules below.
        // Deriving names separately is how a name ends up resolving to
        // something the firewall then drops.
        let mut directory: std::collections::BTreeMap<
            String,
            Vec<burrow_proxy::directory::Member>,
        > = std::collections::BTreeMap::new();
        for sandbox in &all {
            let record = sandbox.record();
            for membership in record
                .policy
                .iter()
                .flat_map(|p| p.networks.iter())
                .filter(|m| !m.network.is_empty())
            {
                directory
                    .entry(membership.network.clone())
                    .or_default()
                    .push(burrow_proxy::directory::Member {
                        sandbox_id: sandbox.id().to_string(),
                        alias: if membership.alias.is_empty() {
                            sandbox.id().to_string()
                        } else {
                            membership.alias.clone()
                        },
                        address: sandbox.lease.guest_ip,
                    });
            }
        }
        for (network, remote_members) in remote.iter() {
            for member in remote_members {
                let Ok(address) = member.guest_ip.parse() else {
                    continue;
                };
                directory.entry(network.clone()).or_default().push(
                    burrow_proxy::directory::Member {
                        sandbox_id: member.sandbox_id.clone(),
                        alias: if member.alias.is_empty() {
                            member.sandbox_id.clone()
                        } else {
                            member.alias.clone()
                        },
                        address,
                    },
                );
            }
        }
        self.directory.replace(directory);
        let mut rules: Vec<firewall::SandboxRules> = all
            .iter()
            .map(|sandbox| {
                let own_ip = sandbox.lease.guest_ip;
                let record = sandbox.record();
                let mut peers: Vec<std::net::Ipv4Addr> = networks_of(&record)
                    .flat_map(|network| {
                        // Local members and members on other nodes are the
                        // same policy; only the path differs.
                        let mut ips = members.get(network).cloned().unwrap_or_default();
                        ips.extend(remote.get(network).into_iter().flatten().filter_map(
                            |member| member.guest_ip.parse::<std::net::Ipv4Addr>().ok(),
                        ));
                        ips
                    })
                    .filter(|ip| *ip != own_ip)
                    .collect();
                peers.sort();
                peers.dedup();

                firewall::SandboxRules {
                    sandbox_id: sandbox.id().to_string(),
                    tap: sandbox.tap.clone(),
                    host_ip: sandbox.lease.host_ip,
                    guest_ip: own_ip,
                    host_ip6: sandbox.lease.host_ip6(),
                    guest_ip6: sandbox.lease.guest_ip6(),
                    mode: policy_mode(&record),
                    allow_cidrs: record
                        .policy
                        .as_ref()
                        .and_then(|p| p.network.as_ref())
                        .map(|n| n.allow_cidrs.clone())
                        .unwrap_or_default(),
                    deny_cidrs: record
                        .policy
                        .as_ref()
                        .and_then(|p| p.network.as_ref())
                        .map(|n| n.deny_cidrs.clone())
                        .unwrap_or_default(),
                    allow_ports: record
                        .policy
                        .as_ref()
                        .and_then(|p| p.network.as_ref())
                        .map(|n| n.allow_ports.clone())
                        .unwrap_or_default(),
                    deny_ports: record
                        .policy
                        .as_ref()
                        .and_then(|p| p.network.as_ref())
                        .map(|n| {
                            n.deny_ports
                                .iter()
                                .map(burrow_net::policy::PortDenial::from)
                                .collect()
                        })
                        .unwrap_or_default(),
                    is_ipv6_denied: record
                        .policy
                        .as_ref()
                        .and_then(|p| p.network.as_ref())
                        .is_some_and(|n| n.is_ipv6_denied),
                    peers,
                    ports: ports.get(sandbox.id()).cloned().unwrap_or_default(),
                    // Filled in below, from the proxy's view of the policy.
                    inspected: None,
                    public: self.public_rules(sandbox, &record),
                }
            })
            .collect();

        // The proxy identifies sandboxes by source address, so its table is
        // refreshed from the same snapshot that produced the firewall rules;
        // otherwise a sandbox could be redirected to a proxy that does not yet
        // know its policy and would deny everything.
        let sandbox_ip6: HashMap<std::net::Ipv4Addr, std::net::Ipv6Addr> = all
            .iter()
            .map(|sandbox| (sandbox.lease.guest_ip, sandbox.lease.guest_ip6()))
            .collect();
        let by_guest_ip: HashMap<std::net::Ipv4Addr, burrow_proxy::SandboxPolicy> = all
            .iter()
            .map(|sandbox| {
                let record = sandbox.record();
                let network = record.policy.as_ref().and_then(|p| p.network.as_ref());
                let egress_mark = rules
                    .iter()
                    .find(|r| r.sandbox_id == sandbox.id())
                    .map_or(0, |r| r.public.mark);
                // The stored record keeps the real values, redaction
                // happening on the way out to callers, so the proxy goes on
                // brokering across a restart and a recover.
                //
                // Patterns are compiled here, once per sync, rather than per
                // request: a policy must never make a request cost work a
                // guest can schedule. A rule that will not compile was refused
                // at the API door, so one arriving here means the policy in
                // force is not the one that was written; it becomes a refusal
                // rather than an allowance.
                let rules = std::sync::Arc::new(
                    network
                        .map(|n| {
                            n.rules
                                .iter()
                                .map(|rule| crate::nodeapi::load_rule(rule, sandbox.id()))
                                .collect()
                        })
                        .unwrap_or_default(),
                );
                (
                    sandbox.lease.guest_ip,
                    burrow_proxy::SandboxPolicy {
                        rules,
                        egress_mark,
                        ..burrow_proxy::SandboxPolicy::from_record(sandbox.id(), network)
                    },
                )
            })
            .collect();

        // Open mode's selective inspection, decided from the same compiled
        // rules the proxy will hold, expiry and binding included, so the
        // redirect and the proxy cannot disagree about which hosts it covers.
        // The addresses are the live pins for those hosts: everything the
        // resolver has redirected so far that is still owed a redirect.
        let now_ms = burrow_proxy::policy::now_unix_ms();
        for sandbox_rules in rules.iter_mut() {
            let Some(policy) = by_guest_ip.get(&sandbox_rules.guest_ip) else {
                continue;
            };
            let hosts = policy.selectively_inspected_hosts(now_ms);
            if hosts.is_empty() {
                continue;
            }
            sandbox_rules.inspected = Some(
                hosts
                    .iter()
                    .flat_map(|host| self.resolutions.live_addresses(&policy.sandbox_id, host))
                    .filter_map(|(address, left)| match address {
                        std::net::IpAddr::V4(v4) => Some((v4, left.as_secs().max(1))),
                        std::net::IpAddr::V6(_) => None,
                    })
                    .collect(),
            );
        }

        let publics: Vec<Publics> = all
            .iter()
            .filter(|sandbox| sandbox.hypervisor.capabilities().is_tap_networked)
            .map(|sandbox| Publics {
                sandbox_id: sandbox.id().to_string(),
                ips: sandbox.base_record.lock().unwrap().public_ips.clone(),
            })
            .collect();

        drop(remote);
        drop(ports);
        drop(sandboxes);

        // A sandbox without a tap is held to the very policy the proxy table
        // and the ruleset get, by its own stack.
        for sandbox_rules in rules.iter().filter(|r| untapped.contains(&r.sandbox_id)) {
            if let Some(proxy) = by_guest_ip.get(&sandbox_rules.guest_ip) {
                self.usernets.update(proxy, sandbox_rules).await;
            }
        }

        // Both of a sandbox's addresses map to its one policy: it is the same
        // sandbox whichever it reaches the proxy from, and an entry missing
        // for one family would read as an unknown source and deny everything.
        // So are its public addresses, which a guest sources from by default.
        let public_sources: HashMap<std::net::Ipv4Addr, Vec<std::net::IpAddr>> = rules
            .iter()
            .map(|r| {
                let mut sources: Vec<std::net::IpAddr> = r
                    .public
                    .v4
                    .iter()
                    .copied()
                    .map(std::net::IpAddr::V4)
                    .collect();
                sources.extend(
                    r.public
                        .v6
                        .iter()
                        .map(|(address, _)| std::net::IpAddr::V6(*address)),
                );
                (r.guest_ip, sources)
            })
            .collect();
        let proxy_table: HashMap<std::net::IpAddr, burrow_proxy::SandboxPolicy> = by_guest_ip
            .into_iter()
            .flat_map(|(guest_ip, policy)| {
                let guest_ip6 = sandbox_ip6.get(&guest_ip).copied();
                let public = public_sources.get(&guest_ip).cloned().unwrap_or_default();
                std::iter::once((std::net::IpAddr::V4(guest_ip), policy.clone()))
                    .chain(guest_ip6.map(|ip6| (std::net::IpAddr::V6(ip6), policy.clone())))
                    .chain(
                        public
                            .into_iter()
                            .map(move |address| (address, policy.clone())),
                    )
            })
            .collect();

        // Pins are keyed by sandbox id, so they are pruned from the same
        // snapshot that defines who exists; a deleted sandbox's promises must
        // not outlive it into whatever reuses its address.
        self.resolutions.retain_live(
            &proxy_table
                .values()
                .map(|policy| policy.sandbox_id.clone())
                .collect(),
        );
        self.proxy_policies.replace(proxy_table);
        let denied = self.denied_addresses();
        // The proxy is told before the ruleset is applied, not after: it is the
        // path that does not go through nftables at all, so the moment to have
        // it enforcing a wider deny list is ahead of the render, never behind.
        // Both families: the proxy dials v6 now, so a control plane reachable
        // over it has to be refused there as well as in the ruleset.
        self.denied.replace(denied.iter().copied());
        if !is_ruleset_needed {
            return Ok(());
        }
        firewall::apply(&firewall::render_with(&rules, &denied))
            .await
            .map_err(|err| {
                tracing::error!(%err, "failed to apply firewall ruleset");
                Status::internal(format!("applying the firewall ruleset: {err}"))
            })?;
        self.sync_public_routes(&rules, &publics).await;
        Ok(())
    }

    /// Re-renders once a sandbox with public addresses starts or stops, so
    /// what arrives for them is delivered, held to wake it, or dropped.
    async fn resync_public(&self, sandbox: &RunningSandbox) {
        let is_public = sandbox.hypervisor.capabilities().is_tap_networked
            && !sandbox.base_record.lock().unwrap().public_ips.is_empty();
        if is_public && let Err(err) = self.sync_firewall().await {
            tracing::warn!(
                sandbox = sandbox.id(),
                err = err.message(),
                "re-rendering public ingress"
            );
        }
    }

    /// Clears the routing rules a previous run left, then starts waking
    /// suspended holders on traffic and auditing public connections.
    pub async fn start_public(&self) {
        if !cfg!(target_os = "linux") {
            return;
        }
        self.host_routes.reset().await;
        #[cfg(target_os = "linux")]
        {
            crate::publicip::spawn_wake(self.clone());
            crate::publicip::spawn_audit(self.clone());
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn public_index(&self) -> &crate::publicip::PublicIndex {
        &self.public_index
    }

    /// Records a connection on a public address beside the proxy's records.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn audit_public(&self, event: burrow_proxy::EgressEvent) {
        if let Some(audit) = self.audit.lock().unwrap().as_ref() {
            audit.record(event);
        }
    }

    /// Routes `ip` to a sandbox here and has its guest take it up.
    ///
    /// Refused for a sandbox without a tap, which has no route for a public
    /// address to arrive on, and for an address another sandbox here holds.
    /// Undone whole when any step fails, so the record never names an address
    /// that does not reach the guest.
    pub async fn attach_public_ip(
        &self,
        sandbox_id: &str,
        ip: common::PublicIp,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;
        if !sandbox.hypervisor.capabilities().is_tap_networked {
            return Err(Status::failed_precondition(
                "this sandbox has no tap: a macOS node's userspace network cannot receive a \
                 routed public address",
            ));
        }
        let address: std::net::IpAddr = ip
            .address
            .parse()
            .map_err(|_| Status::invalid_argument(format!("{:?} is not an address", ip.address)))?;
        for other in self.sandboxes.lock().await.values() {
            if other.id() != sandbox_id
                && other
                    .base_record
                    .lock()
                    .unwrap()
                    .public_ips
                    .iter()
                    .any(|held| held.address == ip.address)
            {
                return Err(Status::already_exists(format!(
                    "{address} is attached to sandbox {} here",
                    other.id()
                )));
            }
        }
        let previous = {
            let mut record = sandbox.base_record.lock().unwrap();
            let previous = record.public_ips.clone();
            record.public_ips.retain(|held| held.address != ip.address);
            record.public_ips.push(ip);
            previous
        };
        let applied = async {
            self.sync_firewall().await?;
            if !self.host_routes.is_applied(address).await {
                return Err(Status::internal(format!(
                    "{address} could not be routed to the sandbox; see the node's log"
                )));
            }
            if sandbox.is_running() {
                self.push_public_addresses(&sandbox).await?;
            }
            Ok(())
        }
        .await;
        if let Err(err) = applied {
            sandbox.base_record.lock().unwrap().public_ips = previous;
            let _ = self.sync_firewall().await;
            return Err(err);
        }
        self.persist(&sandbox).await;
        self.emit(&sandbox, EVENT_IP_ATTACHED, &address.to_string())
            .await;
        Ok(sandbox.record())
    }

    pub async fn detach_public_ip(
        &self,
        sandbox_id: &str,
        address: &str,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;
        let is_held = {
            let mut record = sandbox.base_record.lock().unwrap();
            let before = record.public_ips.len();
            record.public_ips.retain(|held| held.address != address);
            record.public_ips.len() != before
        };
        if !is_held {
            return Ok(sandbox.record());
        }
        self.persist(&sandbox).await;
        self.sync_firewall().await?;
        if sandbox.is_running()
            && let Err(err) = self.push_public_addresses(&sandbox).await
        {
            tracing::warn!(
                sandbox = sandbox_id,
                err = err.message(),
                "guest kept a detached address"
            );
        }
        if let Ok(parsed) = address.parse::<std::net::IpAddr>() {
            firewall::flush_conntrack_address(parsed).await;
        }
        self.emit(&sandbox, EVENT_IP_DETACHED, address).await;
        Ok(sandbox.record())
    }

    /// Tells a running guest the public addresses its record holds.
    async fn push_public_addresses(&self, sandbox: &RunningSandbox) -> Result<(), Status> {
        let network = self
            .guest_network(
                &sandbox.lease,
                &sandbox.record().public_ips,
                sandbox.hypervisor.capabilities().is_tap_networked,
                true,
            )
            .expect("always given");
        if !sandbox.agent_has(PUBLIC_ADDRESSES).await? {
            return Err(Status::failed_precondition(
                "this sandbox's guest agent cannot take a public address; recreate it on a \
                 current template",
            ));
        }
        sandbox.agent().await?.set_public_addresses(network).await?;
        Ok(())
    }

    /// What the guest is told about its addresses: everything on a restore,
    /// and otherwise only when it has public ones to configure, which the
    /// guest applies on any handshake.
    fn guest_network(
        &self,
        lease: &Lease,
        ips: &[common::PublicIp],
        is_tapped: bool,
        is_always: bool,
    ) -> Option<burrow_proto::guest::v1::NetworkConfig> {
        let public_addresses = match is_tapped {
            true => crate::publicip::guest_addresses(ips),
            false => Vec::new(),
        };
        (is_always || !public_addresses.is_empty()).then(|| {
            burrow_proto::guest::v1::NetworkConfig {
                ip: lease.guest_ip.to_string(),
                prefix_len: lease.prefix_len as u32,
                gateway: lease.host_ip.to_string(),
                dns: lease.host_ip.to_string(),
                ip6: lease.guest_ip6().to_string(),
                prefix_len6: lease.prefix_len6() as u32,
                gateway6: lease.host_ip6().to_string(),
                public_addresses,
            }
        })
    }

    /// The sandbox's public side as the ruleset renders it.
    fn public_rules(&self, sandbox: &RunningSandbox, record: &common::Sandbox) -> firewall::Public {
        if !sandbox.hypervisor.capabilities().is_tap_networked {
            return firewall::Public::default();
        }
        let public = &self.config.public;
        let mut out = firewall::Public {
            new_per_sec: public.new_per_sec,
            kbytes_per_sec: public.kbytes_per_sec,
            ..Default::default()
        };
        let (mut smtp4, mut smtp6) = (true, true);
        for ip in &record.public_ips {
            match ip.address.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => {
                    out.v4.push(v4);
                    smtp4 &= ip.is_smtp_allowed;
                }
                Ok(std::net::IpAddr::V6(v6)) => {
                    out.v6.push((v6, ip.prefix_len.clamp(1, 128) as u8));
                    smtp6 &= ip.is_smtp_allowed;
                }
                Err(_) => {}
            }
        }
        out.is_smtp4_allowed = smtp4 && !out.v4.is_empty();
        out.is_smtp6_allowed = smtp6 && !out.v6.is_empty();
        out.ingress = record
            .policy
            .as_ref()
            .and_then(|p| p.network.as_ref())
            .map(|n| {
                n.ingress
                    .iter()
                    .map(burrow_net::policy::IngressRule::from)
                    .collect()
            })
            .unwrap_or_default();
        out.state = if sandbox.is_running() {
            firewall::IngressState::Admit
        } else if sandbox.is_suspended() && record.public_ips.iter().any(|ip| ip.is_wake_on_traffic)
        {
            firewall::IngressState::Wake
        } else {
            firewall::IngressState::Closed
        };
        if !out.v4.is_empty() || !out.v6.is_empty() {
            out.mark = firewall::egress_mark(sandbox.lease.block);
        }
        out
    }

    /// Brings every public address in `rules` to its tap, and records who
    /// holds what for waking and auditing.
    async fn sync_public_routes(&self, rules: &[firewall::SandboxRules], publics: &[Publics]) {
        let public = &self.config.public;
        let mut routes = Vec::new();
        let mut holders = Vec::new();
        for held in publics {
            let Some(rule) = rules.iter().find(|r| r.sandbox_id == held.sandbox_id) else {
                continue;
            };
            let is_waking = rule.public.state == firewall::IngressState::Wake;
            for ip in &held.ips {
                let Ok(address) = ip.address.parse::<std::net::IpAddr>() else {
                    continue;
                };
                let prefix = match address {
                    std::net::IpAddr::V4(_) => 32,
                    std::net::IpAddr::V6(_) => ip.prefix_len.clamp(1, 128) as u8,
                };
                let gateway = ip.gateway.parse::<std::net::IpAddr>().ok();
                let uplink = public.uplink(gateway.unwrap_or(address)).await;
                routes.push(burrow_net::public::Route {
                    tap: rule.tap.clone(),
                    address,
                    prefix,
                    on_link: uplink.clone().filter(|_| ip.is_on_link),
                    egress: gateway
                        .zip(uplink)
                        .map(|(gateway, dev)| burrow_net::public::Egress {
                            gateway,
                            prefix: ip.gateway_prefix_len.clamp(1, 128) as u8,
                            dev,
                        }),
                    mark: rule.public.mark,
                });
                holders.push(crate::publicip::Holder {
                    address,
                    prefix,
                    sandbox_id: rule.sandbox_id.clone(),
                    is_waking,
                });
            }
        }
        self.public_index.replace(holders);
        if let Err(err) = self.host_routes.sync(&routes).await {
            tracing::error!(%err, "could not route every public address");
        }
    }

    /// Replaces a sandbox's network policy and re-renders the boundary.
    ///
    /// Nothing in the guest is told: the policy is enforced entirely on the
    /// host, by the ruleset and the proxy that [`Self::sync_firewall`]
    /// re-renders here. The one thing that cannot be turned on this way is
    /// `is_tls_inspected`, because the guest trusts burrow's CA only through the
    /// handshake that installed it; enabling inspection later would break every
    /// TLS connection the sandbox makes rather than inspecting it.
    ///
    /// A failed render restores the previous policy: the ruleset is applied
    /// transactionally, so leaving the record ahead of it would have the
    /// daemon report a policy the node is not enforcing.
    pub async fn update_network_policy(
        &self,
        sandbox_id: &str,
        network: common::NetworkPolicy,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;

        let previous = {
            let mut record = sandbox.base_record.lock().unwrap();
            let policy = record.policy.get_or_insert_with(Default::default);
            let previous = policy.network.take();
            if network.is_tls_inspected && !previous.as_ref().is_some_and(|n| n.is_tls_inspected) {
                policy.network = previous;
                return Err(Status::invalid_argument(
                    "inspect_tls can only be enabled at creation: the guest is given the \
                     inspection CA at handshake",
                ));
            }
            let mut network = network;
            if let Err(err) = crate::nodeapi::restore_redacted(&mut network, previous.as_ref()) {
                policy.network = previous;
                return Err(err);
            }
            policy.network = Some(network);
            previous
        };

        self.persist(&sandbox).await;
        if let Err(err) = self.sync_firewall().await {
            sandbox
                .base_record
                .lock()
                .unwrap()
                .policy
                .get_or_insert_with(Default::default)
                .network = previous;
            self.persist(&sandbox).await;
            // Best effort: the failed apply changed nothing, so the ruleset
            // already matches the restored record.
            let _ = self.sync_firewall().await;
            return Err(err);
        }
        // The new rules govern new packets; connections opened under the old
        // policy would otherwise ride their conntrack entries past it.
        firewall::flush_conntrack(sandbox.lease.guest_ip, sandbox.lease.guest_ip6()).await;
        tracing::info!(sandbox = sandbox_id, "network policy updated");
        Ok(sandbox.record())
    }

    /// Replaces a sandbox's tags.
    ///
    /// Nothing but the record changes: tags are labels the control plane reads
    /// back, not policy, so there is no ruleset to re-render and no reason to
    /// disturb the guest.
    pub async fn update_tags(
        &self,
        sandbox_id: &str,
        tags: HashMap<String, String>,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;
        sandbox.base_record.lock().unwrap().tags = tags;
        self.persist(&sandbox).await;
        Ok(sandbox.record())
    }

    /// Stamps every Access token issued for a sandbox up to `at_ms` as
    /// revoked, returning the stamp in unix milliseconds.
    /// A stamp never moves back. Persisted with the record, which is what
    /// carries it to the next node when the sandbox moves.
    pub async fn revoke_access(&self, sandbox_id: &str, at_ms: i64) -> Result<i64, Status> {
        if at_ms <= 0 {
            return Err(Status::invalid_argument("a revoke needs its stamp"));
        }
        let sandbox = self.get(sandbox_id).await?;
        let stamp = {
            let mut record = sandbox.base_record.lock().unwrap();
            let stamp = at_ms.max(record.access_revoked_at_ms);
            record.access_revoked_at_ms = stamp;
            stamp
        };
        self.persist(&sandbox).await;
        Ok(stamp)
    }

    /// Replaces a sandbox's exec and file policies.
    ///
    /// A section given here replaces that section wholesale; a section left
    /// out is not touched. Absence is *not* "allow everything" on this path,
    /// unlike a create, where an unset section is what an unrestricted sandbox
    /// looks like: here it would turn tightening `fs` into a silent re-opening
    /// of `exec`.
    ///
    /// Only the record changes. Both policies are enforced by [`crate::nodeapi`]
    /// on the way in, before a command or a path reaches the guest, and the
    /// policy is read off the record on every call, so the new one governs the
    /// next call without anything having to be told.
    pub async fn update_access_policy(
        &self,
        sandbox_id: &str,
        exec: Option<common::ExecPolicy>,
        fs: Option<common::FsPolicy>,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;
        apply_access_policy(
            sandbox
                .base_record
                .lock()
                .unwrap()
                .policy
                .get_or_insert_with(Default::default),
            exec,
            fs,
        );
        self.persist(&sandbox).await;
        tracing::info!(sandbox = sandbox_id, "access policy updated");
        Ok(sandbox.record())
    }

    /// Moves the clocks a sandbox is measured against.
    ///
    /// Only the record changes. Nothing has to be told: the reaper reads the
    /// policy off the sandbox on every pass, so a lifetime extended here is in
    /// force at the next tick without a timer to cancel or reschedule; the
    /// snapshot retention is read when a snapshot is taken. `check` holds the
    /// result to what a create's policy is held to before it is kept.
    pub async fn update_lifetime(
        &self,
        sandbox_id: &str,
        lifetimes: Lifetimes,
        check: impl FnOnce(&common::SnapshotPolicy) -> Result<(), Status>,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;
        if lifetimes.checkpoint_secs.is_some_and(|secs| secs > 0) {
            self.require_checkpoint_store()?;
        }
        {
            let mut record = sandbox.base_record.lock().unwrap();
            let policy = record.policy.get_or_insert_with(Default::default);
            let mut snapshots = policy.snapshots.unwrap_or_default();
            if let Some(secs) = lifetimes.snapshot_expiration_secs {
                snapshots.expiration_secs = secs;
            }
            if let Some(n) = lifetimes.snapshot_keep_last {
                snapshots.keep_last = n;
            }
            if let Some(kept) = lifetimes.is_evicted_snapshot_kept {
                snapshots.is_evicted_kept = kept;
            }
            check(&snapshots)?;
            policy.snapshots = Some(snapshots);
            let lifetime = policy.lifetime.get_or_insert_with(Default::default);
            if let Some(secs) = lifetimes.max_lifetime_secs {
                lifetime.max_lifetime_secs = secs;
            }
            if let Some(secs) = lifetimes.idle_suspend_secs {
                lifetime.idle_suspend_secs = secs;
            }
            if let Some(secs) = lifetimes.suspended_ttl_secs {
                lifetime.suspended_ttl_secs = secs;
            }
            if let Some(secs) = lifetimes.checkpoint_secs {
                lifetime.checkpoint_secs = secs;
            }
            if let Some(memory) = lifetimes.is_memory_checkpointed {
                lifetime.is_memory_checkpointed = memory;
            }
        }
        self.persist(&sandbox).await;
        tracing::info!(sandbox = sandbox_id, "lifetime policy updated");
        Ok(sandbox.record())
    }

    /// Changes a sandbox's vCPUs, memory and root disk, each as far as its
    /// state and hypervisor allow, and says per field what was done. The disk
    /// goes first: a shrink is the one change that can be refused for what
    /// the guest wrote.
    ///
    /// A sandbox that is not running is resized only if the shape it ends
    /// with fits this node, checked before anything changes. With `boot`, a
    /// suspended one is then shut down cleanly so it can take the changes;
    /// booting it on them is the caller's.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_machine(
        &self,
        id: &str,
        vcpus: Option<u32>,
        mem_mib: Option<u32>,
        disk_mib: Option<u32>,
        limits: LimitsUpdate,
        boot: bool,
    ) -> Result<(common::Sandbox, ResourcesUpdated), Status> {
        let sandbox = self.get(id).await?;
        if !sandbox.is_running() {
            self.admit_shape(
                &sandbox,
                vcpus,
                mem_mib,
                disk_mib,
                limits.cpus,
                limits.reserved_cpus,
                boot,
            )
            .await?;
            if boot && sandbox.is_suspended() {
                self.stop(id).await?;
            }
        }
        let mut updated = ResourcesUpdated::default();
        if let Some(mib) = disk_mib {
            let current = sandbox.disk_mib();
            updated.disk_mib = Some(match self.resize_disk(&sandbox, mib).await {
                Ok((change, filesystem_bytes, reason)) => {
                    updated.filesystem_bytes = filesystem_bytes;
                    ResourceOutcome {
                        reason,
                        ..outcome(change, current, mib)
                    }
                }
                Err(err) => refused(err, current)?,
            });
        }
        if vcpus.is_some() || mem_mib.is_some() {
            let current = sandbox.spec.lock().unwrap().limits.clone();
            let cap = limits
                .cpus
                .map_or(current.cpu_max_millis, burrow_common::cpu::cap_millis);
            let reserve = limits
                .reserved_cpus
                .map_or(current.cpu_reserve_millis, burrow_common::cpu::cap_millis);
            let (vcpus, mem_mib) = self.reshape(&sandbox, vcpus, mem_mib, cap, reserve).await?;
            updated.vcpus = vcpus;
            updated.mem_mib = mem_mib;
        }
        if !limits.is_empty() {
            updated.limits = Some(self.update_limits(&sandbox, limits).await?);
        }
        Ok((sandbox.record(), updated))
    }

    /// Refuses a shape for a sandbox that is not running which this node has
    /// no room for, naming the shortfall: the memory ceiling it would boot
    /// with (on a boot, or a grow), the CPU it would be charged, and the disk
    /// it would grow by.
    #[allow(clippy::too_many_arguments)]
    async fn admit_shape(
        &self,
        sandbox: &RunningSandbox,
        vcpus: Option<u32>,
        mem_mib: Option<u32>,
        disk_mib: Option<u32>,
        cpus: Option<f64>,
        reserved_cpus: Option<f64>,
        boot: bool,
    ) -> Result<(), Status> {
        let current_mem = sandbox.mem_mib();
        let mem = mem_mib.unwrap_or(current_mem);
        if boot || mem > current_mem {
            let ceiling = self.config.memory_ceiling_mib(sandbox.hypervisor, mem);
            self.admit_memory(0, ceiling)?;
        }
        let limits = sandbox.spec.lock().unwrap().limits.clone();
        let cap = cpus.map_or(limits.cpu_max_millis, burrow_common::cpu::cap_millis);
        let reserve =
            reserved_cpus.map_or(limits.cpu_reserve_millis, burrow_common::cpu::cap_millis);
        let charge =
            burrow_common::cpu::charge_millis(vcpus.unwrap_or(sandbox.vcpus()), cap, reserve);
        self.admit_cpu(sandbox.cpu_charge_millis(), charge).await?;
        if let Some(mib) = disk_mib.filter(|mib| *mib > sandbox.disk_mib()) {
            self.admit_disk(
                &sandbox.record().node_id,
                "grow a disk",
                u64::from(mib - sandbox.disk_mib()) * burrow_common::disk::MIB,
            )
            .await?;
        }
        Ok(())
    }

    /// Moves a sandbox's host CPU and IO limits: on its running VMM's cgroup
    /// at once, otherwise for when it next runs. Refused with the reason for
    /// a cap above its vCPUs, a charge the node has no room for, or a VMM
    /// whose cgroup cannot take them.
    async fn update_limits(
        &self,
        sandbox: &Arc<RunningSandbox>,
        limits: LimitsUpdate,
    ) -> Result<LimitsOutcome, Status> {
        let refuse = |reason: String| LimitsOutcome {
            change: ResourceChange::Refused as i32,
            reason,
        };
        if sandbox.hypervisor == Hypervisor::Vz {
            return Ok(refuse(
                "a Mac node has no cgroup to hold a sandbox's host CPU or IO limits".into(),
            ));
        }
        let mut resources = sandbox
            .base_record
            .lock()
            .unwrap()
            .policy
            .clone()
            .unwrap_or_default()
            .resources
            .unwrap_or_default();
        let previous = resources.clone();
        limits.apply(&mut resources);
        resources.vcpus = sandbox.vcpus();
        if let Err(reason) = burrow_common::cpu::validate(
            resources.vcpus,
            resources.cpus,
            resources.reserved_cpus,
            resources.cpu_shares,
            &resources.cpuset_cpus,
            resources.blkio_weight,
            Some(node_cpus()),
        ) {
            return Ok(refuse(reason));
        }
        let (memory_mib, current) = {
            let spec = sandbox.spec.lock().unwrap();
            (spec.limits.memory_mib, spec.limits.clone())
        };
        let next = cgroup_limits(&resources, memory_mib);
        let is_unchanged = (
            previous.cpus,
            previous.reserved_cpus,
            previous.cpu_shares,
            &previous.cpuset_cpus,
            previous.blkio_weight,
        ) == (
            resources.cpus,
            resources.reserved_cpus,
            resources.cpu_shares,
            &resources.cpuset_cpus,
            resources.blkio_weight,
        );
        if is_unchanged {
            return Ok(LimitsOutcome {
                change: ResourceChange::Unchanged as i32,
                reason: String::new(),
            });
        }
        let slot = sandbox.vm.lock().await;
        let charge = burrow_common::cpu::charge_millis(
            resources.vcpus,
            next.cpu_max_millis,
            next.cpu_reserve_millis,
        );
        if let Err(err) = self.admit_cpu(sandbox.cpu_charge_millis(), charge).await {
            return Ok(refuse(err.message().to_string()));
        }
        let change = match slot.as_ref() {
            Some(vm) => match vm.set_limits(&next) {
                Ok(()) => ResourceChange::Live,
                Err(err) => {
                    if let Err(err) = vm.set_limits(&current) {
                        tracing::warn!(sandbox = sandbox.id(), %err, "could not restore cgroup limits");
                    }
                    return Ok(refuse(format!("the VMM's cgroup refused them: {err}")));
                }
            },
            None => ResourceChange::NextBoot,
        };
        sandbox.spec.lock().unwrap().limits = next;
        {
            let mut record = sandbox.base_record.lock().unwrap();
            let stored = record
                .policy
                .get_or_insert_with(Default::default)
                .resources
                .get_or_insert_with(Default::default);
            stored.cpus = resources.cpus;
            stored.reserved_cpus = resources.reserved_cpus;
            stored.cpu_shares = resources.cpu_shares;
            stored.cpuset_cpus = resources.cpuset_cpus.clone();
            stored.blkio_weight = resources.blkio_weight;
        }
        drop(slot);
        self.persist(sandbox).await;
        tracing::info!(
            sandbox = sandbox.id(),
            cpus = resources.cpus,
            reserved_cpus = resources.reserved_cpus,
            cpu_shares = resources.cpu_shares,
            cpuset_cpus = resources.cpuset_cpus,
            blkio_weight = resources.blkio_weight,
            "moved a sandbox's host limits"
        );
        Ok(LimitsOutcome {
            change: change as i32,
            reason: String::new(),
        })
    }

    /// Resizes a sandbox's root disk to `mib`, returning what was done and
    /// the filesystem's size where a guest reported it.
    ///
    /// Growing: under a hypervisor that can announce it, a running guest is
    /// told at once and grows its filesystem online; a stopped sandbox's disk
    /// grows on the host, and its guest fills it on its next boot. Shrinking:
    /// only a stopped sandbox, through a helper VM ([`crate::resizer`]). A
    /// suspended guest holds its disk's size in memory, so its disk is not
    /// touched either way. A macOS guest's disk is resized in two halves; see
    /// [`Self::resize_mac_disk`].
    async fn resize_disk(
        &self,
        sandbox: &Arc<RunningSandbox>,
        mib: u32,
    ) -> Result<(ResourceChange, u64, String), Status> {
        let id = sandbox.id();
        let record = sandbox.record();
        let guest_os = burrow_vmm::GuestOs::from_record(&record.guest_os).unwrap_or_default();
        if guest_os == burrow_vmm::GuestOs::Windows {
            return Err(Status::failed_precondition(
                "a Windows guest's disk is not resized: its agent does not grow or shrink NTFS \
                 from inside",
            ));
        }
        let current = sandbox.disk_mib();
        if mib == current {
            return Ok((ResourceChange::Unchanged, 0, String::new()));
        }
        let slot = sandbox.vm.lock().await;
        let is_stopped = slot.is_none()
            && sandbox.state.load(std::sync::atomic::Ordering::Relaxed)
                == common::SandboxState::Stopped as i32;
        if slot.is_none() && !is_stopped {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} is suspended, and its guest holds its disk's size in memory; \
                 resume it or shut it down first"
            )));
        }
        if guest_os == burrow_vmm::GuestOs::MacOs {
            return self
                .resize_mac_disk(sandbox, slot, current, mib, &record.node_id)
                .await;
        }
        let uploading = match is_stopped {
            true => Some(sandbox.durable.stop_uploading().await),
            false => None,
        };
        let applied = self
            .apply_resize(sandbox, slot, current, mib, &record.node_id)
            .await;
        if let Some(uploading) = uploading {
            if applied.is_ok() {
                sandbox.durable.invalidate();
            }
            drop(uploading);
            self.spawn_upload(sandbox);
        }
        let (change, filesystem_bytes) = applied?;
        tracing::info!(
            sandbox = id,
            from_mib = current,
            disk_mib = mib,
            change = change.as_str_name(),
            filesystem_mib = filesystem_bytes / burrow_common::disk::MIB,
            "resized a sandbox's disk"
        );
        Ok((change, filesystem_bytes, String::new()))
    }

    /// Resizes a macOS guest's disk. Virtualization.framework changes a disk
    /// only under a stopped machine and APFS resizes the guest's container
    /// only from inside, so each direction takes a boot. A grow lengthens the
    /// shut-down sandbox's image and the guest's container takes the space on
    /// its next boot; a shrink shrinks the running guest's container, and the
    /// image is cut to the size recorded on its next boot. The recovery
    /// container stays last on the disk throughout, `diskutil` moving it as
    /// the image changes size, so the guest keeps recoveryOS.
    async fn resize_mac_disk(
        &self,
        sandbox: &Arc<RunningSandbox>,
        slot: tokio::sync::MutexGuard<'_, Option<Vm>>,
        current: u32,
        mib: u32,
        node_id: &str,
    ) -> Result<(ResourceChange, u64, String), Status> {
        let id = sandbox.id();
        let bytes = u64::from(mib) * burrow_common::disk::MIB;
        let applied = if mib > current {
            if slot.is_some() {
                return Err(Status::failed_precondition(format!(
                    "Virtualization.framework cannot resize a running guest's disk; shut {id} \
                     down (`burrow shutdown {id}`), resize it, and boot it"
                )));
            }
            let _grown = self
                .admit_disk(
                    node_id,
                    "grow a disk",
                    u64::from(mib - current) * burrow_common::disk::MIB,
                )
                .await?;
            crate::macnode::resize_disk(&sandbox.workdir, mib).await?;
            crate::macnode::request_fill(&sandbox.workdir).await?;
            (ResourceChange::Offline, 0, String::new())
        } else {
            let Some(vm) = slot.as_ref() else {
                return Err(Status::failed_precondition(format!(
                    "a macOS guest's APFS container shrinks only while it runs; boot {id}, \
                     resize it, and its disk is cut on the boot after"
                )));
            };
            let shrunk = container_agent(vm.guest())
                .await?
                .root_disk(burrow_proto::guest::v1::RootDiskRequest {
                    op: burrow_proto::guest::v1::root_disk_request::Op::Shrink as i32,
                    size_bytes: bytes,
                    ..Default::default()
                })
                .await?
                .into_inner();
            if shrunk.minimum_bytes > bytes {
                return Err(Status::failed_precondition(format!(
                    "sandbox {id}'s disk needs at least {} MiB; {mib} MiB was asked for",
                    shrunk.minimum_bytes.div_ceil(burrow_common::disk::MIB)
                )));
            }
            (
                ResourceChange::NextBoot,
                shrunk.size_bytes,
                "the guest's APFS container is shrunk now; the disk is cut on its next boot"
                    .to_string(),
            )
        };
        drop(slot);
        sandbox
            .base_record
            .lock()
            .unwrap()
            .policy
            .get_or_insert_with(Default::default)
            .resources
            .get_or_insert_with(Default::default)
            .disk_mib = mib;
        self.persist(sandbox).await;
        tracing::info!(
            sandbox = id,
            from_mib = current,
            disk_mib = mib,
            change = applied.0.as_str_name(),
            "resized a macOS sandbox's disk"
        );
        Ok(applied)
    }

    /// The resize itself, on a sandbox that is running or stopped, with its
    /// VM slot held so it cannot start or stop underneath. Records the new
    /// size once the disk has it.
    async fn apply_resize(
        &self,
        sandbox: &Arc<RunningSandbox>,
        slot: tokio::sync::MutexGuard<'_, Option<Vm>>,
        current: u32,
        mib: u32,
        node_id: &str,
    ) -> Result<(ResourceChange, u64), Status> {
        let id = sandbox.id();
        let path = sandbox.disk_path();
        let bytes = u64::from(mib) * burrow_common::disk::MIB;
        let applied = if mib > current {
            let _grown = self
                .admit_disk(
                    node_id,
                    "grow a disk",
                    u64::from(mib - current) * burrow_common::disk::MIB,
                )
                .await?;
            match slot.as_ref() {
                Some(vm) => {
                    if !sandbox
                        .hypervisor
                        .capabilities()
                        .is_live_disk_growth_supported
                    {
                        return Err(Status::failed_precondition(format!(
                            "{} grows a disk only while its sandbox is shut down; shut {id} \
                             down, resize it, and boot it",
                            sandbox.hypervisor
                        )));
                    }
                    crate::rootdisk::grow(&path, mib).await?;
                    vm.resize_disk("rootfs", bytes)
                        .await
                        .map_err(|err| Status::internal(format!("resizing the disk: {err}")))?;
                    drop(slot);
                    let grown = sandbox
                        .agent()
                        .await?
                        .root_disk(burrow_proto::guest::v1::RootDiskRequest {
                            op: burrow_proto::guest::v1::root_disk_request::Op::Grow as i32,
                            size_bytes: bytes,
                            ..Default::default()
                        })
                        .await?
                        .into_inner();
                    (ResourceChange::Live, grown.size_bytes)
                }
                None => {
                    crate::rootdisk::grow(&path, mib).await?;
                    (ResourceChange::Offline, 0)
                }
            }
        } else {
            if slot.is_some() {
                return Err(Status::failed_precondition(format!(
                    "sandbox {id} is running, and its filesystem shrinks only unmounted; shut it \
                     down (`burrow shutdown {id}`), resize it, and boot it"
                )));
            }
            let Some(upgrade) = self.config.guest_upgrade.as_ref() else {
                return Err(Status::failed_precondition(
                    "this node has no guest agent to boot a resize helper with",
                ));
            };
            let spec = sandbox.spec.lock().unwrap().clone();
            let overhead_mib = self.config.vmm_overhead_mib(spec.hypervisor());
            let shrunk = self
                .resizer
                .shrink(
                    &self.config.data_dir,
                    &upgrade.path,
                    spec,
                    crate::rootdisk::ROOT_DISK,
                    bytes,
                    overhead_mib,
                    self.config.agent_timeout,
                )
                .await?;
            if shrunk.size_bytes > bytes {
                return Err(Status::failed_precondition(format!(
                    "sandbox {id}'s filesystem needs at least {} MiB; {mib} MiB was asked for",
                    shrunk.minimum_bytes.div_ceil(burrow_common::disk::MIB)
                )));
            }
            crate::rootdisk::cut(&path, mib).await?;
            drop(slot);
            (ResourceChange::Offline, shrunk.size_bytes)
        };
        sandbox
            .base_record
            .lock()
            .unwrap()
            .policy
            .get_or_insert_with(Default::default)
            .resources
            .get_or_insert_with(Default::default)
            .disk_mib = mib;
        self.persist(sandbox).await;
        Ok(applied)
    }

    /// Changes a sandbox's vCPUs and memory: live where the hypervisor can
    /// hotplug them, on a shut-down sandbox for its next boot, and refused on
    /// a suspended one, whose restore needs the machine its snapshot was
    /// taken of.
    async fn reshape(
        &self,
        sandbox: &Arc<RunningSandbox>,
        vcpus: Option<u32>,
        mem_mib: Option<u32>,
        cap_millis: u64,
        reserve_millis: u64,
    ) -> Result<(Option<ResourceOutcome>, Option<ResourceOutcome>), Status> {
        let id = sandbox.id();
        let (current_vcpus, current_mem) = (sandbox.vcpus(), sandbox.mem_mib());
        let guest_os =
            burrow_vmm::GuestOs::from_record(&sandbox.record().guest_os).unwrap_or_default();
        let slot = sandbox.vm.lock().await;
        let is_stopped = slot.is_none()
            && sandbox.state.load(std::sync::atomic::Ordering::Relaxed)
                == common::SandboxState::Stopped as i32;
        let blocked = if guest_os == burrow_vmm::GuestOs::Windows {
            Some(
                "a Windows guest's machine is not reshaped: its agent cannot bring vCPUs or \
                 memory online"
                    .to_string(),
            )
        } else if slot.is_none() && !is_stopped {
            Some(format!(
                "sandbox {id} is suspended, and its restore needs the machine its snapshot was \
                 taken of; resize it with boot to have it shut down cleanly, resized and booted"
            ))
        } else {
            None
        };
        let refuse = |reason: &str, previous| ResourceOutcome {
            change: ResourceChange::Refused as i32,
            previous,
            value: previous,
            reason: reason.to_string(),
        };
        let vcpus = match vcpus {
            None => None,
            Some(want) if want == current_vcpus => {
                Some(outcome(ResourceChange::Unchanged, current_vcpus, want))
            }
            Some(_) if let Some(reason) = &blocked => Some(refuse(reason, current_vcpus)),
            Some(want) if cap_millis.max(reserve_millis) > u64::from(want) * 1000 => Some(refuse(
                &format!(
                    "sandbox {id} is capped at or reserved {} cpus, more than {want} vcpus; \
                     lower its cpus or reserved_cpus with them",
                    cpus_text(cap_millis.max(reserve_millis))
                ),
                current_vcpus,
            )),
            Some(want) => Some(
                match self
                    .admit_vcpus(sandbox, want, cap_millis, reserve_millis)
                    .await
                {
                    Err(err) => refused(err, current_vcpus)?,
                    Ok(()) => match slot.as_ref() {
                        None => outcome(ResourceChange::NextBoot, current_vcpus, want),
                        Some(vm) => {
                            let max_vcpus = sandbox.spec.lock().unwrap().max_vcpus;
                            if !sandbox.hypervisor.capabilities().is_vcpu_hotplug_supported {
                                refuse(
                                    &format!(
                                        "{} cannot change a running guest's vCPUs; shut {id} \
                                     down, update it, and boot it",
                                        sandbox.hypervisor
                                    ),
                                    current_vcpus,
                                )
                            } else if want > max_vcpus {
                                refuse(
                                    &format!(
                                        "sandbox {id} was booted able to take up to {max_vcpus} \
                                     vCPUs; shut it down, update it, and boot it for more"
                                    ),
                                    current_vcpus,
                                )
                            } else {
                                match vm.resize_vcpus(want).await {
                                    Ok(()) => outcome(ResourceChange::Live, current_vcpus, want),
                                    Err(err) => refuse(
                                        &format!(
                                            "{} refused the change: {err}",
                                            sandbox.hypervisor
                                        ),
                                        current_vcpus,
                                    ),
                                }
                            }
                        }
                    },
                },
            ),
        };
        let mem_mib = match mem_mib {
            None => None,
            Some(want) if want == current_mem => {
                Some(outcome(ResourceChange::Unchanged, current_mem, want))
            }
            Some(_) if let Some(reason) = &blocked => Some(refuse(reason, current_mem)),
            Some(want) => Some(match slot.as_ref() {
                None => outcome(ResourceChange::NextBoot, current_mem, want),
                Some(vm) => self.replug(sandbox, vm, want).await?,
            }),
        };
        let applied = |outcome: &Option<ResourceOutcome>| {
            outcome.as_ref().and_then(|o| {
                matches!(
                    ResourceChange::try_from(o.change),
                    Ok(ResourceChange::Live | ResourceChange::NextBoot | ResourceChange::Partial)
                )
                .then_some(o.value)
            })
        };
        let (new_vcpus, new_mem) = (applied(&vcpus), applied(&mem_mib));
        if new_vcpus.is_some() || new_mem.is_some() {
            {
                let mut spec = sandbox.spec.lock().unwrap();
                if let Some(n) = new_vcpus {
                    spec.vcpus = n;
                }
                if let Some(mib) = new_mem {
                    match slot.is_some() {
                        true => spec.mem_plugged_mib = mib - spec.mem_mib,
                        false => (spec.mem_mib, spec.mem_plugged_mib) = (mib, 0),
                    }
                    spec.limits.memory_mib = self.config.memory_ceiling_mib(spec.hypervisor(), mib);
                }
            }
            {
                let mut record = sandbox.base_record.lock().unwrap();
                let resources = record
                    .policy
                    .get_or_insert_with(Default::default)
                    .resources
                    .get_or_insert_with(Default::default);
                if let Some(n) = new_vcpus {
                    resources.vcpus = n;
                }
                if let Some(mib) = new_mem {
                    resources.mem_mib = mib;
                }
            }
            drop(slot);
            self.persist(sandbox).await;
            tracing::info!(
                sandbox = id,
                vcpus = new_vcpus,
                mem_mib = new_mem,
                "reshaped a sandbox"
            );
        }
        Ok((vcpus, mem_mib))
    }

    /// Plugs memory into a running guest or unplugs it, as far as the guest
    /// gets, between the memory it booted with and its growth limit. The
    /// memory cap is raised before a grow and lowered to what was reached
    /// after, so it never sits below what the guest holds.
    async fn replug(
        &self,
        sandbox: &RunningSandbox,
        vm: &Vm,
        want: u32,
    ) -> Result<ResourceOutcome, Status> {
        let id = sandbox.id();
        let current = sandbox.mem_mib();
        let boot = sandbox.boot_mem_mib();
        let max = sandbox.max_mem_mib();
        let region = sandbox.spec.lock().unwrap().mem_hotplug_mib;
        let refuse = |reason: String| ResourceOutcome {
            change: ResourceChange::Refused as i32,
            previous: current,
            value: current,
            reason,
        };
        if !sandbox
            .hypervisor
            .capabilities()
            .is_memory_hotplug_supported
        {
            return Ok(refuse(format!(
                "{} cannot change a running guest's memory; shut {id} down, update it, and \
                 boot it",
                sandbox.hypervisor
            )));
        }
        if region == 0 {
            return Ok(refuse(format!(
                "sandbox {id} booted with no room to plug memory into: its max_mem_mib is its \
                 memory; shut it down, update it, and boot it"
            )));
        }
        if want < boot {
            return Ok(refuse(format!(
                "sandbox {id} booted with {boot} MiB, and a running guest cannot go below the \
                 memory it booted with; shut it down, update it, and boot it"
            )));
        }
        if want > max {
            return Ok(refuse(format!(
                "sandbox {id} can grow to {max} MiB while it runs (its max_mem_mib); shut it \
                 down, update it, and boot it for more"
            )));
        }
        if !(want - boot).is_multiple_of(burrow_vmm::MEMORY_BLOCK_MIB) {
            return Ok(refuse(format!(
                "a running guest's memory moves in steps of {} MiB above the {boot} MiB it \
                 booted with",
                burrow_vmm::MEMORY_BLOCK_MIB
            )));
        }
        let cap = |mib: u32| self.config.memory_ceiling_mib(sandbox.hypervisor, mib);
        if let Err(err) = self.admit_memory(cap(current), cap(want)) {
            return refused(err, current);
        }
        if want > current
            && let Err(err) = vm.set_memory_limit(cap(want))
        {
            return Ok(refuse(format!("could not raise the memory cap: {err}")));
        }
        let reached = match vm.resize_memory(want - boot).await {
            Ok(plugged) => boot + plugged,
            Err(err) => {
                let _ = vm.set_memory_limit(cap(current));
                return Ok(refuse(format!(
                    "{} refused the change: {err}",
                    sandbox.hypervisor
                )));
            }
        };
        if let Err(err) = vm.set_memory_limit(cap(reached)) {
            tracing::warn!(sandbox = id, %err, "could not move the memory cap");
        }
        tracing::info!(
            sandbox = id,
            from = current,
            want,
            reached,
            "replugged memory"
        );
        let reason = match (reached == want, want > current) {
            (true, _) => String::new(),
            (false, true) if reached == current => "the guest plugged none of it: its kernel \
                                                    needs CONFIG_VIRTIO_MEM and \
                                                    memhp_default_state=online_movable to take \
                                                    memory while it runs"
                .to_string(),
            (false, true) => format!(
                "the guest plugged {} of {} MiB and stopped, likely short of the boot memory \
                 that describes what it plugs",
                reached - current,
                want - current
            ),
            (false, false) => format!(
                "the guest unplugged {} of {} MiB: it had no room for what the rest holds, or \
                 could not move it, so the rest stays plugged",
                current - reached,
                current - want
            ),
        };
        Ok(ResourceOutcome {
            change: match reached {
                r if r == want => ResourceChange::Live,
                r if r == current => ResourceChange::Refused,
                _ => ResourceChange::Partial,
            } as i32,
            previous: current,
            value: reached,
            reason,
        })
    }

    /// Refuses raising a VMM's memory ceiling from `current` to `want` MiB
    /// past the memory the node has available, as placement refuses a
    /// create.
    #[allow(clippy::result_large_err)]
    fn admit_memory(&self, current: u32, want: u32) -> Result<(), Status> {
        if want <= current {
            return Ok(());
        }
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let available = sys.available_memory() / burrow_common::disk::MIB;
        let needed = u64::from(want - current);
        if available < needed {
            return Err(Status::resource_exhausted(format!(
                "this node has {available} MiB of memory available; {needed} MiB more do not fit"
            )));
        }
        Ok(())
    }

    /// Refuses giving `sandbox` `vcpus` where the node has no room for what
    /// that charges it under the cap and reservation it will have.
    async fn admit_vcpus(
        &self,
        sandbox: &RunningSandbox,
        vcpus: u32,
        cap_millis: u64,
        reserve_millis: u64,
    ) -> Result<(), Status> {
        let charge = burrow_common::cpu::charge_millis(vcpus, cap_millis, reserve_millis);
        self.admit_cpu(sandbox.cpu_charge_millis(), charge).await
    }

    /// Refuses a charge of more host CPU than the node has uncommitted, both
    /// in thousandths of a CPU.
    async fn admit_cpu(&self, current: u64, want: u64) -> Result<(), Status> {
        if want <= current {
            return Ok(());
        }
        let total = node_cpus() as u64 * 1000;
        let committed = self.committed_cpu_millis().await;
        if committed + (want - current) > total {
            return Err(Status::resource_exhausted(format!(
                "this node has {} CPUs and {} committed; {} more do not fit",
                cpus_text(total),
                cpus_text(committed),
                cpus_text(want - current)
            )));
        }
        Ok(())
    }

    pub async fn count(&self) -> usize {
        self.sandboxes.lock().await.len()
    }

    /// Records the root sandboxes that opt in should trust, and its
    /// fingerprint.
    pub fn set_inspection_ca(&self, pem: String, fingerprint: String) {
        *self.inspection_ca.lock().unwrap() = Some(InspectionRoot { pem, fingerprint });
    }

    /// Holds one of the Mac's macOS guest slots for `id` while its VM starts,
    /// or nothing for any other guest.
    pub(crate) async fn reserve_mac_slot(
        &self,
        id: &str,
        guest_os: burrow_vmm::GuestOs,
    ) -> Result<Option<crate::macnode::Slot>, Status> {
        if !crate::macnode::is_macos(guest_os) {
            return Ok(None);
        }
        let sandboxes = self.sandboxes.lock().await;
        let running = sandboxes
            .values()
            .filter(|sandbox| {
                sandbox.is_running()
                    && burrow_vmm::GuestOs::from_record(
                        &sandbox.base_record.lock().unwrap().guest_os,
                    ) == Some(guest_os)
            })
            .map(|sandbox| sandbox.id().to_string());
        self.mac_slots.reserve(id, running).map(Some)
    }

    /// The audit log node-side policy events are written to.
    pub fn set_audit(&self, audit: burrow_proxy::AuditLog) {
        *self.audit.lock().unwrap() = Some(audit);
    }

    /// What the resolver tells when it answers for a host an open-mode
    /// sandbox inspects: the node's half of selective inspection.
    pub fn inspection_redirect(&self) -> Arc<dyn burrow_proxy::dns::Redirect> {
        Arc::new(InspectionRedirect {
            firewall: Arc::clone(&self.firewall),
            policies: Arc::clone(&self.proxy_policies),
        })
    }

    /// Records each request rule that has expired since the last pass and
    /// re-renders the boundary once if any has.
    ///
    /// The proxy needs neither: it compares every request against the rule's
    /// expiry itself, so an expired rule has already stopped applying by the
    /// time this runs. What this adds is the record that it did, and, for an
    /// open-mode sandbox, the end of the redirect that sent its host's traffic
    /// to the proxy, so that traffic goes back to leaving the node directly.
    pub async fn sweep_expired_rules(&self) {
        let now_ms = burrow_proxy::policy::now_unix_ms();
        let candidates: Vec<_> = self.sandboxes.lock().await.values().cloned().collect();
        let mut newly = Vec::new();
        {
            let mut noted = self.expired_rules.lock().unwrap();
            let mut current = std::collections::HashSet::new();
            for sandbox in &candidates {
                let record = sandbox.record();
                let Some(network) = record.policy.as_ref().and_then(|p| p.network.as_ref()) else {
                    continue;
                };
                for (index, rule) in network.rules.iter().enumerate() {
                    if rule.expires_at_unix_ms == 0 || rule.expires_at_unix_ms > now_ms {
                        continue;
                    }
                    let key = ExpiredRule {
                        sandbox_id: sandbox.id().to_string(),
                        index,
                        domain: rule.domain.clone(),
                        expires_at_unix_ms: rule.expires_at_unix_ms,
                    };
                    if noted.insert(key.clone()) {
                        newly.push((sandbox.lease.guest_ip, key.clone()));
                    }
                    current.insert(key);
                }
            }
            // Forgotten once the rule is gone, so the set is bounded by the
            // rules that exist.
            noted.retain(|key| current.contains(key));
        }
        if newly.is_empty() {
            return;
        }
        let audit = self.audit.lock().unwrap().clone();
        for (guest_ip, expired) in newly {
            tracing::info!(
                sandbox = expired.sandbox_id,
                rule = expired.index,
                domain = expired.domain,
                expires_at_unix_ms = expired.expires_at_unix_ms,
                "request rule expired"
            );
            if let Some(audit) = &audit {
                audit.record(expired.event(guest_ip));
            }
        }
        if let Err(err) = self.sync_firewall().await {
            tracing::warn!(%err, "could not re-render after a request rule expired");
        }
    }

    /// The node's egress pieces for its sandboxes' userspace network
    /// stacks, and the address their published ports listen on.
    #[cfg(target_os = "macos")]
    pub fn set_usernet_node(
        &self,
        node: burrow_net::usernet::Node,
        publish_address: std::net::IpAddr,
    ) {
        self.usernets.set_node(node, publish_address);
    }

    /// Joins the userspace stacks to the node mesh on one UDP socket.
    #[cfg(target_os = "macos")]
    pub async fn start_usernet_mesh(
        &self,
        listen: std::net::SocketAddr,
        private_key: &str,
    ) -> std::io::Result<()> {
        self.usernets.start_mesh(listen, private_key).await
    }

    /// Replaces the userspace mesh's peers, where there is one.
    pub async fn configure_usernet_mesh(&self, peers: &[burrow_net::Peer]) {
        self.usernets.configure_mesh(peers).await;
    }

    /// The CA to hand this sandbox, if its policy asked for inspection.
    fn inspection_ca_for(&self, policy: &common::Policy) -> String {
        let wants = policy
            .network
            .as_ref()
            .is_some_and(|network| network.is_tls_inspected);
        if !wants {
            return String::new();
        }
        self.inspection_ca
            .lock()
            .unwrap()
            .as_ref()
            .map(|root| root.pem.clone())
            .unwrap_or_default()
    }

    /// The fingerprint of the root this node's inspected sandboxes trust.
    fn inspection_root(&self) -> String {
        self.inspection_ca
            .lock()
            .unwrap()
            .as_ref()
            .map(|root| root.fingerprint.clone())
            .unwrap_or_default()
    }

    /// The fingerprint to record for a sandbox given `request`: the node's
    /// root when the handshake carries it, nothing otherwise.
    fn inspection_root_of(&self, request: &burrow_proto::guest::v1::HandshakeRequest) -> String {
        if request.inspection_ca_pem.is_empty() {
            return String::new();
        }
        self.inspection_root()
    }

    /// Refuses to restore a guest that trusts `wanted` here, when this node's
    /// leaves chain to another root: every inspected connection it holds
    /// would fail, and the processes holding them never reread a trust store.
    #[allow(clippy::result_large_err)]
    fn require_inspection_root(&self, id: &str, wanted: &str) -> Result<(), Status> {
        let own = self.inspection_root();
        if wanted.is_empty() || wanted == own {
            return Ok(());
        }
        Err(Status::failed_precondition(format!(
            "sandbox {id}'s guest trusts the TLS inspection root {wanted}, and this node's \
             inspection root is {own}; inspected sandboxes move only between nodes under one \
             fleet root (`burrowd ca`)"
        )))
    }

    /// Bundles this template's image names in its own environment, which the
    /// guest has to have the CA installed into as well as the system store.
    ///
    /// Read only for a sandbox being inspected: an image's environment is no
    /// reason to touch the trust stores of a sandbox that never opted in.
    async fn trust_bundles_for(
        &self,
        template: &str,
        policy: &common::Policy,
    ) -> Vec<burrow_proto::guest::v1::TrustBundle> {
        if self.inspection_ca_for(policy).is_empty() {
            return Vec::new();
        }
        crate::oci::image_environment(&self.config.data_dir, template)
            .await
            .trust_bundles()
    }

    /// The trust bundles an inspected sandbox's guest gets, from the
    /// environment it runs with.
    fn trust_bundles_in(
        &self,
        environment: &crate::oci::ImageEnvironment,
        policy: &common::Policy,
    ) -> Vec<burrow_proto::guest::v1::TrustBundle> {
        match self.inspection_ca_for(policy).is_empty() {
            true => Vec::new(),
            false => environment.trust_bundles(),
        }
    }

    /// The template environment a sandbox runs with: its own copy, kept when
    /// it was taken up from the object store, or its template's.
    pub async fn environment_of(&self, sandbox: &RunningSandbox) -> crate::oci::ImageEnvironment {
        crate::oci::sandbox_environment(&self.config.data_dir, &sandbox.workdir, sandbox.template())
            .await
    }

    /// The trust material to bake into `template`'s warm snapshot.
    ///
    /// Not gated on a policy, because a warm snapshot has no policy: it is
    /// built once and restored by every later create, inspected or not. Doing
    /// the install here is what lets those creates skip it. See
    /// [`crate::warm::Trust`] for what that trades away.
    ///
    /// Empty when the node has no authority yet, which simply means the
    /// snapshot is built the way it always was and its clones install the
    /// certificate themselves.
    async fn warm_trust(&self, template: &str) -> crate::warm::Trust {
        let ca = self
            .inspection_ca
            .lock()
            .unwrap()
            .as_ref()
            .map(|root| root.pem.clone())
            .unwrap_or_default();
        if ca.is_empty() {
            return crate::warm::Trust::default();
        }
        crate::warm::Trust {
            ca,
            bundles: crate::oci::image_environment(&self.config.data_dir, template)
                .await
                .trust_bundles(),
        }
    }

    /// Warms the exact shape a create asked for, so the next one restores.
    ///
    /// The caller that missed still cold-boots: nothing here is awaited on the
    /// create path.
    fn warm_for_demand(&self, key: &ShapeKey) {
        // Not every shape a caller can name is worth a snapshot; see
        // [`WarmShapes::record_demand`] for which ones are.
        let wanted = self
            .warm_shapes
            .lock()
            .unwrap()
            .entry(key.template.clone())
            .or_default()
            .record_demand(key, &self.config.warm);
        if !wanted {
            return;
        }
        self.warm_in_background(
            key.template.clone(),
            common::ResourcePolicy {
                vcpus: key.vcpus,
                mem_mib: key.mem_mib,
                ..Default::default()
            },
        );
    }

    /// Warms every pinned shape of a template that has just landed here.
    pub fn warm_template(&self, template: &str) {
        for shape in &self.config.warm.pinned {
            self.warm_in_background(
                template.to_string(),
                common::ResourcePolicy {
                    vcpus: shape.vcpus,
                    mem_mib: shape.mem_mib,
                    ..Default::default()
                },
            );
        }
    }

    /// Discards every warm snapshot of `template` and lets them be built again.
    ///
    /// A snapshot's memory image is only valid over the rootfs it was captured
    /// on, and `stage_from_warm` links whichever `rootfs.ext4` is there now.
    /// Republishing a template without this leaves the two mismatched, which
    /// restores a guest onto a disk it never saw. Clearing the attempts too is
    /// what lets the replacements be built.
    ///
    /// Taken under the warm build lock, so a build of the old rootfs already
    /// running finishes, and is discarded, before this returns rather than
    /// publishing after it.
    pub async fn invalidate_warm(&self, template: &str) {
        let _no_builds = crate::warm::hold_builds().await;
        self.warm_shapes.lock().unwrap().remove(template);
        let warm = crate::warm::warm_dir(&self.config.templates_dir(), template);
        if let Err(err) = tokio::fs::remove_dir_all(&warm).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(template, %err, "could not discard the warm snapshots");
        }
    }

    /// Builds a warm snapshot of `template` at `resources`, off this task.
    ///
    /// Every trigger comes through here: a template landing on the node, a
    /// pinned shape, and a create that found no snapshot of its shape. All
    /// take the same path, with the same validation, lock and staged swap, so
    /// nothing about the resulting snapshot depends on which asked for it.
    ///
    /// A build boots a VM, so it waits its turn behind other automatic builds
    /// and for the node to have no create in flight, and is given up when the
    /// node could not admit a sandbox of its shape. A shape given up on is
    /// tried again the next time a create asks for it.
    pub fn warm_in_background(&self, template: String, resources: common::ResourcePolicy) {
        let shape = match crate::nodeapi::warm_request(&resources) {
            Ok(request) => request,
            Err(err) => {
                tracing::warn!(template, %err, "not warming this shape");
                return;
            }
        };
        let key = ShapeKey {
            template: template.clone(),
            vcpus: shape.vcpus,
            mem_mib: shape.mem_mib,
            max_mem_mib: shape.max_mem_mib,
        };
        // Claimed before the task is spawned, so a burst of creates of one
        // shape queues one build rather than one each.
        let claimed = self
            .warm_shapes
            .lock()
            .unwrap()
            .entry(template.clone())
            .or_default()
            .claim_attempt(&key);
        if !claimed {
            return;
        }

        let manager = self.clone();
        tokio::spawn(async move {
            let _queued = manager.warm_queue.lock().await;
            match manager.build_warm(&template, shape).await {
                Ok(Some(warm)) => {
                    tracing::info!(
                        template,
                        vcpus = shape.vcpus,
                        mem_mib = shape.mem_mib,
                        bytes = warm.bytes,
                        "warmed a template automatically"
                    );
                    manager.enforce_warm_limits(None).await;
                    // Placement prefers a node that holds the snapshot, and it
                    // only knows about one it has been told about.
                    manager.announce_now();
                    tokio::time::sleep(WARM_BUILD_GAP).await;
                }
                Ok(None) => {}
                Err(err) => {
                    // Not fatal to anything: creates of this shape keep
                    // working, they just keep cold-booting.
                    tracing::warn!(template, %err, "could not warm a template");
                    if err.code() == tonic::Code::ResourceExhausted {
                        manager.forget_warm(&key);
                    }
                }
            }
        });
    }

    /// One automatic build, once the node can spare it. `None` when the shape
    /// turned out to be warm already.
    async fn build_warm(
        &self,
        template: &str,
        shape: crate::warm::Shape,
    ) -> Result<Option<crate::warm::Warm>, Status> {
        let templates_dir = self.config.templates_dir();
        let (hypervisor, _) = self.image_environment(template).await.machine()?;
        // It may already be warm: a pinned shape kept across a restart, or one
        // create's build finishing while another was queued.
        if crate::warm::find(&templates_dir, template, hypervisor, shape)
            .await
            .is_some()
        {
            return Ok(None);
        }
        let shape = crate::warm::resolve_disk(&templates_dir, template, shape).await?;
        let policy = &self.config.warm;
        let image_bytes = tokio::fs::metadata(templates_dir.join(template).join(TEMPLATE_ROOTFS))
            .await
            .map_or(0, |meta| meta.len());
        let estimate = u64::from(shape.mem_mib) * burrow_common::disk::MIB + image_bytes;
        if estimate > policy.per_template_bytes || estimate > policy.per_node_bytes {
            return Err(Status::failed_precondition(format!(
                "a {}x{} snapshot takes about {} MiB, more than the warm disk caps allow",
                shape.vcpus,
                shape.mem_mib,
                estimate / burrow_common::disk::MIB
            )));
        }

        let deadline = std::time::Instant::now() + WARM_IDLE_WAIT;
        while !self.creating.lock().await.is_empty() {
            if std::time::Instant::now() >= deadline {
                return Err(Status::resource_exhausted(
                    "creates kept the node busy; the warm build gave up its turn",
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        self.admit_cpu(0, u64::from(shape.vcpus) * 1000).await?;
        let available_mib = {
            let mut sys = sysinfo::System::new();
            sys.refresh_memory();
            sys.available_memory() / burrow_common::disk::MIB
        };
        let needed_mib = u64::from(self.config.memory_ceiling_mib(hypervisor, shape.mem_mib));
        if available_mib < needed_mib {
            return Err(Status::resource_exhausted(format!(
                "a {}x{} warm build needs {needed_mib} MiB and the node has {available_mib} MiB \
                 available",
                shape.vcpus, shape.mem_mib
            )));
        }
        // What the caps would evict once this snapshot is in goes first, so
        // the disk it frees counts towards admitting the build.
        self.enforce_warm_limits(Some((template, hypervisor, shape, estimate)))
            .await;
        let _charged = self.admit_disk("", "warm a template", estimate).await?;
        let trust = self.warm_trust(template).await;
        crate::warm::build_warm_snapshot(&self.config, template, shape, &trust)
            .await
            .map(Some)
    }

    /// Discards `template`'s snapshot of `shape` under `hypervisor` if it is
    /// there with a file gone, and builds it again. Left in place it would
    /// send every create of its shape to a cold boot until the node
    /// restarted, since the attempt that built it is still recorded.
    async fn rebuild_if_broken(
        &self,
        template: &str,
        hypervisor: Hypervisor,
        shape: crate::warm::Shape,
    ) {
        let templates_dir = self.config.templates_dir();
        let Some(dir) = crate::warm::find_broken(&templates_dir, template, hypervisor, shape).await
        else {
            return;
        };
        match crate::warm::discard_broken(&dir).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                tracing::warn!(template, %err, "could not discard a broken warm snapshot");
                return;
            }
        }
        tracing::warn!(
            template,
            vcpus = shape.vcpus,
            mem_mib = shape.mem_mib,
            "discarded a warm snapshot with a file gone; rebuilding it"
        );
        self.forget_warm(&ShapeKey {
            template: template.to_string(),
            vcpus: shape.vcpus,
            mem_mib: shape.mem_mib,
            max_mem_mib: shape.max_mem_mib,
        });
        self.warm_in_background(
            template.to_string(),
            common::ResourcePolicy {
                vcpus: shape.vcpus,
                mem_mib: shape.mem_mib,
                max_mem_mib: shape.max_mem_mib,
                ..Default::default()
            },
        );
    }

    fn rebuild_in_background_if_broken(
        &self,
        template: &str,
        hypervisor: Hypervisor,
        shape: crate::warm::Shape,
    ) {
        let (manager, template) = (self.clone(), template.to_string());
        tokio::spawn(async move {
            manager
                .rebuild_if_broken(&template, hypervisor, shape)
                .await
        });
    }

    fn forget_warm(&self, key: &ShapeKey) {
        if let Some(shapes) = self.warm_shapes.lock().unwrap().get_mut(&key.template) {
            shapes.forget(key);
        }
    }

    /// Evicts the least recently used warm snapshots past the node's caps,
    /// counting `incoming`, a snapshot about to be built, as the newest.
    async fn enforce_warm_limits(
        &self,
        incoming: Option<(&str, Hypervisor, crate::warm::Shape, u64)>,
    ) {
        let mut entries = crate::warm::list_all(&self.config.templates_dir()).await;
        if let Some((template, hypervisor, shape, bytes)) = incoming {
            entries.push((
                template.to_string(),
                crate::warm::Warm {
                    dir: PathBuf::new(),
                    hypervisor,
                    shape,
                    bytes,
                    used_at: i64::MAX,
                },
            ));
        }
        for index in self.config.warm.evictions(&entries) {
            let (template, warm) = &entries[index];
            if warm.dir.as_os_str().is_empty() {
                continue;
            }
            let _no_builds = crate::warm::hold_builds().await;
            if let Err(err) = tokio::fs::remove_dir_all(&warm.dir).await {
                tracing::warn!(template, %err, "could not evict a warm snapshot");
                continue;
            }
            self.forget_warm(&ShapeKey {
                template: template.clone(),
                vcpus: warm.shape.vcpus,
                mem_mib: warm.shape.mem_mib,
                max_mem_mib: warm.shape.max_mem_mib,
            });
            tracing::info!(
                template,
                vcpus = warm.shape.vcpus,
                mem_mib = warm.shape.mem_mib,
                bytes = warm.bytes,
                used_at = warm.used_at,
                "evicted a warm snapshot"
            );
        }
    }

    /// At startup: discards warm snapshots this build cannot restore, warms
    /// the pinned shapes of every template, and applies the caps, which may
    /// have changed.
    pub async fn sweep_warm(&self) {
        let templates_dir = self.config.templates_dir();
        for template in crate::template::bootable(&self.config.data_dir).await {
            let is_warmable = self
                .image_environment(&template.name)
                .await
                .machine()
                .is_ok_and(|(hypervisor, _)| hypervisor.capabilities().is_warm_pool_supported);
            if !is_warmable {
                continue;
            }
            for path in crate::warm::stale(&templates_dir, &template.name).await {
                let removed = match tokio::fs::metadata(&path).await {
                    Ok(meta) if meta.is_dir() => tokio::fs::remove_dir_all(&path).await,
                    _ => tokio::fs::remove_file(&path).await,
                };
                if let Err(err) = removed {
                    tracing::warn!(template = template.name, %err, "could not discard a stale warm snapshot");
                }
            }
            self.warm_template(&template.name);
        }
        self.enforce_warm_limits(None).await;
    }

    /// Every warm snapshot here, as the node reports them.
    pub async fn warm_shapes(&self) -> Vec<common::WarmShape> {
        crate::warm::list_all(&self.config.templates_dir())
            .await
            .iter()
            .map(|(template, warm)| warm.to_proto(template, &self.config.warm))
            .collect()
    }

    /// Retires build layers and the blobs nothing refers to any more.
    ///
    /// Run from the reaper because it is the only thing on this node that runs
    /// regularly and holds no lock anyone waits on.
    ///
    /// The index is pruned first, so the blob sweep is told what the surviving
    /// entries still refer to. Both use the same age, because they are two
    /// halves of one retention: an entry that has just been dropped leaves a
    /// blob that is now unreferenced, and it goes on the same pass.
    async fn collect_artifacts(&self) {
        let age = self.config.artifact_retention;
        if age.is_zero() {
            return;
        }
        let data_dir = &self.config.data_dir;
        let (entries, referenced) = crate::template::layers::prune(data_dir, age).await;
        let (blobs, freed) = crate::blobs::BlobStore::new(data_dir)
            .collect_garbage(&referenced, age)
            .await;
        if entries > 0 || blobs > 0 {
            tracing::info!(
                layer_entries = entries,
                blobs,
                freed_bytes = freed,
                "collected unreferenced template artifacts"
            );
        }
    }

    /// Gives back everything a sandbox whose guest never answered is holding.
    ///
    /// A warm create returns once the VM is restored, so a handshake that ends
    /// in failure has no create left to fail: the sandbox is registered and
    /// keeps its tap, its address lease and its working directory until
    /// something deletes it. Nothing would, because the create looked like it
    /// succeeded.
    ///
    /// Idempotent, and correct from either side of registration: the handshake
    /// task calls it when it gives up, and the paths that register a sandbox
    /// call it once the sandbox is theirs. Whichever runs second does the work,
    /// so the window between a create's provisioning and its registration is
    /// not one a failure can fall through.
    async fn reclaim_unconfirmed(&self, id: &str) {
        // Re-read rather than trusted from when the failure was recorded: a
        // resume handshakes for itself and clears it, and a sandbox that has
        // since come up must not be destroyed over a VM that is gone.
        let failed = |sandbox: &Arc<RunningSandbox>| {
            matches!(&*sandbox.handshake.borrow(), Handshake::Failed(_))
        };

        // Not registered yet: the create that provisioned it still holds it and
        // reclaims it itself once it is registered.
        if !self.sandboxes.lock().await.get(id).is_some_and(failed) {
            return;
        }
        // At `error` because this is a create the caller was told had
        // succeeded, and it is about to stop existing.
        tracing::error!(
            sandbox = id,
            "the guest agent never came up; releasing the sandbox's tap, lease and directory"
        );
        if let Err(err) = self.delete(id).await {
            tracing::error!(sandbox = id, %err, "could not reclaim a sandbox with no agent");
        }
    }

    /// Keeps every running guest's clock on the node's, which a handshake sets
    /// but nothing else would: a guest drifts when the host or the VM under it
    /// sleeps, or its paravirtual clock does not catch up. Synced every
    /// [`CLOCK_SYNC_INTERVAL`], and as soon as the node's own wall clock jumps
    /// against its monotonic one, which is what the node's host waking from
    /// sleep or having its clock stepped looks like.
    pub async fn keep_clocks(&self) {
        let mut ticker = tokio::time::interval(CLOCK_CHECK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last = None;
        loop {
            ticker.tick().await;
            let now = (std::time::Instant::now(), std::time::SystemTime::now());
            if last.is_some_and(|last| !clocks_due(last, now)) {
                continue;
            }
            let running: Vec<_> = self
                .sandboxes
                .lock()
                .await
                .values()
                .filter(|sandbox| sandbox.is_running())
                .cloned()
                .collect();
            futures::future::join_all(running.iter().map(|sandbox| async move {
                if let Err(err) = sandbox.sync_clock().await {
                    tracing::debug!(sandbox = sandbox.id(), %err, "guest clock not synced");
                }
            }))
            .await;
            last = Some(now);
        }
    }

    /// Applies `idle_suspend_secs` and `max_lifetime_secs`, returning what it
    /// did.
    ///
    /// Suspension is reversible and lifetime expiry is not, so they are
    /// deliberately different actions: an idle sandbox is parked, an expired
    /// one is destroyed.
    pub async fn reap(&self) -> Vec<(String, &'static str)> {
        // The reaper's tick is also what keeps the usage figures on a read
        // fresh: nothing else runs regularly with every sandbox in hand.
        self.sample_usage().await;
        let candidates: Vec<_> = self.sandboxes.lock().await.values().cloned().collect();
        self.metrics.publish(
            candidates
                .iter()
                .map(|sandbox| {
                    let record = sandbox.record();
                    crate::metrics::Reading {
                        mem_mib: match sandbox.is_running() {
                            true => sandbox.mem_mib().into(),
                            false => 0,
                        },
                        sandbox_id: record.id,
                        template: record.template,
                        tags: record.tags,
                        cpu_usage_usec: record.cpu_usage_usec,
                        rx_bytes: record.rx_bytes,
                        tx_bytes: record.tx_bytes,
                    }
                })
                .collect(),
        );

        self.sweep_expired_rules().await;

        let mut acted = Vec::new();
        // Snapshots outlive the sandboxes they were taken from, so they are
        // swept here rather than as part of any one sandbox's retention: the
        // source may well be gone.
        for id in self.snapshots.sweep_expired().await {
            acted.push((id, "snapshot-expired"));
        }
        self.snapshots.collect_orphans().await;
        self.collect_artifacts().await;
        for sandbox in candidates {
            let lifetime = sandbox.lifetime();
            let id = sandbox.id().to_string();
            if self.retire_lost_vmm(&sandbox).await {
                acted.push((id, "vmm-exited"));
                continue;
            }
            tracing::debug!(
                sandbox = id,
                idle_secs = sandbox.idle_secs(),
                age_secs = sandbox.age_secs(),
                idle_suspend_secs = lifetime.idle_suspend_secs,
                max_lifetime_secs = lifetime.max_lifetime_secs,
                suspended_secs = sandbox.suspended_secs(),
                suspended_ttl_secs = lifetime.suspended_ttl_secs,
                "reap check"
            );

            // Checked before the lifetime cap only in the sense that both
            // destroy: whichever comes due first wins, and neither is
            // reversible.
            if lifetime.suspended_ttl_secs > 0
                && !sandbox.is_running()
                && sandbox.suspended_secs() >= lifetime.suspended_ttl_secs as i64
            {
                match self.delete(&id).await {
                    Ok(()) => {
                        tracing::info!(
                            sandbox = id,
                            suspended_ttl_secs = lifetime.suspended_ttl_secs,
                            "sandbox was suspended past its retention and was destroyed"
                        );
                        acted.push((id, "retention-expired"));
                    }
                    Err(err) => {
                        tracing::warn!(sandbox = id, %err, "could not destroy a retired sandbox")
                    }
                }
                continue;
            }

            if lifetime.max_lifetime_secs > 0
                && sandbox.age_secs() >= lifetime.max_lifetime_secs as i64
            {
                match self.delete(&id).await {
                    Ok(()) => {
                        tracing::info!(
                            sandbox = id,
                            max_lifetime_secs = lifetime.max_lifetime_secs,
                            "sandbox reached its maximum lifetime and was destroyed"
                        );
                        acted.push((id, "expired"));
                    }
                    Err(err) => {
                        tracing::warn!(sandbox = id, %err, "could not destroy an expired sandbox")
                    }
                }
                continue;
            }

            // A suspended sandbox is already idle; only a running one has
            // anything to reclaim, and one with a shared connection open is
            // in use however long ago it was last asked for anything.
            if lifetime.idle_suspend_secs > 0
                && sandbox.is_running()
                && sandbox.idle_secs() >= lifetime.idle_suspend_secs as i64
                && self.shares.open_connections(&id).await == 0
            {
                match self.pause(&id).await {
                    Ok(_) => {
                        tracing::info!(
                            sandbox = id,
                            idle_secs = sandbox.idle_secs(),
                            "sandbox idle past its policy and was suspended"
                        );
                        acted.push((id, "idle-suspended"));
                    }
                    Err(err) => {
                        tracing::warn!(sandbox = id, %err, "could not suspend an idle sandbox")
                    }
                }
            }
        }
        acted
    }

    /// This node's inventory, for the orchestrator to adopt.
    ///
    /// Sent whole rather than as a delta: a delta needs the two sides to agree
    /// on where they started, and a full list makes a missed heartbeat
    /// self-correcting.
    pub async fn state_reports(&self) -> Vec<burrow_proto::node::v1::SandboxStateReport> {
        self.fence_if_lapsed().await;
        let report =
            |record: common::Sandbox, is_fenced| burrow_proto::node::v1::SandboxStateReport {
                sandbox_id: record.id,
                state: record.state,
                cpu_usage_usec: record.cpu_usage_usec,
                rx_bytes: record.rx_bytes,
                tx_bytes: record.tx_bytes,
                is_agent_unconfirmed: record.is_agent_unconfirmed,
                is_durable: record.is_durable,
                is_fenced,
                state_reason: record.state_reason,
                checkpoint_at_unix_ms: record.checkpoint_at_unix_ms,
                checkpoint_kind: record.checkpoint_kind,
            };
        let mut reports: Vec<_> = self
            .sandboxes
            .lock()
            .await
            .values()
            .map(|sandbox| report(sandbox.record(), sandbox.durable.is_fenced()))
            .collect();
        reports.extend(
            self.held
                .lock()
                .unwrap()
                .values()
                .map(|held| report(held.record.clone(), false)),
        );
        reports
    }

    /// Host CPU promised across every sandbox this node holds, suspended
    /// included, in thousandths of a CPU.
    ///
    /// A suspended sandbox keeps its address, disks and snapshot and can be
    /// resumed at any moment, so counting only running ones would let a node
    /// accept work it cannot honour when they all come back.
    pub async fn committed_cpu_millis(&self) -> u64 {
        self.sandboxes
            .lock()
            .await
            .values()
            .map(|sandbox| sandbox.cpu_charge_millis())
            .sum()
    }

    /// What this node has provisioned: every sandbox's disks and every
    /// volume, at their sizes, and the disk its warm snapshots take.
    async fn provisioned(&self) -> crate::diskcap::Provisioned {
        let disks = self
            .sandboxes
            .lock()
            .await
            .values()
            .flat_map(|sandbox| sandbox.disk_files())
            .collect();
        let volume_bytes = self
            .volumes
            .list()
            .await
            .iter()
            .map(|volume| volume.size_mib.saturating_mul(burrow_common::disk::MIB))
            .sum();
        let warm_bytes = crate::warm::list_all(&self.config.templates_dir())
            .await
            .iter()
            .map(|(_, warm)| warm.bytes)
            .sum();
        crate::diskcap::Provisioned {
            disks,
            volume_bytes,
            warm_bytes,
        }
    }

    /// This node's disk as admission sees it, logging loudly while free disk
    /// is under the reserve with sandboxes here. `None` when the data
    /// directory cannot be measured.
    pub async fn disk_status(&self) -> Option<(burrow_common::disk::DiskCapacity, bool)> {
        let capacity = self
            .disk_admissions
            .capacity(
                &self.config.disk_dir(),
                self.config.disk,
                self.provisioned().await,
            )
            .await?;
        let running = self
            .sandboxes
            .lock()
            .await
            .values()
            .filter(|sandbox| sandbox.is_running())
            .count();
        let is_low = self.disk_admissions.watch(&capacity, running);
        Some((capacity, is_low))
    }

    /// Admits `request_bytes` more disk for `what`, or refuses with
    /// `ResourceExhausted` naming `node` and the shortfall. Held until the
    /// sandbox is registered, and counted with the rest from then on.
    async fn admit_disk(
        &self,
        node: &str,
        what: &str,
        request_bytes: u64,
    ) -> Result<crate::diskcap::Admitted, Status> {
        let node = if node.is_empty() { "this node" } else { node };
        self.disk_admissions
            .admit(
                node,
                what,
                request_bytes,
                &self.config.disk_dir(),
                self.config.disk,
                self.provisioned().await,
            )
            .await
    }

    pub async fn get(&self, id: &str) -> Result<Arc<RunningSandbox>, Status> {
        if let Some(sandbox) = self.sandboxes.lock().await.get(id) {
            return Ok(Arc::clone(sandbox));
        }
        match self.held.lock().unwrap().get(id) {
            Some(held) => Err(Status::failed_precondition(format!(
                "sandbox {id} is out of service on this node: {}",
                held.record.state_reason
            ))),
            None => Err(Status::not_found(format!("no sandbox {id} on this node"))),
        }
    }

    /// A sandbox's record, one recovery left out of service included.
    pub async fn record_of(&self, id: &str) -> Result<common::Sandbox, Status> {
        if let Some(held) = self.held.lock().unwrap().get(id) {
            return Ok(held.record.clone());
        }
        Ok(self.get(id).await?.record())
    }

    pub async fn list(&self) -> Vec<common::Sandbox> {
        let mut out: Vec<_> = self
            .sandboxes
            .lock()
            .await
            .values()
            .map(|s| s.record())
            .collect();
        out.extend(
            self.held
                .lock()
                .unwrap()
                .values()
                .map(|held| held.record.clone()),
        );
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Builds the VM description for a sandbox.
    ///
    /// Shared by creation and recovery: a restored VM has to be described
    /// with the same resources it was snapshotted with, so the two paths must
    /// not be able to drift apart.
    #[allow(clippy::too_many_arguments)]
    fn build_spec(
        &self,
        id: &str,
        workdir: &Path,
        hypervisor: Hypervisor,
        guest_os: burrow_vmm::GuestOs,
        resources: &common::ResourcePolicy,
        lease: &Lease,
        tap_name: &str,
        volumes: &[common::VolumeMount],
        is_systemd: bool,
        is_console_verbose: bool,
    ) -> VmSpec {
        let mut spec = VmSpec::new(id.to_string(), workdir, self.config.backend(hypervisor));
        spec.guest_os = guest_os;
        let capabilities = hypervisor.capabilities();
        spec.vcpus = resources.vcpus.max(1);
        // Room to hotplug up to the node's CPU count. It costs the guest a
        // few per-CPU areas for each possible vCPU and the VMM nothing until
        // one is plugged.
        if capabilities.is_vcpu_hotplug_supported {
            spec.max_vcpus = std::thread::available_parallelism()
                .map_or(spec.vcpus, |n| n.get() as u32)
                .clamp(spec.vcpus, crate::nodeapi::MAX_VCPUS);
        }
        let mem_mib = if resources.mem_mib == 0 {
            DEFAULT_MEM_MIB
        } else {
            resources.mem_mib
        };
        // What the VM booted with, which a restore must describe; what has
        // been plugged since sits in the hotplug region above it.
        spec.mem_mib = match resources.boot_mem_mib {
            0 => mem_mib,
            boot => boot.min(mem_mib),
        };
        spec.mem_plugged_mib = mem_mib - spec.mem_mib;
        spec.mem_hotplug_mib =
            hotplug_region(hypervisor, guest_os, spec.mem_mib, resources.max_mem_mib);

        spec.limits = cgroup_limits(
            resources,
            self.config.memory_ceiling_mib(spec.hypervisor(), mem_mib),
        );
        spec.cgroup_root = self.config.cgroup_root.clone();
        spec.is_limits_required = self.config.is_resource_limits_required;
        // Only consulted on restore; a cold boot has no memory file to serve.
        spec.is_memory_lazy = self.config.is_memory_lazy && capabilities.is_lazy_memory_supported;
        // Required for diff snapshots, and only useful for them. It costs a
        // little guest write performance, which is a good trade against
        // writing the whole of memory on every suspend.
        spec.is_dirty_pages_tracked = true;
        // Volumes are hotplugged onto sandboxes restored from a warm snapshot,
        // and hotplug needs PCI. Set for every VM rather than only those with
        // volumes, because a snapshot cannot be restored under a different
        // transport than it was taken with, and warm snapshots are shared.
        spec.is_pci_enabled = true;

        spec.drives = crate::rootdisk::drives();
        // After the sandbox's own disks, so the guest devices follow them and
        // match what the handshake tells the agent to mount.
        for (index, mount) in crate::volume::block_mounts(volumes) {
            spec.drives.push(DriveSpec {
                id: crate::volume::drive_id(index, guest_os),
                path: volume_image(index),
                is_root: false,
                is_read_only: mount.is_read_only,
            });
        }
        spec.is_vsock_enabled = true;
        spec.is_nested_virt_enabled = resources.is_nested_virt_enabled;
        spec.net = Some(NetSpec {
            tap: tap_name.to_string(),
            guest_mac: Some(lease.guest_mac()),
        });
        spec.boot = burrow_vmm::Boot::Kernel {
            kernel: TEMPLATE_KERNEL.into(),
            cmdline: format!(
                "{} {} init=/usr/bin/burrow-guest {} burrow.dns={} burrow.ip6={}/{} burrow.ip6gw={} {} {}",
                burrow_vmm::DEFAULT_BOOT_ARGS,
                crate::rootdisk::BOOT_ARGS,
                lease.kernel_ip_arg(),
                lease.host_ip,
                lease.guest_ip6(),
                lease.prefix_len6(),
                lease.host_ip6(),
                guest_mode_arg(is_systemd),
                guest_boot_args(
                    &self.config.extra_boot_args,
                    is_console_verbose || self.config.is_console_verbose
                )
            ),
        };
        if crate::macnode::is_macos(guest_os)
            && let Err(err) = crate::macnode::apply(&mut spec, resources)
        {
            // Booting the unchanged spec fails with the backend's own
            // refusal; this says why it got there.
            tracing::warn!(
                sandbox = id,
                err = err.message(),
                "cannot describe the macOS machine"
            );
        }
        spec
    }

    /// Creates a sandbox, on a task of its own: a caller that gives up does
    /// not stop it half way, holding a lease, a tap and a VMM nothing will
    /// release. The sandbox it makes is registered and reported like any
    /// other, which is how an orchestrator that stopped waiting finds it.
    // Identity, shape and policy all arrive together, which is more than seven
    // things; grouping them into a struct would only move the list.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        id: String,
        template: String,
        policy: common::Policy,
        tags: HashMap<String, String>,
        node_id: String,
        name: String,
        request_id: String,
    ) -> Result<common::Sandbox, Status> {
        self.detached(move |manager| async move {
            manager
                .create_now(id, template, policy, tags, node_id, name, request_id)
                .await
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, fields(sandbox = %id, template = %template, from_warm))]
    async fn create_now(
        &self,
        id: String,
        template: String,
        policy: common::Policy,
        tags: HashMap<String, String>,
        node_id: String,
        name: String,
        request_id: String,
    ) -> Result<common::Sandbox, Status> {
        // A sandbox provisioned ahead of demand needs none of the work below:
        // its VM is already restored, its agent already handshaken, its
        // address already applied. What is left is stamping it with this
        // caller's policy.

        let resources = policy.resources.clone().unwrap_or_default();
        let machine = self.image_environment(&template).await.machine();
        if let Ok((Hypervisor::Vz, _)) = machine
            && has_host_limits(&resources)
        {
            return Err(Status::failed_precondition(
                "a Mac node has no cgroup to hold cpus, reserved_cpus, cpu_shares, cpuset_cpus or \
                 blkio_weight; leave them unset for a macOS sandbox",
            ));
        }
        // A create of a shape with no warm snapshot is exactly the signal that
        // one is worth building, so the next create of it restores. Not for a
        // backend whose restore loses to its boot.
        // Warm snapshots are taken without nested virtualization, which a
        // restore cannot add, so a nested sandbox always boots.
        let is_warmable = !resources.is_nested_virt_enabled
            && machine
                .is_ok_and(|(hypervisor, _)| hypervisor.capabilities().is_warm_pool_supported);
        if is_warmable {
            self.warm_for_demand(&ShapeKey::of(&template, &resources));
        }
        let record = self
            .create_seeded(id, template, policy, tags, node_id, None, name, request_id)
            .await?;
        self.warn_if_root_untrusted(&record);
        Ok(record)
    }

    /// Warns when an inspected macOS guest's Security framework does not
    /// trust the inspection root: curl and OpenSSL tools there verify the
    /// proxy, while URLSession, Safari, Swift and Go reject it.
    fn warn_if_root_untrusted(&self, record: &common::Sandbox) {
        let is_macos = burrow_vmm::GuestOs::from_record(&record.guest_os)
            .is_some_and(crate::macnode::is_macos);
        if !is_macos || record.inspection_root_fingerprint.is_empty() {
            return;
        }
        let manager = self.clone();
        let (id, template) = (record.id.clone(), record.template.clone());
        tokio::spawn(async move {
            let Ok(sandbox) = manager.get(&id).await else {
                return;
            };
            if let Ok(false) = sandbox.agent_has(FEATURE_ROOT_TRUSTED).await {
                tracing::warn!(
                    sandbox = id,
                    template,
                    "this macOS guest's admin trust settings do not trust the TLS inspection \
                     root, so apps on Apple's TLS stack reject inspected connections; writing \
                     it onto the disk before boot failed (logged above)"
                );
            }
        });
    }

    /// Creates a sandbox whose root disk starts from an existing disk rather
    /// than its template's image.
    ///
    /// Only the template builder uses this: a build's disk after a step *is*
    /// the layer, so seeding it is how a rebuild resumes from a cached step
    /// instead of replaying the ones before it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_seeded(
        &self,
        id: String,
        template: String,
        policy: common::Policy,
        tags: HashMap<String, String>,
        node_id: String,
        seed_disk: Option<&Path>,
        name: String,
        request_id: String,
    ) -> Result<common::Sandbox, Status> {
        // Claimed before provisioning, not merely checked: provisioning takes
        // seconds, so two creates of the same id (an orchestrator retry, say)
        // would otherwise both get past the check and then share one lease,
        // tap and workdir, with the second's `prepare_workdir` deleting the
        // first's rootfs out from under a running guest.
        {
            let sandboxes = self.sandboxes.lock().await;
            let mut creating = self.creating.lock().await;
            if sandboxes.contains_key(&id) || !creating.insert(id.clone()) {
                return Err(Status::already_exists(format!("sandbox {id} exists")));
            }
        }
        // Held until the sandbox is registered running, so a create racing
        // this one sees it either starting or running.
        let slot = match self.image_environment(&template).await.machine() {
            Ok((_, guest_os)) => self.reserve_mac_slot(&id, guest_os).await,
            Err(_) => Ok(None),
        };
        let _slot = match slot {
            Ok(slot) => slot,
            Err(err) => {
                self.creating.lock().await.remove(&id);
                return Err(err);
            }
        };

        let provisioned = self
            .provision_with(id.clone(), template, policy, seed_disk, node_id)
            .await;
        let (sandbox, _disk) = match provisioned {
            Ok(provisioned) => provisioned,
            Err(err) => {
                self.creating.lock().await.remove(&id);
                return Err(err);
            }
        };

        // Stamped before the record is taken, or the caller and the store are
        // handed a sandbox with none of the tags they asked for.
        {
            let mut stamped = sandbox.base_record.lock().unwrap();
            stamped.tags = tags;
            stamped.name = name;
            stamped.create_request_id = request_id;
        }
        // Only now that the sandbox exists does its policy exist to render, so
        // its rules land here, before anything can reach it. The window a
        // recycled address block inheriting the previous holder's rules would
        // open is closed at the source instead, by [`Self::delete`] returning
        // the lease only after the render that stopped naming it.
        let registered = self.register_or_discard(&sandbox).await;
        self.creating.lock().await.remove(&id);
        registered?;
        // A create is a VM starting, whether it cold-booted or restored a warm
        // template snapshot: either way the guest begins at the image's state
        // rather than at one this sandbox left behind.
        self.emit(&sandbox, EVENT_CREATED, "").await;
        self.open_session(&sandbox, STARTED_BOOT, None).await;
        let record = sandbox.record();
        let registered = std::time::Instant::now();
        self.persist(&sandbox).await;
        tracing::debug!(
            sandbox = id,
            persist_ms = registered.elapsed().as_millis() as u64,
            "create tail"
        );
        // The other half of the reclaim: a warm create's handshake may have
        // given up while this was still registering, when there was nothing in
        // the registry to reclaim. A no-op in every other case.
        self.reclaim_unconfirmed(&id).await;
        Ok(record)
    }

    /// Refuses mounts of volumes this node can neither attach nor fetch: one
    /// it holds, or a read-only mount of one kept in the object store.
    #[allow(clippy::result_large_err)]
    fn require_volumes(&self, mounts: &[common::VolumeMount]) -> Result<(), Status> {
        for (_, mount) in crate::volume::block_mounts(mounts) {
            let is_reachable = self.volumes.is_local(&mount.volume)
                || (mount.is_read_only && self.volumes.is_durable());
            if !is_reachable {
                return Err(Status::not_found(format!(
                    "no volume {} on this node",
                    mount.volume
                )));
            }
        }
        Ok(())
    }

    /// The image each block mount attaches: the volume itself where this node
    /// holds it, or a read-only copy of a durable volume another node holds,
    /// whose generation is stamped on the mount. `is_pinned` keeps the
    /// generation a mount already names, for a sandbox taken up elsewhere
    /// whose guest read that one; otherwise the latest upload is fetched.
    /// Called once the claims are held, so no reader letting go here removes
    /// a copy in between.
    async fn volume_sources(
        &self,
        sandbox_id: &str,
        mounts: &mut [common::VolumeMount],
        is_pinned: bool,
    ) -> Result<Vec<PathBuf>, Status> {
        let mut sources = Vec::new();
        for mount in mounts.iter_mut().filter(|mount| !mount.is_tmpfs) {
            if self.volumes.is_local(&mount.volume) {
                mount.generation = 0;
                sources.push(self.volumes.image(&mount.volume));
                continue;
            }
            let pinned = (is_pinned && mount.generation != 0).then_some(mount.generation);
            let (copy, generation) = self
                .volumes
                .reader_copy(&mount.volume, pinned, sandbox_id)
                .await?;
            mount.generation = generation;
            sources.push(copy);
        }
        Ok(sources)
    }

    /// Takes one sandbox's volume claims and readies the images under them,
    /// all before anything attaches one; see [`crate::volume::VolumeStore::prepare`].
    async fn claim_volumes(
        &self,
        id: &str,
        volumes: &[common::VolumeMount],
        guest_os: burrow_vmm::GuestOs,
    ) -> Result<(), Status> {
        self.volumes.claim(id, volumes)?;
        let dormant: std::collections::HashSet<String> = self
            .sandboxes
            .lock()
            .await
            .values()
            .filter(|sandbox| sandbox.id() != id && sandbox.is_suspended())
            .flat_map(|sandbox| sandbox.record().policy.unwrap_or_default().volumes)
            .filter(|mount| !mount.is_tmpfs && !mount.is_read_only)
            .map(|mount| mount.volume)
            .collect();
        if let Err(err) = self
            .volumes
            .prepare(volumes, guest_os.as_str(), &dormant)
            .await
        {
            self.volumes.release_all(id);
            return Err(err);
        }
        Ok(())
    }

    async fn provision_with(
        &self,
        id: String,
        template: String,
        mut policy: common::Policy,
        seed_disk: Option<&Path>,
        node_id: String,
    ) -> Result<(Arc<RunningSandbox>, crate::diskcap::Admitted), Status> {
        let began = std::time::Instant::now();
        // The last place it can be checked before it is joined onto the
        // templates directory. The API checks it too, but every create on this
        // node funnels through here, including the ones a build starts for
        // itself, so this is the one that cannot be routed around.
        crate::template::validate_name(&template)?;
        let templates_dir = self.config.templates_dir();
        // The template decides the hypervisor, for this sandbox and every VM
        // it will ever run.
        let environment = self.image_environment(&template).await;
        let (hypervisor, guest_os) = environment.machine()?;
        self.require_hypervisor(hypervisor)?;
        self.require_nested_virt(
            hypervisor,
            policy.resources.as_ref().unwrap_or(&Default::default()),
        )?;
        let capabilities = hypervisor.capabilities();
        if !capabilities.runs(guest_os) {
            return Err(Status::failed_precondition(format!(
                "template {template} is a {} guest, which {hypervisor} cannot run",
                guest_os.as_str()
            )));
        }
        let layout = hypervisor.layout();
        let workdir = self.config.sandbox_dir(&id, hypervisor);
        let mut resources = policy.resources.clone().unwrap_or_default();
        // The disk this sandbox is provisioned: its root disk at the size
        // asked for, or a macOS guest's clone of its template's disk. Charged
        // before anything is made, so a node that cannot hold it refuses
        // without a tap or a directory to give back.
        let disk_bytes = match crate::macnode::disk_file(guest_os) {
            Some(disk) => {
                let bytes =
                    crate::rootdisk::provisioned_bytes(&templates_dir.join(&template).join(disk));
                resources.disk_mib =
                    u32::try_from(bytes.div_ceil(burrow_common::disk::MIB)).unwrap_or(u32::MAX);
                bytes
            }
            None => {
                let image =
                    tokio::fs::metadata(templates_dir.join(&template).join(TEMPLATE_ROOTFS))
                        .await
                        .map_err(|err| {
                            Status::failed_precondition(format!("template {template:?}: {err}"))
                        })?;
                resources.disk_mib = crate::rootdisk::disk_mib(resources.disk_mib, image.len())?;
                u64::from(resources.disk_mib) * burrow_common::disk::MIB
            }
        };
        pin_boot_memory(&mut resources, hypervisor, guest_os)?;
        // The record says the size the disk is, not the size it defaulted to.
        policy.resources = Some(resources.clone());
        let disk = self
            .admit_disk(&node_id, "create a sandbox", disk_bytes)
            .await?;

        // A seeded disk has to survive into the guest untouched, and the warm
        // path stages its own disk, so it is not usable here. Nor is a warm
        // snapshot of the wrong shape: restoring it would give the caller
        // different cpu, memory or disk than they asked for, with no error to
        // say so.
        // Taken before any resource is, so a volume conflict fails the create
        // without a tap, an address or a directory to give back.
        crate::volume::validate_mounts(&policy.volumes)?;
        self.require_volumes(&policy.volumes)?;
        self.claim_volumes(&id, &policy.volumes, guest_os).await?;
        // The claims above are the first thing this create holds, so the guard
        // starts here: everything taken from now on is given back by it, and
        // every failure below answers through [`Provisioning::fail`].
        let mut guard = Provisioning::new(self, &id, &workdir);
        let mut policy = policy;
        let sources = match self.volume_sources(&id, &mut policy.volumes, false).await {
            Ok(sources) => sources,
            Err(err) => return Err(guard.fail(err).await),
        };

        // A warm snapshot was taken without volumes, so they can only reach a
        // sandbox restored from one by being hotplugged; where they cannot
        // be, it boots cold and takes them at boot.
        //
        // A snapshot with a smaller disk than asked for is restored and its
        // disk grown, where the guest's disk can grow live; one with a larger
        // disk cannot be shrunk under the guest, so that create boots.
        let wanted = crate::warm::Shape::wanted(&resources);
        let is_warmable = seed_disk.is_none()
            && !policy.is_console_verbose
            && !resources.is_nested_virt_enabled
            && capabilities.is_warm_pool_supported
            && (capabilities.is_drive_hotplug_supported
                || crate::volume::block_mounts(&policy.volumes)
                    .next()
                    .is_none());
        let found = match is_warmable {
            true => crate::warm::find(&templates_dir, &template, hypervisor, wanted).await,
            false => None,
        };
        if is_warmable && found.is_none() {
            self.rebuild_in_background_if_broken(&template, hypervisor, wanted);
        }
        let warm = found.filter(|warm| {
            warm.shape.disk_mib == wanted.disk_mib
                || (warm.shape.disk_mib < wanted.disk_mib
                    && capabilities.is_live_disk_growth_supported)
        });
        let from_warm = warm.is_some();
        let warm_check_ms = began.elapsed();

        // Networking: a private /30 on a dedicated tap. The guest configures
        // itself from the kernel command line, so no DHCP client is needed.
        // The address is taken first because the tap is named after it.
        // Bound to its own statement so the ipam lock is released before the
        // failure path, which takes it again to hand back the volume claims.
        let allocated = self.ipam.lock().await.allocate(&id);
        let lease = match allocated {
            Ok(lease) => lease,
            Err(err) => {
                return Err(guard
                    .fail(Status::resource_exhausted(format!(
                        "address allocation: {err}"
                    )))
                    .await);
            }
        };
        let ipam_ms = began.elapsed() - warm_check_ms;

        // Copying a root disk is disk work and programming a tap is netlink,
        // so they run together rather than one after the other.
        let stage = async {
            let staging_began = std::time::Instant::now();
            // May come back false: a snapshot swapped out or evicted since it
            // was found, or one with a file gone, which is rebuilt. A cold
            // boot is slower, not wrong, and is a far better answer than
            // failing the create.
            let mut is_warm = from_warm;
            if let Some(snapshot) = &warm
                && let Err(err) =
                    crate::warm::stage_from_warm(&templates_dir, &template, snapshot, &workdir)
                        .await
            {
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(Status::internal(format!("staging warm snapshot: {err}")));
                }
                tracing::warn!(
                    template = %template, %err,
                    "warm snapshot is not there to stage; booting cold"
                );
                self.rebuild_in_background_if_broken(&template, hypervisor, wanted);
                is_warm = false;
            }
            if crate::macnode::is_macos(guest_os) {
                let root = self.inspection_ca_for(&policy);
                crate::macnode::prepare(&templates_dir.join(&template), &workdir, &root)
                    .await
                    .map_err(|err| {
                        Status::failed_precondition(format!("template {template:?}: {err}"))
                    })?;
            } else if !is_warm {
                prepare_workdir(&templates_dir.join(&template), &workdir)
                    .await
                    .map_err(|err| {
                        Status::failed_precondition(format!("template {template:?}: {err}"))
                    })?;
                let disk = workdir.join(crate::rootdisk::ROOT_DISK);
                match seed_disk {
                    Some(seed) => crate::rootdisk::clone(seed, &disk).await.map(drop),
                    None => self.spares.take(&templates_dir, &template, &disk).await,
                }
                .map_err(|err| Status::internal(format!("making the root disk: {err}")))?;
                crate::rootdisk::grow(&disk, resources.disk_mib).await?;
            }
            // Hard-linked in after the template's own files, so a cold boot
            // that rebuilt the directory does not clear them again.
            for ((index, mount), source) in
                crate::volume::block_mounts(&policy.volumes).zip(&sources)
            {
                let dest = workdir.join(crate::sandbox::volume_image(index));
                let _ = tokio::fs::remove_file(&dest).await;
                tokio::fs::hard_link(source, &dest).await.map_err(|err| {
                    Status::internal(format!("attaching volume {}: {err}", mount.volume))
                })?;
            }
            let files_ms = staging_began.elapsed();
            // Ownership is handed over inside the same task, because it has to
            // follow staging and nothing else waits on it.
            if let Some(jail) = self.config.jail_for(hypervisor) {
                // The template's own files are always hard links; a warm boot
                // additionally hard-links the snapshot state and memory image
                // (and, if one exists, the prefetch plan) instead of writing
                // fresh copies. A read-only volume mount is a hard link too,
                // regardless of warm or cold: the many-readers side of the
                // volume store's "many readers, one writer" rule has nothing
                // else keeping a reader from writing back if this doesn't.
                let mut shared: std::collections::HashSet<String> =
                    [TEMPLATE_KERNEL.to_string(), TEMPLATE_ROOTFS.to_string()].into();
                if is_warm {
                    shared.extend(layout.files().map(String::from));
                    shared.insert(crate::warm::PREFETCH_PLAN.to_string());
                }
                for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
                    if mount.is_read_only {
                        shared.insert(crate::sandbox::volume_image(index));
                    }
                }
                // A writable mount is the one shared inode that does get
                // chowned, so its owner is recorded first and put back when the
                // claim goes.
                self.remember_volume_owners(&policy.volumes).await;
                grant_to_jail(&workdir, jail, &shared)
                    .await
                    .map_err(|err| Status::internal(format!("preparing the jail: {err}")))?;
            }
            Ok::<(bool, std::time::Duration, std::time::Duration), Status>((
                is_warm,
                files_ms,
                staging_began.elapsed() - files_ms,
            ))
        };

        // A backend without a tap gets no interface at all, and an empty name
        // that nothing tears down.
        let tap_timed = async {
            let began = std::time::Instant::now();
            if !capabilities.is_tap_networked {
                return (Ok(String::new()), began.elapsed());
            }
            (tap::create(&lease).await, began.elapsed())
        };
        let staged_at = std::time::Instant::now();
        let (staged, (tap, tap_ms)) = tokio::join!(stage, tap_timed);
        let stage_wall_ms = staged_at.elapsed();
        // Recorded before either half is inspected: the tap may well have come
        // up alongside a staging failure, and an interface belonging to a
        // sandbox that never existed must not be left behind.
        guard.tap = tap.as_ref().ok().filter(|name| !name.is_empty()).cloned();
        let (from_warm, files_ms, jail_ms) = match staged {
            Ok(parts) => parts,
            Err(err) => return Err(guard.fail(err).await),
        };
        tracing::Span::current().record("from_warm", from_warm);
        let tap_name = match tap {
            Ok(name) => name,
            Err(err) => {
                return Err(guard
                    .fail(Status::internal(format!("tap setup: {err}")))
                    .await);
            }
        };

        // A warm snapshot was captured with the sandbox's own disk alone, so a
        // restore must describe exactly that; the volumes are hotplugged once
        // it is running. A cold boot hotplugs them too, once its agent is up.
        let is_hotplugged = from_warm
            || (capabilities.is_drive_hotplug_supported && !crate::macnode::is_macos(guest_os));
        let boot_volumes: &[common::VolumeMount] =
            if is_hotplugged { &[] } else { &policy.volumes };
        let is_systemd = environment.systemd;
        let mut spec = self.build_spec(
            &id,
            &workdir,
            hypervisor,
            guest_os,
            &resources,
            &lease,
            &tap_name,
            boot_volumes,
            is_systemd,
            policy.is_console_verbose,
        );
        // Only meaningful on a restore, and only when the template was
        // profiled; a create that boots cold has no snapshot to prefetch from.
        if from_warm
            && capabilities.is_lazy_memory_supported
            && tokio::fs::try_exists(workdir.join(crate::warm::PREFETCH_PLAN))
                .await
                .unwrap_or(false)
        {
            spec.prefetch = Some(crate::warm::PREFETCH_PLAN.to_string());
        }
        if let Err(err) = self.usernets.attach(&id, &lease, &mut spec) {
            return Err(guard.fail(err).await);
        }
        let boot_spec = spec.clone();
        record_working_set(&mut spec, self.config.object_store.is_some());
        let started = std::time::Instant::now();
        let spec_ms = started - staged_at - stage_wall_ms;
        let started_vm = if from_warm {
            // The override points the snapshotted interface at this sandbox's
            // own tap; the address inside the guest is corrected on handshake.
            Vm::restore(spec, true)
                .await
                .map_err(|err| Status::internal(format!("warm restore failed: {err}")))
        } else {
            Vm::boot(spec)
                .await
                .map_err(|err| Status::internal(format!("boot failed: {err}")))
        };
        match started_vm {
            Ok(vm) => guard.vm = Some(vm),
            Err(err) => return Err(guard.fail(err).await),
        }

        // A snapshot taken on a smaller disk than this sandbox asked for: the
        // disk grows under the running guest, as a live resize would, and the
        // guest grows its filesystem once it has handshaken.
        let grow_to = warm
            .filter(|warm| from_warm && warm.shape.disk_mib < wanted.disk_mib)
            .map(|_| u64::from(wanted.disk_mib) * burrow_common::disk::MIB);
        if let Some(bytes) = grow_to {
            let grown = async {
                crate::rootdisk::grow(&workdir.join(crate::rootdisk::ROOT_DISK), wanted.disk_mib)
                    .await?;
                guard
                    .vm()
                    .resize_disk("rootfs", bytes)
                    .await
                    .map_err(|err| Status::internal(format!("growing the warm disk: {err}")))
            }
            .await;
            if let Err(err) = grown {
                return Err(guard.fail(err).await);
            }
        }

        // Attached before the handshake, which is what tells the guest to rescan
        // its bus and mount them: firecracker cannot notify the guest itself.
        if from_warm && let Err(err) = attach_volumes(guard.vm(), &policy.volumes, guest_os).await {
            return Err(guard.fail(err).await);
        }

        // What a guest still has to be told. Assembled before any clock starts,
        // because reading host entropy and the image's trust bundles is host
        // work and charging it to the guest would hide what the guest costs.
        let request = guestconn::handshake_full(
            from_warm,
            self.guest_network(
                &lease,
                &[],
                hypervisor.capabilities().is_tap_networked,
                from_warm,
            ),
            self.inspection_ca_for(&policy),
            self.trust_bundles_for(&template, &policy).await,
            crate::volume::agent_mounts(&policy.volumes, guest_os),
        );
        let inspected = !request.inspection_ca_pem.is_empty();
        let inspection_root = self.inspection_root_of(&request);

        // A warm create does not wait for the guest to answer. The round trip
        // is most of what it costs, and all of it benefits code running
        // *inside* the guest, which cannot run until someone execs; every exec
        // goes through [`RunningSandbox::agent`], which waits for the handshake
        // first.
        //
        // A cold boot still waits. It has already paid a kernel boot, so the
        // round trip is noise beside it, and its trust store is installed by
        // this handshake rather than baked into a snapshot, which makes waiting
        // the only way to know an inspected sandbox can verify the proxy.
        let vmm_ready = std::time::Instant::now();
        let (handshake, agent_up, vsock_up, handshake_ms, guest_timing) = if from_warm {
            (
                Arc::new(tokio::sync::watch::channel(Handshake::Pending).0),
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                burrow_proto::guest::v1::GuestResumeTiming::default(),
            )
        } else {
            // A VM that never produces a reachable agent is useless; tear it
            // down rather than leaving an unusable sandbox in the registry. The
            // first connection that succeeds is kept, rather than probing with
            // one and then dialling another.
            let connected =
                guestconn::connect_when_ready(guard.vm().guest(), self.config.agent_timeout).await;
            let (agent, accepted_at) = match connected {
                Ok(ready) => ready,
                Err(err) => {
                    let failure =
                        NoAgent::Unreachable(self.config.agent_timeout, error_chain(&*err));
                    let reason = no_agent_reason(guard.vm_mut(), failure).await;
                    return Err(guard.fail(Status::internal(reason)).await);
                }
            };
            let agent_up = vmm_ready.elapsed();
            if is_hotplugged
                && let Err(err) = attach_volumes(guard.vm(), &policy.volumes, guest_os).await
            {
                return Err(guard.fail(err).await);
            }
            // Guest wake proper: the VM resuming far enough for the agent's
            // vsock listener to accept. What is left of `agent_up` is the
            // HTTP/2 handshake the guest's gRPC server does on top of it.
            let vsock_up = accepted_at.map_or(agent_up, |at| at.duration_since(vmm_ready));
            let handshake_began = std::time::Instant::now();
            // A failed handshake gets the same teardown as a failed connect. It
            // did not, and a template that reliably fails to handshake would
            // exhaust the node's taps and address blocks one create at a time.
            let guest_timing = match guestconn::handshake_upgrading(
                agent,
                guard.vm().guest(),
                request.clone(),
                self.config.guest_upgrade.as_deref(),
                self.config.agent_timeout,
            )
            .await
            {
                Ok((_, response)) => response.timing.unwrap_or_default(),
                Err(err) => {
                    let failure = NoAgent::Handshake(err.message().to_string());
                    let reason = no_agent_reason(guard.vm_mut(), failure).await;
                    return Err(guard.fail(Status::internal(reason)).await);
                }
            };
            start_cpu_cap(guard.vm(), &boot_spec.limits, &id);
            (
                settled(),
                agent_up,
                vsock_up,
                handshake_began.elapsed(),
                guest_timing,
            )
        };

        // Nothing below this line can fail, so it is where the sandbox takes
        // over what the guard was holding on its behalf.
        let vm = guard.keep().expect("a create that reaches here has a vm");

        let record = common::Sandbox {
            id: id.clone(),
            node_id,
            template,
            state: common::SandboxState::Running as i32,
            policy: Some(policy),
            created_at_unix_ms: burrow_common::unix_now_ms(),
            guest_ip: lease.guest_ip.to_string(),
            hypervisor: hypervisor.to_string(),
            guest_os: guest_os.as_str().to_string(),
            inspection_root_fingerprint: inspection_root,
            // Tags and name are stamped a moment later by the caller's
            // create; usage, reachability and the handshake are filled in
            // from the live sandbox on every read.
            ..Default::default()
        };

        // The one-line summary, unchanged in shape: VM, guest wake, handshake,
        // and the whole of the create including the host work before the VM.
        tracing::info!(
            sandbox = id,
            warm = from_warm,
            vmm_ms = vm.boot_latency().as_millis() as u64,
            agent_up_ms = agent_up.as_millis() as u64,
            handshake_ms = handshake_ms.as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            provision_ms = began.elapsed().as_millis() as u64,
            "sandbox running"
        );
        // The breakdown behind it. Every field is already-collected arithmetic,
        // so this costs nothing when the level is off.
        tracing::debug!(
            sandbox = id,
            warm = from_warm,
            inspected,
            // Host, before the VM exists.
            warm_check_ms = warm_check_ms.as_millis() as u64,
            ipam_ms = ipam_ms.as_millis() as u64,
            stage_wall_ms = stage_wall_ms.as_millis() as u64,
            stage_files_ms = files_ms.as_millis() as u64,
            jail_ms = jail_ms.as_millis() as u64,
            tap_ms = tap_ms.as_millis() as u64,
            spec_ms = spec_ms.as_millis() as u64,
            // The VM, and the wait for a guest to answer on it.
            vmm_ms = vm.boot_latency().as_millis() as u64,
            agent_up_ms = agent_up.as_millis() as u64,
            vsock_up_ms = vsock_up.as_millis() as u64,
            h2_ms = (agent_up - vsock_up).as_millis() as u64,
            // Inside the guest, as the agent reported it.
            guest_parked_us = guest_timing.parked_us,
            guest_accept_to_call_us = guest_timing.accept_to_call_us,
            guest_reseed_us = guest_timing.reseed_us,
            guest_clock_us = guest_timing.clock_us,
            guest_trust_us = guest_timing.trust_us,
            guest_trust_read_us = guest_timing.trust_read_us,
            guest_trust_scan_us = guest_timing.trust_scan_us,
            guest_trust_write_us = guest_timing.trust_write_us,
            guest_network_us = guest_timing.network_us,
            guest_handshake_us = guest_timing.total_us,
            handshake_ms = handshake_ms.as_millis() as u64,
            "create breakdown"
        );
        let sandbox = Arc::new(RunningSandbox {
            id: record.id.clone(),
            template: record.template.clone(),
            hypervisor,
            base_record: std::sync::Mutex::new(record.clone()),
            state: std::sync::atomic::AtomicI32::new(common::SandboxState::Running as i32),
            vm: Mutex::new(Some(vm)),
            spec: std::sync::Mutex::new(boot_spec),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            suspended_at: std::sync::atomic::AtomicI64::new(0),
            agent_channel: Mutex::new(None),
            agent_features: Mutex::new(None),
            agent_timeout: self.config.agent_timeout,
            handshake,
            // A warm-created sandbox already restores from the template's
            // memory file, so its first suspend has a base to diff against.
            memory_chain: Mutex::new(if from_warm {
                layout.memory.map(String::from).into_iter().collect()
            } else {
                Vec::new()
            }),
            usage: std::sync::Mutex::new(Usage::default()),
            session: std::sync::Mutex::new(None),
            durable: Default::default(),
            logs: Arc::new(crate::cmdlogs::CommandLogs::new(
                &self.config.command_logs_dir(&record.id),
                self.config.command_log_rotation,
            )),
            workdir,
            lease,
            tap: tap_name,
        });
        // Started only once the sandbox exists, so the task can hand the
        // channel it handshook on to whoever needs the guest next.
        if from_warm {
            spawn_handshake(self, &sandbox, request, grow_to, self.config.agent_timeout);
        }
        Ok((sandbox, disk))
    }

    /// Snapshots a sandbox to disk and stops its VMM.
    pub async fn pause(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        self.require_vmm(&sandbox).await?;
        sandbox.suspend().await?;
        self.resync_public(&sandbox).await;
        self.usernets.detach(id, false);
        // The VM is stopped, so nothing is touching the volumes; a suspended
        // sandbox holding them would make a volume unusable until deleted.
        self.volumes.release_all(id);
        self.sample_last(&sandbox).await;
        self.persist(&sandbox).await;
        self.close_session(&sandbox, ENDED_SUSPENDED).await;
        self.spawn_upload(&sandbox);
        tracing::info!(sandbox = id, "sandbox suspended");
        Ok(sandbox.record())
    }

    /// Writes a running sandbox's state without stopping it.
    ///
    /// Internal on purpose, and not a public RPC. What it produces is the
    /// guest's memory, not its disk, and the guest goes straight back to
    /// writing to `scratch.ext4`, so the pair stops agreeing the moment it
    /// resumes. Valid only to a caller that consumes it immediately, which is
    /// what `fork` and `create_snapshot` do and a "save a restore point" call
    /// could not.
    ///
    /// The record is persisted whichever way it ends, because a write that
    /// could not resume its guest leaves the sandbox suspended and a store
    /// still saying `Running` would have recovery discard it.
    async fn write_state(
        &self,
        sandbox: &Arc<RunningSandbox>,
        capture: Option<&Path>,
        also: &[(PathBuf, PathBuf)],
    ) -> Result<std::time::Duration, Status> {
        self.require_vmm(sandbox).await?;
        let sandbox = Arc::clone(sandbox);
        let capture = capture.map(Path::to_path_buf);
        let also = also.to_vec();
        // Detached: the guest is paused while it runs, and a caller dropped
        // there would leave it paused.
        self.detached(move |manager| async move {
            let result = sandbox.checkpoint(capture.as_deref(), &also).await;
            // The pause ended the feed along with every other connection, and
            // a command still running has output to send.
            sandbox.ensure_feed();
            // That failure mode leaves the sandbox suspended, which ends its
            // session as surely as a suspend does.
            if result.is_err() && !sandbox.is_running() {
                manager.close_session(&sandbox, ENDED_FAILED).await;
            }
            manager.persist(&sandbox).await;
            result
        })
        .await
    }

    /// This node's snapshot store.
    pub fn snapshots(&self) -> &crate::snapshot::SnapshotStore {
        &self.snapshots
    }

    pub fn volumes(&self) -> &crate::volume::VolumeStore {
        &self.volumes
    }

    /// Takes a sandbox's state and keeps it as a snapshot object.
    ///
    /// The sandbox goes on running. A running source is checkpointed first so
    /// the snapshot holds the state the caller could observe, exactly as a fork
    /// does; the guest is paused only for that write.
    #[tracing::instrument(skip_all, fields(sandbox = %sandbox_id, snapshot = %snapshot_id))]
    pub async fn create_snapshot(
        &self,
        sandbox_id: &str,
        snapshot_id: String,
        expiration_secs: u64,
    ) -> Result<common::Snapshot, Status> {
        crate::snapshot::validate_id(&snapshot_id)?;
        let sandbox = self.get(sandbox_id).await?;
        let capture = sandbox.workdir.join(format!(".capture-{snapshot_id}"));
        let is_captured = sandbox.is_running();
        if is_captured {
            self.write_state(&sandbox, Some(&capture), &[]).await?;
        } else if sandbox.state.load(std::sync::atomic::Ordering::Relaxed)
            != common::SandboxState::Suspended as i32
        {
            return Err(Status::failed_precondition(
                "only a running or suspended sandbox can be snapshotted",
            ));
        }

        let snapshots = sandbox.snapshot_policy();
        // The request wins over the sandbox's default, and 0 in both means the
        // snapshot is kept until something deletes it.
        let expiration_secs = match expiration_secs {
            0 => snapshots.expiration_secs,
            secs => secs,
        };

        let started = std::time::Instant::now();
        let staged = match self.snapshots.begin(&snapshot_id).await {
            Ok(dir) => {
                sandbox
                    .stage_snapshot(&dir, is_captured.then_some(capture.as_path()))
                    .await
            }
            Err(err) => Err(err),
        };
        let _ = tokio::fs::remove_file(&capture).await;
        let staged = match staged {
            Ok(staged) => staged,
            Err(err) => {
                self.snapshots.abandon(&snapshot_id).await;
                return Err(err);
            }
        };
        let snapshot = match self
            .snapshots
            .publish(&snapshot_id, staged, expiration_secs)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(err) => {
                self.snapshots.abandon(&snapshot_id).await;
                return Err(err);
            }
        };

        // Applied as the snapshot lands rather than on a timer: this is the
        // one moment the count grows, so it is the moment to bound it.
        self.snapshots
            .retain_newest(sandbox_id, snapshots.keep_last, snapshots.is_evicted_kept)
            .await;
        self.emit(&sandbox, EVENT_SNAPSHOT_CREATED, &snapshot.id)
            .await;
        tracing::info!(
            size_bytes = snapshot.size_bytes,
            took_ms = started.elapsed().as_millis() as u64,
            "snapshot created"
        );
        Ok(snapshot)
    }

    /// Creates a sandbox by restoring a snapshot object.
    ///
    /// The template and the machine shape come from the snapshot, for the same
    /// reason a fork cannot change them: Firecracker takes a restored VM's
    /// configuration from the snapshot, so a request that disagrees is refused
    /// rather than quietly given something else.
    ///
    /// Detached, as a create is.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_from_snapshot(
        &self,
        id: String,
        snapshot_id: String,
        policy: common::Policy,
        tags: HashMap<String, String>,
        node_id: String,
        name: String,
        request_id: String,
    ) -> Result<common::Sandbox, Status> {
        self.detached(move |manager| async move {
            manager
                .create_from_snapshot_now(id, &snapshot_id, policy, tags, node_id, name, request_id)
                .await
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, fields(sandbox = %id, snapshot = %snapshot_id))]
    async fn create_from_snapshot_now(
        &self,
        id: String,
        snapshot_id: &str,
        policy: common::Policy,
        tags: HashMap<String, String>,
        node_id: String,
        name: String,
        request_id: String,
    ) -> Result<common::Sandbox, Status> {
        let manifest = self.snapshots.manifest_for_restore(snapshot_id).await?;
        let mut policy = policy;
        let wanted = policy.resources.clone().unwrap_or_default();
        let shape = (
            match wanted.vcpus {
                0 => manifest.vcpus,
                n => n,
            },
            match wanted.mem_mib {
                0 => manifest.mem_mib,
                n => n,
            },
            match wanted.disk_mib {
                0 => manifest.disk_mib,
                n => n,
            },
        );
        if shape != (manifest.vcpus, manifest.mem_mib, manifest.disk_mib)
            || wanted.max_mem_mib != 0 && wanted.max_mem_mib != manifest.max_mem_mib
        {
            return Err(Status::invalid_argument(format!(
                "a sandbox created from snapshot {snapshot_id} restores its state and cannot \
                 change its vcpus, memory or disk: the snapshot was taken with \
                 {} vcpu / {} MiB / {} MiB disk; grow the disk once it runs",
                manifest.vcpus, manifest.mem_mib, manifest.disk_mib
            )));
        }
        // Written back so the record, the cgroup and any later restore all
        // describe the machine the snapshot actually holds.
        policy.resources = Some(manifest.resources(policy.resources.take().unwrap_or_default()));

        {
            let sandboxes = self.sandboxes.lock().await;
            let mut creating = self.creating.lock().await;
            if sandboxes.contains_key(&id) || !creating.insert(id.clone()) {
                return Err(Status::already_exists(format!("sandbox {id} exists")));
            }
        }
        if !self.inspection_ca_for(&policy).is_empty() {
            self.require_inspection_root(&id, &manifest.inspection_root)?;
        }
        let provisioned = self
            .provision_restored(
                RestoreSource::Snapshot {
                    id: snapshot_id,
                    template: manifest.template.clone(),
                    hypervisor: manifest.hypervisor()?,
                    disk_mib: manifest.disk_mib,
                },
                id.clone(),
                policy,
                tags,
                node_id,
                name,
            )
            .await;
        let registered = match &provisioned {
            Ok((sandbox, _)) => {
                sandbox.base_record.lock().unwrap().create_request_id = request_id;
                self.register_or_discard(sandbox).await
            }
            Err(_) => Ok(()),
        };
        self.creating.lock().await.remove(&id);
        let (sandbox, _disk) = provisioned?;
        registered?;

        self.emit(&sandbox, EVENT_CREATED, &format!("snapshot:{snapshot_id}"))
            .await;
        self.open_session(&sandbox, STARTED_RESTORE, None).await;
        let record = sandbox.record();
        self.persist(&sandbox).await;
        // The snapshot has just proved itself worth keeping.
        self.snapshots.touch(snapshot_id).await;
        self.compact_if_deep(&sandbox);
        tracing::info!("sandbox created from a snapshot");
        Ok(record)
    }

    /// Creates a sandbox from another's current state.
    ///
    /// A running source is checkpointed first, so the child starts from the
    /// state the caller could observe; a suspended one is forked from the
    /// snapshot it already has. Either way the source is left as it was found.
    ///
    /// The child is built by restoring the copied snapshot rather than booting:
    /// the point of a fork is to arrive with the source's processes and memory,
    /// which a cold boot would discard.
    #[tracing::instrument(skip_all, fields(source = %source_id, sandbox = %child_id))]
    pub async fn fork(
        &self,
        source_id: &str,
        child_id: String,
        policy: Option<common::Policy>,
        node_id: String,
        name: String,
    ) -> Result<common::Sandbox, Status> {
        let source = self.get(source_id).await?;

        // Claimed the same way a create claims one, and before any state is
        // captured: two forks naming the same child would otherwise share a
        // lease, a tap and a working directory.
        {
            let sandboxes = self.sandboxes.lock().await;
            let mut creating = self.creating.lock().await;
            if sandboxes.contains_key(&child_id) || !creating.insert(child_id.clone()) {
                return Err(Status::already_exists(format!("sandbox {child_id} exists")));
            }
        }

        let forked = self
            .fork_inner(&source, child_id.clone(), policy, node_id, name)
            .await;
        // The child has its own address and its own policy, neither of which
        // the ruleset knows about until now.
        let registered = match &forked {
            Ok((sandbox, _)) => self.register_or_discard(sandbox).await,
            Err(_) => Ok(()),
        };
        self.creating.lock().await.remove(&child_id);
        let (sandbox, _disk) = forked?;
        registered?;

        self.emit(&sandbox, EVENT_CREATED, &format!("fork:{source_id}"))
            .await;
        self.open_session(&sandbox, STARTED_RESTORE, None).await;
        let record = sandbox.record();
        self.persist(&sandbox).await;
        self.compact_if_deep(&sandbox);
        tracing::info!(source = source_id, sandbox = child_id, "sandbox forked");
        Ok(record)
    }

    /// The part of a fork that runs with the child's id already claimed.
    async fn fork_inner(
        &self,
        source: &Arc<RunningSandbox>,
        child_id: String,
        policy: Option<common::Policy>,
        node_id: String,
        name: String,
    ) -> Result<(Arc<RunningSandbox>, crate::diskcap::Admitted), Status> {
        // A running source has state in memory that its snapshot does not
        // hold; capturing it is the whole difference between forking a sandbox
        // and cloning its last suspend.
        let capture = source.workdir.join(format!(".capture-{child_id}"));
        let is_captured = source.is_running();
        if is_captured {
            self.write_state(source, Some(&capture), &[]).await?;
        } else if source.state.load(std::sync::atomic::Ordering::Relaxed)
            != common::SandboxState::Suspended as i32
        {
            return Err(Status::failed_precondition(
                "only a running or suspended sandbox can be forked",
            ));
        }

        let (mut inherited, tags) = {
            let record = source.base_record.lock().unwrap();
            (
                record.policy.clone().unwrap_or_default(),
                record.tags.clone(),
            )
        };
        // A fork copies the source's own disk and memory. A volume is separate
        // storage with an identity of its own, so it is not copied and its
        // mount is not inherited: a writable volume admits one sandbox, and a
        // child that inherited the mount could only ever be refused. Mount it
        // on the child explicitly once the source has let go.
        inherited.volumes.clear();
        // Inherited unless overridden, including the network policy and the
        // tags: a fork is meant to be the same sandbox again.
        let policy = match policy {
            None => inherited,
            Some(mut over) => {
                let shape = inherited.resources.clone().unwrap_or_default();
                let wanted = over.resources.clone().unwrap_or_else(|| shape.clone());
                // Firecracker takes a restored VM's machine configuration from
                // the snapshot, and the child's root disk is a copy of the
                // source's. A shape the fork cannot honour is refused rather
                // than accepted and quietly ignored.
                if (wanted.vcpus, wanted.mem_mib, wanted.disk_mib)
                    != (shape.vcpus, shape.mem_mib, shape.disk_mib)
                    || wanted.max_mem_mib != 0 && wanted.max_mem_mib != shape.max_mem_mib
                {
                    let _ = tokio::fs::remove_file(&capture).await;
                    return Err(Status::invalid_argument(
                        "a fork restores the source's snapshot and cannot change its \
                         vcpus, memory or disk",
                    ));
                }
                over.resources = Some(shape);
                // Section by section, because the sections are independent
                // policies that happen to travel together: a child given only
                // an exec policy asked to change exec, not to be stripped of
                // the egress allowlist its source was built with.
                over.network = over.network.or(inherited.network);
                over.exec = over.exec.or(inherited.exec);
                over.fs = over.fs.or(inherited.fs);
                if over.networks.is_empty() {
                    over.networks = inherited.networks;
                }
                over
            }
        };
        if !self.inspection_ca_for(&policy).is_empty() {
            let parent = source
                .base_record
                .lock()
                .unwrap()
                .inspection_root_fingerprint
                .clone();
            if let Err(err) = self.require_inspection_root(&child_id, &parent) {
                let _ = tokio::fs::remove_file(&capture).await;
                return Err(err);
            }
        }
        let restored = self
            .provision_restored(
                RestoreSource::Sandbox(source, is_captured.then(|| capture.clone())),
                child_id,
                policy,
                tags,
                node_id,
                name,
            )
            .await;
        let _ = tokio::fs::remove_file(&capture).await;
        restored
    }

    /// Builds a VM that starts by restoring state rather than booting: its own
    /// lease, tap and working directory, with a copy of someone else's snapshot
    /// staged into it.
    ///
    /// Shared by forking a sandbox and creating from a snapshot object: the two
    /// differ only in where the bytes come from, and everything after staging
    /// is the same restore, the same re-addressing handshake and the same
    /// record.
    ///
    /// Links the template's prefetch plan into a restore's working directory,
    /// returning whether there is one to use. A plan is an optimisation, so a
    /// missing or unlinkable one costs faults rather than the restore.
    async fn link_prefetch_plan(
        &self,
        template: &str,
        hypervisor: Hypervisor,
        resources: &common::ResourcePolicy,
        workdir: &Path,
    ) -> bool {
        let dest = workdir.join(crate::warm::PREFETCH_PLAN);
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            return true;
        }
        let shape = crate::warm::Shape::wanted(resources);
        let Some(warm) =
            crate::warm::find(&self.config.templates_dir(), template, hypervisor, shape).await
        else {
            return false;
        };
        let plan = warm.dir.join(crate::warm::PREFETCH_PLAN);
        tokio::fs::hard_link(&plan, &dest).await.is_ok()
            || tokio::fs::copy(&plan, &dest).await.is_ok()
    }

    /// Flattens a restored sandbox's chain behind the create when it is deep.
    fn compact_if_deep(&self, sandbox: &Arc<RunningSandbox>) {
        let sandbox = Arc::clone(sandbox);
        tokio::spawn(async move {
            let depth = sandbox.memory_chain.lock().await.len();
            if depth > MAX_RESTORED_CHAIN {
                sandbox.compact_memory_chain().await;
            }
        });
    }

    async fn provision_restored(
        &self,
        source: RestoreSource<'_>,
        id: String,
        mut policy: common::Policy,
        tags: HashMap<String, String>,
        node_id: String,
        name: String,
    ) -> Result<(Arc<RunningSandbox>, crate::diskcap::Admitted), Status> {
        // State restores only under the hypervisor that wrote it, so the
        // source decides, whatever the template says now.
        let hypervisor = source.hypervisor()?;
        self.require_hypervisor(hypervisor)?;
        let capabilities = hypervisor.capabilities();
        let workdir = self.config.sandbox_dir(&id, hypervisor);
        let mut resources = policy.resources.clone().unwrap_or_default();
        self.require_nested_virt(hypervisor, &resources)?;
        // A restored sandbox gets a disk of its source's size, provisioned
        // like a created one's. An adopt is charged here too, after its claim
        // in the store, which a refusal hands back.
        resources.disk_mib = source.disk_mib();
        policy.resources = Some(resources.clone());
        let what = match source {
            RestoreSource::Sandbox(..) => "fork a sandbox",
            RestoreSource::Snapshot { .. } => "create a sandbox from a snapshot",
            RestoreSource::Stored { .. } => "adopt a sandbox",
        };
        let disk = self
            .admit_disk(
                &node_id,
                what,
                u64::from(resources.disk_mib) * burrow_common::disk::MIB,
            )
            .await?;
        // A sandbox's own stored state was captured with its volumes attached,
        // and restores with them. Any other was captured without, so they
        // could only arrive by hotplug.
        let is_attached = matches!(source, RestoreSource::Stored { .. });
        if !capabilities.is_drive_hotplug_supported
            && !is_attached
            && crate::volume::block_mounts(&policy.volumes)
                .next()
                .is_some()
        {
            return Err(Status::failed_precondition(format!(
                "{hypervisor} cannot attach a volume to a restored sandbox; create one from the \
                 template with the volume instead"
            )));
        }

        // A restored sandbox mounts volumes exactly as a created one does. It
        // used to take them only as far as the spec and the handshake, which
        // told the guest to mount devices no one had attached and left the
        // volume unclaimed, so a second sandbox could take it writable at the
        // same time. Claimed first, for the reason the create path gives: a
        // conflict must fail before there is a tap or an address to give back.
        crate::volume::validate_mounts(&policy.volumes)?;
        self.require_volumes(&policy.volumes)?;
        let guest_os = match &source {
            RestoreSource::Sandbox(source, _) => {
                burrow_vmm::GuestOs::from_record(&source.record().guest_os).unwrap_or_default()
            }
            RestoreSource::Stored { manifest, .. } => manifest
                .image
                .machine()
                .map_or_else(|_| Default::default(), |(_, os)| os),
            _ => self
                .image_environment(&source.template())
                .await
                .machine()
                .map_or_else(|_| Default::default(), |(_, os)| os),
        };
        self.claim_volumes(&id, &policy.volumes, guest_os).await?;
        let mut guard = Provisioning::new(self, &id, &workdir);
        let sources = match self
            .volume_sources(&id, &mut policy.volumes, is_attached)
            .await
        {
            Ok(sources) => sources,
            Err(err) => return Err(guard.fail(err).await),
        };

        let allocated = self.ipam.lock().await.allocate(&id);
        let lease = match allocated {
            Ok(lease) => lease,
            Err(err) => {
                return Err(guard
                    .fail(Status::resource_exhausted(format!(
                        "address allocation: {err}"
                    )))
                    .await);
            }
        };

        let stage = async {
            if tokio::fs::try_exists(&workdir).await.unwrap_or(false) {
                tokio::fs::remove_dir_all(&workdir)
                    .await
                    .map_err(|err| Status::internal(format!("clearing the workdir: {err}")))?;
            }
            tokio::fs::create_dir_all(&workdir)
                .await
                .map_err(|err| Status::internal(format!("creating the workdir: {err}")))?;
            // Every source brings the output of the commands its guest
            // remembers.
            let logs_dir = self.config.command_logs_dir(&id);
            let _ = tokio::fs::remove_dir_all(&logs_dir).await;
            let (chain, arriving) = source
                .stage_into(&self.snapshots, &workdir, &logs_dir)
                .await?;
            // Linked in the same shape as a create's, so the guest sees the
            // same devices in the same order as the handshake describes.
            for ((index, mount), source) in
                crate::volume::block_mounts(&policy.volumes).zip(&sources)
            {
                let dest = workdir.join(crate::sandbox::volume_image(index));
                let _ = tokio::fs::remove_file(&dest).await;
                tokio::fs::hard_link(source, &dest).await.map_err(|err| {
                    Status::internal(format!("attaching volume {}: {err}", mount.volume))
                })?;
            }
            if let Some(jail) = self.config.jail_for(hypervisor) {
                // Both a fork and a snapshot restore hard-link only the
                // template's own kernel and rootfs; the snapshot state, the
                // memory chain and the root disk are copies (or reflinks)
                // made just for this sandbox, so they still need the chown. A
                // read-only volume mount is a link into the volume store and is
                // left alone, for the reason [`grant_to_jail`] spells out.
                let mut shared: std::collections::HashSet<String> =
                    [TEMPLATE_KERNEL.to_string(), TEMPLATE_ROOTFS.to_string()].into();
                // A fork links its source's memory chain rather than copying
                // it, and those inodes are the source's, already readable by
                // the jail's uid; a snapshot restore copies its chain and
                // the copies are this sandbox's to own.
                if matches!(source, RestoreSource::Sandbox(..)) {
                    shared.extend(chain.iter().cloned());
                }
                for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
                    if mount.is_read_only {
                        shared.insert(crate::sandbox::volume_image(index));
                    }
                }
                self.remember_volume_owners(&policy.volumes).await;
                grant_to_jail(&workdir, jail, &shared)
                    .await
                    .map_err(|err| Status::internal(format!("preparing the jail: {err}")))?;
            }
            Ok::<_, Status>((chain, arriving))
        };

        let (staged, tap) = tokio::join!(stage, tap::create(&lease));
        guard.tap = tap.as_ref().ok().cloned();
        let (chain, mut arriving) = match staged {
            Ok(staged) => staged,
            Err(err) => return Err(guard.fail(err).await),
        };
        // Without the page-fault handler the guest cannot take memory as it
        // faults, so a base still arriving is waited for in full.
        if !capabilities.is_lazy_memory_supported
            && let Some(hydrator) = arriving.take()
        {
            hydrator.wait().await;
        }
        let tap_name = match tap {
            Ok(name) => name,
            Err(err) => {
                return Err(guard
                    .fail(Status::internal(format!("tap setup: {err}")))
                    .await);
            }
        };

        // No volumes in the spec, exactly as a warm create's restore describes
        // none: firecracker takes a restored VM's drives from the snapshot, and
        // the snapshot this is restoring was taken without them. They are
        // hotplugged below instead, before the handshake that tells the guest
        // to rescan for them.
        let is_systemd = match &source {
            RestoreSource::Stored { manifest, .. } => manifest.is_systemd,
            _ => self.image_environment(&source.template()).await.systemd,
        };
        let mut spec = self.build_spec(
            &id,
            &workdir,
            hypervisor,
            guest_os,
            &resources,
            &lease,
            &tap_name,
            match is_attached {
                true => &policy.volumes,
                false => &[],
            },
            is_systemd,
            policy.is_console_verbose,
        );
        // The template's plan names the pages its agent touches on the way to
        // a usable handshake, which is the same code whether the guest was
        // just warmed or has been running for an hour, and the offsets hold
        // across a chain, since every layer is laid out as the base is. A
        // fork or a snapshot restore would otherwise take those pages one
        // stalled vCPU at a time.
        if capabilities.is_lazy_memory_supported {
            let linked = self
                .link_prefetch_plan(&source.template(), hypervisor, &resources, &workdir)
                .await;
            let merged = matches!(source, RestoreSource::Stored { .. })
                && crate::durable::merge_working_set(&workdir, crate::warm::PREFETCH_PLAN)
                    .await
                    .unwrap_or(false);
            if linked || merged {
                spec.prefetch = Some(crate::warm::PREFETCH_PLAN.to_string());
            }
        }
        let boot_spec = spec.clone();
        spec.memory_chain = chain.clone();
        spec.memory_source = arriving.clone().map(|h| burrow_vmm::MemorySource(h));
        record_working_set(&mut spec, self.config.object_store.is_some());

        let started = std::time::Instant::now();
        match Vm::restore(spec, true).await {
            Ok(vm) => guard.vm = Some(vm),
            Err(err) => {
                return Err(guard
                    .fail(Status::internal(format!("restore failed: {err}")))
                    .await);
            }
        }

        if !is_attached
            && let Err(err) = attach_volumes(guard.vm(), &policy.volumes, guest_os).await
        {
            return Err(guard.fail(err).await);
        }

        // The guest wakes holding the address baked into the snapshot, which
        // belongs to someone else; only the host knows this sandbox's own
        // lease. Told behind the response, as a warm create does: the caller
        // has its sandbox as soon as the VM is up, and the first call into
        // the guest waits for the handshake to settle.
        let request = guestconn::handshake_full(
            true,
            self.guest_network(&lease, &[], capabilities.is_tap_networked, true),
            self.inspection_ca_for(&policy),
            match &source {
                RestoreSource::Stored { manifest, .. } => {
                    self.trust_bundles_in(&manifest.image, &policy)
                }
                _ => self.trust_bundles_for(&source.template(), &policy).await,
            },
            match is_attached {
                true => Vec::new(),
                false => crate::volume::agent_mounts(&policy.volumes, guest_os),
            },
        );
        let inspection_root = self.inspection_root_of(&request);
        // Nothing below can fail, so the sandbox takes over here.
        let vm = guard.keep().expect("a restore that reaches here has a vm");

        let record = common::Sandbox {
            id: id.clone(),
            node_id,
            template: source.template(),
            state: common::SandboxState::Running as i32,
            policy: Some(policy),
            created_at_unix_ms: burrow_common::unix_now_ms(),
            tags,
            // A restore does not inherit a name: names are unique, so the new
            // sandbox is named by the caller or not at all.
            name,
            guest_ip: lease.guest_ip.to_string(),
            is_agent_unconfirmed: true,
            hypervisor: hypervisor.to_string(),
            guest_os: guest_os.as_str().to_string(),
            inspection_root_fingerprint: inspection_root,
            ..Default::default()
        };
        tracing::info!(
            sandbox = id,
            layers = chain.len(),
            restore_ms = vm.boot_latency().as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "restored sandbox running; handshake deferred"
        );

        let sandbox = Arc::new(RunningSandbox {
            id: record.id.clone(),
            template: record.template.clone(),
            hypervisor,
            base_record: std::sync::Mutex::new(record),
            state: std::sync::atomic::AtomicI32::new(common::SandboxState::Running as i32),
            vm: Mutex::new(Some(vm)),
            spec: std::sync::Mutex::new(boot_spec),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            suspended_at: std::sync::atomic::AtomicI64::new(0),
            agent_channel: Mutex::new(None),
            agent_features: Mutex::new(None),
            agent_timeout: self.config.agent_timeout,
            handshake: Arc::new(tokio::sync::watch::channel(Handshake::Pending).0),
            memory_chain: Mutex::new(chain),
            // A restore copies state, not the bill for producing it: the child
            // is a new sandbox and starts from nothing.
            usage: std::sync::Mutex::new(Usage::default()),
            session: std::sync::Mutex::new(None),
            durable: Default::default(),
            logs: Arc::new(crate::cmdlogs::CommandLogs::new(
                &self.config.command_logs_dir(&id),
                self.config.command_log_rotation,
            )),
            workdir,
            lease,
            tap: tap_name,
        });
        *sandbox.durable.hydration.lock().unwrap() = arriving;
        spawn_handshake(self, &sandbox, request, None, self.config.agent_timeout);
        Ok((sandbox, disk))
    }

    /// Restores a suspended sandbox from its snapshot.
    pub async fn resume(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        if sandbox.state.load(std::sync::atomic::Ordering::Relaxed)
            == common::SandboxState::Stopped as i32
        {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} is stopped, with no memory image to resume; boot it on its disk \
                 instead (`burrow boot {id}`, StartSandbox)"
            )));
        }
        self.require_vmm(&sandbox).await?;
        self.fence_if_lapsed().await;
        if sandbox.durable.is_fenced() {
            return Err(Status::unavailable(format!(
                "sandbox {id} is kept in the object store, and this node is waiting for the \
                 orchestrator to confirm it still holds it; try again shortly"
            )));
        }
        // Its disk is already counted; what is checked is that the node is not
        // already past its reserve, where a running guest's writes may fail.
        if !sandbox.is_running() {
            self.admit_disk(&sandbox.record().node_id, "resume a sandbox", 0)
                .await?;
        }
        let record = sandbox.record();
        let guest_os = burrow_vmm::GuestOs::from_record(&record.guest_os).unwrap_or_default();
        let _slot = self.reserve_mac_slot(id, guest_os).await?;
        // Sent again, so a guest given another root before this node's
        // changed has the one its leaves now chain to. A guest that already
        // holds it has nothing to do.
        let policy = record.policy.clone().unwrap_or_default();
        let mut request = guestconn::handshake_request(true);
        request.network = self.guest_network(
            &sandbox.lease,
            &record.public_ips,
            sandbox.hypervisor.capabilities().is_tap_networked,
            false,
        );
        request.inspection_ca_pem = self.inspection_ca_for(&policy);
        request.extra_trust_bundles =
            self.trust_bundles_in(&self.environment_of(&sandbox).await, &policy);
        let inspection_root = self.inspection_root_of(&request);
        // Suspending gave the volumes back, so another sandbox may hold them
        // now. Taken before the VM starts, so a sandbox that cannot have them
        // stays suspended rather than resuming without its data.
        let volumes = record.policy.unwrap_or_default().volumes;
        self.claim_volumes(id, &volumes, guest_os).await?;
        self.regrant_volumes(&sandbox, &volumes).await?;
        let uploading = sandbox.durable.stop_uploading().await;
        if let Err(err) = self.mark_running(&sandbox).await {
            self.volumes.release_all(id);
            return Err(err);
        }
        sandbox.durable.invalidate();
        let from = self.boundary(&sandbox).await;
        {
            let mut spec = sandbox.spec.lock().unwrap();
            if let Err(err) = self.usernets.attach(id, &sandbox.lease, &mut spec) {
                drop(spec);
                self.volumes.release_all(id);
                return Err(err);
            }
        }
        let resumed = sandbox
            .resume(
                request,
                self.config.agent_timeout,
                self.config.guest_upgrade.as_deref(),
                self.config.object_store.is_some(),
            )
            .await;
        drop(uploading);
        if let Err(err) = resumed {
            self.volumes.release_all(id);
            // Still suspended on files that did not change, so the stored
            // copy can be made current again.
            self.spawn_upload(&sandbox);
            sandbox.base_record.lock().unwrap().state_reason =
                format!("its last resume failed: {}", err.message());
            self.persist(&sandbox).await;
            return Err(err);
        }
        sandbox
            .base_record
            .lock()
            .unwrap()
            .inspection_root_fingerprint = inspection_root;
        // A fresh stack knows nothing of the sandbox's published ports until
        // a sync hands them over again.
        if !sandbox.hypervisor.capabilities().is_tap_networked
            && let Err(err) = self.sync_firewall().await
        {
            tracing::warn!(
                sandbox = id,
                err = err.message(),
                "republishing ports after resume"
            );
        }
        self.resync_public(&sandbox).await;
        self.open_session(&sandbox, STARTED_RESUME, Some(from))
            .await;
        self.persist(&sandbox).await;
        Ok(sandbox.record())
    }

    /// Shuts a sandbox down, keeping its disks. Unlike a pause, nothing of
    /// the guest's memory survives: a start boots the image's init again.
    ///
    /// A suspended sandbox is resumed first and shut down from there, since
    /// its snapshot can hold writes its guest had not yet put on the disk.
    /// One that cannot be resumed is stopped on what its disk holds, and the
    /// reason says its memory was discarded.
    pub async fn stop(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        let discarded = match sandbox.is_suspended() {
            true => self.resume(id).await.err(),
            false => None,
        };
        if let Some(err) = &discarded {
            tracing::warn!(
                sandbox = id,
                err = err.message(),
                "could not resume a suspended sandbox to stop it cleanly; discarding its memory"
            );
        }
        // The VMM is killed, not powered off, so the guest's page cache
        // would otherwise die with it and the disk a boot comes back to
        // would miss what was last written.
        flush_guest(&sandbox).await;
        sandbox.shutdown().await?;
        if let Some(err) = discarded {
            sandbox.base_record.lock().unwrap().state_reason =
                format!("{REASON_MEMORY_DISCARDED}: {}", err.message());
        }
        self.resync_public(&sandbox).await;
        // Its memory is gone, so what the store holds is a guest that no
        // longer exists.
        self.forget_stored(&sandbox).await;
        self.volumes.release_all(id);
        self.sample_last(&sandbox).await;
        self.persist(&sandbox).await;
        self.close_session(&sandbox, ENDED_STOPPED).await;
        tracing::info!(sandbox = id, "sandbox stopped");
        Ok(sandbox.record())
    }

    /// Shuts a macOS sandbox's guest down from inside, so its disk is as
    /// macOS left it, and returns the directory holding the stopped machine.
    #[cfg(target_os = "macos")]
    pub async fn shut_down_from_inside(
        &self,
        id: &str,
        timeout: std::time::Duration,
    ) -> Result<PathBuf, Status> {
        let sandbox = self.get(id).await?;
        let halt = burrow_proto::guest::v1::ExecStart {
            cmd: vec!["/sbin/shutdown".into(), "-h".into(), "now".into()],
            ..Default::default()
        };
        // The agent goes down with the guest, so the command may never report
        // back.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            guestconn::run_to_completion(&sandbox, halt),
        )
        .await;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let vm = sandbox.vm.lock().await;
                let Some(Vm::Vz(vz)) = vm.as_ref() else {
                    return Err(Status::failed_precondition(format!(
                        "sandbox {id} is not a running macOS guest"
                    )));
                };
                if vz.wait_stopped(std::time::Duration::ZERO).await.is_ok() {
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(Status::deadline_exceeded(format!(
                    "the guest did not shut down within {timeout:?}"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        Ok(sandbox.workdir.clone())
    }

    /// Hands the jail its writable volume images again after a suspend,
    /// which gave their ownership back with the claims. Only those: the rest
    /// of the directory is the jail's already, or links to a template's warm
    /// files that must stay the template's.
    async fn regrant_volumes(
        &self,
        sandbox: &RunningSandbox,
        volumes: &[common::VolumeMount],
    ) -> Result<(), Status> {
        let Some(jail) = self.config.jail_for(sandbox.hypervisor) else {
            return Ok(());
        };
        self.remember_volume_owners(volumes).await;
        for (index, mount) in crate::volume::block_mounts(volumes) {
            if mount.is_read_only {
                continue;
            }
            let image = sandbox.workdir.join(volume_image(index));
            if let Err(err) = std::os::unix::fs::chown(&image, Some(jail.uid), Some(jail.gid)) {
                self.volumes.release_all(sandbox.id());
                return Err(Status::internal(format!("preparing the jail: {err}")));
            }
        }
        Ok(())
    }

    /// Boots a stopped sandbox on its existing disks.
    pub async fn start(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        if sandbox.durable.is_fenced() {
            return Err(Status::unavailable(format!(
                "sandbox {id} has a checkpoint in the object store, and this node is waiting for \
                 the orchestrator to confirm it still holds it; try again shortly"
            )));
        }
        let record = sandbox.record();
        // Refused for the reason a resume is: a node past its reserve.
        if !sandbox.is_running() {
            self.admit_disk(&record.node_id, "start a sandbox", 0)
                .await?;
        }
        let guest_os = burrow_vmm::GuestOs::from_record(&record.guest_os).unwrap_or_default();
        let _slot = self.reserve_mac_slot(id, guest_os).await?;
        let policy = record.policy.unwrap_or_default();
        self.claim_volumes(id, &policy.volumes, guest_os).await?;
        // A stop handed the volume images' ownership back with the claims, so
        // the jail has to be given them again before the VMM opens them.
        if let Some(jail) = self.config.jail_for(sandbox.hypervisor) {
            let mut shared: std::collections::HashSet<String> =
                [TEMPLATE_KERNEL.to_string(), TEMPLATE_ROOTFS.to_string()].into();
            for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
                if mount.is_read_only {
                    shared.insert(volume_image(index));
                }
            }
            self.remember_volume_owners(&policy.volumes).await;
            if let Err(err) = grant_to_jail(&sandbox.workdir, jail, &shared).await {
                self.volumes.release_all(id);
                return Err(Status::internal(format!("preparing the jail: {err}")));
            }
        }
        let mut resources = policy.resources.clone().unwrap_or_default();
        if let Err(err) = pin_boot_memory(&mut resources, sandbox.hypervisor, guest_os) {
            self.volumes.release_all(id);
            return Err(err);
        }
        sandbox
            .base_record
            .lock()
            .unwrap()
            .policy
            .get_or_insert_with(Default::default)
            .resources = Some(resources.clone());
        let environment = self.environment_of(&sandbox).await;
        let is_systemd = environment.systemd;
        // Hotplugged once the agent is up, as a create does.
        let is_hotplugged = sandbox.hypervisor.capabilities().is_drive_hotplug_supported
            && !crate::macnode::is_macos(guest_os);
        let (boot_volumes, hotplugged): (&[common::VolumeMount], &[common::VolumeMount]) =
            match is_hotplugged {
                true => (&[], &policy.volumes),
                false => (&policy.volumes, &[]),
            };
        let mut spec = self.build_spec(
            id,
            &sandbox.workdir,
            sandbox.hypervisor,
            guest_os,
            &resources,
            &sandbox.lease,
            &sandbox.tap,
            boot_volumes,
            is_systemd,
            policy.is_console_verbose,
        );
        let from = self.boundary(&sandbox).await;
        if let Err(err) = self.usernets.attach(id, &sandbox.lease, &mut spec) {
            self.volumes.release_all(id);
            return Err(err);
        }
        let request = guestconn::handshake_full(
            false,
            self.guest_network(
                &sandbox.lease,
                &sandbox.record().public_ips,
                sandbox.hypervisor.capabilities().is_tap_networked,
                false,
            ),
            self.inspection_ca_for(&policy),
            self.trust_bundles_in(&environment, &policy),
            crate::volume::agent_mounts(&policy.volumes, guest_os),
        );
        if let Err(err) = sandbox
            .boot(
                spec,
                request,
                self.config.agent_timeout,
                self.config.guest_upgrade.as_deref(),
                hotplugged,
            )
            .await
        {
            self.volumes.release_all(id);
            sandbox.base_record.lock().unwrap().state_reason =
                format!("its last boot failed: {}", err.message());
            self.persist(&sandbox).await;
            return Err(err);
        }
        if !sandbox.hypervisor.capabilities().is_tap_networked
            && let Err(err) = self.sync_firewall().await
        {
            tracing::warn!(
                sandbox = id,
                err = err.message(),
                "republishing ports after boot"
            );
        }
        self.open_session(&sandbox, STARTED_BOOT, Some(from)).await;
        self.persist(&sandbox).await;
        Ok(sandbox.record())
    }

    /// The environment a template declared.
    pub async fn image_environment(&self, template: &str) -> crate::oci::ImageEnvironment {
        crate::oci::image_environment(&self.config.data_dir, template).await
    }

    /// Records what a Kit sandbox runs with, so execs and later boots see it.
    pub async fn set_kit(
        &self,
        id: &str,
        kit: common::KitSpec,
        env: HashMap<String, String>,
        credentials: HashMap<String, String>,
        selection: String,
    ) -> Result<(), Status> {
        let sandbox = self.get(id).await?;
        {
            let mut record = sandbox.base_record.lock().unwrap();
            record.kit = Some(kit);
            record.env = env;
            record.kit_credentials = credentials;
            record.kit_selection = selection;
        }
        self.persist(&sandbox).await;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<(), Status> {
        let held = self.held.lock().unwrap().remove(id);
        if let Some(held) = held {
            self.remove_held(held).await;
            return Ok(());
        }
        let sandbox = self
            .sandboxes
            .lock()
            .await
            .remove(id)
            .ok_or_else(|| Status::not_found(format!("no sandbox {id} on this node")))?;
        // A writable volume outlives the sandbox, and what the guest had not
        // written back would otherwise die with its page cache. Committed to
        // the journal, it is replayed for the next reader.
        let policy = sandbox.record().policy.unwrap_or_default();
        if sandbox.is_running()
            && crate::volume::block_mounts(&policy.volumes).any(|(_, mount)| !mount.is_read_only)
        {
            flush_guest(&sandbox).await;
        }
        self.forget_stored(&sandbox).await;
        for mount in policy.volumes.iter().filter(|mount| mount.generation != 0) {
            self.volumes.unpin(&mount.volume, id).await;
        }
        // Closed before the rows go, so the same one function ends every
        // session and the store is never left holding an open one.
        self.close_session(&sandbox, ENDED_DELETED).await;
        self.emit(&sandbox, EVENT_DESTROYED, "").await;
        let released = self.tear_down(sandbox).await;
        tracing::info!(sandbox = id, "sandbox deleted");
        released
    }

    /// Releases everything a sandbox held on this node once it is out of the
    /// map. What the object store holds is the caller's business.
    async fn tear_down(&self, sandbox: Arc<RunningSandbox>) -> Result<(), Status> {
        let id = &sandbox.id().to_string();
        self.usernets.detach(id, true);
        sandbox.logs.close();
        if let (Some(hydrator), Some(memory)) =
            (sandbox.durable.arriving(), sandbox.layout().memory)
        {
            hydrator.detach(&sandbox.workdir.join(memory));
        }
        let tap_name = sandbox.tap.clone();
        // Taken from the sandbox rather than derived from its id: a sandbox
        // handed out from the pool was provisioned under a different one.
        let workdir = sandbox.workdir.clone();

        // The VMM is taken out of the sandbox rather than out of an unwrapped
        // `Arc`: an in-flight request holding a clone is ordinary (a warm
        // create's handshake task is one), and leaving the stop to the drop of
        // the last handle kills the process but skips the cgroup removal that
        // `kill` does, so the sandbox's cgroup outlives it.
        //
        // A suspended sandbox has no VMM process left to stop.
        if let Some(vm) = sandbox.vm.lock().await.take()
            && let Err(err) = vm.kill().await
        {
            tracing::warn!(sandbox = id, %err, "kill failed");
        }
        drop(sandbox);

        // Order matters: the VM must be gone before its tap is removed, and
        // the lease must not be reissued while the old rules still reference
        // it, so the firewall is re-rendered before the address goes back to
        // the pool. Releasing first left a window in which a create could take
        // the recycled block and inherit this sandbox's rules.
        tap::delete(&tap_name).await;
        self.volumes.release_all(id);
        self.ports.lock().await.remove(id);
        self.shares.stop(id).await;
        if let Err(err) = self.store.delete_sandbox(id).await {
            tracing::error!(sandbox = id, %err, "failed to remove sandbox from store");
        }
        // A session list describes one sandbox's VMs and has no owner once the
        // sandbox is gone, so it goes with it rather than accumulating on the
        // node for every sandbox ever created here.
        if let Err(err) = self.store.delete_sessions(id).await {
            tracing::error!(sandbox = id, %err, "failed to remove sessions from store");
        }
        // Reported, but only after the directory is gone: a ruleset that would
        // not apply must not also leave a root disk behind.
        let rendered = self.sync_firewall().await;
        // Only now, once the render that stopped naming this address has been
        // applied. Held back rather than skipped when that render fails: the
        // lease has to come back either way, since a node that could not reach
        // nftables would otherwise leak a block per delete forever, and the
        // failure is already being returned to the caller and logged, which is
        // the part someone can act on.
        self.release_lease(id).await;

        if let Err(err) = self.config.remove_workdir(&workdir).await {
            tracing::warn!(sandbox = id, %err, "failed to remove sandbox directory");
        }
        let _ = tokio::fs::remove_dir_all(self.config.command_logs_dir(id)).await;
        rendered
    }
}

/// Keeping suspended sandboxes in the object store, and taking them over.
impl SandboxManager {
    /// Whether a sandbox can live in the object store at all: one mounting
    /// volumes only where they are kept there too.
    fn is_movable(&self, sandbox: &RunningSandbox) -> bool {
        self.volumes.is_durable()
            || crate::volume::block_mounts(&sandbox.record().policy.unwrap_or_default().volumes)
                .next()
                .is_none()
    }

    /// Brings every volume a suspended sandbox mounts up to date in the
    /// store, so the sandbox and its volumes move together.
    async fn sync_volumes(&self, sandbox: &RunningSandbox) -> Result<(), Status> {
        let policy = sandbox.record().policy.unwrap_or_default();
        for (_, mount) in crate::volume::block_mounts(&policy.volumes)
            .filter(|(_, mount)| self.volumes.is_local(&mount.volume))
        {
            self.volumes.sync(&mount.volume).await?;
        }
        Ok(())
    }

    /// Uploads the volumes running sandboxes write, every `every`, and keeps
    /// this node's copies in step with who the store says holds them.
    pub async fn upload_volumes(&self, every: std::time::Duration) {
        if !self.volumes.is_durable() {
            return;
        }
        let tick = match every.is_zero() {
            true => std::time::Duration::from_secs(60),
            false => every.min(std::time::Duration::from_secs(60)),
        };
        let mut last = std::time::Instant::now();
        loop {
            tokio::time::sleep(tick).await;
            self.volumes.reconcile_ownership().await;
            if every.is_zero() || last.elapsed() < every {
                continue;
            }
            last = std::time::Instant::now();
            let running: Vec<Arc<RunningSandbox>> = self
                .sandboxes
                .lock()
                .await
                .values()
                .filter(|sandbox| sandbox.is_running())
                .cloned()
                .collect();
            for sandbox in running {
                // Its checkpoints carry its volumes, at the instant they carry
                // its memory, and an upload between them would be newer.
                let lifetime = sandbox.lifetime();
                if lifetime.checkpoint_secs > 0 && lifetime.is_memory_checkpointed {
                    continue;
                }
                self.upload_live_volumes(&sandbox).await;
            }
        }
    }

    /// The writable volumes a running sandbox holds, with where its guest
    /// mounts each.
    fn written_volumes(&self, sandbox: &RunningSandbox) -> Vec<(String, String)> {
        let policy = sandbox.record().policy.unwrap_or_default();
        crate::volume::block_mounts(&policy.volumes)
            .filter(|(_, mount)| !mount.is_read_only)
            .filter(|(_, mount)| {
                self.volumes.writer(&mount.volume).as_deref() == Some(sandbox.id())
            })
            .map(|(_, mount)| (mount.volume.clone(), mount.path.clone()))
            .collect()
    }

    /// Captures the volumes a running sandbox writes, those that changed and
    /// are not already uploading, with its guest's filesystems frozen for
    /// the clones, and uploads them behind it.
    async fn upload_live_volumes(&self, sandbox: &Arc<RunningSandbox>) {
        let mut held = Vec::new();
        for (name, path) in self.written_volumes(sandbox) {
            if !self.volumes.is_changed(&name).await {
                continue;
            }
            if let Some(guard) = self.volumes.try_lock_upload(&name) {
                held.push((name, path, guard));
            }
        }
        if held.is_empty() {
            return;
        }
        let paths = held.iter().map(|(_, path, _)| path.clone()).collect();
        let (captures, frozen_for, is_frozen) = with_frozen(sandbox, paths, async {
            let mut captures = Vec::new();
            for (name, _, _) in &held {
                captures.push(self.volumes.capture(name).await);
            }
            captures
        })
        .await;
        tracing::info!(
            sandbox = sandbox.id(),
            volumes = held.len(),
            frozen_ms = frozen_for.as_millis() as u64,
            is_frozen,
            "captured the volumes a running sandbox writes"
        );
        for ((name, _, guard), captured) in held.into_iter().zip(captures) {
            let volumes = Arc::clone(&self.volumes);
            tokio::spawn(async move {
                let uploaded = match captured {
                    Ok((capture, stamp)) => volumes.upload_capture(&name, &capture, stamp).await,
                    Err(err) => Err(err),
                };
                drop(guard);
                if let Err(err) = uploaded {
                    tracing::warn!(
                        volume = name,
                        err = err.message(),
                        "could not upload the volume"
                    );
                }
            });
        }
    }

    /// Uploads a suspended sandbox's state behind whatever suspended it, and
    /// tries again with backoff until it is stored or the sandbox moves on: a
    /// resume, stop or delete cancels it.
    fn spawn_upload(&self, sandbox: &Arc<RunningSandbox>) {
        let Some(store) = self.config.object_store.clone() else {
            return;
        };
        if !self.is_movable(sandbox) {
            return;
        }
        let manager = self.clone();
        let sandbox = Arc::clone(sandbox);
        tokio::spawn(async move {
            for attempt in 1.. {
                let token = sandbox.durable.cancel.lock().unwrap().clone();
                let err = match manager.make_durable(&sandbox).await {
                    Ok(_) => return,
                    Err(err) => err,
                };
                // Refused for good: another node holds it, or it cannot be
                // stored at all.
                if matches!(
                    err.code(),
                    tonic::Code::Aborted | tonic::Code::FailedPrecondition
                ) || !sandbox.is_suspended()
                {
                    tracing::warn!(
                        sandbox = sandbox.id(),
                        %err,
                        "could not store the suspended sandbox; it stays on this node until its \
                         next suspend"
                    );
                    return;
                }
                let wait = store.requeue_delay(attempt);
                tracing::warn!(
                    sandbox = sandbox.id(),
                    %err,
                    attempt,
                    retry_in_secs = wait.as_secs(),
                    "could not store the suspended sandbox yet; it is on this node only until a \
                     retry lands"
                );
                tokio::select! {
                    () = token.cancelled() => return,
                    () = tokio::time::sleep(wait) => {}
                }
            }
        });
    }

    /// Brings the stored copy of a suspended sandbox up to date, returning
    /// whether it is. A resume cancels this, so it only ever reads a guest
    /// that is not running.
    async fn make_durable(&self, sandbox: &Arc<RunningSandbox>) -> Result<bool, Status> {
        let Some(store) = &self.config.object_store else {
            return Ok(false);
        };
        if !self.is_movable(sandbox) {
            return Ok(false);
        }
        let token = sandbox.durable.cancel.lock().unwrap().clone();
        let _uploading = sandbox.durable.upload.lock().await;
        if token.is_cancelled() || !sandbox.is_suspended() {
            return Ok(false);
        }
        let synced = tokio::select! {
            () = token.cancelled() => return Ok(false),
            synced = self.sync_volumes(sandbox) => synced,
        };
        if let Err(err) = synced {
            tracing::warn!(
                sandbox = sandbox.id(),
                err = err.message(),
                "a volume the sandbox mounts could not be uploaded; it stays on this node"
            );
            return Ok(false);
        }
        let chain = sandbox.memory_chain.lock().await.clone();
        let previous = sandbox.durable.stored.lock().unwrap().clone();
        if previous
            .as_ref()
            .is_some_and(|stored| stored.is_current(&sandbox.workdir, &chain))
        {
            sandbox
                .durable
                .is_current
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Ok(true);
        }
        let Some(draft) = self.draft_manifest(sandbox, previous.as_ref()).await? else {
            return Ok(false);
        };
        let uploaded = tokio::select! {
            () = token.cancelled() => return Ok(false),
            uploaded = async {
                // The base of a chain that arrived from the store is read
                // directly here, so it has to have arrived.
                sandbox.durable.settle_memory().await;
                crate::durable::upload(
                    store,
                    &crate::blobs::BlobStore::new(&self.config.data_dir),
                    &sandbox.workdir,
                    sandbox.logs.dir(),
                    &chain,
                    draft,
                    previous.as_ref(),
                )
                    .await
            } => uploaded?,
        };
        *sandbox.durable.stored.lock().unwrap() = Some(uploaded);
        sandbox
            .durable
            .is_current
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.announce_now();
        Ok(true)
    }

    /// What a manifest says about a sandbox, before an upload fills in its
    /// generation and digests. `None` when its brokered credentials cannot be
    /// sealed for the store.
    async fn draft_manifest(
        &self,
        sandbox: &RunningSandbox,
        previous: Option<&crate::durable::LocalState>,
    ) -> Result<Option<crate::durable::Manifest>, Status> {
        let record = sandbox.record();
        let Some(secrets) = self.seal_for_store(&record)? else {
            tracing::warn!(
                sandbox = sandbox.id(),
                "sandbox holds brokered credentials and this node has no \
                 --object-store-key-file; it stays on this node"
            );
            return Ok(None);
        };
        let image = self.environment_of(sandbox).await;
        let is_systemd = match previous {
            Some(previous) => previous.manifest.is_systemd,
            None => image.systemd,
        };
        Ok(Some(crate::durable::Manifest {
            format: 0,
            id: sandbox.id().to_string(),
            generation: 0,
            node_id: record.node_id.clone(),
            state: String::new(),
            template: sandbox.template().to_string(),
            vcpus: sandbox.vcpus(),
            mem_mib: sandbox.mem_mib(),
            boot_mem_mib: sandbox.boot_mem_mib(),
            max_mem_mib: sandbox.max_mem_mib(),
            is_nested_virt_enabled: sandbox.is_nested_virt_enabled(),
            disk_mib: size_mib(&sandbox.disk_path()),
            is_systemd,
            arch: std::env::consts::ARCH.to_string(),
            hypervisor_version: self.config.version(sandbox.hypervisor).to_string(),
            hypervisor: sandbox.hypervisor.to_string(),
            cpu: crate::cpuid::host().clone(),
            kernel_digest: String::new(),
            rootfs_digest: String::new(),
            cpu_usage_usec: record.cpu_usage_usec,
            rx_bytes: record.rx_bytes,
            tx_bytes: record.tx_bytes,
            secrets,
            inspection_root: record.inspection_root_fingerprint.clone(),
            checkpoint: String::new(),
            checkpoint_at_ms: 0,
            volumes: Default::default(),
            image,
        }))
    }

    /// The record's brokered credentials sealed for the store, or `None` when
    /// it has some and there is no key to seal them with.
    #[allow(clippy::result_large_err)]
    fn seal_for_store(
        &self,
        record: &common::Sandbox,
    ) -> Result<Option<std::collections::BTreeMap<String, String>>, Status> {
        let found = std::cell::RefCell::new(Vec::new());
        let mut copy = record.clone();
        map_secrets(&mut copy, |context, value| {
            found
                .borrow_mut()
                .push((context.to_string(), value.to_string()));
            Ok(value.to_string())
        })
        .map_err(|err| Status::internal(format!("reading the record's secrets: {err}")))?;
        let found = found.into_inner();
        if found.is_empty() {
            return Ok(Some(Default::default()));
        }
        let Some(vault) = &self.config.store_vault else {
            return Ok(None);
        };
        found
            .into_iter()
            .map(|(context, value)| {
                vault
                    .seal(&context, &value)
                    .map(|sealed| (context, sealed))
                    .map_err(|err| Status::internal(format!("sealing a secret: {err}")))
            })
            .collect::<Result<_, _>>()
            .map(Some)
    }

    /// Puts the brokered credentials stored with a sandbox back into the
    /// redacted record the orchestrator holds.
    #[allow(clippy::result_large_err)]
    fn unseal_from_store(
        &self,
        record: &mut common::Sandbox,
        sealed: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), Status> {
        map_secrets(record, |context, _| {
            let value = sealed.get(context).ok_or_else(|| {
                burrow_common::vault::Error::Open(format!(
                    "{context}, which the stored state does not carry"
                ))
            })?;
            match &self.config.store_vault {
                Some(vault) => vault.unseal(context, value),
                None => Err(burrow_common::vault::Error::Key(
                    "this node has no --object-store-key-file".into(),
                )),
            }
        })
        .map_err(|err| {
            Status::failed_precondition(format!(
                "sandbox {}'s brokered credentials cannot be restored here: {err}",
                record.id
            ))
        })
    }

    /// Records in the store that a sandbox with stored state is about to run
    /// here. Refused rather than skipped when the store cannot be reached: a
    /// node that adopted the sandbox after this one was written off would
    /// otherwise resume the same stored state alongside it. Refused for good,
    /// as `Aborted`, when the store names another node: that node took the
    /// sandbox while this one was not looking.
    async fn mark_running(&self, sandbox: &Arc<RunningSandbox>) -> Result<(), Status> {
        let Some(store) = &self.config.object_store else {
            return Ok(());
        };
        let stored = sandbox.durable.stored.lock().unwrap().clone();
        let Some(mut stored) = stored else {
            return Ok(());
        };
        if stored.manifest.state == crate::durable::STATE_RUNNING {
            return Ok(());
        }
        let node_id = sandbox.record().node_id;
        crate::durable::mark_running(store, &sandbox.workdir, &mut stored, &node_id)
            .await
            .map_err(|err| {
                if err.code() == tonic::Code::Aborted {
                    return err;
                }
                Status::unavailable(format!(
                    "sandbox {} is kept in the object store and cannot resume until the store \
                     records it as running here: {}",
                    sandbox.id(),
                    err.message()
                ))
            })?;
        *sandbox.durable.stored.lock().unwrap() = Some(stored);
        Ok(())
    }

    /// Removes a sandbox's stored state, for a sandbox whose guest is gone.
    async fn forget_stored(&self, sandbox: &RunningSandbox) {
        let _uploading = sandbox.durable.stop_uploading().await;
        sandbox.durable.invalidate();
        let Some(store) = &self.config.object_store else {
            return;
        };
        if sandbox.durable.stored.lock().unwrap().take().is_none() {
            return;
        }
        crate::durable::remove_local(&sandbox.workdir).await;
        let holder = sandbox.record().node_id;
        if let Err(err) = crate::durable::purge(store, sandbox.id(), Some(&holder)).await {
            tracing::warn!(sandbox = sandbox.id(), %err, "could not remove the sandbox's stored state");
        }
    }

    /// Reads back what a recovered sandbox has in the store. Every sandbox
    /// with stored state comes back fenced: while this node was down another
    /// may have adopted it, and only the orchestrator can say.
    async fn recover_durability(&self, sandbox: &Arc<RunningSandbox>) {
        let Some(store) = &self.config.object_store else {
            return;
        };
        let workdir = &sandbox.workdir;
        let Some(memory) = sandbox.layout().memory else {
            return;
        };
        match crate::chunks::Hydrator::resume(store.clone(), &workdir.join(memory)) {
            Some(Ok(hydrator)) => {
                hydrator.start();
                *sandbox.durable.hydration.lock().unwrap() = Some(hydrator);
            }
            Some(Err(err)) => {
                tracing::error!(sandbox = sandbox.id(), %err, "cannot resume filling guest memory")
            }
            None => {}
        }
        let Some(stored) = crate::durable::load_local(workdir).await else {
            if sandbox.is_suspended() {
                self.spawn_upload(sandbox);
            }
            return;
        };
        let chain = sandbox.memory_chain.lock().await.clone();
        let is_current = sandbox.is_suspended() && stored.is_current(workdir, &chain);
        sandbox
            .durable
            .is_current
            .store(is_current, std::sync::atomic::Ordering::Relaxed);
        sandbox.durable.set_fenced(true);
        *sandbox.durable.stored.lock().unwrap() = Some(stored);
        if sandbox.is_suspended() && !is_current {
            self.spawn_upload(sandbox);
        }
    }

    pub fn renew_lease(&self, secs: u32) {
        let mut lease = self.lease.lock().unwrap();
        lease.renewed = Some(std::time::Instant::now());
        lease.length = std::time::Duration::from_secs(secs.into());
    }

    /// Fences every sandbox with stored state once the lease has run out.
    async fn fence_if_lapsed(&self) {
        let lapsed = {
            let lease = self.lease.lock().unwrap();
            !lease.length.is_zero() && lease.renewed.is_none_or(|at| at.elapsed() >= lease.length)
        };
        if !lapsed {
            return;
        }
        let mut checkpointed = Vec::new();
        for sandbox in self.sandboxes.lock().await.values() {
            if sandbox.is_running() && sandbox.record().checkpoint_at_unix_ms > 0 {
                checkpointed.push(sandbox.id().to_string());
                continue;
            }
            if sandbox.durable.has_stored() && !sandbox.is_running() && !sandbox.durable.is_fenced()
            {
                tracing::warn!(
                    sandbox = sandbox.id(),
                    "lost the orchestrator's lease; not resuming this sandbox until it confirms \
                     this node still holds it"
                );
                sandbox.durable.set_fenced(true);
            }
        }
        // Another node may be handed its checkpoint once this one is written
        // off, so it stops here first, suspending into the store if it can.
        for id in checkpointed {
            tracing::warn!(
                sandbox = id,
                "lost the orchestrator's lease; suspending this checkpointed sandbox so it does \
                 not run here while another node recovers it"
            );
            let manager = self.clone();
            tokio::spawn(async move {
                let Ok(sandbox) = manager.get(&id).await else {
                    return;
                };
                match manager.pause(&id).await {
                    Ok(_) => sandbox.durable.set_fenced(true),
                    Err(err) if sandbox.is_running() => {
                        tracing::error!(sandbox = id, %err, "could not suspend")
                    }
                    Err(_) => {}
                }
            });
        }
    }

    /// Unfences sandboxes the orchestrator still places here.
    pub fn confirm(&self, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let sandboxes = self.sandboxes.clone();
        let ids = ids.to_vec();
        tokio::spawn(async move {
            let sandboxes = sandboxes.lock().await;
            for id in ids {
                if let Some(sandbox) = sandboxes.get(&id) {
                    sandbox.durable.set_fenced(false);
                }
            }
        });
    }

    /// Drops this node's copy of sandboxes another node has adopted. Only a
    /// fenced one, which this node has not resumed since it could have lost
    /// it, is dropped: anything else would be a guest someone is using.
    pub async fn relinquish(&self, ids: &[String]) {
        for id in ids {
            let sandbox = {
                let mut sandboxes = self.sandboxes.lock().await;
                match sandboxes.get(id) {
                    Some(sandbox) if sandbox.durable.is_fenced() && !sandbox.is_running() => {
                        sandboxes.remove(id)
                    }
                    Some(_) => {
                        tracing::error!(
                            sandbox = id,
                            "orchestrator says another node holds this sandbox, but it is not \
                             fenced here; keeping it"
                        );
                        None
                    }
                    None => None,
                }
            };
            let Some(sandbox) = sandbox else { continue };
            self.emit(&sandbox, EVENT_STOPPED, "relinquished").await;
            if let Err(err) = self.tear_down(sandbox).await {
                tracing::warn!(sandbox = id, %err, "could not fully release a relinquished sandbox");
            }
            tracing::info!(
                sandbox = id,
                "another node adopted this sandbox; dropped the copy here"
            );
        }
    }

    /// Suspends a sandbox, makes sure its state is in the store, and lets go
    /// of it here.
    pub async fn release(&self, id: &str) -> Result<common::Sandbox, Status> {
        if self.config.object_store.is_none() {
            return Err(Status::failed_precondition(
                "this node has no object store to move sandboxes through",
            ));
        }
        let sandbox = self.get(id).await?;
        if !self.is_movable(&sandbox) {
            return Err(Status::failed_precondition(
                "a sandbox with volumes moves only with an object store to carry them",
            ));
        }
        // The volumes it writes move with it. One it only reads stays where it
        // is, and the new node reads a copy of it.
        let mounted: Vec<String> =
            crate::volume::block_mounts(&sandbox.record().policy.unwrap_or_default().volumes)
                .filter(|(_, mount)| !mount.is_read_only && self.volumes.is_local(&mount.volume))
                .map(|(_, mount)| mount.volume.clone())
                .collect();
        for other in self.sandboxes.lock().await.values() {
            if other.id() == id {
                continue;
            }
            let policy = other.record().policy.unwrap_or_default();
            if let Some((_, shared)) = crate::volume::block_mounts(&policy.volumes)
                .find(|(_, mount)| mounted.contains(&mount.volume))
            {
                return Err(Status::failed_precondition(format!(
                    "volume {} is also mounted by sandbox {}, which stays on this node",
                    shared.volume,
                    other.id()
                )));
            }
        }
        if sandbox.is_running() {
            self.pause(id).await?;
        }
        if !self.make_durable(&sandbox).await? {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} could not be stored: it must be suspended, and one holding \
                 brokered credentials needs --object-store-key-file on every node"
            )));
        }
        // Out of the map before anything else, so nothing can resume it here
        // while it is let go.
        let sandbox = {
            let mut sandboxes = self.sandboxes.lock().await;
            if !sandbox.durable.is_current() {
                return Err(Status::aborted(format!(
                    "sandbox {id} was resumed while moving"
                )));
            }
            sandboxes
                .remove(id)
                .ok_or_else(|| Status::not_found(format!("no sandbox {id} on this node")))?
        };
        let record = sandbox.record();
        self.volumes.release_all(id);
        for name in &mounted {
            if let Err(err) = self.volumes.release(name).await {
                tracing::warn!(
                    sandbox = id,
                    volume = name,
                    err = err.message(),
                    "could not release a volume the moving sandbox mounts; it stays here"
                );
            }
        }
        self.emit(&sandbox, EVENT_STOPPED, "released").await;
        // Behind the response: the sandbox is out of the map and its state is
        // in the store, so the node adopting it has nothing to wait for here.
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let held = Arc::clone(&gate)
            .try_lock_owned()
            .expect("a new gate is free");
        self.releasing
            .lock()
            .unwrap()
            .insert(id.to_string(), Arc::clone(&gate));
        let manager = self.clone();
        let released = id.to_string();
        tokio::spawn(async move {
            if let Err(err) = manager.tear_down(sandbox).await {
                tracing::warn!(sandbox = released, %err, "could not fully release a moved sandbox");
            }
            drop(held);
            let mut releasing = manager.releasing.lock().unwrap();
            if releasing
                .get(&released)
                .is_some_and(|held| Arc::ptr_eq(held, &gate))
            {
                releasing.remove(&released);
            }
        });
        tracing::info!(sandbox = id, "sandbox released to the object store");
        Ok(record)
    }

    /// Deletes a stored sandbox no node holds.
    pub async fn purge(&self, id: &str) -> Result<(), Status> {
        let store = self
            .config
            .object_store
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("this node has no object store"))?;
        crate::durable::purge(store, id, None).await?;
        crate::volstore::unpin_all(store, id).await
    }

    /// Takes over a sandbox from the object store and resumes it here.
    ///
    /// `record` is the orchestrator's: its id, name, policy, tags and
    /// tags are the sandbox's, and only its secrets come from the store.
    #[tracing::instrument(skip_all, fields(sandbox = %record.id))]
    pub async fn adopt(
        &self,
        record: common::Sandbox,
        node_id: String,
    ) -> Result<common::Sandbox, Status> {
        let store = self.config.object_store.as_ref().ok_or_else(|| {
            Status::failed_precondition("this node has no object store to adopt sandboxes from")
        })?;
        let id = record.id.clone();
        let releasing = self.releasing.lock().unwrap().get(&id).cloned();
        if let Some(gate) = releasing {
            drop(gate.lock().await);
        }
        let started = std::time::Instant::now();
        let held = crate::durable::read_manifest(store, &id)
            .await?
            .ok_or_else(|| {
                Status::not_found(format!("sandbox {id} has no state in the object store"))
            })?;
        let manifest = &held.manifest;
        if !manifest.is_adoptable() {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} was running on {} when it was last heard of, with no checkpoint; \
                 what the object store holds is from before that, and is not resumed in its place",
                manifest.node_id
            )));
        }
        let hypervisor = manifest.hypervisor()?;
        self.require_hypervisor(hypervisor)?;
        let mut boots = manifest.checkpoint == crate::durable::CHECKPOINT_DISK;
        if manifest.checkpoint == crate::durable::CHECKPOINT_MEMORY {
            for (name, generation) in &manifest.volumes {
                if self.volumes.generation(name).await != Some(*generation) {
                    tracing::warn!(
                        sandbox = id,
                        volume = name,
                        "volume moved on since the memory checkpoint; booting on its disk instead"
                    );
                    boots = true;
                }
            }
        }
        if manifest.arch != std::env::consts::ARCH
            || (!boots && manifest.hypervisor_version != self.config.version(hypervisor))
        {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} was stored on {} under {hypervisor} {} and cannot restore on this \
                 node ({} under {hypervisor} {})",
                manifest.arch,
                manifest.hypervisor_version,
                std::env::consts::ARCH,
                self.config.version(hypervisor)
            )));
        }
        if !self
            .inspection_ca_for(&record.policy.clone().unwrap_or_default())
            .is_empty()
        {
            self.require_inspection_root(&id, &manifest.inspection_root)?;
        }
        let mut record = record;
        self.unseal_from_store(&mut record, &manifest.secrets)?;
        {
            let sandboxes = self.sandboxes.lock().await;
            let mut creating = self.creating.lock().await;
            if sandboxes.contains_key(&id) || !creating.insert(id.clone()) {
                return Err(Status::already_exists(format!("sandbox {id} exists")));
            }
        }
        let read = started.elapsed();
        if boots {
            let booted = self.adopt_booting(store, &held, record, node_id).await;
            self.creating.lock().await.remove(&id);
            return booted;
        }
        let adopted = self
            .adopt_inner(store, &held, record, node_id.clone())
            .await;
        let (sandbox, from, _disk) = match adopted {
            Ok(adopted) => adopted,
            Err(err) => {
                self.creating.lock().await.remove(&id);
                return Err(err);
            }
        };
        // Read before the sandbox is in the map, so no sample can have
        // counted the restore yet.
        let totals = Some(sandbox.totals());
        let restored = started.elapsed();
        // Waited for here, unlike a create: a sandbox whose guest never
        // answers would otherwise be reclaimed as a failed create, and its
        // stored state is the only copy there is. Its rules are applied
        // before it is registered, so a node that cannot apply them has not
        // let the sandbox run either. Either failure stops the guest and
        // hands the state back untouched for another attempt.
        let registered = match sandbox.await_handshake().await {
            Ok(()) => self.register(&sandbox).await,
            Err(err) => Err(err),
        };
        self.creating.lock().await.remove(&id);
        if let Err(err) = registered {
            if let Err(err) = self.tear_down(Arc::clone(&sandbox)).await {
                tracing::warn!(sandbox = id, %err, "could not release a failed adopt");
            }
            self.hand_back(store, &node_id, manifest).await;
            return Err(err);
        }
        let handshaken = started.elapsed();

        let shape = (sandbox.vcpus(), sandbox.mem_mib());
        self.log_event(
            &with_totals(sandbox.record(), totals),
            shape,
            EVENT_STARTED,
            &format!("adopted:{from}"),
        )
        .await;
        self.open_session(&sandbox, STARTED_RESUME, totals).await;
        let record = sandbox.record();
        self.persist(&sandbox).await;
        tracing::info!(
            from,
            manifest_ms = read.as_millis() as u64,
            restore_ms = (restored - read).as_millis() as u64,
            handshake_ms = (handshaken - restored).as_millis() as u64,
            total_ms = started.elapsed().as_millis() as u64,
            "sandbox adopted from the object store"
        );
        Ok(record)
    }

    async fn adopt_inner(
        &self,
        store: &crate::objstore::ObjectStore,
        held: &crate::durable::Held,
        record: common::Sandbox,
        node_id: String,
    ) -> Result<(Arc<RunningSandbox>, String, crate::diskcap::Admitted), Status> {
        let manifest = &held.manifest;
        let from = manifest.node_id.clone();
        let mut claimed = manifest.clone();
        claimed.state = crate::durable::STATE_RUNNING.to_string();
        claimed.node_id = node_id.clone();
        let mut policy = record.policy.clone().unwrap_or_default();
        policy.resources = Some(manifest.resources(policy.resources.take().unwrap_or_default()));
        // Claimed in the store before the guest starts, the rule a resume
        // follows too, and handed back if it never does. Conditional on the
        // manifest read above, so a node that lost the race to another stops
        // here.
        crate::durable::replace_manifest(store, Some(held), &claimed).await?;
        let provisioned = self
            .provision_restored(
                RestoreSource::Stored {
                    store,
                    manifest: &claimed,
                },
                record.id.clone(),
                policy,
                record.tags.clone(),
                node_id.clone(),
                record.name.clone(),
            )
            .await;
        let (sandbox, disk) = match provisioned {
            Ok(provisioned) => provisioned,
            Err(err) => {
                self.hand_back(store, &node_id, manifest).await;
                return Err(err);
            }
        };
        *sandbox.durable.stored.lock().unwrap() =
            crate::durable::load_local(&sandbox.workdir).await;
        {
            let mut base = sandbox.base_record.lock().unwrap();
            base.created_at_unix_ms = record.created_at_unix_ms;
            base.env = record.env.clone();
            base.kit = record.kit.clone();
            base.kit_credentials = record.kit_credentials.clone();
            base.kit_selection = record.kit_selection.clone();
            base.access_revoked_at_ms = record.access_revoked_at_ms;
            base.public_ips = record.public_ips.clone();
        }
        *sandbox.usage.lock().unwrap() = Usage {
            cpu_usec: record.cpu_usage_usec.max(manifest.cpu_usage_usec),
            rx_bytes: record.rx_bytes.max(manifest.rx_bytes),
            tx_bytes: record.tx_bytes.max(manifest.tx_bytes),
            ..Default::default()
        };
        Ok((sandbox, from, disk))
    }

    /// Takes over a sandbox from a disk checkpoint by booting on it: what
    /// its guest had in memory is gone, and its disk is as the checkpoint
    /// left it.
    async fn adopt_booting(
        &self,
        store: &crate::objstore::ObjectStore,
        held: &crate::durable::Held,
        record: common::Sandbox,
        node_id: String,
    ) -> Result<common::Sandbox, Status> {
        let manifest = &held.manifest;
        let id = record.id.clone();
        let from = manifest.node_id.clone();
        let mut claimed = manifest.clone();
        claimed.state = crate::durable::STATE_RUNNING.to_string();
        claimed.node_id = node_id.clone();
        crate::durable::replace_manifest(store, Some(held), &claimed).await?;
        let sandbox = match self
            .provision_from_checkpoint(store, &claimed, record, node_id.clone())
            .await
        {
            Ok(sandbox) => sandbox,
            Err(err) => {
                self.hand_back(store, &node_id, manifest).await;
                return Err(err);
            }
        };
        if let Err(err) = self.start(&id).await {
            self.sandboxes.lock().await.remove(&id);
            if let Err(err) = self.tear_down(sandbox).await {
                tracing::warn!(sandbox = id, %err, "could not release a failed adopt");
            }
            self.hand_back(store, &node_id, manifest).await;
            return Err(err);
        }
        tracing::info!(
            sandbox = id,
            from,
            checkpoint_at_ms = manifest.checkpoint_at_ms,
            "sandbox booted on its checkpointed disk"
        );
        Ok(sandbox.record())
    }

    /// Builds a stopped sandbox on a checkpoint's disk, in the map and ready
    /// for [`Self::start`].
    async fn provision_from_checkpoint(
        &self,
        store: &crate::objstore::ObjectStore,
        manifest: &crate::durable::Manifest,
        record: common::Sandbox,
        node_id: String,
    ) -> Result<Arc<RunningSandbox>, Status> {
        let id = record.id.clone();
        let hypervisor = manifest.hypervisor()?;
        let workdir = self.config.sandbox_dir(&id, hypervisor);
        let mut policy = record.policy.clone().unwrap_or_default();
        let resources = manifest.resources(policy.resources.take().unwrap_or_default());
        policy.resources = Some(resources.clone());
        let _disk = self
            .admit_disk(
                &node_id,
                "recover a sandbox",
                u64::from(resources.disk_mib) * burrow_common::disk::MIB,
            )
            .await?;
        crate::volume::validate_mounts(&policy.volumes)?;
        self.require_volumes(&policy.volumes)?;
        let guest_os = burrow_vmm::GuestOs::from_record(&record.guest_os).unwrap_or_default();
        let mut guard = Provisioning::new(self, &id, &workdir);
        let sources = match self.volume_sources(&id, &mut policy.volumes, true).await {
            Ok(sources) => sources,
            Err(err) => return Err(guard.fail(err).await),
        };
        let lease = match self.ipam.lock().await.allocate(&id) {
            Ok(lease) => lease,
            Err(err) => {
                return Err(guard
                    .fail(Status::resource_exhausted(format!(
                        "address allocation: {err}"
                    )))
                    .await);
            }
        };
        let stage = async {
            let _ = tokio::fs::remove_dir_all(&workdir).await;
            tokio::fs::create_dir_all(&workdir)
                .await
                .map_err(|err| Status::internal(format!("creating the workdir: {err}")))?;
            let local =
                crate::durable::stage_disk(store, &self.snapshots, manifest, &workdir).await?;
            for ((index, mount), source) in
                crate::volume::block_mounts(&policy.volumes).zip(&sources)
            {
                tokio::fs::hard_link(source, workdir.join(volume_image(index)))
                    .await
                    .map_err(|err| {
                        Status::internal(format!("attaching volume {}: {err}", mount.volume))
                    })?;
            }
            Ok::<_, Status>(local)
        };
        let (staged, tap) = tokio::join!(stage, tap::create(&lease));
        guard.tap = tap.as_ref().ok().cloned();
        let local = match staged {
            Ok(local) => local,
            Err(err) => return Err(guard.fail(err).await),
        };
        let tap_name = match tap {
            Ok(name) => name,
            Err(err) => {
                return Err(guard
                    .fail(Status::internal(format!("tap setup: {err}")))
                    .await);
            }
        };
        let spec = self.build_spec(
            &id,
            &workdir,
            hypervisor,
            guest_os,
            &resources,
            &lease,
            &tap_name,
            &policy.volumes,
            manifest.is_systemd,
            policy.is_console_verbose,
        );
        let record = common::Sandbox {
            id: id.clone(),
            node_id,
            template: manifest.template.clone(),
            state: common::SandboxState::Stopped as i32,
            policy: Some(policy),
            guest_ip: lease.guest_ip.to_string(),
            hypervisor: hypervisor.to_string(),
            guest_os: guest_os.as_str().to_string(),
            state_reason: String::new(),
            ..record
        };
        guard.keep();
        let sandbox = Arc::new(RunningSandbox {
            id: id.clone(),
            template: record.template.clone(),
            hypervisor,
            base_record: std::sync::Mutex::new(record.clone()),
            state: std::sync::atomic::AtomicI32::new(common::SandboxState::Stopped as i32),
            vm: Mutex::new(None),
            spec: std::sync::Mutex::new(spec),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            suspended_at: std::sync::atomic::AtomicI64::new(0),
            agent_channel: Mutex::new(None),
            agent_features: Mutex::new(None),
            agent_timeout: self.config.agent_timeout,
            handshake: settled(),
            memory_chain: Mutex::new(Vec::new()),
            usage: std::sync::Mutex::new(Usage {
                cpu_usec: record.cpu_usage_usec.max(manifest.cpu_usage_usec),
                rx_bytes: record.rx_bytes.max(manifest.rx_bytes),
                tx_bytes: record.tx_bytes.max(manifest.tx_bytes),
                ..Default::default()
            }),
            session: std::sync::Mutex::new(None),
            durable: Default::default(),
            logs: Arc::new(crate::cmdlogs::CommandLogs::new(
                &self.config.command_logs_dir(&id),
                self.config.command_log_rotation,
            )),
            workdir,
            lease,
            tap: tap_name,
        });
        *sandbox.durable.stored.lock().unwrap() = Some(local);
        if let Err(err) = self.register(&sandbox).await {
            let _ = self.tear_down(Arc::clone(&sandbox)).await;
            return Err(err);
        }
        self.persist(&sandbox).await;
        Ok(sandbox)
    }

    /// Puts back the manifest a failed adopt claimed over, provided the store
    /// still names this node: the guest never ran, or was stopped, so the
    /// state is exactly as it was read.
    async fn hand_back(
        &self,
        store: &crate::objstore::ObjectStore,
        node_id: &str,
        manifest: &crate::durable::Manifest,
    ) {
        if let Err(err) = crate::durable::write_held(store, node_id, manifest, false).await {
            tracing::error!(
                sandbox = manifest.id,
                %err,
                "adopt failed and the store still says the sandbox runs here; it cannot be \
                 adopted again until that is corrected"
            );
        }
    }

    /// Collects stored state nothing references, every few hours, with
    /// jitter so a fleet started together does not list the bucket together.
    pub async fn collect_stored_garbage(&self) {
        let Some(store) = self.config.object_store.clone() else {
            return;
        };
        loop {
            let jitter = std::time::Duration::from_secs(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::from(d.subsec_nanos()) % 3600),
            );
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600) + jitter).await;
            if let Err(err) = crate::durable::collect_garbage(&store, &self.snapshots).await {
                tracing::warn!(%err, "could not collect unreferenced stored state");
            }
        }
    }
}

/// When a sandbox was last checkpointed, and what it had done by then.
struct CheckpointClock {
    at: std::time::Instant,
    cpu_usec: u64,
    activity: i64,
}

/// How many sandboxes a node checkpoints at once.
const CHECKPOINTS_AT_ONCE: usize = 2;

/// Checkpointing running sandboxes into the object store.
impl SandboxManager {
    /// Refuses checkpoints on a node with nowhere to keep them.
    #[allow(clippy::result_large_err)]
    pub fn require_checkpoint_store(&self) -> Result<(), Status> {
        match self.config.object_store {
            Some(_) => Ok(()),
            None => Err(Status::failed_precondition(
                "checkpoints need an object store; this node has no --object-store",
            )),
        }
    }

    /// Refuses a policy asking for checkpoints on a node that cannot keep them.
    #[allow(clippy::result_large_err)]
    pub fn require_checkpointable(&self, policy: &common::Policy) -> Result<(), Status> {
        match policy.lifetime.is_some_and(|l| l.checkpoint_secs > 0) {
            true => self.require_checkpoint_store(),
            false => Ok(()),
        }
    }

    /// Checkpoints every running sandbox whose policy asks for it, once its
    /// interval, raised to the node's floor, has passed since the last.
    pub async fn checkpoint_running(&self) {
        if self.config.object_store.is_none() {
            return;
        }
        let floor = self.config.checkpoint_min_secs.max(1);
        let limit = Arc::new(tokio::sync::Semaphore::new(CHECKPOINTS_AT_ONCE));
        let clocks: Arc<std::sync::Mutex<HashMap<String, CheckpointClock>>> = Arc::default();
        let busy: Arc<std::sync::Mutex<std::collections::HashSet<String>>> = Arc::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let running: Vec<Arc<RunningSandbox>> = self
                .sandboxes
                .lock()
                .await
                .values()
                .filter(|sandbox| sandbox.is_running() && sandbox.lifetime().checkpoint_secs > 0)
                .cloned()
                .collect();
            {
                let ids: std::collections::HashSet<&str> =
                    running.iter().map(|sandbox| sandbox.id()).collect();
                clocks
                    .lock()
                    .unwrap()
                    .retain(|id, _| ids.contains(id.as_str()));
            }
            for sandbox in running {
                let every =
                    std::time::Duration::from_secs(sandbox.lifetime().checkpoint_secs.max(floor));
                let id = sandbox.id().to_string();
                let is_due = clocks
                    .lock()
                    .unwrap()
                    .get(&id)
                    .is_none_or(|clock| clock.at.elapsed() >= every);
                if !is_due || !busy.lock().unwrap().insert(id.clone()) {
                    continue;
                }
                let (manager, limit, clocks, busy) = (
                    self.clone(),
                    Arc::clone(&limit),
                    Arc::clone(&clocks),
                    Arc::clone(&busy),
                );
                tokio::spawn(async move {
                    let _slot = limit.acquire().await;
                    let since = clocks.lock().unwrap().remove(&id);
                    let clock = CheckpointClock {
                        at: std::time::Instant::now(),
                        cpu_usec: sandbox.record().cpu_usage_usec,
                        activity: sandbox
                            .last_activity
                            .load(std::sync::atomic::Ordering::Relaxed),
                    };
                    if let Err(err) = manager.checkpoint_sandbox(&sandbox, since.as_ref()).await {
                        tracing::warn!(sandbox = id, err = err.message(), "checkpoint failed");
                    }
                    clocks.lock().unwrap().insert(id.clone(), clock);
                    busy.lock().unwrap().remove(&id);
                });
            }
        }
    }

    /// Whether a sandbox's disks are as its last checkpoint left them and,
    /// for a memory checkpoint, its guest has been idle since: nobody called
    /// into it and it spent under 1% of a CPU.
    async fn is_unchanged_since(
        &self,
        sandbox: &RunningSandbox,
        since: Option<&CheckpointClock>,
        is_memory: bool,
    ) -> bool {
        let Some(stored) = sandbox.durable.stored.lock().unwrap().clone() else {
            return false;
        };
        let kind = match is_memory {
            true => crate::durable::CHECKPOINT_MEMORY,
            false => crate::durable::CHECKPOINT_DISK,
        };
        if !stored.is_published || stored.manifest.checkpoint != kind {
            return false;
        }
        if crate::durable::Stamp::of(&sandbox.disk_path()).ok() != Some(stored.disk) {
            // A freeze and thaw rewrite the superblock alone, which the clone
            // the last disk checkpoint kept tells apart from a guest's writes.
            let (disk, base) = (
                sandbox.disk_path(),
                sandbox.workdir.join(crate::durable::CHECKPOINT_BASE),
            );
            let is_changed = is_memory
                || tokio::task::spawn_blocking(move || {
                    crate::rootdisk::changed_since(&disk, &base).unwrap_or(true)
                })
                .await
                .unwrap_or(true);
            if is_changed {
                return false;
            }
        }
        for (name, _) in self.written_volumes(sandbox) {
            if self.volumes.is_changed(&name).await {
                return false;
            }
        }
        if !is_memory {
            return true;
        }
        let Some(since) = since else {
            return false;
        };
        let spent = sandbox
            .record()
            .cpu_usage_usec
            .saturating_sub(since.cpu_usec);
        sandbox
            .last_activity
            .load(std::sync::atomic::Ordering::Relaxed)
            <= since.activity
            && u128::from(spent) * 100 < since.at.elapsed().as_micros()
    }

    /// Takes one checkpoint of a running sandbox, skipping it when nothing
    /// changed since the last.
    async fn checkpoint_sandbox(
        &self,
        sandbox: &Arc<RunningSandbox>,
        since: Option<&CheckpointClock>,
    ) -> Result<(), Status> {
        let Some(store) = self.config.object_store.clone() else {
            return Ok(());
        };
        self.require_vmm(sandbox).await?;
        let is_memory = sandbox.lifetime().is_memory_checkpointed
            && sandbox.layout().memory.is_some()
            && !crate::macnode::is_macos(
                burrow_vmm::GuestOs::from_record(&sandbox.record().guest_os).unwrap_or_default(),
            );
        if self.is_unchanged_since(sandbox, since, is_memory).await {
            tracing::debug!(
                sandbox = sandbox.id(),
                "nothing changed; checkpoint skipped"
            );
            return Ok(());
        }
        let previous = sandbox.durable.stored.lock().unwrap().clone();
        let Some(mut draft) = self.draft_manifest(sandbox, previous.as_ref()).await? else {
            return Ok(());
        };
        draft.checkpoint_at_ms = burrow_common::unix_now_ms();
        let token = sandbox.durable.cancel.lock().unwrap().clone();
        // Taken before the guest is touched, so the freeze or pause never
        // waits on an upload still running.
        let mut volumes = Vec::new();
        for (name, path) in self.written_volumes(sandbox) {
            let guard = self.volumes.lock_upload(&name).await;
            volumes.push((name, path, guard));
        }
        let capture = sandbox.workdir.join(".checkpoint.ext4");
        let started = std::time::Instant::now();
        // Read before each clone, with the disks still: a later read that
        // matches means nothing was written since the clone either.
        let stamps = || {
            std::iter::once(sandbox.disk_path())
                .chain(volumes.iter().map(|(name, _, _)| self.volumes.image(name)))
                .map(|path| crate::durable::Stamp::of(&path))
                .collect::<std::io::Result<Vec<_>>>()
        };
        let volume_captures: Vec<(PathBuf, PathBuf)> = volumes
            .iter()
            .map(|(name, _, _)| {
                (
                    self.volumes.image(name),
                    sandbox.workdir.join(format!(".checkpoint-{name}.img")),
                )
            })
            .collect();
        let (paused_for, is_frozen, stamps) = match is_memory {
            true => {
                let stamps = stamps()
                    .map_err(|err| Status::internal(format!("reading the disks: {err}")))?;
                let paused_for = self
                    .write_state(sandbox, Some(&capture), &volume_captures)
                    .await?;
                (paused_for, false, stamps)
            }
            false => {
                let mut paths: Vec<String> =
                    volumes.iter().map(|(_, path, _)| path.clone()).collect();
                paths.insert(0, "/".to_string());
                let disk = sandbox.disk_path();
                let (captured, frozen_for, is_frozen) = with_frozen(sandbox, paths, async {
                    let stamps = stamps()?;
                    crate::rootdisk::clone(&disk, &capture).await?;
                    for (image, dest) in &volume_captures {
                        crate::rootdisk::clone(image, dest).await?;
                    }
                    Ok::<_, std::io::Error>(stamps)
                })
                .await;
                let stamps = captured
                    .map_err(|err| Status::internal(format!("capturing the disks: {err}")))?;
                (frozen_for, is_frozen, stamps)
            }
        };
        let mut stamps = stamps.into_iter();
        let stamp = stamps.next().unwrap_or_default();
        tracing::info!(
            sandbox = sandbox.id(),
            kind = if is_memory { "memory" } else { "disk" },
            paused_ms = paused_for.as_millis() as u64,
            is_frozen,
            "checkpoint captured"
        );

        let _uploading = sandbox.durable.upload.lock().await;
        let uploaded = tokio::select! {
            () = token.cancelled() => Err(Status::aborted("the sandbox suspended or stopped")),
            uploaded = async {
                for (((name, _, _), (_, dest)), stamp) in
                    volumes.iter().zip(&volume_captures).zip(stamps)
                {
                    self.volumes.upload_capture(name, dest, stamp).await?;
                    if let Some(generation) = self.volumes.generation(name).await {
                        draft.volumes.insert(name.clone(), generation);
                    }
                }
                let blobs = crate::blobs::BlobStore::new(&self.config.data_dir);
                match is_memory {
                    true => {
                        let staged = sandbox.workdir.join(".checkpoint");
                        let _ = tokio::fs::remove_dir_all(&staged).await;
                        tokio::fs::create_dir_all(&staged)
                            .await
                            .map_err(|err| Status::internal(format!("staging: {err}")))?;
                        draft.checkpoint = crate::durable::CHECKPOINT_MEMORY.to_string();
                        let chain = sandbox.stage_fork(&staged, None, Some(&capture)).await?;
                        let mut uploaded = crate::durable::upload(
                            &store,
                            &blobs,
                            &staged,
                            sandbox.logs.dir(),
                            &chain,
                            draft,
                            previous.as_ref(),
                        )
                        .await;
                        if let Ok(local) = &mut uploaded {
                            local.disk = stamp;
                        }
                        let _ = tokio::fs::remove_dir_all(&staged).await;
                        uploaded
                    }
                    false => {
                        crate::durable::upload_disk_checkpoint(
                            &store,
                            &blobs,
                            &sandbox.workdir,
                            &capture,
                            stamp,
                            draft,
                            previous.as_ref(),
                        )
                        .await
                    }
                }
            } => uploaded,
        };
        drop(volumes);
        for (_, dest) in &volume_captures {
            let _ = tokio::fs::remove_file(dest).await;
        }
        let _ = tokio::fs::remove_file(&capture).await;
        let local = uploaded?;
        // Kept in the working directory as a suspend's record is, so a
        // restarted node knows what the store holds.
        crate::durable::save_local(&sandbox.workdir, &local).await?;
        *sandbox.durable.stored.lock().unwrap() = Some(local);
        self.announce_now();
        tracing::info!(
            sandbox = sandbox.id(),
            took_ms = started.elapsed().as_millis() as u64,
            "checkpoint is in the object store"
        );
        Ok(())
    }
}

/// Has the page-fault handler record what the guest touches, for a sandbox
/// whose state goes to the object store. Only where the handler serves memory
/// anyway: asking for a recording turns it on, and for a single snapshot file
/// the kernel serves memory more cheaply.
fn record_working_set(spec: &mut VmSpec, is_stored: bool) {
    let is_served = spec.is_memory_lazy
        || spec.memory_chain.len() > 1
        || spec.prefetch.is_some()
        || spec.memory_source.is_some();
    if is_stored && is_served {
        spec.record_prefetch = Some(crate::durable::WORKING_SET.to_string());
    }
}

/// Replaces every secret on a record with its sealed form, keyed by the
/// sandbox and the place the value sits, for the row on disk.
fn seal_secrets(
    vault: &burrow_common::vault::Vault,
    record: &mut common::Sandbox,
) -> Result<(), burrow_common::vault::Error> {
    map_secrets(record, |context, value| vault.seal(context, value))
}

fn open_secrets(
    vault: &burrow_common::vault::Vault,
    record: &mut common::Sandbox,
) -> Result<(), burrow_common::vault::Error> {
    map_secrets(record, |context, value| vault.unseal(context, value))
}

/// Rewrites each secret on a record in place, passing `f` the value and a
/// context naming the sandbox and where the value sits.
fn map_secrets(
    record: &mut common::Sandbox,
    f: impl Fn(&str, &str) -> Result<String, burrow_common::vault::Error>,
) -> Result<(), burrow_common::vault::Error> {
    let id = &record.id;
    let apply = |place: String, value: &mut String| -> Result<(), burrow_common::vault::Error> {
        *value = f(&format!("{id}/{place}"), value)?;
        Ok(())
    };
    if let Some(network) = record.policy.as_mut().and_then(|p| p.network.as_mut()) {
        for (i, rule) in network.rules.iter_mut().enumerate() {
            match rule.action.as_mut() {
                Some(common::request_rule::Action::SetHeaders(set)) => {
                    for (j, header) in set.headers.iter_mut().enumerate() {
                        apply(format!("rules/{i}/headers/{j}"), &mut header.value)?;
                    }
                }
                Some(common::request_rule::Action::Forward(forward))
                    if !forward.secret.is_empty() =>
                {
                    apply(format!("rules/{i}/forward"), &mut forward.secret)?;
                }
                _ => {}
            }
        }
    }
    for (service, value) in record.kit_credentials.iter_mut() {
        apply(format!("credentials/{service}"), value)?;
    }
    Ok(())
}

/// Writes the sections a caller named onto a sandbox's policy.
///
/// Present replaces, absent leaves. Written out rather than assigned from a
/// whole `Policy` because `None` here means "the caller said nothing about
/// this", not "the caller wants no restriction": the two are the same value on
/// a create and must not be on an update.
fn apply_access_policy(
    policy: &mut common::Policy,
    exec: Option<common::ExecPolicy>,
    fs: Option<common::FsPolicy>,
) {
    if let Some(exec) = exec {
        policy.exec = Some(exec);
    }
    if let Some(fs) = fs {
        policy.fs = Some(fs);
    }
}

/// Names of the private networks a sandbox belongs to.
fn networks_of(record: &common::Sandbox) -> impl Iterator<Item = &str> {
    record
        .policy
        .iter()
        .flat_map(|p| p.networks.iter())
        .map(|n| n.network.as_str())
        .filter(|name| !name.is_empty())
}

/// A sandbox's declared egress mode. An unset policy means no egress: a
/// sandbox that never stated what it needs gets nothing, rather than
/// inheriting whatever the default happens to be.
fn policy_mode(record: &common::Sandbox) -> firewall::Mode {
    record
        .policy
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .and_then(|n| firewall::Mode::try_from(n.mode).ok())
        .unwrap_or_default()
}

/// A Mac's auxiliary storage, which its machine writes like a disk and its
/// restore reads back as the save left it.
fn aux_storage(boot: &burrow_vmm::Boot) -> Option<String> {
    match boot {
        #[cfg(target_os = "macos")]
        burrow_vmm::Boot::MacOs(boot) => Some(boot.aux.clone()),
        _ => None,
    }
}

/// Hotplugs a sandbox's volumes onto its running VM, in the order the
/// handshake names their devices.
async fn attach_volumes(
    vm: &Vm,
    mounts: &[common::VolumeMount],
    guest_os: burrow_vmm::GuestOs,
) -> Result<(), Status> {
    for (index, mount) in crate::volume::block_mounts(mounts) {
        let drive = DriveSpec {
            id: crate::volume::drive_id(index, guest_os),
            path: volume_image(index),
            is_root: false,
            is_read_only: mount.is_read_only,
        };
        vm.attach_drive(&drive)
            .await
            .map_err(|err| Status::internal(format!("attaching volume {}: {err}", mount.volume)))?;
    }
    Ok(())
}

/// Tells the agent to run the template's systemd under it.
/// The node's extra kernel arguments, made verbose for a sandbox debugging
/// its template: `quiet` and any `loglevel` dropped for `loglevel=7`, so the
/// kernel's whole boot reaches the console.
pub(crate) fn guest_boot_args(extra: &str, is_verbose: bool) -> String {
    if !is_verbose {
        return extra.to_string();
    }
    extra
        .split_whitespace()
        .filter(|arg| *arg != "quiet" && !arg.starts_with("loglevel="))
        .chain(["loglevel=7"])
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn guest_mode_arg(is_systemd: bool) -> &'static str {
    if is_systemd { "burrow.systemd=1" } else { "" }
}

/// Hands a sandbox's staged files to the uid firecracker will drop to.
///
/// `shared` names the entries in `workdir` that are hard links into a
/// directory this sandbox does not own alone (the template's kernel and
/// rootfs, a warm snapshot's memory image, a read-only volume mount), and
/// those are left untouched. Every jailed VMM on the node runs as the same
/// fixed uid, so chowning a shared inode to it doesn't just grant "the jail"
/// read access (an ordinary umask already does that): it grants every other
/// jailed VMM on that uid host-level write access, which the virtio
/// read-only flag can't take back. A guest that escapes Firecracker into its
/// own chroot could then `open(O_RDWR)` the same inode every future sandbox
/// from that template (or every other reader of that volume) boots from.
/// What's not in `shared` is this sandbox's alone, a copy rather than a
/// link, and still needs the chown to be guest-writable.
///
/// The one shared inode that is *not* in `shared` is a writable volume mount,
/// which has to be writable by the jail uid and cannot be a copy without
/// ceasing to be the volume. That grant is therefore made temporary rather
/// than avoided: the image's owner is recorded before this runs (see
/// [`crate::volume::VolumeStore::remember_owner`]) and put back the moment the
/// sandbox's claim is released, so it lasts as long as the mount and not the
/// life of the volume.
pub(crate) async fn grant_to_jail(
    workdir: &Path,
    jail: &burrow_vmm::Jail,
    shared: &std::collections::HashSet<String>,
) -> std::io::Result<()> {
    let workdir = workdir.to_path_buf();
    let shared = shared.clone();
    let (uid, gid) = (jail.uid, jail.gid);
    tokio::task::spawn_blocking(move || {
        fn chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))
        }
        // The directory itself is this sandbox's alone, so it is always
        // handed over: firecracker cannot traverse its own chroot without it.
        chown(&workdir, uid, gid)?;
        for entry in std::fs::read_dir(&workdir)?.flatten() {
            if shared.contains(&entry.file_name().to_string_lossy().into_owned()) {
                continue;
            }
            chown(&entry.path(), uid, gid)?;
        }
        Ok(())
    })
    .await
    .map_err(|err| std::io::Error::other(format!("chown did not run: {err}")))?
}

/// Creates a sandbox working directory with the template's kernel and image
/// linked in. Hard links keep creation cheap; the root disk cloned from the
/// image is the sandbox's own, and the guest never sees the image itself.
async fn prepare_workdir(template_dir: &Path, workdir: &Path) -> std::io::Result<()> {
    if tokio::fs::try_exists(workdir).await.unwrap_or(false) {
        tokio::fs::remove_dir_all(workdir).await?;
    }
    tokio::fs::create_dir_all(workdir).await?;
    for file in [TEMPLATE_KERNEL, TEMPLATE_ROOTFS] {
        let source = template_dir.join(file);
        if !tokio::fs::try_exists(&source).await.unwrap_or(false) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("missing {}", source.display()),
            ));
        }
        tokio::fs::hard_link(&source, workdir.join(file)).await?;
    }
    Ok(())
}

/// A request rule seen to have expired.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpiredRule {
    sandbox_id: String,
    /// Position in the policy, which is how the proxy's audit records name a
    /// rule too.
    index: usize,
    domain: String,
    expires_at_unix_ms: u64,
}

impl ExpiredRule {
    /// The audit record saying the rule stopped applying.
    ///
    /// Filed with the refusals: it is a grant withdrawn, and the refusal
    /// queue is the one the audit log does not shed under load.
    fn event(&self, guest_ip: std::net::Ipv4Addr) -> burrow_proxy::EgressEvent {
        burrow_proxy::EgressEvent {
            at_ms: burrow_proxy::unix_now_ms(),
            sandbox_id: self.sandbox_id.clone(),
            source_ip: guest_ip.to_string(),
            destination: "policy".into(),
            host: Some(self.domain.clone()),
            port: 0,
            is_allowed: false,
            reason: format!(
                "request rule {} for {} expired at unix ms {}; it no longer applies",
                self.index, self.domain, self.expires_at_unix_ms
            ),
            bytes_sent: 0,
            bytes_received: 0,
            dropped_records: 0,
        }
    }
}

/// Redirects an open-mode sandbox's HTTPS to an inspected host's addresses,
/// as the resolver hands them out. See [`burrow_proxy::dns::Redirect`].
struct InspectionRedirect {
    /// The same lock every render holds, so an element added here is never
    /// added in the middle of a render that would flush it.
    firewall: Arc<tokio::sync::Mutex<()>>,
    policies: Arc<burrow_proxy::PolicyTable>,
}

impl burrow_proxy::dns::Redirect for InspectionRedirect {
    fn redirect<'a>(
        &'a self,
        source: std::net::IpAddr,
        addresses: &'a [std::net::IpAddr],
        lifetime: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // The ruleset names sandboxes by their v4 address; a query that
            // arrived over v6 is the same sandbox.
            let guest = match burrow_proxy::policy::unmap(source) {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(_) => self
                    .policies
                    .get(source)
                    .and_then(|policy| self.policies.ipv4_of(&policy.sandbox_id)),
            };
            let Some(guest) = guest else {
                return;
            };
            let v4: Vec<std::net::Ipv4Addr> = addresses
                .iter()
                .filter_map(|address| match burrow_proxy::policy::unmap(*address) {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect();
            let commands = firewall::redirect_inspected(guest, &v4, lifetime.as_secs());
            if commands.is_empty() {
                return;
            }
            let _ordered = self.firewall.lock().await;
            // Failing here costs the brokering, never the secret: the
            // connection leaves the node directly, as open mode's always
            // does, with no credential set on it.
            if let Err(err) = firewall::apply(&commands).await {
                tracing::warn!(%guest, %err, "could not redirect an inspected host's addresses");
            }
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A sandbox's limits become its cgroup's the way runc makes Docker's:
    /// a cap as cpu.max, shares as cpu.weight, Docker's default shares for
    /// each CPU charged when none are named, blkio weight as io.weight.
    #[test]
    fn a_policy_maps_to_cgroup_limits_as_docker_does() {
        let limits = cgroup_limits(
            &common::ResourcePolicy {
                vcpus: 2,
                cpus: 0.5,
                cpuset_cpus: "0-1".into(),
                blkio_weight: 500,
                ..Default::default()
            },
            640,
        );
        assert_eq!(limits.cpu_max_millis, 500);
        assert_eq!(limits.cpu_weight, burrow_common::cpu::shares_to_weight(512));
        assert_eq!(limits.cpuset_cpus, "0-1");
        assert_eq!(limits.io_weight, 4950);
        assert_eq!(limits.memory_mib, 640);

        let uncapped = cgroup_limits(
            &common::ResourcePolicy {
                vcpus: 2,
                cpu_shares: 100,
                ..Default::default()
            },
            640,
        );
        assert_eq!(uncapped.cpu_max_millis, 0);

        let reserved = cgroup_limits(
            &common::ResourcePolicy {
                vcpus: 8,
                reserved_cpus: 4.0,
                ..Default::default()
            },
            640,
        );
        assert_eq!(reserved.cpu_max_millis, 0, "a reservation is no cap");
        assert_eq!(reserved.cpu_reserve_millis, 4000);
        assert_eq!(
            reserved.cpu_weight,
            burrow_common::cpu::shares_to_weight(4096),
            "weighted by the four CPUs reserved, not the eight it may burst to"
        );
        assert_eq!(
            uncapped.cpu_weight,
            burrow_common::cpu::shares_to_weight(100)
        );
        assert_eq!(uncapped.io_weight, 0);
        assert_eq!(
            cgroup_limits(&common::ResourcePolicy::default(), 640).cpu_weight,
            burrow_common::cpu::shares_to_weight(1024)
        );
    }

    /// A sandbox grows to 16 times its memory by default, within the node's
    /// cap, and its region is rounded up to what both backends size one in.
    #[test]
    fn memory_grows_to_the_default_limit_through_a_rounded_region() {
        use burrow_vmm::GuestOs;
        assert_eq!(max_mem_mib(1024, 0), 16384);
        assert_eq!(max_mem_mib(512, 0), 8192);
        assert_eq!(max_mem_mib(4096, 0), 16384);
        assert_eq!(max_mem_mib(32768, 0), 32768);
        assert_eq!(max_mem_mib(1024, 3072), 3072);
        assert_eq!(max_mem_mib(4096, 1024), 4096);

        let fc = Hypervisor::Firecracker;
        assert_eq!(hotplug_region(fc, GuestOs::Linux, 1024, 16384), 15360);
        assert_eq!(hotplug_region(fc, GuestOs::Linux, 1000, 3000), 2048);
        assert_eq!(hotplug_region(fc, GuestOs::Linux, 1024, 1024), 0);
        assert_eq!(hotplug_region(fc, GuestOs::Linux, 1024, 0), 0);
        let ch = Hypervisor::CloudHypervisor;
        assert_eq!(hotplug_region(ch, GuestOs::Linux, 1024, 8192), 7168);
        assert_eq!(hotplug_region(ch, GuestOs::Windows, 4096, 8192), 0);
        assert_eq!(
            hotplug_region(Hypervisor::Vz, GuestOs::MacOs, 4096, 8192),
            0
        );
    }

    /// A VM about to boot starts with all of its memory as boot memory and
    /// its limit resolved, and a guest that cannot take memory live is held
    /// to the memory it has.
    #[test]
    fn a_booting_vm_pins_its_memory() {
        use burrow_vmm::GuestOs;
        let mut resources = common::ResourcePolicy {
            mem_mib: 3072,
            boot_mem_mib: 1024,
            ..Default::default()
        };
        pin_boot_memory(&mut resources, Hypervisor::Firecracker, GuestOs::Linux).unwrap();
        assert_eq!(
            (
                resources.mem_mib,
                resources.boot_mem_mib,
                resources.max_mem_mib
            ),
            (3072, 3072, 16384)
        );

        let mut shrunk = common::ResourcePolicy {
            mem_mib: 8192,
            max_mem_mib: 4096,
            ..Default::default()
        };
        pin_boot_memory(&mut shrunk, Hypervisor::CloudHypervisor, GuestOs::Linux).unwrap();
        assert_eq!(shrunk.max_mem_mib, 8192);

        let mut windows = common::ResourcePolicy::default();
        pin_boot_memory(&mut windows, Hypervisor::CloudHypervisor, GuestOs::Windows).unwrap();
        assert_eq!((windows.mem_mib, windows.max_mem_mib), (512, 512));
        let mut grown = common::ResourcePolicy {
            mem_mib: 4096,
            max_mem_mib: 8192,
            ..Default::default()
        };
        assert!(pin_boot_memory(&mut grown, Hypervisor::Vz, GuestOs::MacOs).is_err());
    }

    #[test]
    fn a_verbose_console_drops_quiet_and_raises_the_log_level() {
        assert_eq!(
            guest_boot_args("quiet loglevel=0 foo=1", false),
            "quiet loglevel=0 foo=1"
        );
        assert_eq!(
            guest_boot_args("quiet loglevel=0 foo=1", true),
            "foo=1 loglevel=7"
        );
        assert_eq!(guest_boot_args("", true), "loglevel=7");
    }

    #[test]
    fn guest_clocks_sync_on_the_interval_or_a_node_clock_jump() {
        use std::time::{Duration, Instant, SystemTime};
        let at = (Instant::now(), SystemTime::now());
        let after = |steady: u64, wall: Duration| (at.0 + Duration::from_secs(steady), at.1 + wall);
        assert!(!clocks_due(at, after(5, Duration::from_secs(5))));
        assert!(!clocks_due(at, after(5, Duration::from_millis(5_900))));
        assert!(clocks_due(at, after(60, Duration::from_secs(60))));
        // The node's host slept for three days.
        assert!(clocks_due(at, after(5, Duration::from_secs(3 * 86_400))));
        assert!(clocks_due(
            at,
            (
                at.0 + Duration::from_secs(5),
                at.1 - Duration::from_secs(10)
            )
        ));
    }

    #[test]
    fn port_rules_reach_the_firewall_whole_and_the_proxy_as_tcp() {
        let rule =
            |protocol: common::PortProtocol, port, port_end, cidrs: &[&str]| common::PortRule {
                protocol: protocol as i32,
                port,
                port_end,
                cidrs: cidrs.iter().map(|c| (*c).to_string()).collect(),
            };
        let tcp = rule(common::PortProtocol::Tcp, 465, 587, &["10.0.0.0/8"]);
        let both = rule(common::PortProtocol::Unspecified, 25, 0, &[]);
        let udp = rule(common::PortProtocol::Udp, 53, 0, &[]);

        let denial = burrow_net::policy::PortDenial::from(&tcp);
        assert_eq!(denial.protocol, Some(firewall::Protocol::Tcp));
        assert_eq!((denial.first, denial.last), (465, 587));
        assert_eq!(denial.cidrs, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(burrow_net::policy::PortDenial::from(&both).protocol, None);
        assert_eq!(
            burrow_net::policy::PortDenial::from(&udp).protocol,
            Some(firewall::Protocol::Udp)
        );
        // An unknown protocol is the broader reading, both.
        let mut unknown = tcp.clone();
        unknown.protocol = 9;
        assert_eq!(
            burrow_net::policy::PortDenial::from(&unknown).protocol,
            None
        );

        // UDP never reaches the proxy, so it is not handed one.
        assert!(burrow_proxy::policy::DeniedPorts::from_rule(&udp).is_none());
        let proxied = burrow_proxy::policy::DeniedPorts::from_rule(&both).unwrap();
        assert_eq!((proxied.first, proxied.last), (25, 25));
        let proxied = burrow_proxy::policy::DeniedPorts::from_rule(&tcp).unwrap();
        assert_eq!((proxied.first, proxied.last), (465, 587));
        // A range that is not one reads as every port.
        let backwards = rule(common::PortProtocol::Tcp, 600, 599, &[]);
        let proxied = burrow_proxy::policy::DeniedPorts::from_rule(&backwards).unwrap();
        assert_eq!((proxied.first, proxied.last), (0, u16::MAX));
    }

    /// A manager with no VMs behind it. Shared with the node edge's tests,
    /// which need a sandbox map to miss in.
    pub(crate) async fn manager() -> SandboxManager {
        SandboxManager::new(
            NodeConfig {
                data_dir: std::env::temp_dir().join(format!("burrow-fork-{}", std::process::id())),
                firecracker_bin: "/nonexistent/firecracker".into(),
                extra_boot_args: String::new(),
                is_console_verbose: false,
                agent_timeout: std::time::Duration::from_millis(1),
                command_log_rotation: Default::default(),
                cgroup_root: None,
                is_resource_limits_required: false,
                is_memory_lazy: false,
                jail: None,
                cloud_hypervisor: burrow_vmm::CloudHypervisorConfig {
                    bin: "/nonexistent/cloud-hypervisor".into(),
                    kernel: None,
                    jail: None,
                },
                hypervisors: vec![Hypervisor::Firecracker],
                is_nested_virt_supported: false,
                vmm_memory_overhead_mib: HashMap::new(),
                artifact_retention: std::time::Duration::from_secs(7 * 24 * 60 * 60),
                control_plane: Vec::new(),
                share: crate::share::ShareOptions {
                    is_enabled: false,
                    is_transparent: false,
                    region: None,
                    derp_map_url: None,
                },
                object_store: None,
                store_vault: None,
                firecracker_version: String::new(),
                cloud_hypervisor_version: String::new(),
                guest_upgrade: None,
                event_delivery: Default::default(),
                disk: Default::default(),
                public: Default::default(),
                warm: Default::default(),
                checkpoint_min_secs: 60,
            },
            Arc::new(burrow_proxy::PolicyTable::default()),
            Arc::new(burrow_proxy::Resolutions::default()),
            Arc::new(burrow_proxy::DeniedAddresses::default()),
            Arc::new(burrow_proxy::directory::Directory::default()),
            Arc::new(burrow_store::Store::open_in_memory().await.unwrap()),
            burrow_common::vault::Vault::open(&std::env::temp_dir().join(format!(
                "burrow-test-{}-{}.key",
                std::process::id(),
                burrow_common::SandboxId::generate()
            )))
            .unwrap(),
        )
    }

    /// A manager whose data directory is its own, for recovery tests.
    /// Firecracker never shows a guest SVM or VMX, and Cloud Hypervisor can
    /// only where the node's KVM nests.
    #[tokio::test]
    async fn nested_virtualization_is_refused_where_it_cannot_be_given() {
        let mut manager = manager().await;
        let nested = common::ResourcePolicy {
            is_nested_virt_enabled: true,
            ..Default::default()
        };
        assert!(
            manager
                .require_nested_virt(Hypervisor::CloudHypervisor, &Default::default())
                .is_ok()
        );
        let err = manager
            .require_nested_virt(Hypervisor::Firecracker, &nested)
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("needs Cloud Hypervisor on x86_64"));
        let err = manager
            .require_nested_virt(Hypervisor::CloudHypervisor, &nested)
            .unwrap_err();
        let why = match cfg!(target_arch = "x86_64") {
            true => "nesting off",
            false => "needs Cloud Hypervisor on x86_64",
        };
        assert!(err.message().contains(why), "{}", err.message());
        manager.config.is_nested_virt_supported = true;
        let supported = manager.require_nested_virt(Hypervisor::CloudHypervisor, &nested);
        assert_eq!(supported.is_ok(), cfg!(target_arch = "x86_64"));
    }

    async fn recovering(name: &str) -> (SandboxManager, PathBuf) {
        let data_dir =
            std::env::temp_dir().join(format!("burrow-recovery-{name}-{}", std::process::id()));
        tokio::fs::remove_dir_all(&data_dir).await.ok();
        let mut manager = manager().await;
        manager.config.data_dir.clone_from(&data_dir);
        (manager, data_dir)
    }

    fn row(id: &str, state: common::SandboxState, lease_block: u32) -> burrow_store::SandboxRow {
        let record = common::Sandbox {
            id: id.into(),
            template: "default".into(),
            hypervisor: Hypervisor::Firecracker.as_str().into(),
            ..Default::default()
        };
        burrow_store::SandboxRow {
            suspended_at: 1,
            id: id.into(),
            template: "default".into(),
            record: prost::Message::encode_to_vec(&record),
            state: state as i32,
            lease_block,
            tap: format!("bt{lease_block}"),
            ports: vec![],
            share: Default::default(),
        }
    }

    async fn events_of(manager: &SandboxManager, id: &str) -> Vec<burrow_store::EventRow> {
        manager.store.list_events(0, Some(id), 100).await.unwrap()
    }

    /// A node killed before it could suspend left a sandbox recorded as
    /// running with no snapshot of that VM. Recovery used to discard it and
    /// its disk without an event. It is kept stopped on its disk, with the
    /// reason, and a `stopped` event closes the running interval.
    #[tokio::test]
    async fn a_sandbox_whose_vm_died_with_the_node_is_kept_stopped() {
        let id = "ghost-lost-vm";
        let (manager, data_dir) = recovering("lost").await;
        let workdir = manager.config.sandbox_dir(id, Hypervisor::Firecracker);
        std::fs::create_dir_all(&workdir).unwrap();
        let layout = Hypervisor::Firecracker.layout();
        // A snapshot from an earlier suspend, older than the disk.
        for file in [layout.state, crate::rootdisk::ROOT_DISK] {
            tokio::fs::write(workdir.join(file), b"old").await.unwrap();
        }
        let stale = row(id, common::SandboxState::Running, 3);
        manager.store.put_sandbox(&stale).await.unwrap();
        let started = burrow_store::EventRow {
            sandbox_id: id.to_string(),
            kind: EVENT_STARTED.into(),
            cpu_usage_usec: 7_000,
            vcpus: 2,
            mem_mib: 1024,
            ..Default::default()
        };
        manager.store.append_event(&started).await.unwrap();

        manager.recover().await;

        let rows = manager.store.list_sandboxes().await.unwrap();
        assert_eq!(rows[0].state, common::SandboxState::Stopped as i32);
        let stored: common::Sandbox = prost::Message::decode(&rows[0].record[..]).unwrap();
        assert_eq!(stored.state_reason, REASON_LOST);
        assert!(workdir.join(crate::rootdisk::ROOT_DISK).exists());
        assert!(!workdir.join(layout.state).exists());
        let events = events_of(&manager, id).await;
        let stopped = &events[1];
        assert_eq!(
            (stopped.kind, stopped.detail.as_str()),
            (EVENT_STOPPED as i32, DETAIL_LOST)
        );
        assert_eq!(stopped.state, common::SandboxState::Stopped as i32);
        assert_eq!(
            (stopped.cpu_usage_usec, stopped.vcpus, stopped.mem_mib),
            (7_000, 2, 1024)
        );
        assert_eq!(events.last().unwrap().kind, EVENT_RECOVERED as i32);
        // Here the tap cannot be made, so it is held rather than restored;
        // either way it is listed.
        assert_eq!(manager.list().await.len(), 1);
        tokio::fs::remove_dir_all(&data_dir).await.ok();
    }

    /// A recorded lease the node cannot hold, here one from the next node's
    /// slice, must not cost the sandbox its snapshot. It is kept out of
    /// service with the reason, and can still be deleted.
    #[tokio::test]
    async fn a_sandbox_whose_lease_cannot_be_reserved_is_held() {
        let id = "ghost-foreign-lease";
        let (manager, data_dir) = recovering("foreign-lease").await;
        let workdir = manager.config.sandbox_dir(id, Hypervisor::Firecracker);
        std::fs::create_dir_all(&workdir).unwrap();
        let layout = Hypervisor::Firecracker.layout();
        for file in [layout.state, crate::rootdisk::ROOT_DISK] {
            tokio::fs::write(workdir.join(file), b"kept").await.unwrap();
        }
        let orphan = data_dir.join("sandboxes").join("ghost-nobody");
        std::fs::create_dir_all(&orphan).unwrap();
        let foreign = row(
            id,
            common::SandboxState::Suspended,
            burrow_net::ipam::BLOCKS_PER_NODE,
        );
        manager.store.put_sandbox(&foreign).await.unwrap();

        manager.recover().await;

        assert_eq!(manager.store.list_sandboxes().await.unwrap().len(), 1);
        assert!(workdir.join(layout.state).exists());
        assert!(!orphan.exists());
        let listed = manager.list().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, common::SandboxState::Failed as i32);
        assert!(
            listed[0].state_reason.contains("address block"),
            "{}",
            listed[0].state_reason
        );
        let reports = manager.state_reports().await;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, common::SandboxState::Failed as i32);
        let err = manager.get(id).await.err().unwrap();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            manager.record_of(id).await.unwrap().state,
            common::SandboxState::Failed as i32
        );
        let kinds: Vec<_> = events_of(&manager, id)
            .await
            .iter()
            .map(|event| event.kind)
            .collect();
        assert_eq!(kinds, [EVENT_RECOVERED as i32]);

        manager.delete(id).await.unwrap();
        assert!(manager.store.list_sandboxes().await.unwrap().is_empty());
        assert!(manager.list().await.is_empty());
        assert!(!workdir.exists());
        let last = events_of(&manager, id).await.pop().unwrap();
        assert_eq!(last.kind, EVENT_DESTROYED as i32);
        tokio::fs::remove_dir_all(&data_dir).await.ok();
    }

    /// A sandbox with neither memory nor disk left is the one thing recovery
    /// drops, and it says so with the last figures the node had.
    #[tokio::test]
    async fn a_sandbox_with_nothing_on_disk_is_recorded_destroyed() {
        let id = "ghost-empty";
        let (manager, data_dir) = recovering("empty").await;
        let stale = row(id, common::SandboxState::Running, 4);
        manager.store.put_sandbox(&stale).await.unwrap();
        let started = burrow_store::EventRow {
            sandbox_id: id.to_string(),
            kind: EVENT_STARTED.into(),
            cpu_usage_usec: 9_000,
            rx_bytes: 40,
            vcpus: 1,
            mem_mib: 512,
            ..Default::default()
        };
        manager.store.append_event(&started).await.unwrap();

        manager.recover().await;

        assert!(manager.store.list_sandboxes().await.unwrap().is_empty());
        assert!(manager.list().await.is_empty());
        let last = events_of(&manager, id).await.pop().unwrap();
        assert_eq!(
            (last.kind, last.detail.as_str()),
            (EVENT_DESTROYED as i32, DETAIL_LOST)
        );
        assert_eq!((last.cpu_usage_usec, last.rx_bytes), (9_000, 40));
        tokio::fs::remove_dir_all(&data_dir).await.ok();
    }

    /// A sandbox under a hypervisor this build does not know used to be read
    /// as a Firecracker one, found without a snapshot, and deleted along with
    /// its files. It stays recorded and on disk, out of service.
    #[tokio::test]
    async fn an_unknown_hypervisor_keeps_the_sandbox_on_recovery() {
        let id = "ghost-unknown-hypervisor";
        let data_dir =
            std::env::temp_dir().join(format!("burrow-recovery-unknown-{}", std::process::id()));
        tokio::fs::remove_dir_all(&data_dir).await.ok();
        let mut manager = manager().await;
        manager.config.data_dir.clone_from(&data_dir);
        let workdir = data_dir.join("sandboxes").join(id);
        std::fs::create_dir_all(&workdir).unwrap();
        tokio::fs::write(workdir.join("snapshot.future"), b"snapshot")
            .await
            .unwrap();
        let record = common::Sandbox {
            id: id.into(),
            hypervisor: "future-vmm".into(),
            ..Default::default()
        };
        let persisted = burrow_store::SandboxRow {
            suspended_at: 1,
            id: id.into(),
            template: "default".into(),
            record: prost::Message::encode_to_vec(&record),
            state: common::SandboxState::Suspended.into(),
            lease_block: 0,
            tap: "bt0".into(),
            ports: vec![],
            share: Default::default(),
        };
        manager.store.put_sandbox(&persisted).await.unwrap();

        manager.recover().await;

        assert_eq!(manager.store.list_sandboxes().await.unwrap().len(), 1);
        assert_eq!(manager.sandboxes.lock().await.len(), 0);
        assert!(workdir.join("snapshot.future").exists());
        tokio::fs::remove_dir_all(&data_dir).await.ok();
    }

    #[tokio::test]
    async fn a_persisted_record_carries_its_secrets_sealed() {
        let manager = manager().await;
        let mut record = common::Sandbox {
            id: "sbx_a".into(),
            policy: Some(common::Policy {
                network: Some(common::NetworkPolicy {
                    rules: vec![common::RequestRule {
                        domain: "api.example.com".into(),
                        r#match: None,
                        action: Some(common::request_rule::Action::SetHeaders(
                            common::SetHeaders {
                                headers: vec![common::HeaderValue {
                                    name: "Authorization".into(),
                                    value: "Bearer token".into(),
                                }],
                            },
                        )),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            kit_credentials: [("github".to_string(), "ghp_x".to_string())].into(),
            ..Default::default()
        };
        seal_secrets(&manager.vault, &mut record).unwrap();
        let encoded = prost::Message::encode_to_vec(&record);
        assert!(!String::from_utf8_lossy(&encoded).contains("Bearer token"));
        assert!(!String::from_utf8_lossy(&encoded).contains("ghp_x"));
        open_secrets(&manager.vault, &mut record).unwrap();
        assert_eq!(record.kit_credentials["github"], "ghp_x");
        let mut moved = record.clone();
        moved.id = "sbx_b".into();
        seal_secrets(&manager.vault, &mut moved).unwrap();
        moved.id = "sbx_a".into();
        assert!(open_secrets(&manager.vault, &mut moved).is_err());
    }

    /// A fork of a sandbox this node does not hold must fail before it claims
    /// an id, or a mistyped source would reserve a child id nothing releases.
    #[tokio::test]
    async fn forking_an_unknown_sandbox_reserves_nothing() {
        let manager = manager().await;
        let err = manager
            .fork(
                "sbx_missing",
                "sbx_child".into(),
                None,
                "node1".into(),
                String::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(
            manager.creating.lock().await.is_empty(),
            "the child id was left claimed"
        );
    }

    /// Every shape a warm build has been started for, across templates.
    fn attempted(manager: &SandboxManager) -> Vec<ShapeKey> {
        manager
            .warm_shapes
            .lock()
            .unwrap()
            .values()
            .flat_map(|shapes| shapes.attempted.clone())
            .collect()
    }

    fn shape(vcpus: u32, mem_mib: u32) -> common::ResourcePolicy {
        common::ResourcePolicy {
            vcpus,
            mem_mib,
            ..Default::default()
        }
    }

    /// A warm build costs a boot and blocks every other one, so a burst of
    /// creates of one shape must queue a single build, not one each.
    #[tokio::test]
    async fn a_shape_is_warmed_at_most_once() {
        let manager = manager().await;
        for _ in 0..5 {
            manager.warm_in_background("app".into(), shape(2, 1024));
        }
        assert_eq!(attempted(&manager).len(), 1);

        // A different shape is a different snapshot, so it gets its own
        // attempt; the same shape spelled as defaults does not, and neither
        // does the same machine with another disk.
        manager.warm_in_background("app".into(), shape(4, 1024));
        manager.warm_in_background("app".into(), common::ResourcePolicy::default());
        manager.warm_in_background("app".into(), shape(1, 512));
        manager.warm_in_background(
            "app".into(),
            common::ResourcePolicy {
                disk_mib: 4096,
                ..shape(4, 1024)
            },
        );
        assert_eq!(attempted(&manager).len(), 3);

        // And a template of its own, however alike its shape.
        manager.warm_in_background("other".into(), shape(2, 1024));
        assert_eq!(attempted(&manager).len(), 4);
    }

    /// A republished template's old snapshots restore a guest onto a rootfs
    /// it never saw, so invalidating must both discard every shape and let
    /// the replacements be built.
    #[tokio::test]
    async fn republishing_a_template_discards_its_warm_snapshots() {
        let manager = manager().await;
        manager.warm_in_background("app".into(), shape(2, 1024));
        manager.warm_in_background("app".into(), shape(4, 2048));
        manager.warm_in_background("other".into(), shape(2, 1024));

        let warm = crate::warm::warm_dir(&manager.config.templates_dir(), "app");
        for name in ["firecracker-2x1024", "firecracker-4x2048"] {
            tokio::fs::create_dir_all(warm.join(name)).await.unwrap();
            tokio::fs::write(
                warm.join(name)
                    .join(burrow_vmm::firecracker::SNAPSHOT_MEM_FILE),
                b"stale",
            )
            .await
            .unwrap();
        }

        manager.invalidate_warm("app").await;

        assert!(!tokio::fs::try_exists(&warm).await.unwrap());
        // Every shape of that template, and nothing of any other.
        let attempts = attempted(&manager);
        assert!(attempts.iter().all(|key| key.template == "other"));
        assert_eq!(attempts.len(), 1);
    }

    /// The shapes come from create requests, so a caller naming a fresh one
    /// every time must not be able to grow this for the life of the node.
    #[tokio::test]
    async fn demand_and_attempts_stay_bounded() {
        let manager = manager().await;
        for mem in 0..1000u32 {
            manager.warm_for_demand(&ShapeKey::of("app", &shape(2, 1000 + mem)));
        }
        let shapes = manager.warm_shapes.lock().unwrap();
        assert!(shapes["app"].demand.len() <= MAX_TRACKED_SHAPES);
        assert_eq!(shapes["app"].attempted.len(), MAX_TRACKED_SHAPES);
        // Oldest first: the earliest shapes are the ones forgotten.
        assert_eq!(shapes["app"].attempted[0].mem_mib, 1984);
    }

    /// Past one create, a shape has to recur `--warm-demand` times before it
    /// is worth a boot; pinned shapes are warmed on sight whatever it is.
    #[test]
    fn demand_is_counted_against_the_threshold() {
        let policy = crate::warm::WarmPolicy {
            demand: 3,
            ..Default::default()
        };
        let mut shapes = WarmShapes::default();
        let key = ShapeKey::of("app", &shape(4, 2048));
        assert!(!shapes.record_demand(&key, &policy));
        assert!(!shapes.record_demand(&key, &policy));
        assert!(shapes.record_demand(&key, &policy));
        let default = ShapeKey::of("app", &common::ResourcePolicy::default());
        assert!(shapes.record_demand(&default, &policy));
        // The default, 1, warms a shape on its first use.
        let mut shapes = WarmShapes::default();
        assert!(shapes.record_demand(&key, &Default::default()));
    }

    /// A shape firecracker would refuse is not worth an attempt, and must not
    /// be recorded as one either.
    #[tokio::test]
    async fn an_unbuildable_shape_is_not_attempted() {
        let manager = manager().await;
        manager.warm_in_background("app".into(), shape(1, u32::MAX));
        assert!(attempted(&manager).is_empty());
    }

    /// The demand path warms the shape that was asked for, not the default:
    /// a snapshot of the wrong shape is one no create can restore from.
    #[tokio::test]
    async fn demand_warms_the_shape_that_was_asked_for() {
        let manager = manager().await;
        manager.warm_for_demand(&ShapeKey::of("app", &shape(4, 2048)));
        let attempts = attempted(&manager);
        let key = attempts.first().expect("an attempt was recorded");
        assert_eq!((key.vcpus, key.mem_mib), (4, 2048));
        assert_eq!(key.template, "app");
    }

    /// A snapshot with a file gone used to stay, its shape still recorded as
    /// attempted, so every create of it booted cold until a restart. It
    /// goes, and its shape is built again.
    #[tokio::test]
    async fn a_broken_warm_snapshot_is_discarded_and_rebuilt() {
        let manager = manager().await;
        let dir = crate::warm::warm_dir(&manager.config.templates_dir(), "app")
            .join("firecracker-2x2048-16384");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let layout = Hypervisor::Firecracker.layout();
        for file in layout.files() {
            tokio::fs::write(dir.join(file), b"x").await.unwrap();
        }
        for (file, text) in [
            ("hypervisor", "firecracker"),
            ("shape", "2 2048 1324 16384"),
            ("format", "7"),
        ] {
            tokio::fs::write(dir.join(file), text).await.unwrap();
        }

        let wanted = crate::warm::Shape::wanted(&shape(2, 2048));
        manager
            .rebuild_if_broken("app", Hypervisor::Firecracker, wanted)
            .await;

        assert!(!tokio::fs::try_exists(&dir).await.unwrap());
        assert_eq!(
            attempted(&manager),
            vec![ShapeKey::of("app", &shape(2, 2048))]
        );
    }

    /// An evicted shape, and one the node declined to build, are given back
    /// so the next create asking for them builds them again.
    #[tokio::test]
    async fn a_forgotten_shape_can_be_warmed_again() {
        let manager = manager().await;
        manager.warm_in_background("app".into(), shape(2, 2048));
        let key = ShapeKey::of("app", &shape(2, 2048));
        manager.forget_warm(&key);
        assert!(attempted(&manager).is_empty());
        manager.warm_in_background("app".into(), shape(2, 2048));
        assert_eq!(attempted(&manager), vec![key]);
    }

    /// A chain longer than the cap is what a failed compaction leaves behind,
    /// and it is still valid: flattening happens *after* the diff that exceeds
    /// the cap is written.
    #[tokio::test]
    async fn a_memory_chain_past_the_cap_is_discovered_whole() {
        let dir = std::env::temp_dir().join(format!("burrow-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing at all until there is a base image to build a chain on.
        assert!(
            discover_memory_chain(&dir, Hypervisor::Firecracker.layout())
                .await
                .is_empty()
        );

        std::fs::write(
            dir.join(burrow_vmm::firecracker::SNAPSHOT_MEM_FILE),
            b"base",
        )
        .unwrap();
        // Two past the cap, and written out of order so nothing can be reading
        // the directory's order as the chain's.
        for index in [3usize, 1, 6, 2, 5, 4] {
            std::fs::write(dir.join(format!("snapshot.diff{index}.mem")), b"diff").unwrap();
        }
        // Names that are nearly a diff but are not one.
        std::fs::write(dir.join("snapshot.diff.mem"), b"no index").unwrap();
        std::fs::write(dir.join("snapshot.diffx.mem"), b"not a number").unwrap();
        std::fs::write(dir.join("scratch.ext4"), b"unrelated").unwrap();

        assert_eq!(
            discover_memory_chain(&dir, Hypervisor::Firecracker.layout()).await,
            vec![
                burrow_vmm::firecracker::SNAPSHOT_MEM_FILE.to_string(),
                "snapshot.diff1.mem".to_string(),
                "snapshot.diff2.mem".to_string(),
                "snapshot.diff3.mem".to_string(),
                "snapshot.diff4.mem".to_string(),
                "snapshot.diff5.mem".to_string(),
                "snapshot.diff6.mem".to_string(),
            ]
        );

        // A gap means a diff is missing, and everything past it describes
        // memory that is no longer on disk.
        std::fs::remove_file(dir.join("snapshot.diff3.mem")).unwrap();
        assert_eq!(
            discover_memory_chain(&dir, Hypervisor::Firecracker.layout()).await,
            vec![
                burrow_vmm::firecracker::SNAPSHOT_MEM_FILE.to_string(),
                "snapshot.diff1.mem".to_string(),
                "snapshot.diff2.mem".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tagging_a_sandbox_this_node_does_not_hold_is_refused() {
        let err = manager()
            .await
            .update_tags("sbx_missing", HashMap::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    fn inspected() -> common::Policy {
        common::Policy {
            network: Some(common::NetworkPolicy {
                is_tls_inspected: true,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Writes an image config beside a template, the way an import does.
    async fn with_image_config(manager: &SandboxManager, template: &str, config: &str) {
        let dir = manager.config.templates_dir().join(template);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("image.json"), config)
            .await
            .unwrap();
    }

    /// The bundles an image names in its own environment are the whole point
    /// of the feature: an image like `curlimages/curl` sets
    /// `CURL_CA_BUNDLE=/cacert.pem` and never reads the system store, so an
    /// inspected sandbox that is handed no bundles verifies nothing.
    ///
    /// This is also the regression test for a template that reached the node
    /// by distribution: `image.json` used not to travel with it, so this
    /// returned empty on every node except the one the image was imported on.
    #[tokio::test]
    async fn an_inspected_sandbox_gets_the_bundles_its_image_names() {
        let manager = manager().await;
        with_image_config(
            &manager,
            "curl-image",
            r#"{"env":["PATH=/usr/bin","CURL_CA_BUNDLE=/cacert.pem"],"working_dir":"/"}"#,
        )
        .await;
        manager.set_inspection_ca("-----BEGIN CERTIFICATE-----\n".into(), "ab".into());

        let bundles = manager.trust_bundles_for("curl-image", &inspected()).await;
        assert_eq!(bundles.len(), 1, "the image's bundle was lost: {bundles:?}");
        assert_eq!(bundles[0].path, "/cacert.pem");
        assert!(
            !bundles[0].is_created_if_missing,
            "a full bundle that is absent must not be invented"
        );
    }

    /// An image's environment is no reason to touch the trust stores of a
    /// sandbox that never asked for inspection.
    #[tokio::test]
    async fn a_sandbox_that_did_not_opt_in_gets_no_bundles() {
        let manager = manager().await;
        with_image_config(
            &manager,
            "curl-image-2",
            r#"{"env":["CURL_CA_BUNDLE=/cacert.pem"],"working_dir":"/"}"#,
        )
        .await;
        manager.set_inspection_ca("-----BEGIN CERTIFICATE-----\n".into(), "ab".into());

        assert!(
            manager
                .trust_bundles_for("curl-image-2", &common::Policy::default())
                .await
                .is_empty()
        );
    }

    /// A registered, running sandbox, for tests about what happens after one
    /// exists rather than about how it was built.
    fn running(id: &str) -> Arc<RunningSandbox> {
        let lease = Ipam::for_node(0).unwrap().allocate(id).unwrap();
        let workdir = std::env::temp_dir().join(format!("burrow-test-{id}"));
        Arc::new(RunningSandbox {
            id: id.into(),
            template: "default".into(),
            hypervisor: Hypervisor::Firecracker,
            base_record: std::sync::Mutex::new(common::Sandbox::default()),
            state: std::sync::atomic::AtomicI32::new(common::SandboxState::Running as i32),
            vm: Mutex::new(None),
            spec: std::sync::Mutex::new(VmSpec::new(
                id,
                &workdir,
                burrow_vmm::Backend::Firecracker(burrow_vmm::FirecrackerConfig {
                    bin: "/nonexistent/firecracker".into(),
                    jail: None,
                }),
            )),
            agent_channel: Mutex::new(None),
            agent_features: Mutex::new(None),
            agent_timeout: std::time::Duration::from_millis(1),
            handshake: settled(),
            memory_chain: Mutex::new(Vec::new()),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            suspended_at: std::sync::atomic::AtomicI64::new(0),
            usage: std::sync::Mutex::new(Usage::default()),
            session: std::sync::Mutex::new(None),
            durable: Default::default(),
            logs: Arc::new(crate::cmdlogs::CommandLogs::new(
                &workdir,
                Default::default(),
            )),
            workdir,
            tap: tap::tap_name(&lease),
            lease,
        })
    }

    /// A create, fork or adopt whose rules would not apply used to leave the
    /// sandbox registered and running while telling the caller it failed. It
    /// is now never registered, and is torn down. macOS has no nftables, so
    /// the apply always fails here.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_sandbox_whose_rules_do_not_apply_is_not_left_running() {
        let manager = manager().await;
        let sandbox = running("sbx_unruled");
        tokio::fs::create_dir_all(&sandbox.workdir).await.unwrap();

        let err = manager.register_or_discard(&sandbox).await.unwrap_err();
        assert!(err.message().contains("firewall"), "{}", err.message());
        assert_eq!(manager.sandboxes.lock().await.len(), 0);
        assert!(!sandbox.workdir.exists());
    }

    /// What a warm create gave up when it stopped waiting for the guest: a
    /// sandbox whose agent never comes up is no longer a failed create, so it
    /// has to become a clear error on the first call that needed the guest.
    #[tokio::test]
    async fn a_guest_that_never_answered_is_named_on_the_call_that_needed_it() {
        let sandbox = running("sbx_never_up");
        sandbox
            .handshake
            .send_replace(Handshake::Failed("no answer within 10s".into()));

        let err = sandbox
            .agent()
            .await
            .expect_err("a sandbox with no agent must not hand back a channel");
        let text = err.to_string();
        assert!(
            text.contains("sbx_never_up"),
            "must name the sandbox: {text}"
        );
        assert!(
            text.contains("guest agent never came up"),
            "must blame the agent rather than the network: {text}"
        );
        // And the record says as much on its own, for a reader who never calls.
        assert!(sandbox.record().is_agent_unconfirmed);
    }

    /// The other half: while the handshake is still in flight the call waits
    /// for it rather than reaching a guest that has not been fixed up yet.
    #[tokio::test]
    async fn a_caller_waits_for_a_handshake_that_has_not_landed() {
        let sandbox = running("sbx_pending");
        sandbox.handshake.send_replace(Handshake::Pending);
        assert!(
            sandbox.record().is_agent_unconfirmed,
            "a create that has not been confirmed must not read as plain running"
        );

        let mut waiting = tokio::spawn({
            let sandbox = sandbox.clone();
            async move { sandbox.await_handshake().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiting)
                .await
                .is_err(),
            "the wait must not resolve while the guest is still waking"
        );

        sandbox.handshake.send_replace(Handshake::Done);
        waiting
            .await
            .expect("the waiter must not panic")
            .expect("a landed handshake releases the wait");
        assert!(!sandbox.record().is_agent_unconfirmed);
    }

    /// A move right after a warm create used to snapshot the guest while its
    /// handshake was in flight. The task driving it outlived the VM, retrying
    /// the vsock path, and handshook the sandbox's next VM on this node at the
    /// same time as that VM's own handshake did: the guest's second address add
    /// answered EEXIST and the move back failed.
    #[tokio::test]
    async fn a_suspend_waits_for_a_handshake_in_flight() {
        let sandbox = running("sbx_waking");
        sandbox.handshake.send_replace(Handshake::Pending);

        let mut suspending = tokio::spawn({
            let sandbox = sandbox.clone();
            async move { sandbox.suspend().await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut suspending)
                .await
                .is_err(),
            "a guest still being handshaken must not be snapshotted"
        );

        sandbox.handshake.send_replace(Handshake::Done);
        // The fixture has no VM, so the suspend gets as far as finding none.
        let err = suspending
            .await
            .expect("the suspend must not panic")
            .expect_err("there is no VM to snapshot");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    /// Firecracker's API as far as a boot, a pause and a snapshot need it,
    /// served when the tests run this binary as their VMM. The snapshot lands
    /// after `BURROW_FAKE_FIRECRACKER_SNAPSHOT_MS`.
    #[tokio::test]
    #[ignore = "run by other tests as a fake VMM"]
    async fn fake_firecracker() {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
        let Ok(delay) = std::env::var("BURROW_FAKE_FIRECRACKER_SNAPSHOT_MS") else {
            return;
        };
        let delay = std::time::Duration::from_millis(delay.parse().unwrap());
        let listener = tokio::net::UnixListener::bind(burrow_vmm::firecracker::API_SOCK).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut stream = tokio::io::BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    stream.read_line(&mut header).await.unwrap();
                    let header = header.trim_end().to_ascii_lowercase();
                    if header.is_empty() {
                        break;
                    }
                    if let Some(value) = header.strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                if line.starts_with("PUT /snapshot/create ") {
                    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    tokio::time::sleep(delay).await;
                    for path in ["snapshot_path", "mem_file_path"] {
                        std::fs::write(request[path].as_str().unwrap(), b"snapshot").unwrap();
                    }
                }
                let _ = stream
                    .get_mut()
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await;
            });
        }
    }

    /// A registered sandbox running under [`fake_firecracker`], whose
    /// snapshots take `snapshot_ms`.
    async fn under_fake_vmm(
        manager: &SandboxManager,
        snapshot_ms: u64,
    ) -> (Arc<RunningSandbox>, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        // Short, since the API socket's path has to fit a socket address.
        let workdir = PathBuf::from(format!(
            "/tmp/burrow-vmm-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let bin = workdir.join("firecracker");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nBURROW_FAKE_FIRECRACKER_SNAPSHOT_MS={snapshot_ms} exec '{}' --exact \
                 sandbox::tests::fake_firecracker --ignored --test-threads=1\n",
                std::env::current_exe().unwrap().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sandbox = Arc::new(sandbox_in(workdir.clone()));
        let spec = {
            let mut spec = sandbox.spec.lock().unwrap();
            spec.backend =
                burrow_vmm::Backend::Firecracker(burrow_vmm::FirecrackerConfig { bin, jail: None });
            spec.cgroup_root = None;
            spec.clone()
        };
        *sandbox.vm.lock().await = Some(Vm::boot(spec).await.unwrap());
        manager
            .sandboxes
            .lock()
            .await
            .insert(sandbox.id().to_string(), Arc::clone(&sandbox));
        (sandbox, workdir)
    }

    /// A pause whose caller gave up mid-snapshot used to drop the VM it had
    /// taken out of its slot, leaving a sandbox marked running with no VMM
    /// that every later pause called already suspended. The suspend now runs
    /// to its end without the caller, and the sandbox lands suspended.
    #[tokio::test]
    async fn a_pause_whose_caller_gives_up_mid_snapshot_still_lands() {
        let manager = manager().await;
        let (sandbox, workdir) = under_fake_vmm(&manager, 300).await;

        let id = sandbox.id().to_string();
        let paused = manager.detached(move |manager| async move { manager.pause(&id).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), paused)
                .await
                .is_err(),
            "the caller must give up while the snapshot is still being written"
        );
        assert!(sandbox.is_running(), "the snapshot had not landed yet");

        for _ in 0..500 {
            if !sandbox.is_running() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sandbox.is_suspended());
        assert!(sandbox.vm.lock().await.is_none());
        assert_eq!(*sandbox.memory_chain.lock().await, vec!["snapshot.mem"]);
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A sandbox whose VMM went away under it is not "already suspended": it
    /// is stopped on its disk with the reason, and the pause says so.
    #[tokio::test]
    async fn a_pause_of_a_sandbox_that_lost_its_vmm_stops_it_with_the_reason() {
        let manager = manager().await;
        let sandbox = running("sbx_vmm_gone");
        manager
            .sandboxes
            .lock()
            .await
            .insert(sandbox.id().to_string(), Arc::clone(&sandbox));

        let err = manager.pause("sbx_vmm_gone").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message().contains(REASON_VMM_EXITED),
            "{}",
            err.message()
        );
        let record = sandbox.record();
        assert_eq!(record.state, common::SandboxState::Stopped as i32);
        assert_eq!(record.state_reason, REASON_VMM_EXITED);
    }

    /// A VMM process that exits on its own is noticed, and its sandbox is
    /// stopped with the reason rather than left running with nothing behind it.
    #[tokio::test]
    async fn a_vmm_that_exits_on_its_own_is_noticed() {
        let manager = manager().await;
        let (sandbox, workdir) = under_fake_vmm(&manager, 0).await;
        assert!(!manager.retire_lost_vmm(&sandbox).await);

        let pid = sandbox.vm.lock().await.as_ref().unwrap().pid().unwrap();
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .unwrap();
        let mut retired = false;
        for _ in 0..500 {
            retired = manager.retire_lost_vmm(&sandbox).await;
            if retired {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(retired);
        let record = sandbox.record();
        assert_eq!(record.state, common::SandboxState::Stopped as i32);
        assert_eq!(record.state_reason, REASON_VMM_EXITED);
        assert!(sandbox.vm.lock().await.is_none());
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A boot that never reached its agent used to say only that it timed
    /// out. It names what happened: the guest kernel's panic, the VMM's exit,
    /// or which step ran out of time, with the console's last lines.
    #[tokio::test]
    async fn an_agent_that_never_came_says_why() {
        let manager = manager().await;
        let (sandbox, workdir) = under_fake_vmm(&manager, 0).await;
        let mut slot = sandbox.vm.lock().await;
        let vm = slot.as_mut().unwrap();
        let timeout = std::time::Duration::from_secs(30);

        let reason = no_agent_reason(vm, NoAgent::Unreachable(timeout, "refused".into())).await;
        assert!(
            reason.starts_with("the guest agent made no vsock connection within 30s: refused"),
            "{reason}"
        );
        // The fake VMM is this test binary, whose own output reached the log.
        assert!(reason.contains("running 1 test"), "{reason}");

        let reason = no_agent_reason(vm, NoAgent::Handshake("bad network".into())).await;
        assert!(
            reason.contains("its handshake failed: bad network"),
            "{reason}"
        );

        std::fs::write(
            workdir.join(burrow_vmm::console::LOG),
            "booting\n[ 0.9] Kernel panic - not syncing: No working init found.\n",
        )
        .unwrap();
        let reason = no_agent_reason(vm, NoAgent::Unreachable(timeout, "refused".into())).await;
        assert!(
            reason.starts_with("the guest kernel panicked: [ 0.9] Kernel panic - not syncing: No working init found."),
            "{reason}"
        );
        assert!(
            reason.contains("console, last 30 lines:\nbooting"),
            "{reason}"
        );

        std::fs::write(workdir.join(burrow_vmm::console::LOG), "unknown option\n").unwrap();
        let pid = vm.pid().unwrap();
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .unwrap();
        for _ in 0..500 {
            if vm.has_exited() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let reason = no_agent_reason(vm, NoAgent::Unreachable(timeout, "refused".into())).await;
        assert!(reason.starts_with("the VMM exited ("), "{reason}");
        assert!(reason.contains("unknown option"), "{reason}");
        drop(slot);
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A sandbox that is not running used to be resized, and a suspended
    /// one shut down for it, before anything asked whether the new shape fit
    /// the node. A shape that does not fit is refused with the shortfall, and
    /// the sandbox is left exactly as it was.
    #[tokio::test]
    async fn a_shape_the_node_has_no_room_for_changes_nothing() {
        let manager = manager().await;
        let stopped = running("sbx_stopped");
        stopped.set_state(common::SandboxState::Stopped);
        let suspended = running("sbx_suspended");
        suspended.enter_suspended();
        for sandbox in [&stopped, &suspended] {
            manager
                .sandboxes
                .lock()
                .await
                .insert(sandbox.id().to_string(), Arc::clone(sandbox));
        }
        let before = (stopped.vcpus(), stopped.mem_mib());

        let err = manager
            .update_machine(
                "sbx_stopped",
                None,
                Some(64 << 20),
                None,
                LimitsUpdate::default(),
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(
            err.message().contains("MiB more do not fit"),
            "{}",
            err.message()
        );

        let err = manager
            .update_machine(
                "sbx_stopped",
                Some(node_cpus() * 64),
                None,
                None,
                LimitsUpdate::default(),
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(
            err.message().contains("more do not fit"),
            "{}",
            err.message()
        );
        assert_eq!((stopped.vcpus(), stopped.mem_mib()), before);

        let err = manager
            .update_machine(
                "sbx_suspended",
                None,
                Some(64 << 20),
                None,
                LimitsUpdate::default(),
                true,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(
            suspended.is_suspended(),
            "nothing may be discarded for a shape that does not fit"
        );
    }

    /// A stop used to discard a suspended sandbox's snapshot outright, and
    /// with it whatever its guest had not written back. It resumes the guest
    /// to shut it down; one that cannot be resumed is still stopped on its
    /// disk, and the reason says its memory went and why.
    #[tokio::test]
    async fn a_suspended_sandbox_that_cannot_resume_is_stopped_with_the_reason() {
        let manager = manager().await;
        let workdir = std::env::temp_dir().join(format!(
            "burrow-stop-suspended-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        for file in ["snapshot.vmstate", "snapshot.mem"] {
            std::fs::write(workdir.join(file), b"x").unwrap();
        }
        let sandbox = Arc::new(sandbox_in(workdir.clone()));
        sandbox.enter_suspended();
        *sandbox.memory_chain.lock().await = vec!["snapshot.mem".into()];
        manager
            .sandboxes
            .lock()
            .await
            .insert(sandbox.id().to_string(), Arc::clone(&sandbox));

        let record = manager.stop("sbx_a").await.unwrap();
        assert_eq!(record.state, common::SandboxState::Stopped as i32);
        assert!(
            record.state_reason.starts_with(REASON_MEMORY_DISCARDED),
            "{}",
            record.state_reason
        );
        assert!(
            record.state_reason.contains("restore failed"),
            "the resume must have been tried first: {}",
            record.state_reason
        );
        assert!(!workdir.join("snapshot.mem").exists());
        assert!(sandbox.memory_chain.lock().await.is_empty());
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A suspend whose upload failed whole, the store throttling every try,
    /// used to stay on its node until its next suspend. The upload is tried
    /// again behind it until it lands.
    #[tokio::test]
    async fn a_failed_upload_is_retried_in_the_background_until_it_lands() {
        use std::sync::atomic::Ordering;
        let mut manager = manager().await;
        let (store, faults) =
            crate::objstore::fake::faulty(crate::objstore::fake::options(1, 32, 8)).await;
        manager.config.object_store = Some(store);
        let workdir =
            std::env::temp_dir().join(format!("burrow-requeue-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&workdir).unwrap();
        for file in [
            TEMPLATE_KERNEL,
            TEMPLATE_ROOTFS,
            "snapshot.vmstate",
            "snapshot.mem",
            crate::rootdisk::ROOT_DISK,
        ] {
            std::fs::write(workdir.join(file), vec![7u8; 8192]).unwrap();
        }
        let sandbox = Arc::new(sandbox_in(workdir.clone()));
        sandbox.enter_suspended();
        *sandbox.memory_chain.lock().await = vec!["snapshot.mem".into()];
        faults.slow_downs.store(usize::MAX, Ordering::Relaxed);

        manager.spawn_upload(&sandbox);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!sandbox.durable.is_current());

        faults.slow_downs.store(0, Ordering::Relaxed);
        for _ in 0..500 {
            if sandbox.durable.is_current() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(sandbox.durable.is_current());
        assert!(sandbox.record().is_durable);
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A resume ends the retries: the guest is running again, and what it was
    /// is no longer worth storing.
    #[tokio::test]
    async fn a_resume_cancels_the_upload_retries() {
        use std::sync::atomic::Ordering;
        let mut manager = manager().await;
        let (store, faults) =
            crate::objstore::fake::faulty(crate::objstore::fake::options(1, 32, 8)).await;
        manager.config.object_store = Some(store);
        let workdir =
            std::env::temp_dir().join(format!("burrow-requeue-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&workdir).unwrap();
        let sandbox = Arc::new(sandbox_in(workdir.clone()));
        sandbox.enter_suspended();
        faults.slow_downs.store(usize::MAX, Ordering::Relaxed);

        manager.spawn_upload(&sandbox);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let uploading = sandbox.durable.stop_uploading().await;
        sandbox.set_state(common::SandboxState::Running);
        drop(uploading);
        faults.slow_downs.store(0, Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!sandbox.durable.is_current());
        assert!(!sandbox.durable.has_stored());
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A warm create returns before its guest has answered, so the handshake
    /// task is the only thing left that learns the guest never came. It used to
    /// record the failure and leave the sandbox registered, holding its tap,
    /// its address lease and its working directory until something deleted it,
    /// which nothing would: the create looked like it had succeeded.
    #[tokio::test]
    async fn a_terminal_handshake_failure_reclaims_the_sandbox() {
        let manager = manager().await;
        let sandbox = running("sbx_no_agent");
        // The registry and the allocator as a warm create leaves them: the
        // record is registered and its lease is held.
        let (id, block) = (sandbox.id(), sandbox.lease.block);
        manager.ipam.lock().await.reserve(id, block).unwrap();
        manager
            .sandboxes
            .lock()
            .await
            .insert(sandbox.id().to_string(), sandbox.clone());
        sandbox.handshake.send_replace(Handshake::Pending);

        // There is no guest behind that working directory, so the handshake can
        // only end one way.
        spawn_handshake(
            &manager,
            &sandbox,
            burrow_proto::guest::v1::HandshakeRequest::default(),
            None,
            std::time::Duration::from_millis(1),
        );
        // The registry's reference is the one that matters; a test holding
        // another would look like an in-flight request.
        drop(sandbox);

        // The lease goes back last, after the registry entry and the firewall
        // re-render, so it is the condition to wait on.
        for _ in 0..200 {
            if manager.ipam.lock().await.get("sbx_no_agent").is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            manager.sandboxes.lock().await.is_empty(),
            "a sandbox whose agent never came up was left registered"
        );
        assert!(
            manager.ipam.lock().await.get("sbx_no_agent").is_none(),
            "its address lease was not released"
        );
    }

    fn suspended_sandbox() -> RunningSandbox {
        sandbox_in(std::path::PathBuf::from("/tmp/burrow-test"))
    }

    fn sandbox_in(workdir: std::path::PathBuf) -> RunningSandbox {
        let lease = Ipam::for_node(0).unwrap().allocate("sbx_a").unwrap();
        RunningSandbox {
            id: "sbx_a".into(),
            template: "default".into(),
            hypervisor: Hypervisor::Firecracker,
            base_record: std::sync::Mutex::new(common::Sandbox::default()),
            state: std::sync::atomic::AtomicI32::new(common::SandboxState::Running as i32),
            vm: Mutex::new(None),
            spec: std::sync::Mutex::new(VmSpec::new(
                "sbx_a",
                &workdir,
                burrow_vmm::Backend::Firecracker(burrow_vmm::FirecrackerConfig {
                    bin: "/nonexistent/firecracker".into(),
                    jail: None,
                }),
            )),
            agent_channel: Mutex::new(None),
            agent_features: Mutex::new(None),
            agent_timeout: std::time::Duration::from_millis(1),
            handshake: settled(),
            memory_chain: Mutex::new(Vec::new()),
            last_activity: std::sync::atomic::AtomicI64::new(burrow_common::unix_now()),
            suspended_at: std::sync::atomic::AtomicI64::new(0),
            usage: std::sync::Mutex::new(Usage::default()),
            session: std::sync::Mutex::new(None),
            durable: Default::default(),
            logs: Arc::new(crate::cmdlogs::CommandLogs::new(
                &workdir,
                Default::default(),
            )),
            workdir,
            tap: tap::tap_name(&lease),
            lease,
        }
    }

    /// A suspend syncs the state, then the memory it wrote, then every disk
    /// the guest can write, then the directory, and only then reports. Disks
    /// the guest cannot write are not synced: nothing of the guest's is in them.
    #[tokio::test]
    async fn a_suspend_syncs_state_memory_and_writable_disks_then_the_directory() {
        let workdir = std::env::temp_dir().join(format!(
            "burrow-suspend-sync-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let sandbox = sandbox_in(workdir.clone());
        sandbox.spec.lock().unwrap().drives = vec![
            DriveSpec::root_rw(crate::rootdisk::ROOT_DISK),
            DriveSpec {
                id: "volume0".into(),
                path: volume_image(0),
                is_root: false,
                is_read_only: false,
            },
            DriveSpec {
                id: "volume1".into(),
                path: volume_image(1),
                is_root: false,
                is_read_only: true,
            },
        ];
        let diff = Layout::diff(1);
        for name in [
            "snapshot.vmstate",
            diff.as_str(),
            TEMPLATE_ROOTFS,
            crate::rootdisk::ROOT_DISK,
            &volume_image(0),
            &volume_image(1),
        ] {
            std::fs::write(workdir.join(name), b"x").unwrap();
        }

        sandbox.sync_snapshot(Some(&diff)).await.unwrap();

        use crate::fsync::Synced;
        assert_eq!(
            crate::fsync::record::under(&workdir),
            vec![
                Synced::File(workdir.join("snapshot.vmstate")),
                Synced::File(workdir.join(&diff)),
                Synced::File(workdir.join(crate::rootdisk::ROOT_DISK)),
                Synced::File(workdir.join(volume_image(0))),
                Synced::Dir(workdir.clone()),
            ]
        );
        let _ = std::fs::remove_dir_all(&workdir);
    }

    /// A suspend whose files cannot be synced fails rather than reporting a
    /// state that may not be on the disk.
    #[tokio::test]
    async fn a_suspend_that_cannot_sync_fails() {
        let workdir = std::env::temp_dir().join(format!(
            "burrow-suspend-nosync-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&workdir).unwrap();
        let sandbox = sandbox_in(workdir.clone());
        sandbox.spec.lock().unwrap().drives =
            vec![DriveSpec::scratch_rw(crate::rootdisk::ROOT_DISK)];
        std::fs::write(workdir.join("snapshot.vmstate"), b"x").unwrap();
        // No memory file: the snapshot did not land, so the suspend must not.
        let err = sandbox
            .sync_snapshot(Some("snapshot.mem"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(
            !crate::fsync::record::under(&workdir)
                .contains(&crate::fsync::Synced::Dir(workdir.clone()))
        );
        let _ = std::fs::remove_dir_all(&workdir);
    }

    #[test]
    fn a_full_suspend_of_a_macos_style_layout_syncs_its_state_disk_and_aux() {
        let layout = Layout {
            state: "save.vzvmsave",
            memory: None,
        };
        assert_eq!(
            suspend_sync_order(
                layout,
                layout.memory,
                vec!["disk.img".into(), "aux.img".into()]
            ),
            ["save.vzvmsave", "disk.img", "aux.img"]
        );
    }

    /// A resume builds a new cgroup and a firewall re-render rebuilds the byte
    /// counters, so both restart at zero while the sandbox has not. A total
    /// that followed the counters would fall.
    #[test]
    fn usage_totals_survive_the_counters_being_replaced() {
        let mut usage = Usage::default();
        usage.advance(
            Some(1_000),
            Some(firewall::Traffic {
                rx_bytes: 100,
                tx_bytes: 200,
            }),
        );
        usage.advance(
            Some(1_500),
            Some(firewall::Traffic {
                rx_bytes: 150,
                tx_bytes: 200,
            }),
        );
        assert_eq!(
            (usage.cpu_usec, usage.rx_bytes, usage.tx_bytes),
            (1_500, 150, 200)
        );

        // Both counters are replaced and start again from a smaller value.
        usage.advance(
            Some(40),
            Some(firewall::Traffic {
                rx_bytes: 10,
                tx_bytes: 5,
            }),
        );
        assert_eq!(
            (usage.cpu_usec, usage.rx_bytes, usage.tx_bytes),
            (1_540, 160, 205)
        );

        // A sample with nothing to read leaves the totals where they were.
        usage.advance(None, None);
        assert_eq!(usage.cpu_usec, 1_540);
    }

    /// What reaches a suspended sandbox's tap reaches no guest, so it moves
    /// the baseline and not the total.
    #[test]
    fn bytes_reaching_a_parked_sandbox_are_not_counted() {
        let traffic = |rx_bytes, tx_bytes| firewall::Traffic { rx_bytes, tx_bytes };
        let mut usage = Usage::default();
        usage.advance(None, Some(traffic(100, 50)));
        usage.rebase(traffic(400, 60));
        usage.advance(None, Some(traffic(450, 70)));
        assert_eq!((usage.rx_bytes, usage.tx_bytes), (150, 60));
    }

    /// The work of restoring a VM used to land in the suspended interval its
    /// `started` event ended. That event now carries the totals from before
    /// the restore, so the running interval it starts has it.
    #[tokio::test]
    async fn a_started_event_is_bounded_by_the_totals_before_the_vm() {
        let manager = manager().await;
        let sandbox = running("sbx_resumed");
        sandbox.base_record.lock().unwrap().id = "sbx_resumed".into();
        sandbox.usage.lock().unwrap().cpu_usec = 1_000;
        let before = sandbox.totals();
        sandbox.usage.lock().unwrap().advance(Some(5_300_000), None);
        manager
            .open_session(&sandbox, STARTED_RESUME, Some(before))
            .await;
        let started = events_of(&manager, "sbx_resumed").await.pop().unwrap();
        assert_eq!(started.kind, EVENT_STARTED as i32);
        assert_eq!(started.cpu_usage_usec, 1_000);
        assert_eq!(sandbox.record().cpu_usage_usec, 5_301_000);
    }

    /// A sandbox reports what it has spent, not what its current VM has: the
    /// figures are read off the record and have to include the VMs it already
    /// ran.
    #[test]
    fn a_record_carries_the_running_totals() {
        let sandbox = suspended_sandbox();
        sandbox.usage.lock().unwrap().advance(
            Some(2_000),
            Some(firewall::Traffic {
                rx_bytes: 42,
                tx_bytes: 7,
            }),
        );
        let record = sandbox.record();
        assert_eq!(record.cpu_usage_usec, 2_000);
        assert_eq!((record.rx_bytes, record.tx_bytes), (42, 7));
    }

    /// Retention is measured from the moment a sandbox was parked, not from
    /// the last time anyone used it: a resume restarts the clock, and a
    /// sandbox that was never suspended has no clock at all.
    #[test]
    fn the_retention_clock_runs_only_while_suspended() {
        let sandbox = suspended_sandbox();
        assert_eq!(sandbox.suspended_secs(), 0);
        assert_eq!(sandbox.suspended_at(), 0);

        sandbox.enter_suspended();
        assert!(sandbox.suspended_at() > 0);
        // Backdated, because a test cannot wait out a real TTL.
        sandbox.suspended_at.store(
            burrow_common::unix_now() - 120,
            std::sync::atomic::Ordering::Relaxed,
        );
        assert!(sandbox.suspended_secs() >= 120);

        sandbox
            .suspended_at
            .store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(sandbox.suspended_secs(), 0);
    }

    /// The semantics that would be easiest to get wrong: a caller tightening
    /// files must not re-open exec on the way past.
    #[test]
    fn an_absent_section_leaves_that_policy_alone() {
        let mut policy = common::Policy {
            exec: Some(common::ExecPolicy {
                is_exec_allowed: false,
            }),
            fs: Some(common::FsPolicy {
                is_upload_allowed: true,
                is_download_allowed: true,
                path_scopes: vec!["/work".into()],
                max_upload_bytes: 0,
            }),
            ..Default::default()
        };

        apply_access_policy(
            &mut policy,
            None,
            Some(common::FsPolicy {
                is_upload_allowed: false,
                is_download_allowed: true,
                path_scopes: vec!["/data".into()],
                max_upload_bytes: 64,
            }),
        );

        assert!(
            !policy.exec.as_ref().unwrap().is_exec_allowed,
            "an untouched exec policy was re-opened"
        );
        let fs = policy.fs.as_ref().unwrap();
        assert!(!fs.is_upload_allowed);
        assert_eq!(fs.path_scopes, vec!["/data".to_string()]);
        assert_eq!(fs.max_upload_bytes, 64);
    }

    /// And the other way: exec moves without disturbing the fs scopes.
    #[test]
    fn a_present_section_replaces_that_policy_wholesale() {
        let mut policy = common::Policy {
            exec: Some(common::ExecPolicy {
                is_exec_allowed: false,
            }),
            fs: Some(common::FsPolicy {
                is_upload_allowed: false,
                is_download_allowed: false,
                path_scopes: vec!["/work".into()],
                max_upload_bytes: 8,
            }),
            ..Default::default()
        };

        apply_access_policy(
            &mut policy,
            Some(common::ExecPolicy {
                is_exec_allowed: true,
            }),
            None,
        );

        assert!(policy.exec.as_ref().unwrap().is_exec_allowed);
        let fs = policy.fs.as_ref().unwrap();
        assert!(!fs.is_upload_allowed, "the fs policy was not left alone");
        assert_eq!(fs.path_scopes, vec!["/work".to_string()]);
        assert_eq!(fs.max_upload_bytes, 8);
    }

    /// A sandbox created without either section can still be tightened, and
    /// gains only the section that was named.
    #[test]
    fn an_unrestricted_sandbox_gains_only_the_named_section() {
        let mut policy = common::Policy::default();
        apply_access_policy(
            &mut policy,
            Some(common::ExecPolicy {
                is_exec_allowed: false,
            }),
            None,
        );
        assert!(!policy.exec.as_ref().unwrap().is_exec_allowed);
        assert!(
            policy.fs.is_none(),
            "an unnamed section must stay absent rather than become permissive"
        );
    }
}
