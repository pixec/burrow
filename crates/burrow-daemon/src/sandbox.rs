//! Node-local sandbox lifecycle.
//!
//! Owns the microVMs running on this node: creating their working directories,
//! booting them, holding the agent connection, and tearing them down.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::{Status, transport::Channel};

use burrow_net::{Ipam, Lease, firewall, tap};
use burrow_proto::common::v1 as common;
use burrow_proto::guest::v1::guest_client::GuestClient;
use burrow_vmm::{DriveSpec, GuestAddr, Hypervisor, Layout, NetSpec, Vm, VmSpec};

use crate::guestconn;

/// Conventional filenames inside a template directory.
const TEMPLATE_KERNEL: &str = "vmlinux";
const TEMPLATE_ROOTFS: &str = "rootfs.ext4";
/// Per-sandbox writable disk, union-mounted over the rootfs by the agent.
const SCRATCH_IMAGE: &str = "scratch.ext4";

/// A volume's image, hard-linked into the sandbox's working directory.
///
/// Linked rather than referenced in place because firecracker takes drive
/// paths relative to the VM's working directory, which under the jailer is the
/// chroot: a path outside it does not exist as far as the VMM is concerned.
/// The link shares the inode, so the volume's bytes are not copied and
/// removing the sandbox's directory does not remove the volume.
fn volume_image(index: usize) -> String {
    format!("volume{index}.ext4")
}
const DEFAULT_SCRATCH_MIB: u32 = 1024;

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
}

impl NodeConfig {
    pub(crate) fn templates_dir(&self) -> PathBuf {
        self.data_dir.join("images")
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
        }
    }

    /// The jail a VM under `hypervisor` runs in, where it can run in one.
    pub(crate) fn jail_for(&self, hypervisor: Hypervisor) -> Option<&burrow_vmm::Jail> {
        // Cloud Hypervisor's own confinement is off only where the operator
        // turned it off: see `--unjailed-cloud-hypervisor`.
        let is_jailed = match hypervisor {
            Hypervisor::Firecracker => true,
            Hypervisor::CloudHypervisor => self.cloud_hypervisor.jail.is_some(),
            #[cfg(target_os = "macos")]
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
            #[cfg(target_os = "macos")]
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
            Some(jail) => jail.chroot_for(id),
            None => self.data_dir.join("sandboxes").join(id),
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
const STARTED_BOOT: &str = "boot";
const STARTED_RESTORE: &str = "restore";
const STARTED_RESUME: &str = "resume";
/// How one stopped.
const ENDED_SUSPENDED: &str = "suspended";
const ENDED_DELETED: &str = "deleted";
const ENDED_FAILED: &str = "failed";
const ENDED_STOPPED: &str = "stopped";
/// A session that was still open when the node died. Nothing observed when its
/// VM stopped, so its end time stays unset rather than being invented.
const ENDED_UNKNOWN: &str = "unknown";

/// Event kinds, as the log records them. A sandbox's life reads
/// created, started, agent_ready, then stopped and started per suspend and
/// resume, then destroyed; snapshot_created sits wherever a commit happened.
const EVENT_CREATED: &str = "created";
const EVENT_STARTED: &str = "started";
const EVENT_AGENT_READY: &str = "agent_ready";
const EVENT_STOPPED: &str = "stopped";
const EVENT_DESTROYED: &str = "destroyed";
const EVENT_SNAPSHOT_CREATED: &str = "snapshot_created";

fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn event_to_proto(row: burrow_store::EventRow) -> common::Event {
    common::Event {
        seq: row.seq,
        node_id: row.node_id,
        node_seq: row.node_seq,
        at_unix_ms: row.at_unix_ms,
        sandbox_id: row.sandbox_id,
        r#type: row.kind,
        state: row.state,
        detail: row.detail,
        template: row.template,
        metadata: serde_json::from_str(&row.metadata_json).unwrap_or_default(),
        cpu_usage_usec: row.cpu_usage_usec,
        rx_bytes: row.rx_bytes,
        tx_bytes: row.tx_bytes,
        vcpus: row.vcpus,
        mem_mib: row.mem_mib,
    }
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
        let _ = tokio::fs::remove_dir_all(&self.workdir).await;
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
                let _ = tokio::fs::remove_dir_all(&workdir).await;
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
fn spawn_handshake(
    manager: &SandboxManager,
    sandbox: &Arc<RunningSandbox>,
    request: burrow_proto::guest::v1::HandshakeRequest,
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
        let outcome = match tokio::time::timeout(timeout, async {
            let (agent, _) = guestconn::connect_when_ready(guest.clone(), timeout).await?;
            *step.lock().unwrap() = "waiting for the agent to answer the handshake";
            let (agent, _) =
                guestconn::handshake_upgrading(agent, guest, request, upgrade.as_deref(), timeout)
                    .await?;
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
                let console = match &*sandbox.vm.lock().await {
                    Some(vm) => vm.console_tail(30).await,
                    None => String::new(),
                };
                tracing::error!(
                    sandbox = id,
                    %err,
                    console,
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
    /// sandbox is stamped with the requesting caller's policy and metadata
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
        if record.is_durable
            && let Some(stored) = self.durable.stored.lock().unwrap().as_ref()
        {
            record.arch = stored.manifest.arch.clone();
            record.firecracker_version = stored.manifest.firecracker_version.clone();
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

    /// Folds a reading of this sandbox's byte counters into its totals.
    fn absorb_traffic(&self, traffic: firewall::Traffic) {
        self.usage.lock().unwrap().advance(None, Some(traffic));
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

    /// The overlay scratch disk backing this sandbox's writable filesystem.
    pub fn scratch_path(&self) -> PathBuf {
        self.workdir.join(SCRATCH_IMAGE)
    }

    /// The template this sandbox was created from.
    pub fn template(&self) -> &str {
        &self.template
    }

    fn layout(&self) -> Layout {
        self.hypervisor.layout()
    }

    /// vCPUs this sandbox is promised, whether or not its VMM is running.
    pub fn vcpus(&self) -> u32 {
        self.spec.lock().unwrap().vcpus
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

    fn resources(&self) -> common::ResourcePolicy {
        self.base_record
            .lock()
            .unwrap()
            .policy
            .as_ref()
            .and_then(|policy| policy.resources)
            .unwrap_or_default()
    }

    /// Seconds since creation, or 0 if the record's timestamp is unreadable.
    /// 0 reads as "brand new", so an unparseable timestamp never causes a
    /// deletion.
    fn age_secs(&self) -> i64 {
        burrow_common::unix_from_rfc3339(&self.base_record.lock().unwrap().created_at)
            .map(|created| burrow_common::unix_now() - created)
            .unwrap_or(0)
    }

    fn set_state(&self, state: common::SandboxState) {
        self.state
            .store(state as i32, std::sync::atomic::Ordering::Relaxed);
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
    }

    /// Whether the agent says it supports `feature`. An agent that predates
    /// the list says nothing, which reads as no.
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

    /// Starts draining the guest's output feed into this sandbox's logs, if
    /// nothing is yet. Ends with the VM; the next call starts it again.
    pub fn ensure_feed(self: &Arc<Self>) {
        if !self.is_running() || !self.logs.claim_feed() {
            return;
        }
        let weak = Arc::downgrade(self);
        let logs = Arc::clone(&self.logs);
        tokio::spawn(async move {
            if let Err(err) = feed(weak, &logs).await {
                tracing::debug!(%err, "command output feed ended");
            }
            logs.release_feed();
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
        self.forget_agent().await;
        let mut slot = self.vm.lock().await;
        let Some(vm) = slot.take() else {
            return Err(Status::failed_precondition("sandbox is already suspended"));
        };

        // A diff records only the pages touched since the snapshot this VM was
        // restored from, which is nearly always a small fraction of the guest.
        // It is only possible when there is something to diff *against*, and
        // under a hypervisor that can take one.
        let chain = self.memory_chain.lock().await.clone();
        let diff = !chain.is_empty() && vm.capabilities().is_diff_snapshot_supported;
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
        self.absorb_cpu(&vm);

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
            move || Self::merge_chain(&paths, &target)
        })
        .await;

        match merged {
            Ok(Ok(())) => {
                *chain = vec![memory.to_string()];
                drop(chain);
                Self::remove_stale_diffs(&self.workdir).await;
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

    #[cfg(target_os = "linux")]
    fn merge_chain(paths: &[std::path::PathBuf], target: &Path) -> std::io::Result<()> {
        burrow_vmm::merge_chain(paths, target)
    }

    #[cfg(not(target_os = "linux"))]
    fn merge_chain(_paths: &[std::path::PathBuf], _target: &Path) -> std::io::Result<()> {
        Err(std::io::Error::other("merging is linux-only"))
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
        let vm = Vm::restore(spec, true)
            .await
            .map_err(|err| Status::internal(format!("restore failed: {err}")))?;
        // Retried to the deadline, as a warm create's handshake is, and the
        // connection that succeeds is the one kept. Probing first and then
        // dialling again failed a resume outright whenever the second dial was
        // cut off, which a guest still waking does now and then.
        let guest = vm.guest();
        let (agent, _) = guestconn::connect_when_ready(guest.clone(), agent_timeout)
            .await
            .map_err(|err| {
                Status::internal(format!("agent did not come back: {}", error_chain(&*err)))
            })?;

        // `restored: true` is what tells the guest to reseed its RNG and reset
        // its clock, which it cannot know on its own.
        guestconn::handshake_upgrading(
            agent,
            guest,
            guestconn::handshake_request(true),
            upgrade,
            agent_timeout,
        )
        .await?;
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
            self.absorb_cpu(&vm);
            if let Err(err) = vm.kill().await {
                tracing::error!(sandbox = self.id(), %err, "vmm did not stop");
            }
        } else if self.state.load(std::sync::atomic::Ordering::Relaxed)
            != common::SandboxState::Suspended as i32
        {
            return Err(Status::failed_precondition("sandbox is already stopped"));
        }
        // A suspended sandbox's memory is on disk; stopping it discards that
        // too, since a boot must not come back to a snapshot a later resume
        // would restore around.
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
        Ok(())
    }

    /// Cold-boots a stopped sandbox on its existing disks and handshakes.
    #[tracing::instrument(skip_all, fields(sandbox = %self.id()))]
    async fn boot(
        &self,
        spec: VmSpec,
        request: burrow_proto::guest::v1::HandshakeRequest,
        agent_timeout: std::time::Duration,
        upgrade: Option<&guestconn::GuestUpgrade>,
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
        let vm = Vm::boot(spec.clone())
            .await
            .map_err(|err| Status::internal(format!("boot failed: {err}")))?;
        let (agent, _) = match guestconn::connect_when_ready(vm.guest(), agent_timeout).await {
            Ok(ready) => ready,
            Err(err) => {
                let console = vm.console_tail(30).await;
                let _ = vm.kill().await;
                return Err(Status::internal(format!(
                    "agent never became reachable: {err}\nconsole:\n{console}"
                )));
            }
        };
        if let Err(err) =
            guestconn::handshake_upgrading(agent, vm.guest(), request, upgrade, agent_timeout).await
        {
            let _ = vm.kill().await;
            return Err(err);
        }
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
        Ok(())
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
    #[tracing::instrument(skip_all, fields(sandbox = %self.id(), diff))]
    async fn checkpoint(&self) -> Result<(), Status> {
        // As in a suspend: a fork restores whatever the snapshot caught.
        self.await_handshake().await?;
        let mut slot = self.vm.lock().await;
        let Some(vm) = slot.as_ref() else {
            return Err(Status::failed_precondition(
                "sandbox is suspended; resume it first",
            ));
        };

        let chain = self.memory_chain.lock().await.clone();
        let diff = !chain.is_empty() && vm.capabilities().is_diff_snapshot_supported;
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
            // Nothing usable was written; the VM is only paused.
            let _ = vm.resume().await;
            return Err(Status::internal(format!("snapshot failed: {err}")));
        }

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

        if let Err(err) = vm.resume().await {
            let vm = slot.take().expect("the vm was present a moment ago");
            self.forget_agent().await;
            self.enter_suspended();
            self.absorb_cpu(&vm);
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
        Ok(())
    }

    /// Copies everything a fork needs into `dest`, returning the child's
    /// memory chain.
    ///
    /// The VM slot is held throughout, so a suspend, resume or checkpoint
    /// cannot add a layer to the chain half way through copying it.
    ///
    /// The chain is copied whole rather than flattened: the restore path
    /// already reads a chain, being how every suspended sandbox comes back, and
    /// flattening here would put an extra full-image rewrite on the fork's
    /// critical path for a cost the child pays lazily anyway.
    async fn stage_fork(&self, dest: &Path) -> Result<Vec<String>, Status> {
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
        // The one file both sides write: a copy, reflinked where the
        // filesystem supports it, which makes it metadata-only.
        crate::warm::copy_sparse(&self.workdir.join(SCRATCH_IMAGE), &dest.join(SCRATCH_IMAGE))
            .await
            .map_err(|err| io(SCRATCH_IMAGE, err))?;
        Ok(chain)
    }

    /// Copies everything a snapshot object needs into `dest`.
    ///
    /// The same files a fork stages, plus the shape they were taken with:
    /// Firecracker restores a machine configuration from the snapshot rather
    /// than from what a later caller asks for, and a snapshot that outlives its
    /// sandbox has nothing else left to read it from.
    async fn stage_snapshot(&self, dest: &Path) -> Result<crate::snapshot::Staged, Status> {
        let chain = self.stage_fork(dest).await?;
        let resources = self.resources();
        let (vcpus, mem_mib) = {
            let spec = self.spec.lock().unwrap();
            (spec.vcpus, spec.mem_mib)
        };
        Ok(crate::snapshot::Staged {
            sandbox_id: self.id.clone(),
            template: self.template.clone(),
            hypervisor: self.hypervisor,
            vcpus,
            mem_mib,
            scratch_disk_mib: if resources.scratch_disk_mib == 0 {
                DEFAULT_SCRATCH_MIB
            } else {
                resources.scratch_disk_mib
            },
            chain,
        })
    }
}

/// Where the state a new sandbox restores from comes from.
///
/// A live sandbox and a snapshot object hold the same files under the same
/// names, which is what makes both restorable, so they differ only in the copy.
enum RestoreSource<'a> {
    Sandbox(&'a Arc<RunningSandbox>),
    Snapshot {
        id: &'a str,
        template: String,
        hypervisor: Hypervisor,
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
            Self::Sandbox(source) => Ok((source.stage_fork(dest).await?, None)),
            Self::Snapshot { id, .. } => snapshots.stage_into(id, dest).await,
            Self::Stored { store, manifest } => {
                crate::durable::stage(store, snapshots, manifest, dest, logs_dir).await
            }
        }
    }

    fn template(&self) -> String {
        match self {
            Self::Sandbox(source) => source.template().to_string(),
            Self::Snapshot { template, .. } => template.clone(),
            Self::Stored { manifest, .. } => manifest.template.clone(),
        }
    }

    /// The hypervisor the state was written by, which is the only one that
    /// can restore it.
    #[allow(clippy::result_large_err)]
    fn hypervisor(&self) -> Result<Hypervisor, Status> {
        match self {
            Self::Sandbox(source) => Ok(source.hypervisor),
            Self::Snapshot { hypervisor, .. } => Ok(*hypervisor),
            Self::Stored { manifest, .. } => manifest.hypervisor(),
        }
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
    /// PEM handed to sandboxes that opted in to TLS inspection. Set once at
    /// startup, read on every create.
    inspection_ca: Arc<std::sync::Mutex<Option<String>>>,
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
    /// How long this node may go on resuming durable sandboxes without
    /// hearing from the orchestrator.
    lease: Arc<std::sync::Mutex<NodeLease>>,
    /// Sandboxes moved off this node whose teardown is still running, each
    /// gate held until it finishes. A move straight back waits on it, or the
    /// teardown would take the returning sandbox's directory and lease too.
    releasing: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

/// Renewed by every heartbeat the orchestrator answers. Once it runs out the
/// orchestrator may write this node off and let another adopt its durable
/// sandboxes, so from then on this node resumes none of them on its own say.
#[derive(Default)]
struct NodeLease {
    renewed: Option<std::time::Instant>,
    length: std::time::Duration,
}

/// Shapes one template will build a warm snapshot for before it stops.
///
/// A snapshot is disk and a build is a boot, so the node warms a handful of
/// shapes per template rather than every shape anyone has ever asked for. The
/// oldest attempt is forgotten past this, which lets a template whose traffic
/// has moved to a new shape eventually warm it.
const MAX_WARM_SHAPES: usize = 4;

/// Distinct shapes of one template whose demand is counted.
///
/// Only a tally, so it is cheap, but it is keyed by numbers a caller chooses
/// and therefore has to be bounded like everything else. The least-requested
/// entry makes way, which keeps the shapes that recur and drops the one-offs.
const MAX_TRACKED_SHAPES: usize = 16;

/// Creates of one shape before an automatic warm build is worth its cost.
///
/// A template's default shape is exempt: it is what a create with no resource
/// policy asks for, so it is warmed on the first sight of it. Anything else has
/// to recur, because a snapshot built for a shape that is never asked for again
/// is a boot and a memory image spent on nothing.
const WARM_DEMAND_THRESHOLD: u32 = 3;

/// One template's warm bookkeeping.
#[derive(Default)]
struct WarmShapes {
    /// Creates seen per shape, capped at [`MAX_TRACKED_SHAPES`].
    demand: Vec<(ShapeKey, u32)>,
    /// Shapes a build has already been started for, oldest first.
    ///
    /// One attempt per shape while it is remembered: a build holds the node's
    /// warm build lock, and one that failed usually fails again for the same
    /// reason.
    attempted: Vec<ShapeKey>,
}

impl WarmShapes {
    /// Counts one create of `key` and says whether it now deserves a snapshot.
    fn record_demand(&mut self, key: &ShapeKey) -> bool {
        // The shape a create with no resource policy asks for, which is the one
        // an explicit warm builds too: warmed on sight rather than on repetition.
        if key.is_default() {
            return true;
        }
        if let Some(entry) = self.demand.iter_mut().find(|(shape, _)| shape == key) {
            entry.1 = entry.1.saturating_add(1);
            return entry.1 >= WARM_DEMAND_THRESHOLD;
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
        WARM_DEMAND_THRESHOLD <= 1
    }

    /// Claims the one attempt this shape gets, or says it is already taken.
    fn claim_attempt(&mut self, key: &ShapeKey) -> bool {
        if self.attempted.iter().any(|shape| shape == key) {
            return false;
        }
        self.attempted.push(key.clone());
        // Oldest first, so the cap forgets the shape that has gone longest
        // without being asked for rather than refusing the new one: an explicit
        // warm must never be turned away because of what a create asked for.
        if self.attempted.len() > MAX_WARM_SHAPES {
            self.attempted.remove(0);
        }
        true
    }
}

/// The machine a warm snapshot was taken as.
///
/// All of these are fixed when the VM is built and cannot be changed on a
/// running guest, so a create only restores from a snapshot that agrees on
/// every one of them. The scratch disk is included because it is formatted at
/// build time: a caller asking for a larger one must not silently get the
/// size the snapshot was taken with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ShapeKey {
    template: String,
    vcpus: u32,
    mem_mib: u32,
    scratch_disk_mib: u32,
}

impl ShapeKey {
    /// The shape a create that named no resources asks for, which is also the
    /// one an explicit warm builds.
    fn is_default(&self) -> bool {
        *self == Self::of(&self.template, &common::ResourcePolicy::default())
    }

    fn of(template: &str, resources: &common::ResourcePolicy) -> Self {
        Self {
            template: template.to_string(),
            vcpus: resources.vcpus.max(1),
            mem_mib: if resources.mem_mib == 0 {
                512
            } else {
                resources.mem_mib
            },
            scratch_disk_mib: if resources.scratch_disk_mib == 0 {
                DEFAULT_SCRATCH_MIB
            } else {
                resources.scratch_disk_mib
            },
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
            warm_shapes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            firewall: Arc::new(tokio::sync::Mutex::new(())),
            snapshots: Arc::new(crate::snapshot::SnapshotStore::new(
                &config.data_dir,
                config.object_store.clone(),
                Hypervisor::ALL
                    .into_iter()
                    .map(|h| (h, config.version(h).to_string()))
                    .collect(),
            )),
            volumes: Arc::new(crate::volume::VolumeStore::new(&config.data_dir)),
            events: tokio::sync::broadcast::channel(1024).0,
            shares: Arc::new(crate::share::Shares::new(
                config.share.clone(),
                &config.data_dir,
            )),
            config,
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            creating: Arc::new(Mutex::new(std::collections::HashSet::new())),
            // Replaced once the orchestrator assigns this node its slice.
            // Node 0 is the first slice of the pool and always in range, so
            // the only way this fails is a pool with no slices at all.
            ipam: Arc::new(Mutex::new(Arc::new(
                Ipam::for_node(0).expect("node 0 is always inside the address pool"),
            ))),
            ports: Arc::new(Mutex::new(HashMap::new())),
            usernets: Default::default(),
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

    /// Moves a sandbox's files into its jail when they were left outside one:
    /// a Cloud Hypervisor sandbox from before it could be jailed, or from a
    /// run with `--jailer` off. Without this the sandbox would be found with
    /// no snapshot and discarded.
    async fn move_into_jail(&self, id: &str, hypervisor: Hypervisor, workdir: &Path) {
        let Some(jail) = self.config.jail_for(hypervisor) else {
            return;
        };
        let unjailed = self.config.data_dir.join("sandboxes").join(id);
        if tokio::fs::try_exists(workdir).await.unwrap_or(true)
            || !tokio::fs::try_exists(&unjailed).await.unwrap_or(false)
        {
            return;
        }
        let moved = async {
            if let Some(parent) = workdir.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::rename(&unjailed, workdir).await?;
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
                    self.volumes.release_all(sandbox.id());
                    self.close_session(&sandbox, ENDED_SUSPENDED).await;
                    self.persist(&sandbox).await;
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

    /// Appends to the event log and hands the event to anyone following it.
    ///
    /// Written before it is broadcast, and with the position the store gave
    /// it, so a tail that replays and then follows sees every event exactly
    /// once. The usage figures are the sandbox's totals at this instant.
    async fn emit(&self, sandbox: &RunningSandbox, kind: &str, detail: &str) {
        let record = sandbox.record();
        let resources = record
            .policy
            .as_ref()
            .and_then(|p| p.resources)
            .unwrap_or_default();
        let row = burrow_store::EventRow {
            seq: 0,
            node_id: String::new(),
            node_seq: 0,
            at_unix_ms: unix_now_ms(),
            sandbox_id: record.id.clone(),
            kind: kind.to_string(),
            state: record.state,
            detail: detail.to_string(),
            template: record.template.clone(),
            metadata_json: serde_json::to_string(&record.metadata).unwrap_or_else(|_| "{}".into()),
            cpu_usage_usec: record.cpu_usage_usec,
            rx_bytes: record.rx_bytes,
            tx_bytes: record.tx_bytes,
            vcpus: resources.vcpus,
            mem_mib: resources.mem_mib,
        };
        let seq = match self.store.append_event(&row).await {
            Ok(seq) => seq,
            Err(err) => {
                tracing::error!(sandbox = record.id, kind, %err, "could not record an event");
                return;
            }
        };
        let _ = self
            .events
            .send(event_to_proto(burrow_store::EventRow { seq, ..row }));
    }

    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<common::Event> {
        self.events.subscribe()
    }

    /// Records that a VM has started for this sandbox.
    ///
    /// Every way a sandbox gets a VM comes through here (a cold or warm boot, a
    /// restore from a fork or a snapshot, a resume), so the list is the whole
    /// history rather than the subset one code path remembered to write.
    async fn open_session(&self, sandbox: &RunningSandbox, started_by: &'static str) {
        let row = burrow_store::SessionRow {
            id: burrow_common::SessionId::generate().to_string(),
            sandbox_id: sandbox.id().to_string(),
            started_at: burrow_common::unix_now(),
            ended_at: 0,
            started_by: started_by.to_string(),
            ended_by: String::new(),
        };
        if let Err(err) = self.store.put_session(&row).await {
            tracing::error!(sandbox = sandbox.id(), %err, "could not record a session");
            return;
        }
        *sandbox.session.lock().unwrap() = Some(row.id);
        self.emit(sandbox, EVENT_STARTED, started_by).await;
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
    async fn close_session(&self, sandbox: &RunningSandbox, ended_by: &'static str) {
        let Some(id) = sandbox.session.lock().unwrap().take() else {
            return;
        };
        if let Err(err) = self
            .store
            .end_session(&id, burrow_common::unix_now(), ended_by)
            .await
        {
            tracing::error!(sandbox = sandbox.id(), %err, "could not close a session");
        }
        self.emit(sandbox, EVENT_STOPPED, ended_by).await;
    }

    /// Every VM a sandbox has run, newest first.
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
                started_at: burrow_common::rfc3339_from_unix_secs(row.started_at),
                // 0 means nothing observed when it ended, which is exactly what
                // an empty timestamp says.
                ended_at: match row.ended_at {
                    0 => String::new(),
                    at => burrow_common::rfc3339_from_unix_secs(at),
                },
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
            if let Some(counted) = traffic.get(&sandbox.lease.guest_ip) {
                sandbox.absorb_traffic(*counted);
            }
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

    /// Reattaches to sandboxes recorded by a previous run of this daemon.
    ///
    /// A VMM does not survive its parent, so nothing is running at this point.
    /// Sandboxes that were snapshotted (paused explicitly, or suspended during
    /// a graceful shutdown) can be resumed and are restored to `SUSPENDED`;
    /// anything that was running when the daemon died has no snapshot and is
    /// unrecoverable, so its resources are released rather than leaked.
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
        match self.store.close_open_sessions(ENDED_UNKNOWN).await {
            Ok(0) => {}
            Ok(closed) => tracing::info!(closed, "closed sessions left open by the previous run"),
            Err(err) => tracing::error!(%err, "could not close open sessions"),
        }

        // Not returned early when there are no rows: a node that crashed
        // mid-create has nothing recorded and everything to clean up.
        let (mut restored, mut discarded) = (0, 0);
        // Sandboxes left out of service whose files must survive the orphan
        // sweep below.
        let mut held = std::collections::HashSet::new();
        for row in rows {
            // Read before anything else, because it decides where the
            // sandbox's files are. Secrets are sealed field by field, so the
            // record decodes without them.
            let named = <common::Sandbox as prost::Message>::decode(&row.record[..])
                .map(|record| record.hypervisor)
                .unwrap_or_default();
            // A hypervisor this build does not know (a newer build's, say)
            // puts the files somewhere this one cannot look, and not finding
            // a snapshot there is no reason to destroy the sandbox.
            let Some(hypervisor) = Hypervisor::from_record(&named) else {
                tracing::error!(
                    sandbox = row.id,
                    hypervisor = named,
                    "sandbox runs under a hypervisor this build does not know; left out of \
                     service with its state untouched"
                );
                held.insert(row.id.clone());
                continue;
            };
            let workdir = self.config.sandbox_dir(&row.id, hypervisor);
            self.move_into_jail(&row.id, hypervisor, &workdir).await;
            let snapshot = workdir.join(hypervisor.layout().state);
            let resumable = row.state == common::SandboxState::Suspended as i32
                && tokio::fs::try_exists(&snapshot).await.unwrap_or(false);
            // A stopped sandbox is its disks: nothing of the VM to find.
            let stopped = row.state == common::SandboxState::Stopped as i32
                && tokio::fs::try_exists(workdir.join(SCRATCH_IMAGE))
                    .await
                    .unwrap_or(false);

            if !resumable && !stopped {
                tracing::warn!(
                    sandbox = row.id,
                    "no usable snapshot; discarding sandbox and releasing its resources"
                );
                tap::delete(&row.tap).await;
                let _ = tokio::fs::remove_dir_all(&workdir).await;
                let _ = self.store.delete_sandbox(&row.id).await;
                // Sessions describe a sandbox's VMs and have no owner once it
                // is gone.
                let _ = self.store.delete_sessions(&row.id).await;
                discarded += 1;
                continue;
            }

            // Hold the recorded lease before anything else can be allocated,
            // so a recovered sandbox keeps the address baked into its snapshot.
            if let Err(err) = self.ipam.lock().await.reserve(&row.id, row.lease_block) {
                tracing::error!(sandbox = row.id, %err, "cannot restore recorded lease; skipping");
                // A duplicate lease may name a tap the accepted sandbox owns;
                // the orphan sweep below removes only taps no sandbox kept.
                let _ = tokio::fs::remove_dir_all(&workdir).await;
                self.volumes.release_all(&row.id);
                if let Err(cleanup_err) = self.store.delete_sandbox(&row.id).await {
                    tracing::error!(sandbox = row.id, %cleanup_err, "failed to remove rejected sandbox from store");
                }
                if let Err(cleanup_err) = self.store.delete_sessions(&row.id).await {
                    tracing::error!(sandbox = row.id, %cleanup_err, "failed to remove rejected sandbox sessions");
                }
                discarded += 1;
                continue;
            }
            let Some(lease) = self.ipam.lock().await.get(&row.id) else {
                self.ipam.lock().await.release(&row.id);
                self.volumes.release_all(&row.id);
                continue;
            };
            if hypervisor.capabilities().is_tap_networked
                && let Err(err) = tap::create(&lease).await
            {
                tracing::error!(sandbox = row.id, %err, "cannot recreate tap; skipping");
                self.ipam.lock().await.release(&row.id);
                self.volumes.release_all(&row.id);
                continue;
            }

            let record = match <common::Sandbox as prost::Message>::decode(&row.record[..])
                .map_err(|err| err.to_string())
                .and_then(|mut record| {
                    open_secrets(&self.vault, &mut record)
                        .map(|()| record)
                        .map_err(|err| err.to_string())
                }) {
                Ok(record) => record,
                Err(err) => {
                    tracing::error!(sandbox = row.id, %err, "unreadable stored record; skipping");
                    // Giving up on the sandbox means giving back what was
                    // taken for it a moment ago; otherwise a node accumulates
                    // taps and address blocks nothing will ever use.
                    tap::delete(&row.tap).await;
                    self.ipam.lock().await.release(&row.id);
                    self.volumes.release_all(&row.id);
                    continue;
                }
            };
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
            let is_systemd = self.image_environment(&record.template).await.systemd;
            let guest_os = burrow_vmm::GuestOs::from_record(&record.guest_os).unwrap_or_default();
            let spec = self.build_spec(
                &row.id, &workdir, hypervisor, guest_os, &resources, &lease, &row.tap, &volumes,
                is_systemd,
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
                memory_chain: Mutex::new(
                    discover_memory_chain(&workdir, hypervisor.layout()).await,
                ),
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
            self.sandboxes.lock().await.insert(row.id.clone(), sandbox);
            restored += 1;
            // Restarted from its stored keys, so the address clients hold is
            // still the one that works. A relay that is unreachable right now
            // is not a reason to lose the share: the server keeps trying.
            if let Some(share) = row.share
                && let Err(err) = self.shares.start(self, &row.id, share).await
            {
                tracing::error!(sandbox = row.id, %err, "could not restart the sandbox's share");
            }
        }

        self.collect_orphan_workdirs(&held).await;
        tracing::info!(restored, discarded, "sandbox recovery complete");
        if let Err(err) = self.sync_firewall().await {
            tracing::error!(%err, "recovered sandboxes have no firewall rules");
        }
    }

    /// Removes sandbox directories with no corresponding record.
    ///
    /// These accumulate from crashes. Each holds a scratch disk and possibly
    /// a memory snapshot, so left alone they quietly consume the node's disk.
    async fn collect_orphan_workdirs(&self, held: &std::collections::HashSet<String>) {
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
        known.extend(held.iter().cloned());

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
            roots.push((
                jail.chroot_base.join("firecracker"),
                known.iter().map(|id| jail.dir_for(id)).collect(),
            ));
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
                Ok(()) => {
                    self.volumes.release_all(sandbox.id());
                    self.close_session(&sandbox, ENDED_SUSPENDED).await;
                    self.persist(&sandbox).await;
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
            lease.map(|lease| lease.guest_ip)
        };
        if let Some(guest_ip) = guest_ip {
            firewall::flush_conntrack(guest_ip).await;
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
        let rules: Vec<firewall::SandboxRules> = all
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
                    peers,
                    ports: ports.get(sandbox.id()).cloned().unwrap_or_default(),
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
                (
                    sandbox.lease.guest_ip,
                    burrow_proxy::SandboxPolicy {
                        sandbox_id: sandbox.id().to_string(),
                        // The same mode the firewall renders, from the same
                        // snapshot: the proxy and the ruleset disagreeing
                        // about a sandbox's egress is how a policy gets half
                        // applied.
                        mode: match policy_mode(&record) {
                            firewall::Mode::Open => burrow_proxy::policy::NetworkMode::Open,
                            firewall::Mode::Allowlist => {
                                burrow_proxy::policy::NetworkMode::Allowlist
                            }
                            firewall::Mode::None => burrow_proxy::policy::NetworkMode::None,
                        },
                        allow_domains: network.map(|n| n.allow_domains.clone()).unwrap_or_default(),
                        is_tls_inspected: network.is_some_and(|n| n.is_tls_inspected),
                        deny_cidrs: network.map(|n| n.deny_cidrs.clone()).unwrap_or_default(),
                        deny_domains: network.map(|n| n.deny_domains.clone()).unwrap_or_default(),
                        http_rules: std::sync::Arc::new(
                            network
                                .map(|n| n.http_rules.iter().map(proxy_http_rule).collect())
                                .unwrap_or_default(),
                        ),
                        // The stored record keeps the real values, redaction
                        // happening on the way out to callers, so the proxy
                        // goes on brokering across a restart and a recover.
                        //
                        // Patterns are compiled here, once per sync, rather
                        // than per request: a policy must never make a request
                        // cost work a guest can schedule. A rule that will not
                        // compile was refused at the API door, so one arriving
                        // here means the policy in force is not the one that
                        // was written; it becomes a refusal rather than an
                        // allowance.
                        rules: std::sync::Arc::new(
                            network
                                .map(|n| {
                                    n.rules
                                        .iter()
                                        .map(|rule| {
                                            crate::nodeapi::compile_rule(rule).unwrap_or_else(
                                                |err| burrow_proxy::policy::Rule {
                                                    domain: rule.domain.clone(),
                                                    matcher: None,
                                                    action: burrow_proxy::policy::Action::Refuse(
                                                        format!("unusable policy rule: {err}"),
                                                    ),
                                                },
                                            )
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        ),
                    },
                )
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
        let proxy_table: HashMap<std::net::IpAddr, burrow_proxy::SandboxPolicy> = by_guest_ip
            .into_iter()
            .flat_map(|(guest_ip, policy)| {
                let guest_ip6 = sandbox_ip6.get(&guest_ip).copied();
                std::iter::once((std::net::IpAddr::V4(guest_ip), policy.clone()))
                    .chain(guest_ip6.map(|ip6| (std::net::IpAddr::V6(ip6), policy)))
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
            })
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
        firewall::flush_conntrack(sandbox.lease.guest_ip).await;
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
        sandbox.base_record.lock().unwrap().metadata = tags;
        self.persist(&sandbox).await;
        Ok(sandbox.record())
    }

    /// Stamps every Access token issued for a sandbox so far as revoked,
    /// returning the stamp. Persisted with the record, which is what carries
    /// it to the next node when the sandbox moves.
    pub async fn revoke_access(&self, sandbox_id: &str) -> Result<i64, Status> {
        let sandbox = self.get(sandbox_id).await?;
        let now = burrow_common::unix_now();
        sandbox.base_record.lock().unwrap().access_revoked_at = now;
        self.persist(&sandbox).await;
        Ok(now)
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
    /// force at the next tick without a timer to cancel or reschedule.
    ///
    /// The machine shape deliberately has no path in, a running VM's
    /// configuration being fixed and a restore taking it from the snapshot, so
    /// a caller who asks for one is told rather than quietly given the old
    /// shape back. See [`crate::nodeapi`] for where that is refused.
    pub async fn update_resources(
        &self,
        sandbox_id: &str,
        max_lifetime_secs: Option<u64>,
        idle_suspend_secs: Option<u64>,
        suspended_ttl_secs: Option<u64>,
    ) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(sandbox_id).await?;
        {
            let mut record = sandbox.base_record.lock().unwrap();
            let policy = record.policy.get_or_insert_with(Default::default);
            let resources = policy.resources.get_or_insert_with(Default::default);
            if let Some(secs) = max_lifetime_secs {
                resources.max_lifetime_secs = secs;
            }
            if let Some(secs) = idle_suspend_secs {
                resources.idle_suspend_secs = secs;
            }
            if let Some(secs) = suspended_ttl_secs {
                resources.suspended_ttl_secs = secs;
            }
        }
        self.persist(&sandbox).await;
        tracing::info!(sandbox = sandbox_id, "resource policy updated");
        Ok(sandbox.record())
    }

    pub async fn count(&self) -> usize {
        self.sandboxes.lock().await.len()
    }

    /// Records the authority sandboxes that opt in should trust.
    pub fn set_inspection_ca(&self, pem: String) {
        *self.inspection_ca.lock().unwrap() = Some(pem);
    }

    /// The node's egress pieces for its sandboxes' userspace network stacks.
    #[cfg(target_os = "macos")]
    pub fn set_usernet_node(&self, node: burrow_net::usernet::Node) {
        self.usernets.set_node(node);
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
            .clone()
            .unwrap_or_default()
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
            .clone()
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
            .record_demand(key);
        if !wanted {
            return;
        }
        self.warm_in_background(
            key.template.clone(),
            common::ResourcePolicy {
                vcpus: key.vcpus,
                mem_mib: key.mem_mib,
                scratch_disk_mib: key.scratch_disk_mib,
                ..Default::default()
            },
        );
    }

    /// Discards `template`'s warm snapshot and lets it be built again.
    ///
    /// A snapshot's memory image is only valid over the rootfs it was captured
    /// on, and `stage_from_warm` links whichever `rootfs.ext4` is there now.
    /// Republishing a template without this leaves the two mismatched, which
    /// restores a guest onto a disk it never saw. Clearing `warm_attempted` too
    /// is what lets the replacement be built, since the key is only ever
    /// inserted.
    pub async fn invalidate_warm(&self, template: &str) {
        self.warm_shapes.lock().unwrap().remove(template);
        let warm = crate::warm::warm_dir(&self.config.templates_dir(), template);
        if let Err(err) = tokio::fs::remove_dir_all(&warm).await
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(template, %err, "could not discard the warm snapshot");
        }
    }

    /// Builds a warm snapshot of `template` at `resources`, off this task.
    ///
    /// Every trigger comes through here: a template landing on the node, and a
    /// create that found no snapshot of its shape. Both take the same path,
    /// with the same validation, lock and staged swap, so nothing about the
    /// resulting snapshot depends on which of the two asked for it.
    pub fn warm_in_background(&self, template: String, resources: common::ResourcePolicy) {
        let (shape, scratch_disk_mib) = match crate::nodeapi::warm_request(&resources) {
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
            scratch_disk_mib,
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
            let templates_dir = manager.config.templates_dir();
            // It may already be warm: a template that was warmed explicitly,
            // or one create's build finishing while another was queued.
            if crate::warm::is_warm_for(&templates_dir, &template, shape).await {
                return;
            }
            let trust = manager.warm_trust(&template).await;
            match crate::warm::build_warm_snapshot(
                &manager.config,
                &template,
                scratch_disk_mib,
                shape,
                &trust,
            )
            .await
            {
                Ok(snapshot_bytes) => {
                    tracing::info!(
                        template,
                        vcpus = shape.vcpus,
                        mem_mib = shape.mem_mib,
                        snapshot_bytes,
                        "warmed a template automatically"
                    );
                    // Placement prefers a node that holds the snapshot, and it
                    // only knows about one it has been told about.
                    manager.announce_now();
                }
                // Not fatal to anything: creates of this template keep working,
                // they just keep cold-booting.
                Err(err) => tracing::warn!(template, %err, "could not warm a template"),
            }
        });
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
            let resources = sandbox.resources();
            let id = sandbox.id().to_string();
            tracing::debug!(
                sandbox = id,
                idle_secs = sandbox.idle_secs(),
                age_secs = sandbox.age_secs(),
                idle_suspend_secs = resources.idle_suspend_secs,
                max_lifetime_secs = resources.max_lifetime_secs,
                suspended_secs = sandbox.suspended_secs(),
                suspended_ttl_secs = resources.suspended_ttl_secs,
                "reap check"
            );

            // Checked before the lifetime cap only in the sense that both
            // destroy: whichever comes due first wins, and neither is
            // reversible.
            if resources.suspended_ttl_secs > 0
                && !sandbox.is_running()
                && sandbox.suspended_secs() >= resources.suspended_ttl_secs as i64
            {
                match self.delete(&id).await {
                    Ok(()) => {
                        tracing::info!(
                            sandbox = id,
                            suspended_ttl_secs = resources.suspended_ttl_secs,
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

            if resources.max_lifetime_secs > 0
                && sandbox.age_secs() >= resources.max_lifetime_secs as i64
            {
                match self.delete(&id).await {
                    Ok(()) => {
                        tracing::info!(
                            sandbox = id,
                            max_lifetime_secs = resources.max_lifetime_secs,
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
            if resources.idle_suspend_secs > 0
                && sandbox.is_running()
                && sandbox.idle_secs() >= resources.idle_suspend_secs as i64
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
        self.sandboxes
            .lock()
            .await
            .values()
            .map(|sandbox| {
                let record = sandbox.record();
                burrow_proto::node::v1::SandboxStateReport {
                    sandbox_id: record.id,
                    state: record.state,
                    cpu_usage_usec: record.cpu_usage_usec,
                    rx_bytes: record.rx_bytes,
                    tx_bytes: record.tx_bytes,
                    is_agent_unconfirmed: record.is_agent_unconfirmed,
                    is_durable: record.is_durable,
                    is_fenced: sandbox.durable.is_fenced(),
                }
            })
            .collect()
    }

    /// vCPUs promised across every sandbox this node holds, suspended included.
    ///
    /// A suspended sandbox keeps its address, disks and snapshot and can be
    /// resumed at any moment, so counting only running ones would let a node
    /// accept work it cannot honour when they all come back.
    pub async fn committed_vcpus(&self) -> u32 {
        let live: u32 = self
            .sandboxes
            .lock()
            .await
            .values()
            .map(|sandbox| sandbox.vcpus())
            .sum();
        live
    }

    pub async fn get(&self, id: &str) -> Result<Arc<RunningSandbox>, Status> {
        self.sandboxes
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| Status::not_found(format!("no sandbox {id} on this node")))
    }

    pub async fn list(&self) -> Vec<common::Sandbox> {
        let mut out: Vec<_> = self
            .sandboxes
            .lock()
            .await
            .values()
            .map(|s| s.record())
            .collect();
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
    ) -> VmSpec {
        let mut spec = VmSpec::new(id.to_string(), workdir, self.config.backend(hypervisor));
        spec.guest_os = guest_os;
        let capabilities = hypervisor.capabilities();
        spec.vcpus = resources.vcpus.max(1);
        spec.mem_mib = if resources.mem_mib == 0 {
            512
        } else {
            resources.mem_mib
        };

        // Firecracker bounds guest memory on its own, but nothing bounds host
        // CPU: a 1-vCPU guest spinning saturates a core. The cgroup is what
        // stops one sandbox starving its neighbours.
        spec.limits = burrow_vmm::Limits {
            cpus: spec.vcpus,
            // Headroom over the guest allocation for the VMM's own footprint;
            // too tight and the VMM itself gets OOM-killed.
            memory_mib: spec.mem_mib + capabilities.memory_headroom_mib,
            pids_max: 0,
        };
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

        spec.drives = vec![
            DriveSpec::root_ro(TEMPLATE_ROOTFS),
            DriveSpec::scratch_rw(SCRATCH_IMAGE),
        ];
        // After the two fixed drives, so the guest devices are /dev/vdc
        // onwards and match what the handshake tells the agent to mount.
        for (index, mount) in crate::volume::block_mounts(volumes) {
            spec.drives.push(DriveSpec {
                id: format!("volume{index}"),
                path: volume_image(index),
                is_root: false,
                is_read_only: mount.is_read_only,
            });
        }
        spec.is_vsock_enabled = true;
        spec.net = Some(NetSpec {
            tap: tap_name.to_string(),
            guest_mac: Some(lease.guest_mac()),
        });
        spec.boot = burrow_vmm::Boot::Kernel {
            kernel: TEMPLATE_KERNEL.into(),
            cmdline: format!(
                "{} root=/dev/vda ro init=/usr/bin/burrow-guest {} burrow.dns={} burrow.ip6={}/{} burrow.ip6gw={} {} {}",
                burrow_vmm::DEFAULT_BOOT_ARGS,
                lease.kernel_ip_arg(),
                lease.host_ip,
                lease.guest_ip6(),
                lease.prefix_len6(),
                lease.host_ip6(),
                guest_mode_arg(is_systemd),
                self.config.extra_boot_args
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

    // Identity, shape and policy all arrive together, which is more than seven
    // things; grouping them into a struct would only move the list.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip_all, fields(sandbox = %id, template = %template, from_warm))]
    pub async fn create(
        &self,
        id: String,
        template: String,
        policy: common::Policy,
        metadata: HashMap<String, String>,
        node_id: String,
        name: String,
    ) -> Result<common::Sandbox, Status> {
        // A sandbox provisioned ahead of demand needs none of the work below:
        // its VM is already restored, its agent already handshaken, its
        // address already applied. What is left is stamping it with this
        // caller's policy.

        let resources = policy.resources.unwrap_or_default();
        // A create of a shape with no warm snapshot is exactly the signal that
        // one is worth building, so the next create of it restores. Not for a
        // backend whose restore loses to its boot.
        let is_warmable = self
            .image_environment(&template)
            .await
            .machine()
            .is_ok_and(|(hypervisor, _)| hypervisor.capabilities().is_warm_pool_supported);
        if is_warmable {
            self.warm_for_demand(&ShapeKey::of(&template, &resources));
        }
        self.create_seeded(id, template, policy, metadata, node_id, None, name)
            .await
    }

    /// Creates a sandbox whose scratch disk starts from an existing image.
    ///
    /// Only the template builder uses this. A build's scratch *is* the layer,
    /// the overlay's upper directory holding exactly what the steps changed, so
    /// seeding it is how a rebuild resumes from a cached step instead of
    /// replaying the ones before it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_seeded(
        &self,
        id: String,
        template: String,
        policy: common::Policy,
        metadata: HashMap<String, String>,
        node_id: String,
        seed_scratch: Option<&Path>,
        name: String,
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

        let provisioned = self
            .provision_with(id.clone(), template, policy, seed_scratch, node_id)
            .await;
        let sandbox = match provisioned {
            Ok(sandbox) => sandbox,
            Err(err) => {
                self.creating.lock().await.remove(&id);
                return Err(err);
            }
        };

        // Stamped before the record is taken, or the caller and the store are
        // handed a sandbox with none of the metadata they asked for.
        {
            let mut stamped = sandbox.base_record.lock().unwrap();
            stamped.metadata = metadata;
            stamped.name = name;
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
        self.open_session(&sandbox, STARTED_BOOT).await;
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

    async fn provision_with(
        &self,
        id: String,
        template: String,
        policy: common::Policy,
        seed_scratch: Option<&Path>,
        node_id: String,
    ) -> Result<Arc<RunningSandbox>, Status> {
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
        let capabilities = hypervisor.capabilities();
        if !capabilities.runs(guest_os) {
            return Err(Status::failed_precondition(format!(
                "template {template} is a {} guest, which {hypervisor} cannot run",
                guest_os.as_str()
            )));
        }
        if crate::macnode::is_macos(guest_os) {
            let running = self
                .sandboxes
                .lock()
                .await
                .values()
                .filter(|sandbox| sandbox.hypervisor == hypervisor && sandbox.is_running())
                .count();
            crate::macnode::check_running(running)?;
        }
        let layout = hypervisor.layout();
        let workdir = self.config.sandbox_dir(&id, hypervisor);
        let resources = policy.resources.unwrap_or_default();
        let scratch_mib = if resources.scratch_disk_mib == 0 {
            DEFAULT_SCRATCH_MIB
        } else {
            resources.scratch_disk_mib
        };

        // A seeded scratch has to survive into the guest untouched, and the
        // warm path stages its own scratch, so it is not usable here. Nor is a
        // warm snapshot of the wrong shape: restoring it would give the caller
        // different cpu and memory than they asked for, with no error to say so.
        // Taken before any resource is, so a volume conflict fails the create
        // without a tap, an address or a directory to give back.
        crate::volume::validate_mounts(&policy.volumes)?;
        for (_, mount) in crate::volume::block_mounts(&policy.volumes) {
            if !tokio::fs::try_exists(self.volumes.image(&mount.volume))
                .await
                .unwrap_or(false)
            {
                return Err(Status::not_found(format!(
                    "no volume {} on this node",
                    mount.volume
                )));
            }
        }
        self.volumes.claim(&id, &policy.volumes)?;
        // The claims above are the first thing this create holds, so the guard
        // starts here: everything taken from now on is given back by it, and
        // every failure below answers through [`Provisioning::fail`].
        let mut guard = Provisioning::new(self, &id, &workdir);

        // A warm snapshot was taken without volumes, so they can only reach a
        // sandbox restored from one by being hotplugged; where they cannot
        // be, it boots cold and takes them at boot.
        let from_warm = seed_scratch.is_none()
            && capabilities.is_warm_pool_supported
            && (capabilities.is_drive_hotplug_supported
                || crate::volume::block_mounts(&policy.volumes)
                    .next()
                    .is_none())
            && crate::warm::is_warm_for(
                &templates_dir,
                &template,
                crate::warm::Shape::wanted(&resources),
            )
            .await;
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

        // Copying a scratch disk is disk work and programming a tap is netlink,
        // so they run together rather than one after the other.
        let stage = async {
            let staging_began = std::time::Instant::now();
            // May come back false: the warm directory is rebuilt in place, so
            // a create landing in that window finds pieces of it missing. A
            // cold boot is slower, not wrong, and is a far better answer than
            // failing a create because of a race with a rebuild.
            let mut warm = from_warm;
            if warm
                && let Err(err) =
                    crate::warm::stage_from_warm(&templates_dir, &template, &workdir).await
            {
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(Status::internal(format!("staging warm snapshot: {err}")));
                }
                tracing::warn!(
                    template = %template, %err,
                    "warm snapshot is not there to stage; booting cold"
                );
                warm = false;
            }
            if crate::macnode::is_macos(guest_os) {
                crate::macnode::prepare(&templates_dir.join(&template), &workdir)
                    .await
                    .map_err(|err| {
                        Status::failed_precondition(format!("template {template:?}: {err}"))
                    })?;
            } else if !warm {
                prepare_workdir(&templates_dir.join(&template), &workdir)
                    .await
                    .map_err(|err| {
                        Status::failed_precondition(format!("template {template:?}: {err}"))
                    })?;
                match seed_scratch {
                    Some(seed) => crate::warm::copy_sparse(seed, &workdir.join(SCRATCH_IMAGE))
                        .await
                        .map_err(|err| Status::internal(format!("seeding scratch disk: {err}")))?,
                    None => create_scratch(&workdir.join(SCRATCH_IMAGE), scratch_mib)
                        .await
                        .map_err(|err| Status::internal(format!("scratch disk: {err}")))?,
                }
            }
            // Hard-linked in after the template's own files, so a cold boot
            // that rebuilt the directory does not clear them again.
            for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
                let dest = workdir.join(crate::sandbox::volume_image(index));
                let _ = tokio::fs::remove_file(&dest).await;
                tokio::fs::hard_link(self.volumes.image(&mount.volume), &dest)
                    .await
                    .map_err(|err| {
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
                if warm {
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
                warm,
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

        // A warm snapshot was captured with the rootfs and scratch drives alone,
        // so a restore must describe exactly those; the volumes are hotplugged
        // once it is running. A cold boot has no such constraint and takes them
        // at boot, which needs no rescan in the guest.
        let boot_volumes: &[common::VolumeMount] = if from_warm { &[] } else { &policy.volumes };
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

        // Attached before the handshake, which is what tells the guest to rescan
        // its bus and mount them: firecracker cannot notify the guest itself.
        if from_warm {
            for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
                let drive = DriveSpec {
                    id: format!("volume{index}"),
                    path: volume_image(index),
                    is_root: false,
                    is_read_only: mount.is_read_only,
                };
                if let Err(err) = guard.vm().attach_drive(&drive).await {
                    let message = format!("attaching volume {}: {err}", mount.volume);
                    return Err(guard.fail(Status::internal(message)).await);
                }
            }
        }

        // What a guest still has to be told. Assembled before any clock starts,
        // because reading host entropy and the image's trust bundles is host
        // work and charging it to the guest would hide what the guest costs.
        let request = guestconn::handshake_full(
            from_warm,
            from_warm.then(|| burrow_proto::guest::v1::NetworkConfig {
                ip: lease.guest_ip.to_string(),
                prefix_len: lease.prefix_len as u32,
                gateway: lease.host_ip.to_string(),
                dns: lease.host_ip.to_string(),
                ip6: lease.guest_ip6().to_string(),
                prefix_len6: lease.prefix_len6() as u32,
                gateway6: lease.host_ip6().to_string(),
            }),
            self.inspection_ca_for(&policy),
            self.trust_bundles_for(&template, &policy).await,
            crate::volume::agent_mounts(&policy.volumes),
        );
        let inspected = !request.inspection_ca_pem.is_empty();

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
                    let console = guard.vm().console_tail(30).await;
                    return Err(guard
                        .fail(Status::internal(format!(
                            "agent never became reachable: {err}\nconsole:\n{console}"
                        )))
                        .await);
                }
            };
            let agent_up = vmm_ready.elapsed();
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
                Err(err) => return Err(guard.fail(err).await),
            };
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
            created_at: burrow_common::now_rfc3339(),
            // Both are stamped a moment later by the caller's create.
            metadata: HashMap::new(),
            name: String::new(),
            guest_ip: lease.guest_ip.to_string(),
            // Describes the node's reachability, which is the orchestrator's
            // to judge on a read. A node cannot report itself unreachable.
            is_unreachable: false,
            // Filled in from the sandbox's own totals on every read; a record
            // built here has none yet.
            cpu_usage_usec: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            // Filled in from the live handshake on every read; this is only its
            // starting value.
            is_agent_unconfirmed: false,
            env: HashMap::new(),
            kit: None,
            kit_credentials: HashMap::new(),
            kit_selection: String::new(),
            is_durable: false,
            arch: String::new(),
            firecracker_version: String::new(),
            access_revoked_at: 0,
            hypervisor: hypervisor.to_string(),
            guest_os: guest_os.as_str().to_string(),
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
            spawn_handshake(self, &sandbox, request, self.config.agent_timeout);
        }
        Ok(sandbox)
    }

    /// Snapshots a sandbox to disk and stops its VMM.
    pub async fn pause(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        sandbox.suspend().await?;
        self.usernets.detach(id, false);
        // The VM is stopped, so nothing is touching the volumes; a suspended
        // sandbox holding them would make a volume unusable until deleted.
        self.volumes.release_all(id);
        self.close_session(&sandbox, ENDED_SUSPENDED).await;
        self.persist(&sandbox).await;
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
    async fn write_state(&self, sandbox: &Arc<RunningSandbox>) -> Result<(), Status> {
        let result = sandbox.checkpoint().await;
        // That failure mode leaves the sandbox suspended, which ends its
        // session as surely as a suspend does.
        if result.is_err() && !sandbox.is_running() {
            self.close_session(sandbox, ENDED_FAILED).await;
        }
        self.persist(sandbox).await;
        result
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
        if sandbox.is_running() {
            self.write_state(&sandbox).await?;
        } else if sandbox.state.load(std::sync::atomic::Ordering::Relaxed)
            != common::SandboxState::Suspended as i32
        {
            return Err(Status::failed_precondition(
                "only a running or suspended sandbox can be snapshotted",
            ));
        }

        let resources = sandbox.resources();
        // The request wins over the sandbox's default, and 0 in both means the
        // snapshot is kept until something deletes it.
        let expiration_secs = match expiration_secs {
            0 => resources.snapshot_expiration_secs,
            secs => secs,
        };

        let started = std::time::Instant::now();
        let dir = self.snapshots.begin(&snapshot_id).await?;
        let staged = match sandbox.stage_snapshot(&dir).await {
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
            .retain_newest(
                sandbox_id,
                resources.keep_last_snapshots,
                resources.is_evicted_snapshot_kept,
            )
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
    #[tracing::instrument(skip_all, fields(sandbox = %id, snapshot = %snapshot_id))]
    pub async fn create_from_snapshot(
        &self,
        id: String,
        snapshot_id: &str,
        policy: common::Policy,
        metadata: HashMap<String, String>,
        node_id: String,
        name: String,
    ) -> Result<common::Sandbox, Status> {
        let manifest = self.snapshots.manifest_for_restore(snapshot_id).await?;
        let mut policy = policy;
        let wanted = policy.resources.unwrap_or_default();
        let shape = (
            match wanted.vcpus {
                0 => manifest.vcpus,
                n => n,
            },
            match wanted.mem_mib {
                0 => manifest.mem_mib,
                n => n,
            },
            match wanted.scratch_disk_mib {
                0 => manifest.scratch_disk_mib,
                n => n,
            },
        );
        if shape != (manifest.vcpus, manifest.mem_mib, manifest.scratch_disk_mib) {
            return Err(Status::invalid_argument(format!(
                "a sandbox created from snapshot {snapshot_id} restores its state and cannot \
                 change its vcpus, memory or scratch disk: the snapshot was taken with \
                 {} vcpu / {} MiB / {} MiB scratch",
                manifest.vcpus, manifest.mem_mib, manifest.scratch_disk_mib
            )));
        }
        // Written back so the record, the cgroup and any later restore all
        // describe the machine the snapshot actually holds.
        policy.resources = Some(common::ResourcePolicy {
            vcpus: manifest.vcpus,
            mem_mib: manifest.mem_mib,
            scratch_disk_mib: manifest.scratch_disk_mib,
            ..wanted
        });

        {
            let sandboxes = self.sandboxes.lock().await;
            let mut creating = self.creating.lock().await;
            if sandboxes.contains_key(&id) || !creating.insert(id.clone()) {
                return Err(Status::already_exists(format!("sandbox {id} exists")));
            }
        }
        let provisioned = self
            .provision_restored(
                RestoreSource::Snapshot {
                    id: snapshot_id,
                    template: manifest.template.clone(),
                    hypervisor: manifest.hypervisor()?,
                },
                id.clone(),
                policy,
                metadata,
                node_id,
                name,
            )
            .await;
        let registered = match &provisioned {
            Ok(sandbox) => self.register_or_discard(sandbox).await,
            Err(_) => Ok(()),
        };
        self.creating.lock().await.remove(&id);
        let sandbox = provisioned?;
        registered?;

        self.emit(&sandbox, EVENT_CREATED, &format!("snapshot:{snapshot_id}"))
            .await;
        self.open_session(&sandbox, STARTED_RESTORE).await;
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
            Ok(sandbox) => self.register_or_discard(sandbox).await,
            Err(_) => Ok(()),
        };
        self.creating.lock().await.remove(&child_id);
        let sandbox = forked?;
        registered?;

        self.emit(&sandbox, EVENT_CREATED, &format!("fork:{source_id}"))
            .await;
        self.open_session(&sandbox, STARTED_RESTORE).await;
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
    ) -> Result<Arc<RunningSandbox>, Status> {
        // A running source has state in memory that its snapshot does not
        // hold; capturing it is the whole difference between forking a sandbox
        // and cloning its last suspend.
        if source.is_running() {
            self.write_state(source).await?;
        } else if source.state.load(std::sync::atomic::Ordering::Relaxed)
            != common::SandboxState::Suspended as i32
        {
            return Err(Status::failed_precondition(
                "only a running or suspended sandbox can be forked",
            ));
        }

        let (mut inherited, metadata) = {
            let record = source.base_record.lock().unwrap();
            (
                record.policy.clone().unwrap_or_default(),
                record.metadata.clone(),
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
                let shape = inherited.resources.unwrap_or_default();
                let wanted = over.resources.unwrap_or(shape);
                // Firecracker takes a restored VM's machine configuration from
                // the snapshot, and the child's scratch disk is a copy of the
                // source's. A shape the fork cannot honour is refused rather
                // than accepted and quietly ignored.
                if (wanted.vcpus, wanted.mem_mib, wanted.scratch_disk_mib)
                    != (shape.vcpus, shape.mem_mib, shape.scratch_disk_mib)
                {
                    return Err(Status::invalid_argument(
                        "a fork restores the source's snapshot and cannot change its \
                         vcpus, memory or scratch disk",
                    ));
                }
                over.resources = Some(wanted);
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
        self.provision_restored(
            RestoreSource::Sandbox(source),
            child_id,
            policy,
            metadata,
            node_id,
            name,
        )
        .await
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
    async fn link_prefetch_plan(&self, template: &str, workdir: &Path) -> bool {
        let dest = workdir.join(crate::warm::PREFETCH_PLAN);
        if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
            return true;
        }
        let plan = self
            .config
            .templates_dir()
            .join(template)
            .join("warm")
            .join(crate::warm::PREFETCH_PLAN);
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
        policy: common::Policy,
        metadata: HashMap<String, String>,
        node_id: String,
        name: String,
    ) -> Result<Arc<RunningSandbox>, Status> {
        // State restores only under the hypervisor that wrote it, so the
        // source decides, whatever the template says now.
        let hypervisor = source.hypervisor()?;
        self.require_hypervisor(hypervisor)?;
        let capabilities = hypervisor.capabilities();
        let workdir = self.config.sandbox_dir(&id, hypervisor);
        let resources = policy.resources.unwrap_or_default();
        // The state was captured without volumes, so they could only arrive by
        // hotplug.
        if !capabilities.is_drive_hotplug_supported
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
        for (_, mount) in crate::volume::block_mounts(&policy.volumes) {
            if !tokio::fs::try_exists(self.volumes.image(&mount.volume))
                .await
                .unwrap_or(false)
            {
                return Err(Status::not_found(format!(
                    "no volume {} on this node",
                    mount.volume
                )));
            }
        }
        self.volumes.claim(&id, &policy.volumes)?;
        let mut guard = Provisioning::new(self, &id, &workdir);

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
            // A fork or a snapshot starts with no output; an adopted sandbox
            // brings its own.
            let logs_dir = self.config.command_logs_dir(&id);
            let _ = tokio::fs::remove_dir_all(&logs_dir).await;
            let (chain, arriving) = source
                .stage_into(&self.snapshots, &workdir, &logs_dir)
                .await?;
            // Linked in the same shape as a create's, so the guest sees the
            // same devices in the same order as the handshake describes.
            for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
                let dest = workdir.join(crate::sandbox::volume_image(index));
                let _ = tokio::fs::remove_file(&dest).await;
                tokio::fs::hard_link(self.volumes.image(&mount.volume), &dest)
                    .await
                    .map_err(|err| {
                        Status::internal(format!("attaching volume {}: {err}", mount.volume))
                    })?;
            }
            if let Some(jail) = self.config.jail_for(hypervisor) {
                // Both a fork and a snapshot restore hard-link only the
                // template's own kernel and rootfs; the snapshot state, the
                // memory chain and the scratch disk are copies (or reflinks)
                // made just for this sandbox, so they still need the chown. A
                // read-only volume mount is a link into the volume store and is
                // left alone, for the reason [`grant_to_jail`] spells out.
                let mut shared: std::collections::HashSet<String> =
                    [TEMPLATE_KERNEL.to_string(), TEMPLATE_ROOTFS.to_string()].into();
                // A fork links its source's memory chain rather than copying
                // it, and those inodes are the source's, already readable by
                // the jail's uid; a snapshot restore copies its chain and
                // the copies are this sandbox's to own.
                if matches!(source, RestoreSource::Sandbox(_)) {
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
        let guest_os = match &source {
            RestoreSource::Sandbox(source) => {
                burrow_vmm::GuestOs::from_record(&source.record().guest_os).unwrap_or_default()
            }
            _ => self
                .image_environment(&source.template())
                .await
                .machine()
                .map_or_else(|_| Default::default(), |(_, os)| os),
        };
        let mut spec = self.build_spec(
            &id,
            &workdir,
            hypervisor,
            guest_os,
            &resources,
            &lease,
            &tap_name,
            &[],
            is_systemd,
        );
        // The template's plan names the pages its agent touches on the way to
        // a usable handshake, which is the same code whether the guest was
        // just warmed or has been running for an hour, and the offsets hold
        // across a chain, since every layer is laid out as the base is. A
        // fork or a snapshot restore would otherwise take those pages one
        // stalled vCPU at a time.
        if capabilities.is_lazy_memory_supported {
            let linked = self.link_prefetch_plan(&source.template(), &workdir).await;
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

        for (index, mount) in crate::volume::block_mounts(&policy.volumes) {
            let drive = DriveSpec {
                id: format!("volume{index}"),
                path: volume_image(index),
                is_root: false,
                is_read_only: mount.is_read_only,
            };
            if let Err(err) = guard.vm().attach_drive(&drive).await {
                let message = format!("attaching volume {}: {err}", mount.volume);
                return Err(guard.fail(Status::internal(message)).await);
            }
        }

        // The guest wakes holding the address baked into the snapshot, which
        // belongs to someone else; only the host knows this sandbox's own
        // lease. Told behind the response, as a warm create does: the caller
        // has its sandbox as soon as the VM is up, and the first call into
        // the guest waits for the handshake to settle.
        let request = guestconn::handshake_full(
            true,
            Some(burrow_proto::guest::v1::NetworkConfig {
                ip: lease.guest_ip.to_string(),
                prefix_len: lease.prefix_len as u32,
                gateway: lease.host_ip.to_string(),
                dns: lease.host_ip.to_string(),
                ip6: lease.guest_ip6().to_string(),
                prefix_len6: lease.prefix_len6() as u32,
                gateway6: lease.host_ip6().to_string(),
            }),
            self.inspection_ca_for(&policy),
            self.trust_bundles_for(&source.template(), &policy).await,
            crate::volume::agent_mounts(&policy.volumes),
        );
        // Nothing below can fail, so the sandbox takes over here.
        let vm = guard.keep().expect("a restore that reaches here has a vm");

        let record = common::Sandbox {
            id: id.clone(),
            node_id,
            template: source.template(),
            state: common::SandboxState::Running as i32,
            policy: Some(policy),
            created_at: burrow_common::now_rfc3339(),
            metadata,
            // A restore does not inherit a name: names are unique, so the new
            // sandbox is named by the caller or not at all.
            name,
            guest_ip: lease.guest_ip.to_string(),
            is_unreachable: false,
            cpu_usage_usec: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            is_agent_unconfirmed: true,
            env: HashMap::new(),
            kit: None,
            kit_credentials: HashMap::new(),
            kit_selection: String::new(),
            is_durable: false,
            arch: String::new(),
            firecracker_version: String::new(),
            access_revoked_at: 0,
            hypervisor: hypervisor.to_string(),
            guest_os: guest_os.as_str().to_string(),
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
        spawn_handshake(self, &sandbox, request, self.config.agent_timeout);
        Ok(sandbox)
    }

    /// Restores a suspended sandbox from its snapshot.
    pub async fn resume(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        self.fence_if_lapsed().await;
        if sandbox.durable.is_fenced() {
            return Err(Status::unavailable(format!(
                "sandbox {id} is kept in the object store, and this node is waiting for the \
                 orchestrator to confirm it still holds it; try again shortly"
            )));
        }
        // Suspending gave the volumes back, so another sandbox may hold them
        // now. Taken before the VM starts, so a sandbox that cannot have them
        // stays suspended rather than resuming without its data.
        let volumes = sandbox.record().policy.unwrap_or_default().volumes;
        self.volumes.claim(id, &volumes)?;
        let uploading = sandbox.durable.stop_uploading().await;
        if let Err(err) = self.mark_running(&sandbox).await {
            self.volumes.release_all(id);
            return Err(err);
        }
        sandbox.durable.invalidate();
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
            return Err(err);
        }
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
        self.open_session(&sandbox, STARTED_RESUME).await;
        self.persist(&sandbox).await;
        Ok(sandbox.record())
    }

    /// Shuts a sandbox down, keeping its disks. Unlike a pause, nothing of
    /// the guest's memory survives: a start boots the image's init again.
    pub async fn stop(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        // The VMM is killed, not powered off, so the guest's page cache
        // would otherwise die with it and the disk a boot comes back to
        // would miss what was last written. Best effort: a guest that has
        // stopped answering is stopped all the same.
        let sync = burrow_proto::guest::v1::ExecStart {
            cmd: vec!["sync".to_string()],
            ..Default::default()
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            guestconn::run_to_completion(&sandbox, sync),
        )
        .await;
        sandbox.shutdown().await?;
        // Its memory is gone, so what the store holds is a guest that no
        // longer exists.
        self.forget_stored(&sandbox).await;
        self.volumes.release_all(id);
        self.close_session(&sandbox, ENDED_STOPPED).await;
        self.persist(&sandbox).await;
        tracing::info!(sandbox = id, "sandbox stopped");
        Ok(sandbox.record())
    }

    /// Boots a stopped sandbox on its existing disks.
    pub async fn start(&self, id: &str) -> Result<common::Sandbox, Status> {
        let sandbox = self.get(id).await?;
        let record = sandbox.record();
        let policy = record.policy.unwrap_or_default();
        self.volumes.claim(id, &policy.volumes)?;
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
        let resources = policy.resources.unwrap_or_default();
        let is_systemd = self.image_environment(sandbox.template()).await.systemd;
        let guest_os = burrow_vmm::GuestOs::from_record(&record.guest_os).unwrap_or_default();
        let mut spec = self.build_spec(
            id,
            &sandbox.workdir,
            sandbox.hypervisor,
            guest_os,
            &resources,
            &sandbox.lease,
            &sandbox.tap,
            &policy.volumes,
            is_systemd,
        );
        if let Err(err) = self.usernets.attach(id, &sandbox.lease, &mut spec) {
            self.volumes.release_all(id);
            return Err(err);
        }
        let request = guestconn::handshake_full(
            false,
            None,
            self.inspection_ca_for(&policy),
            self.trust_bundles_for(sandbox.template(), &policy).await,
            crate::volume::agent_mounts(&policy.volumes),
        );
        if let Err(err) = sandbox
            .boot(
                spec,
                request,
                self.config.agent_timeout,
                self.config.guest_upgrade.as_deref(),
            )
            .await
        {
            self.volumes.release_all(id);
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
        self.open_session(&sandbox, STARTED_BOOT).await;
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
        let sandbox = self
            .sandboxes
            .lock()
            .await
            .remove(id)
            .ok_or_else(|| Status::not_found(format!("no sandbox {id} on this node")))?;
        self.forget_stored(&sandbox).await;
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
        // not apply must not also leave a scratch disk behind.
        let rendered = self.sync_firewall().await;
        // Only now, once the render that stopped naming this address has been
        // applied. Held back rather than skipped when that render fails: the
        // lease has to come back either way, since a node that could not reach
        // nftables would otherwise leak a block per delete forever, and the
        // failure is already being returned to the caller and logged, which is
        // the part someone can act on.
        self.release_lease(id).await;

        if let Err(err) = tokio::fs::remove_dir_all(&workdir).await {
            tracing::warn!(sandbox = id, %err, "failed to remove sandbox directory");
        }
        let _ = tokio::fs::remove_dir_all(self.config.command_logs_dir(id)).await;
        rendered
    }
}

/// Keeping suspended sandboxes in the object store, and taking them over.
impl SandboxManager {
    /// Whether a sandbox can live in the object store at all. A volume is
    /// storage on this node with an identity of its own, and does not move.
    fn is_movable(sandbox: &RunningSandbox) -> bool {
        sandbox
            .record()
            .policy
            .unwrap_or_default()
            .volumes
            .is_empty()
    }

    /// Uploads a suspended sandbox's state behind whatever suspended it.
    fn spawn_upload(&self, sandbox: &Arc<RunningSandbox>) {
        if self.config.object_store.is_none() || !Self::is_movable(sandbox) {
            return;
        }
        let manager = self.clone();
        let sandbox = Arc::clone(sandbox);
        tokio::spawn(async move {
            if let Err(err) = manager.make_durable(&sandbox).await {
                tracing::warn!(
                    sandbox = sandbox.id(),
                    %err,
                    "could not store the suspended sandbox; it stays on this node until its next suspend"
                );
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
        if !Self::is_movable(sandbox) {
            return Ok(false);
        }
        let token = sandbox.durable.cancel.lock().unwrap().clone();
        let _uploading = sandbox.durable.upload.lock().await;
        if token.is_cancelled() || !sandbox.is_suspended() {
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
        let record = sandbox.record();
        let Some(secrets) = self.seal_for_store(&record)? else {
            tracing::warn!(
                sandbox = sandbox.id(),
                "sandbox holds brokered credentials and this node has no \
                 --object-store-key-file; it stays on this node"
            );
            return Ok(false);
        };
        let resources = sandbox.resources();
        let (vcpus, mem_mib) = {
            let spec = sandbox.spec.lock().unwrap();
            (spec.vcpus, spec.mem_mib)
        };
        let is_systemd = match &previous {
            Some(previous) => previous.manifest.is_systemd,
            None => self.image_environment(sandbox.template()).await.systemd,
        };
        let draft = crate::durable::Manifest {
            format: 0,
            id: sandbox.id().to_string(),
            generation: 0,
            node_id: record.node_id.clone(),
            state: String::new(),
            template: sandbox.template().to_string(),
            vcpus,
            mem_mib,
            scratch_disk_mib: match resources.scratch_disk_mib {
                0 => DEFAULT_SCRATCH_MIB,
                mib => mib,
            },
            is_systemd,
            arch: std::env::consts::ARCH.to_string(),
            firecracker_version: self.config.version(sandbox.hypervisor).to_string(),
            hypervisor: sandbox.hypervisor.to_string(),
            kernel_digest: String::new(),
            rootfs_digest: String::new(),
            cpu_usage_usec: record.cpu_usage_usec,
            rx_bytes: record.rx_bytes,
            tx_bytes: record.tx_bytes,
            secrets,
        };
        let uploaded = tokio::select! {
            () = token.cancelled() => return Ok(false),
            uploaded = async {
                // The base of a chain that arrived from the store is read
                // directly here, so it has to have arrived.
                sandbox.durable.settle_memory().await;
                crate::durable::upload(
                    store,
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
        if let Err(err) = crate::durable::purge(store, sandbox.id()).await {
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
        for sandbox in self.sandboxes.lock().await.values() {
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
        if !Self::is_movable(&sandbox) {
            return Err(Status::failed_precondition(
                "a sandbox with volumes cannot move: its volumes stay on the node that holds them",
            ));
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
        crate::durable::purge(store, id).await
    }

    /// Takes over a sandbox from the object store and resumes it here.
    ///
    /// `record` is the orchestrator's: its id, name, policy, metadata and
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
        if !record.policy.clone().unwrap_or_default().volumes.is_empty() {
            return Err(Status::failed_precondition(
                "a sandbox with volumes cannot move: its volumes stay on the node that holds them",
            ));
        }
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
        if manifest.state != crate::durable::STATE_SUSPENDED {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} was running on {} when it was last heard of; what the object store \
                 holds is from before that, and is not resumed in its place",
                manifest.node_id
            )));
        }
        let hypervisor = manifest.hypervisor()?;
        self.require_hypervisor(hypervisor)?;
        if manifest.arch != std::env::consts::ARCH
            || manifest.firecracker_version != self.config.version(hypervisor)
        {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} was stored on {} under {hypervisor} {} and cannot restore on this \
                 node ({} under {hypervisor} {})",
                manifest.arch,
                manifest.firecracker_version,
                std::env::consts::ARCH,
                self.config.version(hypervisor)
            )));
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
        let adopted = self
            .adopt_inner(store, &held, record, node_id.clone())
            .await;
        let (sandbox, from) = match adopted {
            Ok(adopted) => adopted,
            Err(err) => {
                self.creating.lock().await.remove(&id);
                return Err(err);
            }
        };
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

        self.emit(&sandbox, EVENT_STARTED, &format!("adopted:{from}"))
            .await;
        self.open_session(&sandbox, STARTED_RESUME).await;
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
    ) -> Result<(Arc<RunningSandbox>, String), Status> {
        let manifest = &held.manifest;
        let from = manifest.node_id.clone();
        let mut claimed = manifest.clone();
        claimed.state = crate::durable::STATE_RUNNING.to_string();
        claimed.node_id = node_id.clone();
        let mut policy = record.policy.clone().unwrap_or_default();
        let wanted = policy.resources.unwrap_or_default();
        policy.resources = Some(common::ResourcePolicy {
            vcpus: manifest.vcpus,
            mem_mib: manifest.mem_mib,
            scratch_disk_mib: manifest.scratch_disk_mib,
            ..wanted
        });
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
                record.metadata.clone(),
                node_id.clone(),
                record.name.clone(),
            )
            .await;
        let sandbox = match provisioned {
            Ok(sandbox) => sandbox,
            Err(err) => {
                self.hand_back(store, &node_id, manifest).await;
                return Err(err);
            }
        };
        *sandbox.durable.stored.lock().unwrap() =
            crate::durable::load_local(&sandbox.workdir).await;
        {
            let mut base = sandbox.base_record.lock().unwrap();
            base.created_at = record.created_at.clone();
            base.env = record.env.clone();
            base.kit = record.kit.clone();
            base.kit_credentials = record.kit_credentials.clone();
            base.kit_selection = record.kit_selection.clone();
            base.access_revoked_at = record.access_revoked_at;
        }
        *sandbox.usage.lock().unwrap() = Usage {
            cpu_usec: record.cpu_usage_usec.max(manifest.cpu_usage_usec),
            rx_bytes: record.rx_bytes.max(manifest.rx_bytes),
            tx_bytes: record.tx_bytes.max(manifest.tx_bytes),
            ..Default::default()
        };
        Ok((sandbox, from))
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

/// The proxy's form of a policy's HTTP rule.
fn proxy_http_rule(rule: &common::HttpRule) -> burrow_proxy::policy::HttpRule {
    burrow_proxy::policy::HttpRule {
        hosts: rule.hosts.clone(),
        methods: rule.methods.clone(),
        paths: rule.paths.clone(),
        is_denying: rule.is_denied,
    }
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

/// Maps a sandbox's declared network policy onto a firewall mode.
///
/// An unset policy means no egress: a sandbox that never stated what it needs
/// gets nothing, rather than inheriting whatever the default happens to be.
fn policy_mode(record: &common::Sandbox) -> firewall::Mode {
    let mode = record
        .policy
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .map(|n| n.mode)
        .unwrap_or(common::NetworkMode::Unspecified as i32);

    match common::NetworkMode::try_from(mode) {
        Ok(common::NetworkMode::Open) => firewall::Mode::Open,
        Ok(common::NetworkMode::Allowlist) => firewall::Mode::Allowlist,
        _ => firewall::Mode::None,
    }
}

/// Tells the agent to run the template's systemd under it.
pub(crate) fn guest_mode_arg(is_systemd: bool) -> &'static str {
    if is_systemd { "burrow.systemd=1" } else { "" }
}

/// Formats a sparse ext4 image for the sandbox's writable layer.
///
/// The file is sparse, so a 1 GiB disk costs only what the guest actually
/// writes. `lazy_itable_init` and `lazy_journal_init` keep formatting off the
/// sandbox-creation critical path; the kernel finishes the work in the guest.
pub(crate) async fn create_scratch(path: &Path, size_mib: u32) -> std::io::Result<()> {
    let output = tokio::process::Command::new("mkfs.ext4")
        .args([
            "-q",
            "-F",
            "-L",
            "burrow-scratch",
            "-b",
            "4096",
            "-E",
            "lazy_itable_init=1,lazy_journal_init=1",
        ])
        .arg(path)
        .arg(format!("{size_mib}M"))
        .output()
        .await?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "mkfs.ext4 failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
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

/// Creates a sandbox working directory backed by the template's kernel and
/// rootfs. Hard links keep creation cheap and let many sandboxes share one
/// read-only base image; the guest mounts it read-only so nothing writes back.
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A manager with no VMs behind it. Shared with the node edge's tests,
    /// which need a sandbox map to miss in.
    pub(crate) async fn manager() -> SandboxManager {
        SandboxManager::new(
            NodeConfig {
                data_dir: std::env::temp_dir().join(format!("burrow-fork-{}", std::process::id())),
                firecracker_bin: "/nonexistent/firecracker".into(),
                extra_boot_args: String::new(),
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

    #[tokio::test]
    async fn an_invalid_recovered_lease_is_removed_from_store() {
        let id = "ghost-invalid-lease";
        let data_dir = std::env::temp_dir().join(format!("burrow-recovery-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        let mut manager = manager().await;
        manager.config.data_dir = data_dir.clone();
        let workdir = manager.config.sandbox_dir(id, Hypervisor::Firecracker);
        tokio::fs::create_dir_all(&workdir).await.unwrap();
        tokio::fs::write(
            workdir.join(Hypervisor::Firecracker.layout().state),
            b"snapshot",
        )
        .await
        .unwrap();

        let invalid_block = burrow_net::ipam::BLOCKS_PER_NODE;
        manager
            .store
            .put_sandbox(&burrow_store::SandboxRow {
                id: id.into(),
                template: "default".into(),
                record: Vec::new(),
                state: common::SandboxState::Suspended as i32,
                lease_block: invalid_block,
                tap: format!("bt{invalid_block}"),
                ports: Vec::new(),
                share: None,
                suspended_at: 1,
            })
            .await
            .unwrap();
        manager
            .store
            .put_session(&burrow_store::SessionRow {
                id: "session-ghost-invalid-lease".into(),
                sandbox_id: id.into(),
                started_at: 1,
                ended_at: 1,
                started_by: "test".into(),
                ended_by: "test".into(),
            })
            .await
            .unwrap();

        manager.recover().await;

        assert!(manager.store.list_sandboxes().await.unwrap().is_empty());
        assert!(manager.store.list_sessions(id).await.unwrap().is_empty());
        assert!(manager.sandboxes.lock().await.is_empty());
        assert!(!workdir.exists());
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
    }

    /// A sandbox under a hypervisor this build does not know used to be read
    /// as a Firecracker one, found without a snapshot, and deleted along with
    /// its files. It stays recorded and on disk, out of service.
    #[tokio::test]
    async fn an_unknown_hypervisor_keeps_the_sandbox_on_recovery() {
        let id = "ghost-unknown-hypervisor";
        let data_dir =
            std::env::temp_dir().join(format!("burrow-recovery-unknown-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
        let mut manager = manager().await;
        manager.config.data_dir = data_dir.clone();
        let workdir = data_dir.join("sandboxes").join(id);
        tokio::fs::create_dir_all(&workdir).await.unwrap();
        tokio::fs::write(workdir.join("snapshot.future"), b"snapshot")
            .await
            .unwrap();
        let record = common::Sandbox {
            id: id.into(),
            hypervisor: "future-vmm".into(),
            ..Default::default()
        };
        manager
            .store
            .put_sandbox(&burrow_store::SandboxRow {
                id: id.into(),
                template: "default".into(),
                record: prost::Message::encode_to_vec(&record),
                state: common::SandboxState::Suspended as i32,
                lease_block: 0,
                tap: "bt0".into(),
                ports: Vec::new(),
                share: None,
                suspended_at: 1,
            })
            .await
            .unwrap();

        manager.recover().await;

        assert_eq!(manager.store.list_sandboxes().await.unwrap().len(), 1);
        assert!(manager.sandboxes.lock().await.is_empty());
        assert!(workdir.join("snapshot.future").exists());
        let _ = tokio::fs::remove_dir_all(&data_dir).await;
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
        // attempt; the same shape spelled as defaults does not.
        manager.warm_in_background("app".into(), shape(4, 1024));
        manager.warm_in_background("app".into(), common::ResourcePolicy::default());
        manager.warm_in_background("app".into(), shape(1, 512));
        assert_eq!(attempted(&manager).len(), 3);

        // And a template of its own, however alike its shape.
        manager.warm_in_background("other".into(), shape(2, 1024));
        assert_eq!(attempted(&manager).len(), 4);
    }

    /// A republished template's old snapshot restores a guest onto a rootfs it
    /// never saw, so invalidating must both discard it and let the replacement
    /// be built: `warm_attempted` is otherwise insert-only for the node's life.
    #[tokio::test]
    async fn republishing_a_template_discards_its_warm_snapshot() {
        let manager = manager().await;
        manager.warm_in_background("app".into(), shape(2, 1024));
        manager.warm_in_background("app".into(), shape(4, 2048));
        manager.warm_in_background("other".into(), shape(2, 1024));

        let warm = crate::warm::warm_dir(&manager.config.templates_dir(), "app");
        tokio::fs::create_dir_all(&warm).await.unwrap();
        tokio::fs::write(
            warm.join(burrow_vmm::firecracker::SNAPSHOT_MEM_FILE),
            b"stale",
        )
        .await
        .unwrap();

        manager.invalidate_warm("app").await;

        assert!(!tokio::fs::try_exists(&warm).await.unwrap());
        // Every shape of that template, and nothing of any other.
        let attempts = attempted(&manager);
        assert!(attempts.iter().all(|key| key.template == "other"));
        assert_eq!(attempts.len(), 1);
    }

    /// The shapes come from create requests, so a caller naming a fresh one
    /// every time must not be able to grow this for the life of the node, nor
    /// to queue a boot and a memory image for each.
    #[tokio::test]
    async fn a_novel_shape_does_not_buy_itself_a_warm_build() {
        let manager = manager().await;
        manager.warm_for_demand(&ShapeKey::of("app", &shape(7, 3333)));
        assert!(attempted(&manager).is_empty());

        // The shape a create with no resource policy asks for is the exception:
        // it is what an explicit warm builds, and it is warmed on sight.
        manager.warm_for_demand(&ShapeKey::of("app", &common::ResourcePolicy::default()));
        assert_eq!(attempted(&manager).len(), 1);

        // A thousand one-off shapes leave the tally bounded and add no builds.
        for mem in 0..1000u32 {
            manager.warm_for_demand(&ShapeKey::of("app", &shape(2, 1000 + mem)));
        }
        let shapes = manager.warm_shapes.lock().unwrap();
        assert!(shapes["app"].demand.len() <= MAX_TRACKED_SHAPES);
        drop(shapes);
        assert_eq!(attempted(&manager).len(), 1);
    }

    /// A build is a boot and a snapshot is disk, so one template warms a
    /// handful of shapes rather than every shape ever asked for. The oldest
    /// makes way, so an explicit warm is never refused.
    #[tokio::test]
    async fn attempts_are_capped_per_template() {
        let manager = manager().await;
        for vcpus in 1..=(MAX_WARM_SHAPES as u32 + 3) {
            manager.warm_in_background("app".into(), shape(vcpus, 1024));
        }
        let shapes = manager.warm_shapes.lock().unwrap();
        assert_eq!(shapes["app"].attempted.len(), MAX_WARM_SHAPES);
        // Oldest first: the earliest shapes are the ones forgotten.
        assert_eq!(shapes["app"].attempted[0].vcpus, 4);
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
        // Once is not demand; a shape has to recur before it is worth a boot.
        for _ in 0..WARM_DEMAND_THRESHOLD {
            manager.warm_for_demand(&ShapeKey::of("app", &shape(4, 2048)));
        }
        let attempts = attempted(&manager);
        let key = attempts.first().expect("an attempt was recorded");
        assert_eq!((key.vcpus, key.mem_mib), (4, 2048));
        assert_eq!(key.template, "app");
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
        manager.set_inspection_ca("-----BEGIN CERTIFICATE-----\n".into());

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
        manager.set_inspection_ca("-----BEGIN CERTIFICATE-----\n".into());

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
        assert!(manager.sandboxes.lock().await.is_empty());
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
        manager
            .ipam
            .lock()
            .await
            .reserve(sandbox.id(), sandbox.lease.block)
            .unwrap();
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
        let lease = Ipam::for_node(0).unwrap().allocate("sbx_a").unwrap();
        let workdir = std::path::PathBuf::from("/tmp/burrow-test");
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
