//! The hypervisor-neutral VM interface the daemon drives.
//!
//! A sandbox runs under one hypervisor, chosen when it is created and fixed for
//! its life. Everything the daemon does to a VM goes through [`Vm`], and
//! everything it decides about one comes from [`Capabilities`]: a lifecycle
//! path asks whether the backend can take a diff or hotplug a drive, never
//! which backend it is talking to.
//!
//! The backends are an enum rather than trait objects. The set is closed and
//! lives in this crate, every operation is async (which a `dyn` trait can only
//! express by boxing each future), and a `match` makes a new backend answer for
//! every operation at compile time instead of inheriting a default that does
//! the wrong thing quietly.

mod cgroup;
pub mod console;
mod error;
mod guest;
mod http;

pub mod cloud_hypervisor;
pub mod firecracker;
pub mod memfile;
#[cfg(target_os = "macos")]
pub mod vz;

use std::path::PathBuf;
use std::time::Duration;

pub use cgroup::{Cgroup, Limits, is_io_weight_supported};
pub use cloud_hypervisor::{ChJail, CloudHypervisorConfig};
pub use error::{Error, Result};
pub use firecracker::{FirecrackerConfig, Jail, MemorySource, PageSource};
pub use guest::{GUEST_CID, GuestAddr, VSOCK_UDS};
pub use memfile::{data_extents, merge_chain};
#[cfg(target_os = "macos")]
pub use vz::{MacOsBoot, Requirements, VzConfig};

/// `console=ttyS0` is the guest serial port, which both backends capture to
/// the VM's console log; `panic=1 reboot=k` makes a panicking guest exit the
/// VMM rather than hang.
/// `pci=off` is deliberately absent: virtio devices sit on a PCI bus so that
/// volumes can be hotplugged onto a sandbox restored from a warm snapshot, and
/// a guest told to ignore the bus would never see them.
/// `memhp_default_state=online_movable` onlines memory virtio-mem plugs as
/// soon as it arrives, there being no udev in the guest to do it, and in
/// ZONE_MOVABLE, which the kernel keeps its own allocations out of so that the
/// memory can be emptied and unplugged again.
pub const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable";

/// What a guest's memory moves in, the virtio-mem block size both backends
/// use.
pub const MEMORY_BLOCK_MIB: u32 = 2;
/// What a hotplug region is sized in: Firecracker's slot, and Cloud
/// Hypervisor's alignment for a virtio-mem region.
pub const MEMORY_REGION_ALIGN_MIB: u32 = 128;

/// A disk the guest sees, in the order it sees them.
#[derive(Debug, Clone)]
pub struct DriveSpec {
    pub id: String,
    /// Path relative to the VM working directory.
    pub path: String,
    pub is_root: bool,
    pub is_read_only: bool,
}

impl DriveSpec {
    pub fn root_ro(path: impl Into<String>) -> Self {
        Self {
            id: "rootfs".into(),
            path: path.into(),
            is_root: true,
            is_read_only: true,
        }
    }

    /// The sandbox's own root disk, which the guest mounts read-write as `/`.
    pub fn root_rw(path: impl Into<String>) -> Self {
        Self {
            id: "rootfs".into(),
            path: path.into(),
            is_root: true,
            is_read_only: false,
        }
    }

    pub fn scratch_rw(path: impl Into<String>) -> Self {
        Self {
            id: "scratch".into(),
            path: path.into(),
            is_root: false,
            is_read_only: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetSpec {
    /// Host tap device name. A restore names the sandbox's own, whatever the
    /// snapshot was taken with.
    pub tap: String,
    pub guest_mac: Option<String>,
}

pub use burrow_common::hypervisor::{GuestOs, Hypervisor};

const MEMORY_POLL: Duration = Duration::from_millis(50);
/// How long a guest may make no progress plugging or unplugging before it is
/// taken to have stopped where it is.
const MEMORY_STALL: Duration = Duration::from_secs(3);
const MEMORY_TIMEOUT: Duration = Duration::from_secs(120);

/// The framework's save file, device state and memory in one: both halves of
/// the vz backend's [`Layout`]. Named here so every build knows the layout
/// of state a Mac node wrote.
pub const VZ_SAVE_FILE: &str = "snapshot.vzsave";

/// What this crate knows about each hypervisor: what its backend can do and
/// the files its snapshots are made of.
pub trait HypervisorExt {
    fn capabilities(self) -> Capabilities;
    /// The files a snapshot of this hypervisor's VM is made of.
    fn layout(self) -> Layout;
}

impl HypervisorExt for Hypervisor {
    fn capabilities(self) -> Capabilities {
        match self {
            Self::Firecracker => Capabilities {
                is_diff_snapshot_supported: true,
                is_lazy_memory_supported: true,
                is_drive_hotplug_supported: true,
                is_jailable: true,
                guest_oses: &[GuestOs::Linux],
                is_warm_pool_supported: true,
                is_tap_networked: true,
                is_live_disk_growth_supported: true,
                is_vcpu_hotplug_supported: false,
                is_memory_hotplug_supported: true,
                is_nested_virt_supported: false,
            },
            // Cloud Hypervisor copies guest memory in at restore, and its
            // own on-demand mode cannot be pointed at burrow's page-fault
            // handler: no chains, no prefetch plans, no memory still arriving
            // from the object store.
            Self::CloudHypervisor => Capabilities {
                is_diff_snapshot_supported: false,
                is_lazy_memory_supported: false,
                is_drive_hotplug_supported: true,
                is_jailable: true,
                guest_oses: &[GuestOs::Linux],
                is_warm_pool_supported: true,
                is_tap_networked: true,
                is_live_disk_growth_supported: true,
                // arm64 KVM creates every vCPU before the VM first runs, and
                // refuses one created after with EBUSY.
                is_vcpu_hotplug_supported: cfg!(target_arch = "x86_64"),
                is_memory_hotplug_supported: true,
                is_nested_virt_supported: cfg!(target_arch = "x86_64"),
            },
            // The framework saves a machine as one opaque file, reads it back
            // itself and attaches storage only at configuration time.
            Self::Vz => Capabilities {
                is_diff_snapshot_supported: false,
                is_lazy_memory_supported: false,
                is_drive_hotplug_supported: false,
                is_jailable: false,
                guest_oses: &[GuestOs::MacOs],
                // A restore takes longer than a cold boot, and a saved state
                // restores into only one running machine at a time.
                is_warm_pool_supported: false,
                is_tap_networked: false,
                is_live_disk_growth_supported: false,
                is_vcpu_hotplug_supported: false,
                // A running machine's memory can only be ballooned below what
                // it was configured with, never raised.
                is_memory_hotplug_supported: false,
                is_nested_virt_supported: false,
            },
        }
    }

    fn layout(self) -> Layout {
        match self {
            Self::Firecracker => Layout {
                state: firecracker::SNAPSHOT_FILE,
                memory: Some(firecracker::SNAPSHOT_MEM_FILE),
            },
            Self::CloudHypervisor => Layout {
                state: cloud_hypervisor::STATE_FILE,
                memory: Some(cloud_hypervisor::MEMORY_FILE),
            },
            Self::Vz => Layout {
                state: VZ_SAVE_FILE,
                memory: None,
            },
        }
    }
}

/// What a backend can do, which is all the daemon branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// A snapshot can record only the pages dirtied since the last one, layered
    /// over it as a chain, so a suspend writes a fraction of the guest.
    pub is_diff_snapshot_supported: bool,
    /// Restored memory can be served by burrow's page-fault handler: a chain of
    /// layers, a prefetch plan, a base still arriving from the object store.
    /// Without it a restore needs the whole memory image on disk first.
    pub is_lazy_memory_supported: bool,
    /// A drive can be attached to a running guest. It is how a volume reaches a
    /// sandbox restored from a snapshot taken without it; without it such a
    /// sandbox has to boot cold to get one.
    pub is_drive_hotplug_supported: bool,
    /// The VMM can run confined to the sandbox's directory as an unprivileged
    /// uid: Firecracker under its jailer, Cloud Hypervisor in the jail burrowd
    /// builds for it. A backend without it keeps its files in the ordinary
    /// sandbox directory and runs as the daemon does.
    pub is_jailable: bool,
    /// Guests it can boot.
    pub guest_oses: &'static [GuestOs],
    /// Restoring a template's warm snapshot beats booting it, and one
    /// snapshot can be restored into many sandboxes at once.
    pub is_warm_pool_supported: bool,
    /// The guest's NIC is a host tap, which the node's firewall polices. A
    /// backend without one has no network until it is given its own.
    pub is_tap_networked: bool,
    /// A running guest can be told its disk grew ([`Vm::resize_disk`]), and
    /// grow the filesystem on it. Without it a disk grows only while its
    /// sandbox is shut down.
    pub is_live_disk_growth_supported: bool,
    /// A running guest can be given vCPUs up to [`VmSpec::max_vcpus`] and
    /// have them taken away again ([`Vm::resize_vcpus`]).
    pub is_vcpu_hotplug_supported: bool,
    /// A Linux guest can be booted with a virtio-mem region of
    /// [`VmSpec::mem_hotplug_mib`] and have memory plugged into it and
    /// unplugged from it while it runs ([`Vm::resize_memory`]). The guest
    /// kernel needs `CONFIG_VIRTIO_MEM`.
    pub is_memory_hotplug_supported: bool,
    /// A guest can be shown the host's virtualization extensions and run
    /// KVM itself ([`VmSpec::is_nested_virt_enabled`]). Firecracker masks
    /// them out of every guest's CPUID.
    pub is_nested_virt_supported: bool,
}

impl Capabilities {
    pub fn runs(&self, os: GuestOs) -> bool {
        self.guest_oses.contains(&os)
    }
}

/// Whether this host's KVM lets a guest run KVM itself: `kvm_amd` or
/// `kvm_intel` loaded with `nested` on, which a node that is itself a VM has
/// only where its own host passes the extensions through.
pub fn is_nested_virt_supported() -> bool {
    ["kvm_amd", "kvm_intel"].iter().any(|module| {
        std::fs::read_to_string(format!("/sys/module/{module}/parameters/nested"))
            .is_ok_and(|value| is_on(&value))
    })
}

/// A KVM module parameter's reading: `kvm_amd` prints an int, `kvm_intel` a
/// bool.
fn is_on(value: &str) -> bool {
    matches!(value.trim(), "1" | "Y")
}

/// Where a snapshot's two halves live in a VM's working directory.
///
/// Fixed names, identical for every sandbox under one hypervisor, which is what
/// lets a snapshot be linked from one sandbox's directory into another's and
/// restored there unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// The device and vCPU state, small, rewritten by every snapshot.
    pub state: &'static str,
    /// The guest's memory, or the base of its chain where diffs are supported.
    /// `None` where the backend saves memory inside the state file, so there
    /// is no memory image to chunk, serve lazily or layer diffs over.
    pub memory: Option<&'static str>,
}

impl Layout {
    /// The snapshot's files, state first.
    pub fn files(&self) -> impl Iterator<Item = &'static str> {
        std::iter::once(self.state).chain(self.memory)
    }

    /// The diff written by a suspend while `index` layers already exist.
    pub fn diff(index: usize) -> String {
        format!("snapshot.diff{index}.mem")
    }

    /// The index [`Self::diff`] named `file` with, if it is a diff at all.
    pub fn diff_index(file: &str) -> Option<usize> {
        file.strip_prefix("snapshot.diff")
            .and_then(|rest| rest.strip_suffix(".mem"))
            .and_then(|index| index.parse().ok())
    }
}

/// The hypervisor a VM runs under, and how this node runs it.
#[derive(Debug, Clone)]
pub enum Backend {
    Firecracker(FirecrackerConfig),
    CloudHypervisor(CloudHypervisorConfig),
    #[cfg(target_os = "macos")]
    Vz(VzConfig),
}

impl Backend {
    pub fn hypervisor(&self) -> Hypervisor {
        match self {
            Self::Firecracker(_) => Hypervisor::Firecracker,
            Self::CloudHypervisor(_) => Hypervisor::CloudHypervisor,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Hypervisor::Vz,
        }
    }
}

impl Default for Boot {
    /// The template's own kernel, which is every Linux sandbox's boot.
    fn default() -> Self {
        Self::Kernel {
            kernel: "vmlinux".into(),
            cmdline: DEFAULT_BOOT_ARGS.into(),
        }
    }
}

/// What the machine boots from, beneath its drives.
#[derive(Debug, Clone)]
pub enum Boot {
    /// A Linux kernel, relative to the VM's working directory, with its
    /// command line.
    Kernel { kernel: String, cmdline: String },
    /// UEFI firmware, which boots the first drive. `None` is the one the
    /// backend ships; a Windows guest under Cloud Hypervisor gets that even
    /// when its spec names a kernel, as it always has.
    Firmware { firmware: Option<PathBuf> },
    /// A macOS install's own boot loader and platform identity.
    #[cfg(target_os = "macos")]
    MacOs(MacOsBoot),
}

/// Everything needed to start or restore one VM.
///
/// Paths are relative to `workdir`, so a snapshot restored in another
/// sandbox's directory finds the same files under the same names.
#[derive(Debug, Clone)]
pub struct VmSpec {
    pub vm_id: String,
    pub workdir: PathBuf,
    pub backend: Backend,
    pub guest_os: GuestOs,
    pub boot: Boot,
    /// In the order the guest sees them: it finds its disks by position.
    pub drives: Vec<DriveSpec>,
    /// Put virtio devices on a PCI bus instead of MMIO. Firecracker only: Cloud
    /// Hypervisor is always PCI. See [`firecracker::MicroVmSpec::is_pci_enabled`].
    pub is_pci_enabled: bool,
    pub vcpus: u32,
    /// vCPUs the guest is booted able to take, where
    /// [`Capabilities::is_vcpu_hotplug_supported`]; never below `vcpus`.
    pub max_vcpus: u32,
    /// The memory the guest boots with.
    pub mem_mib: u32,
    /// The virtio-mem region above it, which memory is plugged into while the
    /// guest runs; 0 for none. A multiple of [`MEMORY_REGION_ALIGN_MIB`], and
    /// only where [`Capabilities::is_memory_hotplug_supported`]. A restore
    /// takes the region and what is plugged in it from the snapshot.
    pub mem_hotplug_mib: u32,
    /// How much of the region is plugged now: none at a boot, what the
    /// snapshot holds at a restore, and whatever [`Vm::resize_memory`] reached
    /// since.
    pub mem_plugged_mib: u32,
    pub net: Option<NetSpec>,

    /// Enable virtio-vsock, the transport the guest agent speaks.
    pub is_vsock_enabled: bool,
    /// Needed for diff snapshots.
    pub is_dirty_pages_tracked: bool,
    /// The lazy-memory knobs below are honoured only where
    /// [`Capabilities::is_lazy_memory_supported`]; see
    /// [`firecracker::MicroVmSpec`] for each.
    pub is_memory_lazy: bool,
    pub memory_chain: Vec<String>,
    pub prefetch: Option<String>,
    pub record_prefetch: Option<String>,
    pub memory_source: Option<MemorySource>,
    /// Host resource caps, applied to the VMM process.
    pub limits: Limits,
    /// cgroup2 mount point; `None` disables limit enforcement.
    pub cgroup_root: Option<PathBuf>,
    pub is_limits_required: bool,
    /// Puts a Cloud Hypervisor guest's console on a socket the caller holds,
    /// so it takes input the way Firecracker's does on its stdin. For the dev
    /// harness: output reaches the console log only while the VM's handle is
    /// alive to copy it there.
    pub is_console_interactive: bool,
    /// Shows the guest the host's virtualization extensions (SVM or VMX), so
    /// it gets a `/dev/kvm` of its own. Only where
    /// [`Capabilities::is_nested_virt_supported`], on a host whose KVM has
    /// nesting on ([`is_nested_virt_supported`]); the guest kernel needs
    /// `CONFIG_KVM_AMD` or `CONFIG_KVM_INTEL`.
    pub is_nested_virt_enabled: bool,
}

impl VmSpec {
    pub fn new(vm_id: impl Into<String>, workdir: impl Into<PathBuf>, backend: Backend) -> Self {
        Self {
            vm_id: vm_id.into(),
            workdir: workdir.into(),
            backend,
            guest_os: GuestOs::Linux,
            boot: Boot::default(),
            drives: Vec::new(),
            is_pci_enabled: false,
            vcpus: 1,
            max_vcpus: 0,
            mem_mib: 512,
            mem_hotplug_mib: 0,
            mem_plugged_mib: 0,
            net: None,
            is_vsock_enabled: false,
            is_dirty_pages_tracked: false,
            is_memory_lazy: false,
            memory_chain: Vec::new(),
            prefetch: None,
            record_prefetch: None,
            memory_source: None,
            limits: Limits::default(),
            cgroup_root: Some(PathBuf::from("/sys/fs/cgroup")),
            is_limits_required: false,
            is_console_interactive: false,
            is_nested_virt_enabled: false,
        }
    }

    pub fn hypervisor(&self) -> Hypervisor {
        self.backend.hypervisor()
    }

    pub fn capabilities(&self) -> Capabilities {
        self.hypervisor().capabilities()
    }

    pub fn layout(&self) -> Layout {
        self.hypervisor().layout()
    }
}

/// A running (or paused) VM under any backend. Boxed, since each carries
/// hundreds of bytes of process and spec and the handle is moved through
/// every lifecycle call.
pub enum Vm {
    Firecracker(Box<firecracker::MicroVm>),
    CloudHypervisor(Box<cloud_hypervisor::ChVm>),
    #[cfg(target_os = "macos")]
    Vz(Box<vz::VzVm>),
}

impl Vm {
    /// Starts a VM and boots its guest from [`VmSpec::boot`].
    pub async fn boot(spec: VmSpec) -> Result<Self> {
        match spec.backend.clone() {
            Backend::Firecracker(config) => Ok(Self::Firecracker(Box::new(
                firecracker::MicroVm::boot(firecracker::spec(spec, config)?).await?,
            ))),
            Backend::CloudHypervisor(config) => Ok(Self::CloudHypervisor(Box::new(
                cloud_hypervisor::ChVm::boot(spec, config).await?,
            ))),
            #[cfg(target_os = "macos")]
            Backend::Vz(config) => Ok(Self::Vz(Box::new(vz::VzVm::boot(spec, config).await?))),
        }
    }

    /// Starts a VM from the snapshot in `spec.workdir` instead of booting.
    /// `spec` must describe the same machine the snapshot was taken of.
    pub async fn restore(spec: VmSpec, resume: bool) -> Result<Self> {
        match spec.backend.clone() {
            Backend::Firecracker(config) => Ok(Self::Firecracker(Box::new(
                firecracker::MicroVm::restore(firecracker::spec(spec, config)?, resume).await?,
            ))),
            Backend::CloudHypervisor(config) => Ok(Self::CloudHypervisor(Box::new(
                cloud_hypervisor::ChVm::restore(spec, config, resume).await?,
            ))),
            #[cfg(target_os = "macos")]
            Backend::Vz(config) => Ok(Self::Vz(Box::new(
                vz::VzVm::restore(spec, config, resume).await?,
            ))),
        }
    }

    pub fn hypervisor(&self) -> Hypervisor {
        match self {
            Self::Firecracker(_) => Hypervisor::Firecracker,
            Self::CloudHypervisor(_) => Hypervisor::CloudHypervisor,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Hypervisor::Vz,
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        self.hypervisor().capabilities()
    }

    /// Where the guest's vsock listeners are reached from the host.
    pub fn guest(&self) -> GuestAddr {
        match self {
            Self::Firecracker(vm) => GuestAddr::in_workdir(&vm.spec().workdir),
            Self::CloudHypervisor(vm) => GuestAddr::in_workdir(vm.workdir()),
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => GuestAddr::in_workdir(vm.workdir()),
        }
    }

    /// Waits for a guest vsock listener to accept, which is the agent's
    /// readiness signal.
    pub async fn wait_for_vsock(&self, port: u32, timeout: Duration) -> Result<Duration> {
        self.guest().wait(port, timeout).await
    }

    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Firecracker(vm) => vm.pid(),
            Self::CloudHypervisor(vm) => vm.pid(),
            // The XPC service the framework spawned for the machine.
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.pid(),
        }
    }

    /// Whether the VMM process has exited on its own. A vz machine runs in a
    /// service process this node does not own, so it never reads as exited.
    pub fn has_exited(&mut self) -> bool {
        match self {
            Self::Firecracker(vm) => vm.has_exited(),
            Self::CloudHypervisor(vm) => vm.has_exited(),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => false,
        }
    }

    /// From spawning the VMM to a guest that is running or ready to.
    pub fn boot_latency(&self) -> Duration {
        match self {
            Self::Firecracker(vm) => vm.boot_latency(),
            Self::CloudHypervisor(vm) => vm.boot_latency(),
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.boot_latency(),
        }
    }

    /// Host CPU this VM has consumed, in microseconds; `None` without a
    /// cgroup, or for a vz machine whose process could not be found.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        match self {
            Self::Firecracker(vm) => vm.cpu_usage_usec(),
            Self::CloudHypervisor(vm) => vm.cpu_usage_usec(),
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.cpu_usage_usec(),
        }
    }

    /// How the VMM process ended, once it has.
    pub fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        match self {
            Self::Firecracker(vm) => vm.exit_status(),
            Self::CloudHypervisor(vm) => vm.exit_status(),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => None,
        }
    }

    /// The last of what the VMM itself printed. Firecracker's goes to the
    /// console log with the guest's.
    pub async fn vmm_log_tail(&self, lines: usize) -> String {
        match self {
            Self::Firecracker(vm) => vm.console_tail(lines).await,
            Self::CloudHypervisor(vm) => vm.vmm_log_tail(lines).await,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => String::new(),
        }
    }

    pub async fn console_tail(&self, lines: usize) -> String {
        match self {
            Self::Firecracker(vm) => vm.console_tail(lines).await,
            Self::CloudHypervisor(vm) => vm.console_tail(lines).await,
            // A macOS guest writes nothing to a serial console.
            #[cfg(target_os = "macos")]
            Self::Vz(_) => String::new(),
        }
    }

    /// Writes to the guest serial console, for dev and rescue only.
    pub async fn console_write(&mut self, input: &str) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.console_write(input).await?),
            Self::CloudHypervisor(vm) => vm.console_write(input).await,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Err(Error::ConsoleUnavailable),
        }
    }

    pub async fn pause(&self) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.pause().await?),
            Self::CloudHypervisor(vm) => vm.pause().await,
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.pause().await.map(drop),
        }
    }

    pub async fn resume(&self) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.resume().await?),
            Self::CloudHypervisor(vm) => vm.resume().await,
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.resume().await.map(drop),
        }
    }

    /// Snapshots a **paused** VM in full, into its [`Layout`].
    pub async fn snapshot(&self) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.snapshot(firecracker::SnapshotType::Full).await?),
            Self::CloudHypervisor(vm) => vm.snapshot().await,
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.snapshot().await.map(drop),
        }
    }

    /// Snapshots a **paused** VM's dirtied pages into `mem_file`, layered over
    /// the memory it was restored from. Only where
    /// [`Capabilities::is_diff_snapshot_supported`].
    pub async fn snapshot_diff(&self, mem_file: &str) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm
                .snapshot_to(firecracker::SnapshotType::Diff, mem_file)
                .await?),
            Self::CloudHypervisor(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::CloudHypervisor,
                what: "take a diff snapshot",
            }),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::Vz,
                what: "take a diff snapshot",
            }),
        }
    }

    /// Whether a diff taken now would know exactly which pages it holds. A
    /// suspend or checkpoint that cannot takes a full snapshot instead.
    pub fn can_map_diff(&self) -> bool {
        match self {
            Self::Firecracker(vm) => vm.can_map_diff(),
            _ => false,
        }
    }

    /// Attaches a drive to the running guest. Only where
    /// [`Capabilities::is_drive_hotplug_supported`].
    pub async fn attach_drive(&self, drive: &DriveSpec) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.attach_drive(drive).await?),
            Self::CloudHypervisor(vm) => vm.attach_drive(drive).await,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::Vz,
                what: "attach a drive to a running guest",
            }),
        }
    }

    /// Tells the running guest that the drive `id` is now `bytes` long.
    /// Cloud Hypervisor sets the length itself; Firecracker reopens a file the
    /// caller has grown already. Only where
    /// [`Capabilities::is_live_disk_growth_supported`].
    pub async fn resize_disk(&self, id: &str, bytes: u64) -> Result<()> {
        match self {
            Self::CloudHypervisor(vm) => vm.resize_disk(id, bytes).await,
            Self::Firecracker(vm) => Ok(vm.resize_drive(id).await?),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::Vz,
                what: "grow a disk the guest has mounted",
            }),
        }
    }

    /// Sets the running guest's vCPUs to `vcpus`, within the
    /// [`VmSpec::max_vcpus`] it was booted with.
    /// Only where [`Capabilities::is_vcpu_hotplug_supported`].
    pub async fn resize_vcpus(&self, vcpus: u32) -> Result<()> {
        match self {
            Self::CloudHypervisor(vm) => vm.resize_vcpus(vcpus).await,
            Self::Firecracker(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::Firecracker,
                what: "change a running guest's vcpus",
            }),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::Vz,
                what: "change a running guest's vcpus",
            }),
        }
    }

    /// Moves the running VMM's CPU and IO limits.
    pub fn set_limits(&self, limits: &Limits) -> Result<()> {
        let cgroup = match self {
            Self::Firecracker(vm) => vm.cgroup(),
            Self::CloudHypervisor(vm) => vm.cgroup(),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => {
                return Err(Error::Unsupported {
                    hypervisor: Hypervisor::Vz,
                    what: "limit a machine's host CPU or IO",
                });
            }
        };
        match cgroup {
            Some(cgroup) => cgroup.set_limits(limits),
            None => Err(Error::CgroupUnavailable {
                reason: "this VM runs under no cgroup".into(),
            }),
        }
    }

    /// Asks the guest to have `plugged_mib` of its virtio-mem region plugged
    /// and follows it there, returning the MiB plugged once it arrives or
    /// stops making progress. A guest that stops short is asked to stay
    /// where it stopped, so the device does not keep pulling at memory the
    /// caller was told it kept. Only where
    /// [`Capabilities::is_memory_hotplug_supported`], on a VM booted with a
    /// region.
    pub async fn resize_memory(&self, plugged_mib: u32) -> Result<u32> {
        let mut plugged = self.plugged_memory().await?;
        if plugged == plugged_mib {
            return Ok(plugged);
        }
        self.request_memory(plugged_mib).await?;
        let started = std::time::Instant::now();
        let mut progressed = started;
        while plugged != plugged_mib
            && progressed.elapsed() < MEMORY_STALL
            && started.elapsed() < MEMORY_TIMEOUT
        {
            tokio::time::sleep(MEMORY_POLL).await;
            let now = self.plugged_memory().await?;
            if now != plugged {
                plugged = now;
                progressed = std::time::Instant::now();
            }
        }
        if plugged != plugged_mib {
            self.request_memory(plugged).await?;
            plugged = self.plugged_memory().await?;
        }
        Ok(plugged)
    }

    async fn request_memory(&self, plugged_mib: u32) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.request_memory(plugged_mib).await?),
            Self::CloudHypervisor(vm) => vm.request_memory(plugged_mib).await,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Err(Error::Unsupported {
                hypervisor: Hypervisor::Vz,
                what: "change a running guest's memory",
            }),
        }
    }

    /// MiB of the virtio-mem region the guest has plugged.
    pub async fn plugged_memory(&self) -> Result<u32> {
        match self {
            Self::Firecracker(vm) => Ok(vm.plugged_memory().await?),
            Self::CloudHypervisor(vm) => vm.plugged_memory().await,
            #[cfg(target_os = "macos")]
            Self::Vz(_) => Ok(0),
        }
    }

    /// Moves the VMM's memory cap. A grow raises it before memory is plugged
    /// and a shrink lowers it once memory is out, so the cap never sits below
    /// what the guest holds.
    pub fn set_memory_limit(&self, mib: u32) -> Result<()> {
        let cgroup = match self {
            Self::Firecracker(vm) => vm.cgroup(),
            Self::CloudHypervisor(vm) => vm.cgroup(),
            #[cfg(target_os = "macos")]
            Self::Vz(_) => None,
        };
        match cgroup {
            Some(cgroup) => cgroup.set_memory(mib),
            None => Ok(()),
        }
    }

    /// Stops the VMM and reaps it, then releases its cgroup.
    pub async fn kill(self) -> Result<()> {
        match self {
            Self::Firecracker(vm) => Ok(vm.kill().await?),
            Self::CloudHypervisor(vm) => vm.kill().await,
            #[cfg(target_os = "macos")]
            Self::Vz(vm) => vm.kill().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_reads_on_from_either_kvm_module() {
        assert!(is_on("1\n"));
        assert!(is_on("Y\n"));
        assert!(!is_on("0\n"));
        assert!(!is_on("N\n"));
    }

    #[test]
    fn names_round_trip_and_an_empty_record_is_refused() {
        for hypervisor in Hypervisor::ALL {
            assert_eq!(hypervisor.as_str().parse::<Hypervisor>(), Ok(hypervisor));
        }
        assert_eq!(Hypervisor::from_record(""), None);
        assert_eq!(Hypervisor::from_record("kvmtool"), None);
        assert_eq!(GuestOs::from_record(""), Some(GuestOs::Linux));
    }

    /// A Windows template has no Firecracker to fall back on, and a Linux one
    /// keeps the backend every existing sandbox runs under.
    #[test]
    fn the_default_hypervisor_follows_the_guest() {
        assert_eq!(GuestOs::Linux.default_hypervisor(), Hypervisor::Firecracker);
        assert_eq!(
            GuestOs::Windows.default_hypervisor(),
            Hypervisor::CloudHypervisor
        );
    }

    /// Two backends sharing a file name would let one restore the other's
    /// snapshot, which fails deep inside the VMM rather than at a check.
    #[test]
    fn each_backend_owns_distinct_snapshot_files() {
        let fc = Hypervisor::Firecracker.layout();
        assert_eq!(fc.state, "snapshot.vmstate");
        assert_eq!(fc.memory, Some("snapshot.mem"));
        for hypervisor in &Hypervisor::ALL[1..] {
            let layout = hypervisor.layout();
            for name in layout.files() {
                assert!(fc.files().all(|fc| fc != name), "{name} is shared");
                assert_eq!(Layout::diff_index(name), None);
            }
        }
    }

    /// Only a backend that keeps memory inside its state has no memory file,
    /// which is what keeps the daemon from chunking or serving one.
    #[test]
    fn memory_is_a_file_of_its_own_on_linux_backends() {
        assert!(Hypervisor::Firecracker.layout().memory.is_some());
        assert!(Hypervisor::CloudHypervisor.layout().memory.is_some());
    }

    #[test]
    fn diffs_are_numbered_and_parsed_back() {
        assert_eq!(Layout::diff(3), "snapshot.diff3.mem");
        assert_eq!(Layout::diff_index("snapshot.diff10.mem"), Some(10));
        assert_eq!(Layout::diff_index("snapshot.mem"), None);
        assert_eq!(Layout::diff_index("snapshot.diffx.mem"), None);
    }
}
