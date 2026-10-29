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
mod error;
mod guest;
mod http;

pub mod cloud_hypervisor;
pub mod firecracker;
#[cfg(target_os = "macos")]
pub mod vz;

use std::path::PathBuf;
use std::time::Duration;

pub use cgroup::{Cgroup, Limits};
pub use cloud_hypervisor::{ChJail, CloudHypervisorConfig};
pub use error::{Error, Result};
pub use firecracker::{FirecrackerConfig, Jail, MemorySource, PageSource};
#[cfg(target_os = "linux")]
pub use firecracker::{data_extents, merge_chain};
pub use guest::{GUEST_CID, GuestAddr, VSOCK_UDS};
#[cfg(target_os = "macos")]
pub use vz::{MacOsBoot, Requirements, VzConfig};

/// `console=ttyS0` is the guest serial port, which both backends capture to
/// the VM's console log; `panic=1 reboot=k` makes a panicking guest exit the
/// VMM rather than hang.
/// `pci=off` is deliberately absent: virtio devices sit on a PCI bus so that
/// volumes can be hotplugged onto a sandbox restored from a warm snapshot, and
/// a guest told to ignore the bus would never see them.
pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1";

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

/// A hypervisor burrow can run a guest under.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Hypervisor {
    /// What a sandbox gets when nothing says otherwise, and what every record
    /// written before there was a choice ran under.
    #[default]
    Firecracker,
    CloudHypervisor,
    /// Apple's Virtualization.framework, for macOS guests on a Mac node.
    #[cfg(target_os = "macos")]
    Vz,
}

impl Hypervisor {
    #[cfg(not(target_os = "macos"))]
    pub const ALL: [Hypervisor; 2] = [Hypervisor::Firecracker, Hypervisor::CloudHypervisor];
    #[cfg(target_os = "macos")]
    pub const ALL: [Hypervisor; 3] = [
        Hypervisor::Firecracker,
        Hypervisor::CloudHypervisor,
        Hypervisor::Vz,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::CloudHypervisor => "cloud-hypervisor",
            #[cfg(target_os = "macos")]
            Self::Vz => "vz",
        }
    }

    /// The name a record carries. Empty is a record from before the field
    /// existed, which can only have been Firecracker.
    pub fn from_record(name: &str) -> Option<Self> {
        match name {
            "" => Some(Self::Firecracker),
            name => name.parse().ok(),
        }
    }

    pub fn capabilities(self) -> Capabilities {
        match self {
            Self::Firecracker => Capabilities {
                is_diff_snapshot_supported: true,
                is_lazy_memory_supported: true,
                is_drive_hotplug_supported: true,
                is_jailable: true,
                guest_oses: &[GuestOs::Linux],
                memory_headroom_mib: 128,
                is_warm_pool_supported: true,
                is_tap_networked: true,
            },
            // Cloud Hypervisor restores memory copy-on-write from its own
            // mapping, which is lazy in effect, but it cannot be pointed at
            // burrow's page-fault handler: no chains, no prefetch plans, no
            // memory still arriving from the object store.
            Self::CloudHypervisor => Capabilities {
                is_diff_snapshot_supported: false,
                is_lazy_memory_supported: false,
                is_drive_hotplug_supported: true,
                is_jailable: true,
                guest_oses: &[GuestOs::Linux],
                memory_headroom_mib: 128,
                is_warm_pool_supported: true,
                is_tap_networked: true,
            },
            // The framework saves a machine as one opaque file, reads it back
            // itself and attaches storage only at configuration time. There
            // is no cgroup on macOS for the headroom to size.
            #[cfg(target_os = "macos")]
            Self::Vz => Capabilities {
                is_diff_snapshot_supported: false,
                is_lazy_memory_supported: false,
                is_drive_hotplug_supported: false,
                is_jailable: false,
                guest_oses: &[GuestOs::MacOs],
                memory_headroom_mib: 0,
                // A restore takes longer than a cold boot, and a saved state
                // restores into only one running machine at a time.
                is_warm_pool_supported: false,
                is_tap_networked: false,
            },
        }
    }

    /// The files a snapshot of this hypervisor's VM is made of.
    pub fn layout(self) -> Layout {
        match self {
            Self::Firecracker => Layout {
                state: firecracker::SNAPSHOT_FILE,
                memory: Some(firecracker::SNAPSHOT_MEM_FILE),
            },
            Self::CloudHypervisor => Layout {
                state: cloud_hypervisor::STATE_FILE,
                memory: Some(cloud_hypervisor::MEMORY_FILE),
            },
            #[cfg(target_os = "macos")]
            Self::Vz => Layout {
                state: vz::SAVE_FILE,
                memory: None,
            },
        }
    }
}

impl std::fmt::Display for Hypervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Hypervisor {
    type Err = String;

    fn from_str(name: &str) -> std::result::Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|h| h.as_str() == name)
            .ok_or_else(|| {
                let names: Vec<_> = Self::ALL.iter().map(|h| h.as_str()).collect();
                format!(
                    "unknown hypervisor {name:?}: expected one of {}",
                    names.join(", ")
                )
            })
    }
}

/// The operating system a guest runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum GuestOs {
    #[default]
    Linux,
    Windows,
    #[cfg(target_os = "macos")]
    MacOs,
}

impl GuestOs {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            #[cfg(target_os = "macos")]
            Self::MacOs => "macos",
        }
    }

    /// Empty is every template imported before the field existed, all Linux.
    pub fn from_record(name: &str) -> Option<Self> {
        match name {
            "" | "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            #[cfg(target_os = "macos")]
            "macos" => Some(Self::MacOs),
            _ => None,
        }
    }

    /// The hypervisor a template of this OS gets when its build names none.
    pub fn default_hypervisor(self) -> Hypervisor {
        match self {
            Self::Linux => Hypervisor::Firecracker,
            Self::Windows => Hypervisor::CloudHypervisor,
            #[cfg(target_os = "macos")]
            Self::MacOs => Hypervisor::Vz,
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
    /// Host memory its VMM needs beyond the guest's own, added to the cgroup's
    /// ceiling. Too tight and the kernel kills the VMM rather than the guest.
    pub memory_headroom_mib: u32,
    /// Restoring a template's warm snapshot beats booting it, and one
    /// snapshot can be restored into many sandboxes at once.
    pub is_warm_pool_supported: bool,
    /// The guest's NIC is a host tap, which the node's firewall polices. A
    /// backend without one has no network until it is given its own.
    pub is_tap_networked: bool,
}

impl Capabilities {
    pub fn runs(&self, os: GuestOs) -> bool {
        self.guest_oses.contains(&os)
    }
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
    pub mem_mib: u32,
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
            mem_mib: 512,
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
            // Its console goes to a file, with no input side to write to.
            Self::CloudHypervisor(_) => Err(Error::ConsoleUnavailable),
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
    fn names_round_trip_and_an_empty_record_is_firecracker() {
        for hypervisor in Hypervisor::ALL {
            assert_eq!(hypervisor.as_str().parse::<Hypervisor>(), Ok(hypervisor));
        }
        assert_eq!(Hypervisor::from_record(""), Some(Hypervisor::Firecracker));
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
