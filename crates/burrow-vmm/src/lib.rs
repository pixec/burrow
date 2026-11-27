//! The hypervisor-neutral VM interface the daemon drives.
//!
//! A sandbox runs under one hypervisor, chosen when it is created and fixed for
//! its life. Everything the daemon does to a VM goes through [`Vm`], and
//! everything it decides about one comes from [`Capabilities`]: a lifecycle
//! path asks whether the backend can take a diff or hotplug a drive, never
//! which backend it is talking to.
//!
//! The backends are an enum rather than trait objects. The set is closed and
//! lives in this crate, and every operation is async, which a `dyn` trait can
//! only express by boxing each future. Each variant implements
//! `Machine`, whose defaults refuse what a backend cannot do, and
//! [`Vm`] dispatches to it.

mod caps;
mod cgroup;
mod child;
pub mod console;
mod error;
mod guest;
mod http;
pub mod jail;
mod machine;
mod process;
mod snapfile;
mod spec;
mod vsock;

pub mod cloud_hypervisor;
pub mod firecracker;
pub mod memfile;
pub mod swtpm;
#[cfg(target_os = "macos")]
pub mod vz;

use std::time::Duration;

pub use caps::{
    Capabilities, HypervisorExt, Layout, VZ_AUX_FILE, VZ_DISK_FILE, VZ_HARDWARE_MODEL_FILE,
    VZ_MACHINE_ID_FILE, VZ_REQUIREMENTS_FILE, VZ_SAVE_FILE, is_nested_virt_supported,
};
pub use cgroup::{Cgroup, Limits, is_io_weight_supported, sweep_empty_cgroups};
pub use cloud_hypervisor::{ChJail, CloudHypervisorConfig};
pub use error::{Error, Result};
pub use firecracker::{FirecrackerConfig, IoEngine, Jail, MemorySource, PageSource};
pub use guest::{GUEST_CID, GuestAddr, VSOCK_UDS};
pub use jail::JailLayout;
use machine::Machine;
pub use memfile::{data_extents, merge_chain};
pub use spec::{
    Backend, Boot, ConsoleSpec, CpuSpec, Devices, DriveSpec, MachineSpec, MemorySpec, NetSpec,
    RestoreMemory, RestoreSpec, TpmSpec,
};
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
/// What an ACPI memory hotplug adds at least and in multiples of: Cloud
/// Hypervisor's DIMM alignment.
pub const ACPI_MEMORY_BLOCK_MIB: u32 = 128;
/// How many ACPI memory hotplugs a running guest can take, Cloud
/// Hypervisor's DIMM slots.
pub const ACPI_MEMORY_SLOTS: usize = 8;

/// Where a VM start spent its time, phase by phase, in the order they ran.
#[derive(Debug, Clone, Default)]
pub struct Phases {
    marks: Vec<(&'static str, Duration)>,
    last: Option<std::time::Instant>,
}

impl Phases {
    pub fn start() -> Self {
        Self {
            marks: Vec::new(),
            last: Some(std::time::Instant::now()),
        }
    }

    /// Starts timing again from now, leaving out the time since the last mark.
    pub fn restart(&mut self) {
        self.last = Some(std::time::Instant::now());
    }

    /// Charges the time since the previous mark to `name`.
    pub fn mark(&mut self, name: &'static str) {
        let now = std::time::Instant::now();
        let since = self.last.replace(now).unwrap_or(now);
        self.marks.push((name, now - since));
    }

    /// Records a phase that ran alongside the others, without moving the mark.
    pub fn add(&mut self, name: &'static str, took: Duration) {
        self.marks.push((name, took));
    }

    pub fn append(&mut self, other: &Phases) {
        self.marks.extend_from_slice(&other.marks);
    }
}

impl std::fmt::Display for Phases {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, (name, took)) in self.marks.iter().enumerate() {
            let sep = if index == 0 { "" } else { " " };
            write!(f, "{sep}{name}={:.1}", took.as_secs_f64() * 1000.0)?;
        }
        Ok(())
    }
}

/// A VM restore under way: its VMM started, its snapshot not yet loaded.
pub enum Restoring {
    Firecracker(Box<firecracker::MicroVm>),
    /// A backend that starts and loads in one step, which happens at load.
    Later(Box<MachineSpec>),
}

impl Restoring {
    pub async fn load(self, resume: bool) -> Result<Vm> {
        match self {
            Self::Firecracker(vm) => Ok(Vm::Firecracker(Box::new(vm.load(resume).await?))),
            Self::Later(spec) => Vm::restore(*spec, resume).await,
        }
    }

    pub async fn abandon(self) {
        if let Self::Firecracker(vm) = self {
            vm.abandon().await;
        }
    }
}

pub use burrow_common::hypervisor::{GuestOs, Hypervisor};

const MEMORY_POLL: Duration = Duration::from_millis(50);
/// How long a guest may make no progress plugging or unplugging before it is
/// taken to have stopped where it is.
const MEMORY_STALL: Duration = Duration::from_secs(3);
const MEMORY_TIMEOUT: Duration = Duration::from_secs(120);

/// Runs `$body` with `$vm` bound to the backend VM inside a [`Vm`].
macro_rules! dispatch {
    ($self:expr, $vm:ident => $body:expr) => {
        match $self {
            Vm::Firecracker($vm) => $body,
            Vm::CloudHypervisor($vm) => $body,
            #[cfg(target_os = "macos")]
            Vm::Vz($vm) => $body,
        }
    };
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
    /// Starts a VM and boots its guest from [`MachineSpec::boot`].
    pub async fn boot(spec: MachineSpec) -> Result<Self> {
        spec.capabilities().check(&spec, None)?;
        match spec.backend.clone() {
            Backend::Firecracker(config) => Ok(Self::Firecracker(Box::new(
                firecracker::MicroVm::boot(spec, config).await?,
            ))),
            Backend::CloudHypervisor(config) => Ok(Self::CloudHypervisor(Box::new(
                cloud_hypervisor::ChVm::boot(spec, config).await?,
            ))),
            #[cfg(target_os = "macos")]
            Backend::Vz(config) => Ok(Self::Vz(Box::new(vz::VzVm::boot(spec, config).await?))),
        }
    }

    /// Starts the VMM for [`Restoring::load`], before the snapshot it loads
    /// need be in `spec.workdir`, so the two can be made ready together.
    pub async fn launch(spec: MachineSpec) -> Result<Restoring> {
        match spec.backend.clone() {
            Backend::Firecracker(config) => {
                spec.capabilities().check(&spec, Some(&spec.restore))?;
                Ok(Restoring::Firecracker(Box::new(
                    firecracker::MicroVm::launch(spec, config).await?,
                )))
            }
            _ => Ok(Restoring::Later(Box::new(spec))),
        }
    }

    /// Starts a VM from the snapshot in `spec.workdir` instead of booting.
    /// `spec` must describe the same machine the snapshot was taken of.
    pub async fn restore(spec: MachineSpec, resume: bool) -> Result<Self> {
        spec.capabilities().check(&spec, Some(&spec.restore))?;
        match spec.backend.clone() {
            Backend::Firecracker(config) => Ok(Self::Firecracker(Box::new(
                firecracker::MicroVm::restore(spec, config, resume).await?,
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
        dispatch!(self, vm => vm.hypervisor())
    }

    pub fn capabilities(&self) -> Capabilities {
        self.hypervisor().capabilities()
    }

    /// Where the guest's vsock listeners are reached from the host.
    pub fn guest(&self) -> GuestAddr {
        dispatch!(self, vm => GuestAddr::in_workdir(vm.workdir()))
    }

    /// Waits for a guest vsock listener to accept, which is the agent's
    /// readiness signal.
    pub async fn wait_for_vsock(&self, port: u32, timeout: Duration) -> Result<Duration> {
        self.guest().wait(port, timeout).await
    }

    /// The VMM's pid; for vz, the XPC service the framework spawned for the
    /// machine.
    pub fn pid(&self) -> Option<u32> {
        dispatch!(self, vm => vm.pid())
    }

    /// Whether the VMM process has exited on its own. A vz machine runs in a
    /// service process this node does not own, so it never reads as exited.
    pub fn has_exited(&mut self) -> bool {
        dispatch!(self, vm => vm.process_mut().is_some_and(|process| process.has_exited()))
    }

    /// The phases of this VM's start; empty for a backend that does not
    /// record them.
    pub fn phases(&self) -> Phases {
        dispatch!(self, vm => vm.phases())
    }

    /// From spawning the VMM to a guest that is running or ready to.
    pub fn boot_latency(&self) -> Duration {
        dispatch!(self, vm => vm.boot_latency())
    }

    /// Host CPU this VM has consumed, in microseconds; `None` without a
    /// cgroup, or for a vz machine whose process could not be found.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        dispatch!(self, vm => vm.cpu_usage_usec())
    }

    /// How the VMM process ended, once it has.
    pub fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        dispatch!(self, vm => vm.process_mut()?.exit_status())
    }

    /// The last of what the VMM itself printed. Firecracker's goes to the
    /// console log with the guest's.
    pub async fn vmm_log_tail(&self, lines: usize) -> String {
        match self.process() {
            Some(process) => process.output_tail(lines).await,
            None => String::new(),
        }
    }

    /// The last of the guest's serial console. A macOS guest writes nothing
    /// to one.
    pub async fn console_tail(&self, lines: usize) -> String {
        dispatch!(self, vm => vm.console_tail(lines).await)
    }

    /// Writes to the guest serial console, for dev and rescue only.
    pub async fn console_write(&mut self, input: &str) -> Result<()> {
        dispatch!(self, vm => vm.console_write(input).await)
    }

    pub async fn pause(&self) -> Result<()> {
        dispatch!(self, vm => vm.pause().await)
    }

    pub async fn resume(&self) -> Result<()> {
        dispatch!(self, vm => vm.resume().await)
    }

    /// Snapshots a **paused** VM in full, into its [`Layout`].
    pub async fn snapshot(&self) -> Result<()> {
        let _outside = self.snapshotting();
        dispatch!(self, vm => vm.snapshot().await)
    }

    /// Snapshots a **paused** VM's dirtied pages into `mem_file`, layered over
    /// the memory it was restored from. Only where
    /// [`Capabilities::is_diff_snapshot_supported`].
    pub async fn snapshot_diff(&self, mem_file: &str) -> Result<()> {
        let _outside = self.snapshotting();
        dispatch!(self, vm => vm.snapshot_diff(mem_file).await)
    }

    /// Waits for the guest to shut itself down, as after a `shutdown -h` in
    /// it. Only a vz machine is watched for that.
    pub async fn wait_stopped(&self, timeout: Duration) -> Result<()> {
        dispatch!(self, vm => vm.wait_stopped(timeout).await)
    }

    fn process(&self) -> Option<&process::VmmProcess> {
        dispatch!(self, vm => vm.process())
    }

    fn cgroup(&self) -> Option<&Cgroup> {
        self.process()?.cgroup()
    }

    /// Moves the VMM out of its cgroup for a snapshot, so the page cache the
    /// write fills is not charged against the guest's memory ceiling. A VMM
    /// that cannot be moved snapshots where it is, only slower.
    fn snapshotting(&self) -> Option<cgroup::Snapshotting<'_>> {
        self.cgroup()?
            .snapshotting()
            .inspect_err(
                |err| tracing::warn!(%err, "could not move the vmm out of its cgroup to snapshot"),
            )
            .ok()
    }

    /// Whether a diff taken now would know exactly which pages it holds. A
    /// suspend or checkpoint that cannot takes a full snapshot instead.
    pub fn can_map_diff(&self) -> bool {
        dispatch!(self, vm => vm.can_map_diff())
    }

    /// Attaches a drive to the running guest. Only where
    /// [`Capabilities::is_drive_hotplug_supported`].
    pub async fn attach_drive(&self, drive: &DriveSpec) -> Result<()> {
        dispatch!(self, vm => vm.attach_drive(drive).await)
    }

    /// Tells the running guest that the drive `id` is now `bytes` long.
    /// Cloud Hypervisor sets the length itself; Firecracker reopens a file the
    /// caller has grown already. Only where
    /// [`Capabilities::is_live_disk_growth_supported`].
    pub async fn resize_disk(&self, id: &str, bytes: u64) -> Result<()> {
        dispatch!(self, vm => vm.resize_disk(id, bytes).await)
    }

    /// Sets the running guest's vCPUs to `vcpus`, within the
    /// [`CpuSpec::max_vcpus`] it was booted with.
    /// Only where [`Capabilities::is_vcpu_hotplug_supported`].
    pub async fn resize_vcpus(&self, vcpus: u32) -> Result<()> {
        dispatch!(self, vm => vm.resize_vcpus(vcpus).await)
    }

    /// Moves the running VMM's CPU and IO limits.
    pub fn set_limits(&self, limits: &Limits) -> Result<()> {
        let Some(process) = self.process() else {
            return Err(Error::Unsupported {
                hypervisor: self.hypervisor(),
                what: "limit a machine's host CPU or IO",
            });
        };
        match process.cgroup() {
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
        dispatch!(self, vm => vm.request_memory(plugged_mib).await)
    }

    /// MiB of the hotplug region the guest has plugged.
    pub async fn plugged_memory(&self) -> Result<u32> {
        dispatch!(self, vm => vm.plugged_memory().await)
    }

    /// Moves the VMM's memory cap. A grow raises it before memory is plugged
    /// and a shrink lowers it once memory is out, so the cap never sits below
    /// what the guest holds.
    pub fn set_memory_limit(&self, mib: u32) -> Result<()> {
        match self.cgroup() {
            Some(cgroup) => cgroup.set_memory(mib),
            None => Ok(()),
        }
    }

    /// Stops the VMM and reaps it, then releases its cgroup.
    pub async fn kill(self) -> Result<()> {
        dispatch!(self, vm => (*vm).kill().await)
    }
}
