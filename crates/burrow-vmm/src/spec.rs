//! The machine a backend is asked to start or restore.

use std::path::PathBuf;

use crate::{
    Capabilities, CloudHypervisorConfig, DEFAULT_BOOT_ARGS, FirecrackerConfig, GuestOs, Hypervisor,
    HypervisorExt, Layout, Limits, MemorySource,
};
#[cfg(target_os = "macos")]
use crate::{MacOsBoot, VzConfig};

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
pub struct MachineSpec {
    pub vm_id: String,
    pub workdir: PathBuf,
    pub backend: Backend,
    pub guest_os: GuestOs,
    pub boot: Boot,
    pub cpu: CpuSpec,
    pub memory: MemorySpec,
    pub devices: Devices,
    /// How a restore finds the guest's memory, which a boot ignores.
    pub restore: RestoreSpec,
    /// Host resource caps, applied to the VMM process.
    pub limits: Limits,
    /// cgroup2 mount point; `None` disables limit enforcement.
    pub cgroup_root: Option<PathBuf>,
    pub is_limits_required: bool,
    /// Shows the guest the host's virtualization extensions (SVM or VMX), so
    /// it gets a `/dev/kvm` of its own. Only where
    /// [`Capabilities::is_nested_virt_supported`], on a host whose KVM has
    /// nesting on ([`crate::is_nested_virt_supported`]); the guest kernel needs
    /// `CONFIG_KVM_AMD` or `CONFIG_KVM_INTEL`.
    pub is_nested_virt_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct CpuSpec {
    pub vcpus: u32,
    /// vCPUs the guest is booted able to take, where
    /// [`Capabilities::is_vcpu_hotplug_supported`]; never below `vcpus`.
    pub max_vcpus: u32,
}

#[derive(Debug, Clone)]
pub struct MemorySpec {
    /// The memory the guest boots with.
    pub mib: u32,
    /// The virtio-mem region above it, which memory is plugged into while the
    /// guest runs; 0 for none. A multiple of
    /// [`crate::MEMORY_REGION_ALIGN_MIB`], and only where
    /// [`Capabilities::is_memory_hotplug_supported`]. A restore takes the
    /// region and what is plugged in it from the snapshot.
    pub hotplug_mib: u32,
    /// How much of the region is plugged now: none at a boot, what the
    /// snapshot holds at a restore, and whatever [`crate::Vm::resize_memory`]
    /// reached since.
    pub plugged_mib: u32,
}

/// The devices the guest is given, which each backend translates.
#[derive(Debug, Clone)]
pub struct Devices {
    /// In the order the guest sees them: it finds its disks by position.
    pub drives: Vec<DriveSpec>,
    pub net: Option<NetSpec>,
    /// Enable virtio-vsock, the transport the guest agent speaks.
    pub is_vsock_enabled: bool,
    pub console: ConsoleSpec,
    /// A TPM 2.0 for the guest, from an swtpm the backend starts and stops
    /// with the VMM. Cloud Hypervisor only.
    pub tpm: Option<TpmSpec>,
    /// A display with a keyboard and a tablet, where
    /// [`Capabilities::is_display_supported`].
    pub display: Option<DisplaySpec>,
}

/// What a VM with a display may hold in host memory beyond one without: the
/// frame a subscribed client reads, up to 3840x2160, and the cursor.
pub const DISPLAY_OVERHEAD_MIB: u32 = 40;

/// The display's preferred mode when the VM boots. A restore keeps the mode
/// the snapshot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplaySpec {
    pub width: u32,
    pub height: u32,
}

/// Where the guest's serial console goes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConsoleSpec {
    /// Copied into the console log.
    #[default]
    Captured,
    /// On a socket the caller holds, so a Cloud Hypervisor guest takes input
    /// the way Firecracker's does on its stdin. For the dev harness: output
    /// reaches the console log only while the VM's handle is alive to copy
    /// it there.
    Interactive,
}

#[derive(Debug, Clone, Default)]
pub struct RestoreSpec {
    /// Needed for diff snapshots. Firecracker only turns on KVM's dirty log
    /// for a restore that maps the memory file directly.
    pub is_dirty_pages_tracked: bool,
    pub memory: RestoreMemory,
}

/// How restored memory is served. Honoured only where
/// [`Capabilities::is_lazy_memory_supported`].
#[derive(Debug, Clone, Default)]
pub struct RestoreMemory {
    /// Serve guest memory lazily instead of letting the kernel page the whole
    /// memory file in.
    pub is_lazy: bool,
    /// Memory files to restore from, oldest first: a full base followed by any
    /// diff snapshots layered over it. Empty means the conventional memory
    /// file alone. More than one entry forces the page-fault handler on,
    /// because a chain has no single file for the kernel to map.
    pub chain: Vec<String>,
    /// Pages to populate before the guest runs, relative to the working
    /// directory. Recorded from an earlier restore of the same snapshot.
    pub prefetch: Option<String>,
    /// Where to record the pages this VM faults on, relative to the working
    /// directory. Set only when profiling a snapshot.
    pub record_prefetch: Option<String>,
    /// Where the base of `chain` is still being filled in from. Forces the
    /// page-fault handler on, since the kernel would map the holes as zeroes.
    pub source: Option<MemorySource>,
}

/// Where a guest's TPM emulator comes from and keeps its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmSpec {
    pub swtpm: PathBuf,
    /// The emulator's state and control socket, outside the VM's working
    /// directory.
    pub dir: PathBuf,
    /// The uid and gid the emulator runs as: its sandbox's alone, neither
    /// root, the jail's, nor another sandbox's, so it can neither read
    /// another TPM's state nor signal another process.
    pub uid: u32,
}

impl MachineSpec {
    pub fn new(vm_id: impl Into<String>, workdir: impl Into<PathBuf>, backend: Backend) -> Self {
        Self {
            vm_id: vm_id.into(),
            workdir: workdir.into(),
            backend,
            guest_os: GuestOs::Linux,
            boot: Boot::default(),
            cpu: CpuSpec {
                vcpus: 1,
                max_vcpus: 0,
            },
            memory: MemorySpec {
                mib: 512,
                hotplug_mib: 0,
                plugged_mib: 0,
            },
            devices: Devices {
                drives: Vec::new(),
                net: None,
                is_vsock_enabled: false,
                console: ConsoleSpec::Captured,
                tpm: None,
                display: None,
            },
            restore: RestoreSpec::default(),
            limits: Limits::default(),
            cgroup_root: Some(PathBuf::from("/sys/fs/cgroup")),
            is_limits_required: false,
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
