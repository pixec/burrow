//! What each backend can do, and the files its snapshots are made of.

use crate::error::{Error, Result};
use crate::{GuestOs, Hypervisor, MachineSpec, RestoreSpec, cloud_hypervisor, firecracker};

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
                is_acpi_memory_hotplug_supported: false,
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
                // Windows on arm64 needs a vPMU, which KVM on the hosts tried
                // could not give it.
                guest_oses: if cfg!(target_arch = "x86_64") {
                    &[GuestOs::Linux, GuestOs::Windows]
                } else {
                    &[GuestOs::Linux]
                },
                is_warm_pool_supported: true,
                is_tap_networked: true,
                is_live_disk_growth_supported: true,
                // arm64 KVM creates every vCPU before the VM first runs, and
                // refuses one created after with EBUSY.
                is_vcpu_hotplug_supported: cfg!(target_arch = "x86_64"),
                is_memory_hotplug_supported: true,
                is_acpi_memory_hotplug_supported: cfg!(target_arch = "x86_64"),
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
                is_acpi_memory_hotplug_supported: false,
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
    /// A running guest can be told its disk grew ([`crate::Vm::resize_disk`]), and
    /// grow the filesystem on it. Without it a disk grows only while its
    /// sandbox is shut down.
    pub is_live_disk_growth_supported: bool,
    /// A running guest can be given vCPUs up to [`CpuSpec::max_vcpus`] and
    /// have them taken away again ([`crate::Vm::resize_vcpus`]).
    pub is_vcpu_hotplug_supported: bool,
    /// A Linux guest can be booted with a virtio-mem region of
    /// [`MemorySpec::hotplug_mib`] and have memory plugged into it and
    /// unplugged from it while it runs ([`crate::Vm::resize_memory`]). The guest
    /// kernel needs `CONFIG_VIRTIO_MEM`.
    pub is_memory_hotplug_supported: bool,
    /// A Windows guest, which has no virtio-mem driver, can be booted with an
    /// ACPI hotplug region of [`MemorySpec::hotplug_mib`] and have memory
    /// added to it in [`crate::ACPI_MEMORY_BLOCK_MIB`] steps while it runs, at most
    /// [`crate::ACPI_MEMORY_SLOTS`] times per boot. Nothing added is taken away
    /// until the guest boots again.
    pub is_acpi_memory_hotplug_supported: bool,
    /// A guest can be shown the host's virtualization extensions and run
    /// KVM itself ([`MachineSpec::is_nested_virt_enabled`]). Firecracker masks
    /// them out of every guest's CPUID.
    pub is_nested_virt_supported: bool,
}

impl Capabilities {
    pub fn runs(&self, os: GuestOs) -> bool {
        self.guest_oses.contains(&os)
    }

    /// Refuses a machine, or a restore of one, this backend cannot run.
    pub fn check(&self, spec: &MachineSpec, restore: Option<&RestoreSpec>) -> Result<()> {
        let refuse = |what| {
            Err(Error::Unsupported {
                hypervisor: spec.hypervisor(),
                what,
            })
        };
        if spec.is_nested_virt_enabled && !self.is_nested_virt_supported {
            return refuse("give a guest nested virtualization");
        }
        if let Some(restore) = restore
            && !self.is_lazy_memory_supported
            && (restore.memory.chain.len() > 1 || restore.memory.source.is_some())
        {
            return refuse("restore from a memory chain or from memory still arriving");
        }
        Ok(())
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
