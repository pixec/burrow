//! The hypervisors and guest operating systems burrow names, as every
//! component spells them: records, templates, placement and the API all
//! carry these names, so one definition serves them all. Which of them a
//! node can actually run is the node's to say.

/// A hypervisor burrow can run a guest under.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Hypervisor {
    /// What a sandbox gets when nothing says otherwise, and what every record
    /// written before there was a choice ran under.
    #[default]
    Firecracker,
    CloudHypervisor,
    /// Apple's Virtualization.framework, for macOS guests on a Mac node.
    Vz,
}

impl Hypervisor {
    pub const ALL: [Hypervisor; 3] = [
        Hypervisor::Firecracker,
        Hypervisor::CloudHypervisor,
        Hypervisor::Vz,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::CloudHypervisor => "cloud-hypervisor",
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
}

/// Host page tables over guest memory, per GiB of guest: KVM's stage-2
/// tables and the VMM's own mapping of it, 8 bytes per 4 KiB page each.
/// Measured 4 MiB per GiB under Firecracker, which tracks dirty pages and so
/// maps 4 KiB pages, and 2.3 under Cloud Hypervisor.
const PAGE_TABLE_MIB_PER_GIB: u32 = 4;

impl Hypervisor {
    /// Host memory this hypervisor's VMM holds beyond its guest and the page
    /// tables over it: the VMM's own heap and device buffers, slab and kernel
    /// stacks. A node can set its own (`--vmm-memory-overhead-mib`).
    ///
    /// Measured on the arm64 dev harness (2026-11-12) as what a 512 MiB
    /// guest's cgroup holds beyond guest RAM once the guest has touched all
    /// of it. Cloud Hypervisor v54.0 holds about 49 MiB: 6 MiB of its own,
    /// 9 MiB of kernel memory and 33 MiB of page cache for its binary and the
    /// guest kernel. A warm restore touches all guest memory at once, so a
    /// tighter ceiling is hit before the guest runs. Its default is that with
    /// room for more vCPUs and queues. Firecracker v1.16.1 holds less of its
    /// own, but its disks go through host page cache, and what is dirty
    /// cannot be reclaimed until it is written back.
    pub fn default_vmm_overhead_mib(self) -> u32 {
        match self {
            Self::Firecracker => 64,
            Self::CloudHypervisor => 64,
            Self::Vz => 0,
        }
    }

    /// The host memory a guest of `guest_mib` may hold under this hypervisor
    /// with a VMM needing `overhead_mib` beyond it: its cgroup's
    /// `memory.max`, and what placement charges a node for it. Host page
    /// cache gets no room: Cloud Hypervisor opens disks `O_DIRECT`, and what
    /// Firecracker's guest I/O caches is reclaimed inside the ceiling.
    pub fn memory_ceiling_mib(self, guest_mib: u32, overhead_mib: u32) -> u32 {
        match self {
            Self::Firecracker | Self::CloudHypervisor => {
                guest_mib + overhead_mib + guest_mib.div_ceil(1024) * PAGE_TABLE_MIB_PER_GIB
            }
            // No cgroup on a Mac node, and the framework's own footprint is
            // the host's to absorb.
            Self::Vz => guest_mib,
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

    fn from_str(name: &str) -> Result<Self, String> {
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
    MacOs,
}

impl GuestOs {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::MacOs => "macos",
        }
    }

    /// Empty is every template imported before the field existed, all Linux.
    pub fn from_record(name: &str) -> Option<Self> {
        match name {
            "" | "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            "macos" => Some(Self::MacOs),
            _ => None,
        }
    }

    /// The hypervisor a template of this OS gets when its build names none.
    pub fn default_hypervisor(self) -> Hypervisor {
        match self {
            Self::Linux => Hypervisor::Firecracker,
            Self::Windows => Hypervisor::CloudHypervisor,
            Self::MacOs => Hypervisor::Vz,
        }
    }
}

impl std::fmt::Display for GuestOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ceiling_is_the_guest_its_vmm_and_the_page_tables_over_it() {
        let fc = Hypervisor::Firecracker;
        assert_eq!(fc.memory_ceiling_mib(512, 40), 512 + 40 + 4);
        assert_eq!(fc.memory_ceiling_mib(8192, 40), 8192 + 40 + 32);
        assert_eq!(fc.memory_ceiling_mib(1025, 40), 1025 + 40 + 8);
        assert_eq!(Hypervisor::Vz.memory_ceiling_mib(8192, 40), 8192);
    }
}
