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
