//! Disk admission: whether a node has room to provision another sandbox a
//! disk.
//!
//! Each sandbox is charged its whole disk at its provisioned size, and each
//! volume its size, whatever blocks they share with an image, a snapshot or
//! each other. Sharing is how disks are made cheaply, not a promise that they
//! stay small: a guest that rewrites its disk unshares every block of it. The
//! rule is the same on every node and is the one both sides apply, the node
//! when it admits a create, fork, restore, resume or adopt and the
//! orchestrator when it places one:
//!
//! ```text
//! provisioned + request <= overcommit * (total - reserve)
//! ```
//!
//! With `overcommit` 1.0, the default, every provisioned byte has a byte of
//! the filesystem behind it. Above 1.0 an operator accepts that guests might
//! fill it. Separately, and for every admission including a resume that asks
//! for nothing new, a node whose free disk is already under its reserve
//! refuses: its running guests' writes are what is at risk.

/// Bytes in a MiB.
pub const MIB: u64 = 1 << 20;

/// The share of the filesystem a node keeps free when no reserve is given.
pub const DEFAULT_RESERVE_PERCENT: u64 = 5;

/// A node's disk as admission sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskCapacity {
    /// Free on the filesystem holding the sandboxes' disks, to the node.
    pub free_bytes: u64,
    /// The filesystem's size. Zero means not reported, and nothing is checked.
    pub total_bytes: u64,
    /// What the node keeps free and provisions to no sandbox.
    pub reserve_bytes: u64,
    /// Every sandbox's disk and every volume, at their full sizes.
    pub provisioned_bytes: u64,
    /// How far provisioned disk may exceed the filesystem less its reserve;
    /// 1.0 means never.
    pub overcommit: f64,
}

/// Which limit a refused admission ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Free disk is already under the reserve.
    Reserve,
    /// The disks provisioned here would exceed what the node may provision.
    Capacity,
}

/// What a refused admission was short of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortfall {
    pub bytes: u64,
    pub limit: Limit,
}

impl Shortfall {
    /// Rounded up, so a shortfall is never reported as zero.
    pub fn mib(&self) -> u64 {
        self.bytes.div_ceil(MIB)
    }
}

/// The reserve a node keeps: the operator's, or 5% of the filesystem.
pub fn reserve_bytes(configured_mib: Option<u64>, total_bytes: u64) -> u64 {
    match configured_mib {
        Some(mib) => mib.saturating_mul(MIB),
        None => total_bytes / 100 * DEFAULT_RESERVE_PERCENT,
    }
}

impl DiskCapacity {
    pub fn is_reported(&self) -> bool {
        self.total_bytes > 0
    }

    /// Free disk has fallen below the reserve.
    pub fn is_below_reserve(&self) -> bool {
        self.is_reported() && self.free_bytes < self.reserve_bytes
    }

    /// What the node may provision in all: the filesystem less its reserve,
    /// times the overcommit.
    pub fn capacity_bytes(&self) -> f64 {
        self.total_bytes.saturating_sub(self.reserve_bytes) as f64 * self.overcommit
    }

    /// Admits `request_bytes` more provisioned disk, or says what it is short
    /// of. A request of nothing, a resume's, checks only the reserve.
    pub fn admit(&self, request_bytes: u64) -> Result<(), Shortfall> {
        if !self.is_reported() {
            return Ok(());
        }
        if self.is_below_reserve() {
            return Err(Shortfall {
                bytes: self.reserve_bytes - self.free_bytes,
                limit: Limit::Reserve,
            });
        }
        if request_bytes == 0 {
            return Ok(());
        }
        let wanted = self.provisioned_bytes.saturating_add(request_bytes) as f64;
        let capacity = self.capacity_bytes();
        if wanted <= capacity {
            return Ok(());
        }
        Err(Shortfall {
            bytes: (wanted - capacity).ceil().max(1.0) as u64,
            limit: Limit::Capacity,
        })
    }

    /// The fraction of what could be provisioned that is not yet, 0.0 to 1.0,
    /// for ranking nodes. 1.0 for a node that has not reported.
    pub fn headroom(&self) -> f64 {
        if !self.is_reported() {
            return 1.0;
        }
        let capacity = self.capacity_bytes();
        if capacity <= 0.0 || self.is_below_reserve() {
            return 0.0;
        }
        ((capacity - self.provisioned_bytes as f64) / capacity).clamp(0.0, 1.0)
    }
}

/// The refusal a node gives, and the orchestrator repeats, when a disk does
/// not fit: which node, how much was asked, and what it ran into.
pub fn refusal(node: &str, what: &str, request_bytes: u64, short: Shortfall) -> String {
    match short.limit {
        Limit::Reserve => format!(
            "node {node} has no room to {what}: its free disk is {} MiB below its reserve",
            short.mib()
        ),
        Limit::Capacity => format!(
            "node {node} has no room to {what} with a {} MiB disk: it would provision {} MiB more \
             disk than it may",
            request_bytes.div_ceil(MIB),
            short.mib(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * MIB;

    fn node(free_gib: u64, provisioned_gib: u64, overcommit: f64) -> DiskCapacity {
        DiskCapacity {
            free_bytes: free_gib * GIB,
            total_bytes: 100 * GIB,
            reserve_bytes: 5 * GIB,
            provisioned_bytes: provisioned_gib * GIB,
            overcommit,
        }
    }

    #[test]
    fn a_disk_within_capacity_is_admitted() {
        // 95 may be provisioned, 70 is.
        assert_eq!(node(50, 70, 1.0).admit(25 * GIB), Ok(()));
    }

    /// Free space does not enter into it: reflinked disks share their blocks,
    /// and each is charged at its size all the same.
    #[test]
    fn a_disk_past_capacity_is_refused_however_much_is_free() {
        let refused = node(90, 70, 1.0).admit(26 * GIB).unwrap_err();
        assert_eq!(refused.limit, Limit::Capacity);
        assert_eq!(refused.mib(), 1024);
    }

    #[test]
    fn overcommit_scales_what_may_be_provisioned() {
        // 95 twice over is 190.
        assert_eq!(node(50, 70, 2.0).admit(120 * GIB), Ok(()));
        let refused = node(50, 70, 2.0).admit(121 * GIB).unwrap_err();
        assert_eq!(refused.mib(), 1024);
    }

    #[test]
    fn a_node_under_its_reserve_refuses_even_a_resume() {
        let low = node(4, 0, 1.0);
        assert!(low.is_below_reserve());
        let refused = low.admit(0).unwrap_err();
        assert_eq!(refused.limit, Limit::Reserve);
        assert_eq!(refused.mib(), 1024);
    }

    /// A resume asks for nothing new, so a node that is fully provisioned,
    /// and over it after an operator lowered the overcommit, still resumes
    /// what it holds while its disk has room.
    #[test]
    fn a_resume_checks_only_the_reserve() {
        assert_eq!(node(50, 200, 1.0).admit(0), Ok(()));
        assert!(node(50, 200, 1.0).admit(MIB).is_err());
    }

    #[test]
    fn an_unreported_node_admits_anything() {
        let unknown = DiskCapacity {
            free_bytes: 0,
            total_bytes: 0,
            reserve_bytes: 0,
            provisioned_bytes: 0,
            overcommit: 0.0,
        };
        assert_eq!(unknown.admit(u64::MAX), Ok(()));
        assert!(!unknown.is_below_reserve());
        assert_eq!(unknown.headroom(), 1.0);
    }

    #[test]
    fn the_default_reserve_is_five_percent_of_the_filesystem() {
        assert_eq!(reserve_bytes(None, 100 * GIB), 5 * GIB);
        assert_eq!(reserve_bytes(Some(2048), 100 * GIB), 2 * GIB);
        assert_eq!(reserve_bytes(Some(0), 100 * GIB), 0);
    }

    #[test]
    fn the_refusal_names_the_node_and_what_it_ran_into() {
        let short = node(50, 70, 1.0).admit(26 * GIB).unwrap_err();
        assert_eq!(
            refusal("node-a", "create a sandbox", 26 * GIB, short),
            "node node-a has no room to create a sandbox with a 26624 MiB disk: it would \
             provision 1024 MiB more disk than it may"
        );
        let low = node(4, 0, 1.0).admit(0).unwrap_err();
        assert_eq!(
            refusal("node-a", "resume a sandbox", 0, low),
            "node node-a has no room to resume a sandbox: its free disk is 1024 MiB below its \
             reserve"
        );
    }

    #[test]
    fn headroom_falls_as_disk_is_provisioned() {
        let empty = node(95, 0, 1.0);
        let half = node(95, 45, 1.0);
        assert!(empty.headroom() > half.headroom());
        assert_eq!(node(95, 95, 1.0).headroom(), 0.0);
        assert_eq!(node(4, 0, 1.0).headroom(), 0.0);
    }
}
