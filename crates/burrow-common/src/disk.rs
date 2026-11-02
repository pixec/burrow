//! Disk admission: whether a node has room to promise another sandbox a disk.
//!
//! Sandbox disks are sparse (and, warm, reflinked): a disk takes space only as
//! the guest writes it. Nothing stopped a node promising more disk than it
//! had, and when its filesystem filled every guest on it got write errors at
//! once. The rule here is the one both sides apply, the node when it admits a
//! create, resume or adopt and the orchestrator when it places one:
//!
//! ```text
//! unwritten + request <= overcommit * (free - reserve)
//! ```
//!
//! `free` is what the data directory's filesystem has free now, which already
//! counts everything written so far by sandboxes, snapshots, templates and
//! anything else. `unwritten` is what the node has promised and not yet
//! seen written: each sandbox's disk size less what its disk file occupies.
//! With `overcommit` 1.0, the default, every promised byte has a free byte
//! behind it and the reserve is never crossed; above 1.0 an operator accepts
//! that it might be.

/// Bytes in a MiB.
pub const MIB: u64 = 1 << 20;

/// The share of the filesystem a node keeps free when no reserve is given.
pub const DEFAULT_RESERVE_PERCENT: u64 = 5;

/// A node's disk as admission sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskCapacity {
    /// Free on the data directory's filesystem, to the node.
    pub free_bytes: u64,
    /// The filesystem's size. Zero means not reported, and nothing is checked.
    pub total_bytes: u64,
    /// What the node keeps free and promises to no sandbox.
    pub reserve_bytes: u64,
    /// Disk promised to sandboxes and not yet written.
    pub unwritten_bytes: u64,
    /// How far promises may exceed free space; at least 1.0 means never.
    pub overcommit: f64,
}

/// What a refused admission was short of: the free disk it would have needed
/// beyond what the node has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shortfall {
    pub bytes: u64,
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

/// An overcommit a node can run with: positive and finite. Zero and anything
/// unreported read as 1.0, which is what a node from before the field meant.
pub fn effective_overcommit(overcommit: f64) -> f64 {
    if overcommit.is_finite() && overcommit > 0.0 {
        overcommit
    } else {
        1.0
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

    /// Admits a promise of `request_bytes` more disk, or says how much free
    /// disk it is short of.
    pub fn admit(&self, request_bytes: u64) -> Result<(), Shortfall> {
        if !self.is_reported() {
            return Ok(());
        }
        let overcommit = effective_overcommit(self.overcommit);
        let promised = self.unwritten_bytes.saturating_add(request_bytes) as f64;
        // Free disk the promises need behind them, against what is free above
        // the reserve. Signed: a node already under its reserve has less than
        // nothing to offer.
        let needed = promised / overcommit;
        let available = self.free_bytes as f64 - self.reserve_bytes as f64;
        if needed <= available {
            return Ok(());
        }
        Err(Shortfall {
            bytes: (needed - available).ceil().max(1.0) as u64,
        })
    }

    /// The fraction of what could be promised that is still unpromised, 0.0
    /// to 1.0, for ranking nodes. 1.0 for a node that has not reported.
    pub fn headroom(&self) -> f64 {
        if !self.is_reported() {
            return 1.0;
        }
        let overcommit = effective_overcommit(self.overcommit);
        let promisable = (self.free_bytes as f64 - self.reserve_bytes as f64) * overcommit;
        let capacity = (self.total_bytes as f64 - self.reserve_bytes as f64) * overcommit;
        if capacity <= 0.0 {
            return 0.0;
        }
        ((promisable - self.unwritten_bytes as f64) / capacity).clamp(0.0, 1.0)
    }
}

/// The refusal a node gives, and the orchestrator repeats, when a disk does
/// not fit: which node, how much was asked, and how much free disk it lacked.
pub fn refusal(node: &str, what: &str, request_bytes: u64, short: Shortfall) -> String {
    format!(
        "node {node} has no room to {what} with a {} MiB disk: short by {} MiB of free disk \
         above its reserve",
        request_bytes.div_ceil(MIB),
        short.mib(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * MIB;

    fn node(free_gib: u64, unwritten_gib: u64, overcommit: f64) -> DiskCapacity {
        DiskCapacity {
            free_bytes: free_gib * GIB,
            total_bytes: 100 * GIB,
            reserve_bytes: 5 * GIB,
            unwritten_bytes: unwritten_gib * GIB,
            overcommit,
        }
    }

    #[test]
    fn a_disk_that_fits_above_the_reserve_is_admitted() {
        // 50 free, 5 reserved, 20 promised: 25 left.
        assert_eq!(node(50, 20, 1.0).admit(25 * GIB), Ok(()));
    }

    #[test]
    fn a_disk_that_would_cross_the_reserve_is_refused_with_the_shortfall() {
        let refused = node(50, 20, 1.0).admit(26 * GIB).unwrap_err();
        assert_eq!(refused.mib(), 1024);
    }

    #[test]
    fn overcommit_lets_promises_exceed_free_space_by_its_factor() {
        // 45 above the reserve, twice over is 90, 20 of it promised.
        assert_eq!(node(50, 20, 2.0).admit(70 * GIB), Ok(()));
        let refused = node(50, 20, 2.0).admit(72 * GIB).unwrap_err();
        assert_eq!(refused.mib(), 1024);
    }

    #[test]
    fn a_node_already_under_its_reserve_refuses_even_a_resume() {
        let low = node(4, 0, 1.0);
        assert!(low.is_below_reserve());
        assert_eq!(low.admit(0).unwrap_err().mib(), 1024);
    }

    #[test]
    fn an_unreported_node_admits_anything() {
        let unknown = DiskCapacity {
            free_bytes: 0,
            total_bytes: 0,
            reserve_bytes: 0,
            unwritten_bytes: 0,
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
    fn a_missing_overcommit_means_none() {
        assert_eq!(effective_overcommit(0.0), 1.0);
        assert_eq!(effective_overcommit(f64::NAN), 1.0);
        assert_eq!(effective_overcommit(1.5), 1.5);
        // Reported as 0 by an older node: the same answer as 1.0.
        assert_eq!(
            node(50, 20, 0.0).admit(26 * GIB),
            node(50, 20, 1.0).admit(26 * GIB)
        );
    }

    #[test]
    fn the_refusal_names_the_node_and_the_shortfall() {
        let short = node(50, 20, 1.0).admit(26 * GIB).unwrap_err();
        let message = refusal("node-a", "create a sandbox", 26 * GIB, short);
        assert_eq!(
            message,
            "node node-a has no room to create a sandbox with a 26624 MiB disk: short by 1024 MiB \
             of free disk above its reserve"
        );
    }

    #[test]
    fn headroom_falls_as_disk_is_promised() {
        let empty = node(95, 0, 1.0);
        let half = node(95, 45, 1.0);
        assert!(empty.headroom() > half.headroom());
        assert_eq!(node(5, 0, 1.0).headroom(), 0.0);
    }
}
