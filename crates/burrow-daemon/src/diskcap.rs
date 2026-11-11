//! This node's side of disk admission: measuring the filesystem its sandboxes'
//! disks are on, adding up what it has provisioned, and refusing a create,
//! fork, restore, resume or adopt that does not fit. The rule itself is
//! [`burrow_common::disk`], which the orchestrator applies too.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use burrow_common::disk::{DiskCapacity, MIB};
use tonic::Status;

/// How this node admits disk, from `--disk-overcommit` and `--disk-reserve-mib`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskPolicy {
    pub overcommit: f64,
    /// `None` keeps 5% of the filesystem.
    pub reserve_mib: Option<u64>,
}

impl Default for DiskPolicy {
    fn default() -> Self {
        Self {
            overcommit: 1.0,
            reserve_mib: None,
        }
    }
}

/// How often a node short of disk says so again while it stays short.
const LOW_DISK_REPEAT_SECS: i64 = 60;

/// Admission state shared by every clone of the sandbox manager.
#[derive(Default)]
pub struct Admissions {
    /// Held across measuring and charging, so two creates cannot both fit
    /// into the same room.
    gate: tokio::sync::Mutex<()>,
    /// Disk admitted to operations whose sandbox is not registered yet, so
    /// the sum over registered sandboxes cannot see it.
    pending: Arc<AtomicU64>,
    /// When free disk under the reserve was last logged, 0 for not short.
    low_logged_at: AtomicI64,
}

/// Disk charged to an admitted operation until it is dropped, which its
/// caller does once the sandbox is registered and counted on its own.
pub struct Admitted {
    pending: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.pending.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// What admission adds up: the disks of the sandboxes registered here, each
/// at its size, the node's volumes, each at its size, and the blocks its warm
/// snapshots take.
#[derive(Debug, Default, Clone)]
pub struct Provisioned {
    pub disks: Vec<PathBuf>,
    pub volume_bytes: u64,
    pub warm_bytes: u64,
}

/// Free and total bytes of the filesystem holding `dir`.
pub fn filesystem_space(dir: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("the disk directory's path holds a NUL"))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is NUL-terminated and `stat` is a valid out-pointer.
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let block = stat.f_frsize as u64;
    // `f_bavail`, not `f_bfree`: what an unprivileged writer can use, which
    // is the smaller and the safer of the two to promise against.
    Ok((
        (stat.f_bavail as u64).saturating_mul(block),
        (stat.f_blocks as u64).saturating_mul(block),
    ))
}

/// A disk at its provisioned size, the size its guest sees: a sparse or
/// cloned file takes less, and is charged all of it anyway.
fn provisioned_size(path: &Path) -> u64 {
    crate::rootdisk::provisioned_bytes(path)
}

impl Admissions {
    /// This node's disk as admission sees it, or `None` when `disk_dir` cannot
    /// be measured, in which case nothing is refused.
    pub async fn capacity(
        &self,
        disk_dir: &Path,
        policy: DiskPolicy,
        provisioned: Provisioned,
    ) -> Option<DiskCapacity> {
        let dir = disk_dir.to_path_buf();
        let measured = tokio::task::spawn_blocking(move || {
            let space = filesystem_space(&dir);
            let disks: u64 = provisioned
                .disks
                .iter()
                .map(|path| provisioned_size(path))
                .sum();
            space.map(|(free, total)| {
                (
                    free,
                    total,
                    disks + provisioned.volume_bytes + provisioned.warm_bytes,
                )
            })
        })
        .await;
        let (free_bytes, total_bytes, provisioned_bytes) = match measured {
            Ok(Ok(measured)) => measured,
            Ok(Err(err)) => {
                tracing::warn!(dir = %disk_dir.display(), %err, "could not measure the filesystem sandboxes' disks are on");
                return None;
            }
            Err(err) => {
                tracing::warn!(%err, "disk measurement did not run");
                return None;
            }
        };
        Some(DiskCapacity {
            free_bytes,
            total_bytes,
            reserve_bytes: burrow_common::disk::reserve_bytes(policy.reserve_mib, total_bytes),
            provisioned_bytes: provisioned_bytes
                .saturating_add(self.pending.load(Ordering::Relaxed)),
            overcommit: burrow_common::disk::effective_overcommit(policy.overcommit),
        })
    }

    /// Admits `request_bytes` more provisioned disk on `node`, or refuses with
    /// `ResourceExhausted` naming the node and what it ran into. The charge
    /// is held by what is returned.
    pub async fn admit(
        &self,
        node: &str,
        what: &str,
        request_bytes: u64,
        disk_dir: &Path,
        policy: DiskPolicy,
        provisioned: Provisioned,
    ) -> Result<Admitted, Status> {
        let _gate = self.gate.lock().await;
        if let Some(capacity) = self.capacity(disk_dir, policy, provisioned).await {
            capacity.admit(request_bytes).map_err(|short| {
                let message = burrow_common::disk::refusal(node, what, request_bytes, short);
                tracing::warn!(
                    free_mib = capacity.free_bytes / MIB,
                    reserve_mib = capacity.reserve_bytes / MIB,
                    provisioned_mib = capacity.provisioned_bytes / MIB,
                    capacity_mib = (capacity.capacity_bytes() / MIB as f64) as u64,
                    "{message}"
                );
                Status::resource_exhausted(message)
            })?;
        }
        self.pending.fetch_add(request_bytes, Ordering::Relaxed);
        Ok(Admitted {
            pending: Arc::clone(&self.pending),
            bytes: request_bytes,
        })
    }

    /// Says so, at error level, while free disk is under the reserve with
    /// sandboxes on the node: on the way down, then once a minute, and once
    /// more when it recovers. Returns whether the node is short.
    pub fn watch(&self, capacity: &DiskCapacity, sandboxes: usize) -> bool {
        let is_low = sandboxes > 0 && capacity.is_below_reserve();
        let now = burrow_common::unix_now();
        let last = self.low_logged_at.load(Ordering::Relaxed);
        if is_low {
            if last == 0 || now - last >= LOW_DISK_REPEAT_SECS {
                tracing::error!(
                    free_mib = capacity.free_bytes / MIB,
                    reserve_mib = capacity.reserve_bytes / MIB,
                    total_mib = capacity.total_bytes / MIB,
                    sandboxes,
                    "free disk is below the reserve with sandboxes running: their writes may \
                     start failing; creates, resumes and adopts are refused until disk is freed"
                );
                self.low_logged_at.store(now.max(1), Ordering::Relaxed);
            }
        } else if last != 0 {
            tracing::warn!(
                free_mib = capacity.free_bytes / MIB,
                reserve_mib = capacity.reserve_bytes / MIB,
                "free disk is back above the reserve"
            );
            self.low_logged_at.store(0, Ordering::Relaxed);
        }
        is_low
    }
}

/// `--disk-overcommit`: a positive, finite factor.
pub fn parse_overcommit(text: &str) -> Result<f64, String> {
    let value: f64 = text
        .parse()
        .map_err(|_| format!("{text:?} is not a number"))?;
    if !value.is_finite() || value <= 0.0 {
        return Err("must be greater than 0; 1.0 never overcommits".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "burrow-diskcap-{name}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_disk_directory_is_measured() {
        let dir = temp("space");
        let (free, total) = filesystem_space(&dir).unwrap();
        assert!(total > 0);
        assert!(free <= total);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sparse disk takes almost nothing and is charged its whole size, a
    /// volume its size, whether or not any sandbox mounts it, and warm
    /// snapshots what they take.
    #[tokio::test]
    async fn disks_and_volumes_count_at_their_sizes() {
        let dir = temp("sizes");
        let disk = dir.join("root.ext4");
        std::fs::File::create(&disk)
            .unwrap()
            .set_len(64 * MIB)
            .unwrap();
        let admissions = Admissions::default();
        let capacity = admissions
            .capacity(
                &dir,
                DiskPolicy::default(),
                Provisioned {
                    disks: vec![disk, dir.join("gone.ext4")],
                    volume_bytes: 16 * MIB,
                    warm_bytes: 8 * MIB,
                },
            )
            .await
            .unwrap();
        assert_eq!(capacity.provisioned_bytes, 88 * MIB);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_admission_is_charged_until_dropped() {
        let dir = temp("charge");
        let admissions = Admissions::default();
        let policy = DiskPolicy {
            overcommit: 1.0,
            reserve_mib: Some(0),
        };
        let none = Provisioned::default;
        let before = admissions.capacity(&dir, policy, none()).await.unwrap();
        let admitted = admissions
            .admit("node-a", "create a sandbox", 10 * MIB, &dir, policy, none())
            .await
            .unwrap();
        let during = admissions.capacity(&dir, policy, none()).await.unwrap();
        assert_eq!(
            during.provisioned_bytes,
            before.provisioned_bytes + 10 * MIB
        );
        drop(admitted);
        let after = admissions.capacity(&dir, policy, none()).await.unwrap();
        assert_eq!(after.provisioned_bytes, before.provisioned_bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A create past what the node may provision is refused with the node
    /// named, and a resume, asking for nothing new, still goes through.
    #[tokio::test]
    async fn a_create_past_capacity_is_refused_and_a_resume_is_not() {
        let dir = temp("refuse");
        let (_, total) = filesystem_space(&dir).unwrap();
        let policy = DiskPolicy {
            overcommit: 1.0,
            reserve_mib: Some(0),
        };
        let admissions = Admissions::default();
        let full = Provisioned {
            disks: Vec::new(),
            volume_bytes: total,
            warm_bytes: 0,
        };
        let refused = admissions
            .admit(
                "node-a",
                "create a sandbox",
                MIB,
                &dir,
                policy,
                full.clone(),
            )
            .await
            .err()
            .expect("refused");
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
        assert!(
            refused.message().contains("node node-a"),
            "{}",
            refused.message()
        );
        // Nothing was charged for the refusal.
        let capacity = admissions
            .capacity(&dir, policy, Provisioned::default())
            .await
            .unwrap();
        assert_eq!(capacity.provisioned_bytes, 0);
        assert!(
            admissions
                .admit("node-a", "resume a sandbox", 0, &dir, policy, full)
                .await
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reserve bigger than the filesystem can never be met, so even a
    /// resume is refused.
    #[tokio::test]
    async fn a_node_under_its_reserve_refuses_a_resume() {
        let dir = temp("low");
        let (free, _) = filesystem_space(&dir).unwrap();
        let policy = DiskPolicy {
            overcommit: 1.0,
            reserve_mib: Some(free / MIB + 1024),
        };
        let refused = Admissions::default()
            .admit(
                "node-a",
                "resume a sandbox",
                0,
                &dir,
                policy,
                Provisioned::default(),
            )
            .await
            .err()
            .expect("refused");
        assert!(
            refused.message().contains("below its reserve"),
            "{}",
            refused.message()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn low_disk_is_reported_only_with_sandboxes_on_the_node() {
        let admissions = Admissions::default();
        let low = DiskCapacity {
            free_bytes: MIB,
            total_bytes: 100 * MIB,
            reserve_bytes: 5 * MIB,
            provisioned_bytes: 0,
            overcommit: 1.0,
        };
        assert!(!admissions.watch(&low, 0));
        assert!(admissions.watch(&low, 2));
        let fine = DiskCapacity {
            free_bytes: 50 * MIB,
            ..low
        };
        assert!(!admissions.watch(&fine, 2));
    }

    #[test]
    fn overcommit_must_be_positive() {
        assert_eq!(parse_overcommit("1.0"), Ok(1.0));
        assert_eq!(parse_overcommit("2.5"), Ok(2.5));
        assert!(parse_overcommit("0").is_err());
        assert!(parse_overcommit("-1").is_err());
        assert!(parse_overcommit("inf").is_err());
        assert!(parse_overcommit("lots").is_err());
    }
}
