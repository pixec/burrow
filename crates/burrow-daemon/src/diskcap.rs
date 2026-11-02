//! This node's side of disk admission: measuring the data directory, counting
//! what its sandboxes have been promised, and refusing a create, resume or
//! adopt that would cross the reserve. The rule itself is
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
    /// into the same free space.
    gate: tokio::sync::Mutex<()>,
    /// Disk admitted to creates still building: their disk files do not exist
    /// yet, so the measurement cannot see them.
    pending: Arc<AtomicU64>,
    /// When free disk under the reserve was last logged, 0 for not short.
    low_logged_at: AtomicI64,
}

/// Disk charged to an admitted operation until it is dropped, by which time
/// its disk file exists and is counted on its own.
pub struct Admitted {
    pending: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.pending.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// Free and total bytes of the filesystem holding `dir`.
pub fn filesystem_space(dir: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("the data directory's path holds a NUL"))?;
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

/// What a disk file can still grow by: its size less the blocks it holds.
fn unwritten(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::metadata(path) {
        Ok(meta) => meta.len().saturating_sub(meta.blocks().saturating_mul(512)),
        Err(_) => 0,
    }
}

impl Admissions {
    /// This node's disk as admission sees it, or `None` when the data
    /// directory cannot be measured, in which case nothing is refused.
    pub async fn capacity(
        &self,
        data_dir: &Path,
        policy: DiskPolicy,
        disks: Vec<PathBuf>,
    ) -> Option<DiskCapacity> {
        let dir = data_dir.to_path_buf();
        let measured = tokio::task::spawn_blocking(move || {
            let space = filesystem_space(&dir);
            let unwritten: u64 = disks.iter().map(|path| unwritten(path)).sum();
            space.map(|(free, total)| (free, total, unwritten))
        })
        .await;
        let (free_bytes, total_bytes, unwritten_bytes) = match measured {
            Ok(Ok(measured)) => measured,
            Ok(Err(err)) => {
                tracing::warn!(dir = %data_dir.display(), %err, "could not measure the data directory's filesystem");
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
            unwritten_bytes: unwritten_bytes.saturating_add(self.pending.load(Ordering::Relaxed)),
            overcommit: burrow_common::disk::effective_overcommit(policy.overcommit),
        })
    }

    /// Admits `request_bytes` more disk on `node`, or refuses with
    /// `ResourceExhausted` naming the node and the shortfall. The charge is
    /// held by what is returned.
    pub async fn admit(
        &self,
        node: &str,
        what: &str,
        request_bytes: u64,
        data_dir: &Path,
        policy: DiskPolicy,
        disks: Vec<PathBuf>,
    ) -> Result<Admitted, Status> {
        let _gate = self.gate.lock().await;
        if let Some(capacity) = self.capacity(data_dir, policy, disks).await {
            capacity.admit(request_bytes).map_err(|short| {
                let message = burrow_common::disk::refusal(node, what, request_bytes, short);
                tracing::warn!(
                    free_mib = capacity.free_bytes / MIB,
                    reserve_mib = capacity.reserve_bytes / MIB,
                    unwritten_mib = capacity.unwritten_bytes / MIB,
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
    fn the_data_directory_is_measured() {
        let dir = temp("space");
        let (free, total) = filesystem_space(&dir).unwrap();
        assert!(total > 0);
        assert!(free <= total);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sparse disk counts at its size less what it already holds.
    #[tokio::test]
    async fn a_sparse_disk_is_counted_as_unwritten() {
        let dir = temp("sparse");
        let disk = dir.join("scratch.ext4");
        std::fs::File::create(&disk)
            .unwrap()
            .set_len(64 * MIB)
            .unwrap();
        let admissions = Admissions::default();
        let capacity = admissions
            .capacity(
                &dir,
                DiskPolicy::default(),
                vec![disk.clone(), dir.join("gone.ext4")],
            )
            .await
            .unwrap();
        // Nearly all of it: a sparse file holds a block or none.
        assert!(capacity.unwritten_bytes > 63 * MIB, "{capacity:?}");
        assert!(capacity.unwritten_bytes <= 64 * MIB);
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
        let before = admissions.capacity(&dir, policy, vec![]).await.unwrap();
        let admitted = admissions
            .admit("node-a", "create a sandbox", 10 * MIB, &dir, policy, vec![])
            .await
            .unwrap();
        let during = admissions.capacity(&dir, policy, vec![]).await.unwrap();
        assert_eq!(during.unwritten_bytes, before.unwritten_bytes + 10 * MIB);
        drop(admitted);
        let after = admissions.capacity(&dir, policy, vec![]).await.unwrap();
        assert_eq!(after.unwritten_bytes, before.unwritten_bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reserve bigger than the filesystem can never be met, so every
    /// create is refused, with the node named and what it is short of.
    #[tokio::test]
    async fn a_create_that_would_cross_the_reserve_is_refused() {
        let dir = temp("refuse");
        let (free, _) = filesystem_space(&dir).unwrap();
        let policy = DiskPolicy {
            overcommit: 1.0,
            reserve_mib: Some(free / MIB + 1024),
        };
        let admissions = Admissions::default();
        let refused = admissions
            .admit("node-a", "create a sandbox", MIB, &dir, policy, vec![])
            .await
            .err()
            .expect("refused");
        assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
        assert!(
            refused.message().contains("node node-a"),
            "{}",
            refused.message()
        );
        assert!(
            refused.message().contains("short by"),
            "{}",
            refused.message()
        );
        // Nothing was charged for the refusal.
        let capacity = admissions.capacity(&dir, policy, vec![]).await.unwrap();
        assert_eq!(capacity.unwritten_bytes, 0);
        // And a resume, asking for nothing new, is refused as well.
        assert!(
            admissions
                .admit("node-a", "resume a sandbox", 0, &dir, policy, vec![])
                .await
                .is_err()
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
            unwritten_bytes: 0,
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
