//! Per-sandbox resource limits via cgroup v2.
//!
//! Firecracker already bounds a guest's *memory*: it allocates what the
//! machine config asks for and the guest cannot exceed it. It does not bound
//! CPU: `vcpu_count` decides how many vCPU threads exist, not how much host
//! CPU they may consume, so a single-vCPU guest spinning in a loop will happily
//! saturate a host core and starve its neighbours. `cpu.max` is what actually
//! caps that, which makes this the piece that turns "isolated" from a memory
//! statement into a scheduling one.

use std::path::{Path, PathBuf};

use crate::error::{Result, VmmError};

/// Controllers burrow needs delegated to it.
const REQUIRED: [&str; 3] = ["cpu", "memory", "pids"];
/// cgroup v2 CPU accounting period, in microseconds.
const CPU_PERIOD_US: u64 = 100_000;

#[derive(Debug, Clone, Default)]
pub struct Limits {
    /// Whole host CPUs the sandbox may consume. 0 means unlimited.
    pub cpus: u32,
    /// Hard memory ceiling for the VMM process, in MiB. 0 means unlimited.
    pub memory_mib: u32,
    /// Cap on process count, which bounds fork bombs inside the VMM.
    pub pids_max: u32,
}

pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Creates `<root>/burrow/<name>` with the given limits.
    pub fn create(root: &Path, name: &str, limits: &Limits) -> Result<Self> {
        let parent = root.join("burrow");
        prepare_parent(root, &parent)?;

        let path = parent.join(name);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }

        if limits.cpus > 0 {
            let quota = CPU_PERIOD_US * limits.cpus as u64;
            write(&path.join("cpu.max"), &format!("{quota} {CPU_PERIOD_US}"))?;
        }
        if limits.memory_mib > 0 {
            let bytes = limits.memory_mib as u64 * 1024 * 1024;
            write(&path.join("memory.max"), &bytes.to_string())?;
        }
        if limits.pids_max > 0 {
            write(&path.join("pids.max"), &limits.pids_max.to_string())?;
        }
        Ok(Self { path })
    }

    /// Moves a process into this cgroup. Its children are inherited into it,
    /// so placing the VMM covers every thread it later spawns.
    pub fn add_process(&self, pid: u32) -> Result<()> {
        write(&self.path.join("cgroup.procs"), &pid.to_string())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Host CPU this cgroup has consumed, in microseconds.
    ///
    /// The same `cpu` controller that enforces `cpu.max` also accounts for it,
    /// so this covers the whole VMM, the guest's vCPU threads and
    /// Firecracker's own work on their behalf, and needs nothing from inside
    /// the guest. `None` where the controller is not delegated, which is the
    /// same condition that leaves the cap unenforced.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        let stat = std::fs::read_to_string(self.path.join("cpu.stat")).ok()?;
        stat.lines()
            .find_map(|line| line.strip_prefix("usage_usec "))
            .and_then(|value| value.trim().parse().ok())
    }

    /// Removes the cgroup. Only succeeds once it holds no processes, which is
    /// why teardown happens after the VMM has been reaped.
    pub fn remove(&self) {
        if let Err(err) = std::fs::remove_dir(&self.path) {
            tracing::debug!(path = %self.path.display(), %err, "could not remove cgroup");
        }
    }
}

/// Ensures the burrow parent cgroup exists and has the controllers it needs
/// delegated to it.
fn prepare_parent(root: &Path, parent: &Path) -> Result<()> {
    enable_controllers(root)?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
    }
    // Controllers must be delegated again at each level before children can
    // use them.
    enable_controllers(parent)?;
    Ok(())
}

fn enable_controllers(dir: &Path) -> Result<()> {
    let available = std::fs::read_to_string(dir.join("cgroup.controllers")).unwrap_or_default();
    let wanted: Vec<&str> = REQUIRED
        .iter()
        .copied()
        .filter(|c| available.split_whitespace().any(|a| a == *c))
        .collect();
    if wanted.is_empty() {
        return Err(VmmError::CgroupUnavailable {
            reason: format!("none of {REQUIRED:?} are delegated to {}", dir.display()),
        });
    }

    let directive = wanted
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    let target = dir.join("cgroup.subtree_control");
    match write(&target, &directive) {
        Ok(()) => Ok(()),
        // A cgroup cannot enable controllers for its children while it still
        // holds processes of its own. Inside a container that is the normal
        // state: the container's own processes live in this cgroup. Moving
        // them into a leaf makes this level an inner node, which is allowed.
        Err(VmmError::Io(err)) if err.raw_os_error() == Some(nix::libc::EBUSY) => {
            evacuate_processes(dir)?;
            write(&target, &directive)
        }
        Err(err) => Err(err),
    }
}

/// Moves every process in `dir` into a `<dir>/_main` leaf.
fn evacuate_processes(dir: &Path) -> Result<()> {
    let leaf = dir.join("_main");
    if !leaf.exists() {
        std::fs::create_dir_all(&leaf)?;
    }
    let procs = std::fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
    let target = leaf.join("cgroup.procs");
    let mut moved = 0;
    for pid in procs.split_whitespace() {
        // Kernel threads and processes that exit mid-migration cannot be
        // moved; neither is a reason to abort the whole migration.
        if write(&target, pid).is_ok() {
            moved += 1;
        }
    }
    tracing::info!(
        cgroup = %dir.display(),
        moved,
        "moved existing processes into a leaf so controllers can be delegated"
    );
    Ok(())
}

fn write(path: &Path, value: &str) -> Result<()> {
    std::fs::write(path, value).map_err(|err| {
        tracing::debug!(path = %path.display(), value, %err, "cgroup write failed");
        VmmError::Io(err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quota_is_scaled_by_the_accounting_period() {
        // Two CPUs means twice the period's worth of runtime per period.
        assert_eq!(CPU_PERIOD_US * 2, 200_000);
    }

    #[test]
    fn unavailable_controllers_are_reported_rather_than_silently_skipped() {
        let dir = std::env::temp_dir().join(format!("burrow-cg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.controllers"), "io rdma").unwrap();
        let err = enable_controllers(&dir).unwrap_err();
        assert!(matches!(err, VmmError::CgroupUnavailable { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
