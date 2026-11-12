//! Per-sandbox resource limits via cgroup v2.
//!
//! Firecracker already bounds a guest's *memory*: it allocates what the
//! machine config asks for and the guest cannot exceed it. Its vCPU count
//! bounds the guest's CPU too, since each vCPU is one thread, but not the
//! VMM's own threads, and not how host CPU is shared when the node is busy.
//! `cpu.weight` shares it in proportion to what each sandbox was charged, so
//! a busy neighbour cannot starve one of what placement promised it.
//! `cpu.max` is set only for a sandbox that asked for a cap: one at the vCPU
//! count throttled the VMM's device threads along with the vCPUs, stalling a
//! busy guest for the rest of each period, and kept no neighbour safer than
//! the weight does. A VMM starts without it: a cap below its vCPUs stalls a
//! kernel boot past the agent's deadline, so its owner writes the cap with
//! [`Cgroup::set_limits`] once the guest has answered.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Controllers burrow delegates where it can. `cpuset` and `io` are needed
/// only by a sandbox that pins CPUs or weighs its IO.
const CONTROLLERS: [&str; 5] = ["cpu", "memory", "pids", "cpuset", "io"];
/// The kernel's `cpu.weight` and `io.weight` default.
const DEFAULT_WEIGHT: u64 = 100;
/// cgroup v2 CPU accounting period, in microseconds.
const CPU_PERIOD_US: u64 = 100_000;
/// Times the processes are moved out before delegation is given up on. A
/// process spawned just before the move is still in the cgroup, so one pass is
/// not always enough.
const EVACUATE_ATTEMPTS: usize = 5;

#[derive(Debug, Clone, Default)]
pub struct Limits {
    /// Host CPU the VMM may consume, in thousandths of a CPU (`cpu.max`). 0
    /// means unlimited.
    pub cpu_max_millis: u64,
    /// Host CPU reserved for the VM, in thousandths of a CPU: what its node
    /// is charged and what `cpu_weight` was derived from. Not a cgroup file of
    /// its own. 0 means none.
    pub cpu_reserve_millis: u64,
    /// `cpu.weight`, 1 to 10000. 0 is the kernel's default.
    pub cpu_weight: u64,
    /// `cpuset.cpus`, in its list syntax such as "0-3,6". Empty is any CPU.
    pub cpuset_cpus: String,
    /// `io.weight`, 1 to 10000. 0 is the kernel's default.
    pub io_weight: u64,
    /// Hard memory ceiling for the VMM process, in MiB. 0 means unlimited.
    pub memory_mib: u32,
    /// Cap on process count, which bounds fork bombs inside the VMM.
    pub pids_max: u32,
}

impl Limits {
    /// These limits without the `cpu.max` cap, which a VMM boots or restores
    /// under.
    pub fn uncapped(&self) -> Self {
        Self {
            cpu_max_millis: 0,
            ..self.clone()
        }
    }
}

pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Creates `<root>/burrow/<name>` with the given limits, all but the
    /// `cpu.max` cap.
    pub fn create(root: &Path, name: &str, limits: &Limits) -> Result<Self> {
        let parent = root.join("burrow");
        prepare_parent(root, &parent)?;

        let path = parent.join(name);
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }

        let cgroup = Self { path };
        cgroup.set_limits(&limits.uncapped())?;
        let path = &cgroup.path;
        if limits.memory_mib > 0 {
            let bytes = limits.memory_mib as u64 * 1024 * 1024;
            write(&path.join("memory.max"), &bytes.to_string())?;
        }
        if limits.pids_max > 0 {
            write(&path.join("pids.max"), &limits.pids_max.to_string())?;
        }
        Ok(cgroup)
    }

    /// The cgroup a VM's VMM is to join, made before the VMM is spawned. One
    /// that cannot be made refuses the VM where its limits are required, and
    /// otherwise leaves it unlimited, loudly.
    pub(crate) fn for_vm(
        root: Option<&Path>,
        vm_id: &str,
        limits: &Limits,
        is_required: bool,
    ) -> Result<Option<Self>> {
        let Some(root) = root else {
            return Ok(None);
        };
        match Self::create(root, vm_id, limits) {
            Ok(cgroup) => Ok(Some(cgroup)),
            // A pin or an IO weight is never dropped quietly: the caller
            // asked for it by name.
            Err(err) if !is_required && limits.cpuset_cpus.is_empty() && limits.io_weight == 0 => {
                // Loud, because the sandbox is about to run without the CPU
                // cap its policy asked for.
                tracing::error!(
                    vm_id, %err,
                    "resource limits NOT enforced; sandbox can consume unbounded host cpu"
                );
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Has a command's child join this cgroup before it execs, so the VMM is
    /// in it from its first instruction rather than moved in once it already
    /// runs, uncapped and uncounted until then. Its children and threads are
    /// inherited into it.
    pub(crate) fn join_before_exec(&self, command: &mut tokio::process::Command) -> Result<()> {
        use std::os::fd::AsRawFd as _;
        let procs = std::fs::OpenOptions::new()
            .write(true)
            .open(self.path.join("cgroup.procs"))?;
        // SAFETY: the hook runs between fork and exec, where only
        // async-signal-safe calls are allowed; it makes one write(2) of a
        // static buffer to a descriptor opened above. "0" is the writer.
        unsafe {
            command.pre_exec(move || {
                match libc::write(procs.as_raw_fd(), b"0".as_ptr().cast(), 1) {
                    1 => Ok(()),
                    _ => Err(std::io::Error::last_os_error()),
                }
            });
        }
        Ok(())
    }

    /// Writes the CPU and IO limits, on a new cgroup or a running VMM's. One
    /// left at 0 or empty is put back to the kernel's default.
    pub fn set_limits(&self, limits: &Limits) -> Result<()> {
        write(&self.path.join("cpu.max"), &cpu_max(limits.cpu_max_millis))?;
        let weight = match limits.cpu_weight {
            0 => DEFAULT_WEIGHT,
            weight => weight,
        };
        write(&self.path.join("cpu.weight"), &weight.to_string())?;
        let cpuset = self.path.join("cpuset.cpus");
        if !limits.cpuset_cpus.is_empty() || cpuset.exists() {
            write_controlled(&cpuset, &limits.cpuset_cpus, "cpuset_cpus")?;
        }
        let io = self.path.join("io.weight");
        if limits.io_weight > 0 || io.exists() {
            let weight = match limits.io_weight {
                0 => DEFAULT_WEIGHT,
                weight => weight,
            };
            write_controlled(&io, &format!("default {weight}"), "blkio_weight")?;
        }
        Ok(())
    }

    /// Moves the memory cap, for a guest given memory or relieved of it.
    pub fn set_memory(&self, mib: u32) -> Result<()> {
        write(
            &self.path.join("memory.max"),
            &(u64::from(mib) * 1024 * 1024).to_string(),
        )
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

/// Whether VMs under `root` can be given an io.weight: the io controller is
/// delegated to burrow's cgroups and the kernel exposes io.weight there.
pub fn is_io_weight_supported(root: &Path) -> bool {
    let parent = root.join("burrow");
    prepare_parent(root, &parent).is_ok() && parent.join("io.weight").exists()
}

/// Ensures the burrow parent cgroup exists and has the controllers it needs
/// delegated to it.
fn prepare_parent(root: &Path, parent: &Path) -> Result<()> {
    // Held across both levels: two VMs started together each found the root
    // busy, and the one whose evacuation lost the race was left with no limits.
    static PREPARING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _held = PREPARING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    let wanted: Vec<&str> = CONTROLLERS
        .iter()
        .copied()
        .filter(|c| available.split_whitespace().any(|a| a == *c))
        .collect();
    if wanted.is_empty() {
        return Err(Error::CgroupUnavailable {
            reason: format!("none of {CONTROLLERS:?} are delegated to {}", dir.display()),
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
        Err(Error::Io(err)) if err.raw_os_error() == Some(nix::libc::EBUSY) => {
            let mut outcome = Err(Error::Io(err));
            for _ in 0..EVACUATE_ATTEMPTS {
                evacuate_processes(dir)?;
                outcome = write(&target, &directive);
                match &outcome {
                    Err(Error::Io(err)) if err.raw_os_error() == Some(nix::libc::EBUSY) => {}
                    _ => break,
                }
            }
            outcome
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

/// `cpu.max` for a cap in thousandths of a CPU, or no cap.
fn cpu_max(millis: u64) -> String {
    match millis {
        0 => format!("max {CPU_PERIOD_US}"),
        millis => format!("{} {CPU_PERIOD_US}", CPU_PERIOD_US * millis / 1000),
    }
}

/// Writes a file only a controller burrow may not have been delegated
/// provides, naming the limit that needs it when it is missing.
fn write_controlled(path: &Path, value: &str, limit: &str) -> Result<()> {
    if !path.exists() {
        return Err(Error::CgroupUnavailable {
            reason: format!(
                "{limit} needs {}, which this node's cgroup does not have: its controller is \
                 not delegated to burrowd or the kernel lacks it",
                path.display()
            ),
        });
    }
    write(path, value)
}

fn write(path: &Path, value: &str) -> Result<()> {
    std::fs::write(path, value).map_err(|err| {
        tracing::debug!(path = %path.display(), value, %err, "cgroup write failed");
        Error::Io(err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quota_is_scaled_by_the_accounting_period() {
        assert_eq!(cpu_max(2000), "200000 100000");
        assert_eq!(cpu_max(500), "50000 100000");
        assert_eq!(cpu_max(10), "1000 100000");
        assert_eq!(cpu_max(0), "max 100000");
    }

    /// The files a cgroup holds, for a test standing in for one.
    fn fake(name: &str, files: &[&str]) -> Cgroup {
        let path = std::env::temp_dir().join(format!("burrow-cg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        for file in files {
            std::fs::write(path.join(file), "").unwrap();
        }
        Cgroup { path }
    }

    #[test]
    fn limits_are_written_and_cleared() {
        let cgroup = fake(
            "limits",
            &["cpu.max", "cpu.weight", "cpuset.cpus", "io.weight"],
        );
        let read = |file: &str| std::fs::read_to_string(cgroup.path.join(file)).unwrap();
        cgroup
            .set_limits(&Limits {
                cpu_max_millis: 500,
                cpu_weight: 20,
                cpuset_cpus: "0-1".into(),
                io_weight: 4950,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(read("cpu.max"), "50000 100000");
        assert_eq!(read("cpu.weight"), "20");
        assert_eq!(read("cpuset.cpus"), "0-1");
        assert_eq!(read("io.weight"), "default 4950");
        cgroup.set_limits(&Limits::default()).unwrap();
        assert_eq!(read("cpu.max"), "max 100000");
        assert_eq!(read("cpu.weight"), "100");
        assert_eq!(read("cpuset.cpus"), "");
        assert_eq!(read("io.weight"), "default 100");
        let _ = std::fs::remove_dir_all(&cgroup.path);
    }

    /// io.weight is offered only where the io controller reaches burrow's
    /// cgroups and the kernel gives them the file.
    #[test]
    fn io_weight_is_offered_only_where_the_kernel_gives_it() {
        let root = std::env::temp_dir().join(format!("burrow-cg-io-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in [root.clone(), root.join("burrow")] {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cgroup.controllers"), "cpu io").unwrap();
        }
        assert!(!is_io_weight_supported(&root));
        std::fs::write(root.join("burrow").join("io.weight"), "default 100").unwrap();
        assert!(is_io_weight_supported(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A VMM's cgroup is made without its `cpus` cap, so a kernel boot or a
    /// restore is not throttled past the agent's deadline, and with every
    /// other limit. The cap is written once the guest has answered.
    #[test]
    fn a_new_cgroup_starts_without_its_cpu_cap() {
        let root = std::env::temp_dir().join(format!("burrow-cg-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in [root.clone(), root.join("burrow")] {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cgroup.controllers"), "cpu memory").unwrap();
        }
        let limits = Limits {
            cpu_max_millis: 500,
            cpu_weight: 20,
            memory_mib: 580,
            ..Default::default()
        };
        let cgroup = Cgroup::create(&root, "vm", &limits).unwrap();
        let read = |file: &str| std::fs::read_to_string(cgroup.path.join(file)).unwrap();
        assert_eq!(read("cpu.max"), "max 100000");
        assert_eq!(read("cpu.weight"), "20");
        assert_eq!(read("memory.max"), (580u64 << 20).to_string());
        cgroup.set_limits(&limits).unwrap();
        assert_eq!(read("cpu.max"), "50000 100000");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A pin or an IO weight on a node without the controller is refused by
    /// name, not dropped.
    #[test]
    fn a_missing_controller_is_named() {
        let cgroup = fake("nocontroller", &["cpu.max", "cpu.weight"]);
        cgroup.set_limits(&Limits::default()).unwrap();
        let err = cgroup
            .set_limits(&Limits {
                io_weight: 100,
                ..Default::default()
            })
            .unwrap_err();
        assert!(err.to_string().contains("blkio_weight"), "{err}");
        let err = cgroup
            .set_limits(&Limits {
                cpuset_cpus: "0".into(),
                ..Default::default()
            })
            .unwrap_err();
        assert!(err.to_string().contains("cpuset_cpus"), "{err}");
        let _ = std::fs::remove_dir_all(&cgroup.path);
    }

    #[test]
    fn unavailable_controllers_are_reported_rather_than_silently_skipped() {
        let dir = std::env::temp_dir().join(format!("burrow-cg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.controllers"), "rdma hugetlb").unwrap();
        let err = enable_controllers(&dir).unwrap_err();
        assert!(matches!(err, Error::CgroupUnavailable { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
