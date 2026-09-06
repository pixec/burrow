//! Firecracker microVM supervision: spawn the VMM, configure it over its API
//! socket, boot it, and drive pause/resume/snapshot.

mod api;
pub mod cgroup;
mod error;
mod model;
mod process;
#[cfg(target_os = "linux")]
pub mod uffd;
pub mod vsock;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use api::FcApi;
pub use cgroup::{Cgroup, Limits};
pub use error::{Result, VmmError};
pub use model::{InstanceInfo, NetworkOverride, SnapshotType, VmState};
pub use process::{FcProcess, Jail};
#[cfg(target_os = "linux")]
pub use uffd::{UffdBackend, merge_chain};

use model::*;

/// Conventional filenames inside a VM's working directory. Keeping these
/// identical for every sandbox is what makes snapshot restore portable across
/// sandboxes on a node.
pub const API_SOCK: &str = "fc.sock";
pub const VSOCK_UDS: &str = "vsock.sock";
pub const SNAPSHOT_FILE: &str = "snapshot.vmstate";
pub const SNAPSHOT_MEM_FILE: &str = "snapshot.mem";

/// First usable vsock context id (0-2 are reserved).
pub const GUEST_CID: u32 = 3;

#[derive(Debug, Clone)]
pub struct DriveSpec {
    pub id: String,
    /// Path relative to the VM working directory.
    pub path: String,
    pub is_root: bool,
    pub read_only: bool,
}

impl DriveSpec {
    pub fn root_ro(path: impl Into<String>) -> Self {
        Self {
            id: "rootfs".into(),
            path: path.into(),
            is_root: true,
            read_only: true,
        }
    }

    pub fn scratch_rw(path: impl Into<String>) -> Self {
        Self {
            id: "scratch".into(),
            path: path.into(),
            is_root: false,
            read_only: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetSpec {
    /// Host tap device name. Must match at snapshot restore time.
    pub tap: String,
    pub guest_mac: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MicroVmSpec {
    pub vm_id: String,
    /// Working directory; all resource paths are relative to it.
    pub workdir: PathBuf,
    pub firecracker_bin: PathBuf,
    /// Kernel path relative to `workdir`.
    pub kernel: String,
    pub boot_args: String,
    pub drives: Vec<DriveSpec>,
    /// Put virtio devices on a PCI bus instead of MMIO.
    ///
    /// Required for hotplug, which is the only way to attach a volume to a
    /// sandbox restored from a warm snapshot: a snapshot restores only into
    /// the drive set it was captured with, and the warm snapshot is shared by
    /// every sandbox restored from it. Enabling it changes the transport for
    /// every device, so a snapshot taken under one setting cannot be restored
    /// under the other.
    pub enable_pci: bool,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub net: Option<NetSpec>,
    /// Enable virtio-vsock, the transport the guest agent speaks.
    pub vsock: bool,
    /// Needed for diff snapshots.
    pub track_dirty_pages: bool,
    /// Confines firecracker to a chroot under an unprivileged uid. `None`
    /// runs it as root with the host filesystem visible.
    pub jail: Option<process::Jail>,
    /// Serve guest memory lazily on restore instead of letting the kernel page
    /// the whole memory file in. Ignored on a cold boot, which has no memory
    /// file to serve from.
    pub lazy_memory: bool,
    /// Memory files to restore from, oldest first: a full base followed by any
    /// diff snapshots layered over it. Empty means the conventional
    /// `snapshot.mem` alone. More than one entry forces the page-fault handler
    /// on, because a chain has no single file for the kernel to map.
    pub memory_chain: Vec<String>,
    /// Pages to populate before the guest runs, relative to the working
    /// directory. Recorded from an earlier restore of the same snapshot.
    pub prefetch: Option<String>,
    /// Where to record the pages this VM faults on, relative to the working
    /// directory. Set only when profiling a snapshot.
    pub record_prefetch: Option<String>,
    /// Host resource caps. Applied to the VMM process, so they bound the guest
    /// and Firecracker's own overhead together.
    pub limits: Limits,
    /// cgroup2 mount point; `None` disables limit enforcement.
    pub cgroup_root: Option<PathBuf>,
    /// Whether a sandbox may run when its limits could not be applied. False
    /// keeps the stack usable where cgroups are unavailable, at the cost of
    /// unbounded CPU; true refuses to run an unbounded guest at all.
    pub require_limits: bool,
}

impl MicroVmSpec {
    pub fn new(vm_id: impl Into<String>, workdir: impl Into<PathBuf>) -> Self {
        Self {
            vm_id: vm_id.into(),
            workdir: workdir.into(),
            firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
            kernel: "vmlinux".into(),
            boot_args: DEFAULT_BOOT_ARGS.into(),
            drives: Vec::new(),
            enable_pci: false,
            vcpus: 1,
            mem_mib: 512,
            net: None,
            vsock: false,
            track_dirty_pages: false,
            prefetch: None,
            record_prefetch: None,
            jail: None,
            lazy_memory: false,
            memory_chain: Vec::new(),
            limits: Limits::default(),
            cgroup_root: Some(PathBuf::from("/sys/fs/cgroup")),
            require_limits: false,
        }
    }
}

/// `console=ttyS0` sends guest serial to firecracker's stdout, which we
/// capture; `panic=1 reboot=k` makes a panicking guest exit the VMM rather
/// than hang.
/// `pci=off` is deliberately absent: virtio devices sit on a PCI bus so that
/// volumes can be hotplugged onto a sandbox restored from a warm snapshot, and
/// a guest told to ignore the bus would never see them.
pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1";

/// A running (or paused) Firecracker VM.
pub struct MicroVm {
    process: FcProcess,
    api: FcApi,
    spec: MicroVmSpec,
    /// Time from process spawn to a successful `InstanceStart`.
    boot_latency: Duration,
    /// Held for the VM's lifetime; removed once the process is reaped.
    cgroup: Option<Cgroup>,
    /// Serves this VM's page faults when restored with lazy memory. Dropped
    /// only after the VMM is gone, because a live guest whose faults stop being
    /// answered hangs instead of failing.
    #[cfg(target_os = "linux")]
    memory: Option<UffdBackend>,
}

/// Places the VMM under its resource limits.
///
/// Applied between spawn and `InstanceStart`, so the guest never runs even
/// briefly outside its caps.
fn apply_limits(spec: &MicroVmSpec, pid: Option<u32>) -> Result<Option<Cgroup>> {
    let (Some(root), Some(pid)) = (spec.cgroup_root.as_ref(), pid) else {
        return Ok(None);
    };
    let cgroup = Cgroup::create(root, &spec.vm_id, &spec.limits)?;
    cgroup.add_process(pid)?;
    tracing::debug!(
        vm_id = spec.vm_id,
        cgroup = %cgroup.path().display(),
        cpus = spec.limits.cpus,
        memory_mib = spec.limits.memory_mib,
        "resource limits applied"
    );
    Ok(Some(cgroup))
}

/// Unlinks the files a snapshot is about to be written to.
///
/// Sandboxes created from a warm snapshot **hard-link** the template's
/// `snapshot.vmstate` and `snapshot.mem` into their working directory, which is
/// what makes a create cheap. Firecracker then writes a new snapshot to those
/// same relative paths, and writing through a hard link writes into the
/// template: one sandbox's entire guest memory becomes the image every later
/// sandbox restores from. That is a cross-sandbox leak of whatever was in RAM,
/// credentials included, not merely a corrupted template.
///
/// Unlinking first gives Firecracker a fresh inode and leaves the template
/// untouched. It is safe while the VM is running: an open mapping of the old
/// inode (the page-fault handler's) keeps serving the memory the guest is still
/// using until the VMM exits.
async fn detach_snapshot_targets(workdir: &Path, mem_file: &str) -> Result<()> {
    for name in [SNAPSHOT_FILE, mem_file] {
        match tokio::fs::remove_file(workdir.join(name)).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

/// Removes sockets left behind by a previous VM in the same working
/// directory. Firecracker binds the vsock UDS itself and fails with EADDRINUSE
/// if the file already exists, so a reused workdir must be swept first. It
/// also creates one `<uds>_<port>` socket per guest-initiated connection,
/// which are stale for the same reason.
async fn clear_stale_sockets(spec: &MicroVmSpec) -> Result<()> {
    if !spec.vsock {
        return Ok(());
    }
    let mut entries = match tokio::fs::read_dir(&spec.workdir).await {
        Ok(entries) => entries,
        // A fresh workdir has nothing to clean.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == VSOCK_UDS || name.starts_with(&format!("{VSOCK_UDS}_")) {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

impl MicroVm {
    /// Spawns the VMM, applies the configuration, and starts the instance.
    pub async fn boot(spec: MicroVmSpec) -> Result<Self> {
        let start = Instant::now();
        clear_stale_sockets(&spec).await?;
        let process = FcProcess::spawn(
            &spec.firecracker_bin,
            &spec.vm_id,
            &spec.workdir,
            API_SOCK,
            spec.jail.as_ref(),
            spec.enable_pci,
        )
        .await?;
        let api = FcApi::new(spec.workdir.join(API_SOCK));

        // Configure, then start. Any failure here kills the VMM so we never
        // leak a half-configured firecracker process.
        let mut vm = Self {
            process,
            api,
            spec,
            boot_latency: Duration::ZERO,
            cgroup: None,
            #[cfg(target_os = "linux")]
            memory: None,
        };
        vm.cgroup = match apply_limits(&vm.spec, vm.process.pid()) {
            Ok(cgroup) => cgroup,
            Err(err) if !vm.spec.require_limits => {
                // Loud, because the sandbox is now running without the CPU cap
                // its policy asked for.
                tracing::error!(
                    vm_id = vm.spec.vm_id, %err,
                    "resource limits NOT enforced; sandbox can consume unbounded host cpu"
                );
                None
            }
            Err(err) => {
                let _ = vm.process.kill().await;
                return Err(err);
            }
        };
        if let Err(err) = vm.configure().await {
            let _ = vm.process.kill().await;
            return Err(err);
        }
        if let Err(err) = vm.api.start_instance().await {
            let _ = vm.process.kill().await;
            return Err(err);
        }
        vm.boot_latency = start.elapsed();
        tracing::info!(
            vm_id = vm.spec.vm_id,
            pid = vm.process.pid(),
            latency_ms = vm.boot_latency.as_millis() as u64,
            "microvm started"
        );
        Ok(vm)
    }

    async fn configure(&self) -> Result<()> {
        self.api
            .set_machine_config(&MachineConfig {
                vcpu_count: self.spec.vcpus,
                mem_size_mib: self.spec.mem_mib,
                smt: None,
                track_dirty_pages: self.spec.track_dirty_pages,
            })
            .await?;

        self.api
            .set_boot_source(&BootSource {
                kernel_image_path: self.spec.kernel.clone(),
                boot_args: self.spec.boot_args.clone(),
                initrd_path: None,
            })
            .await?;

        for drive in &self.spec.drives {
            self.api
                .add_drive(&Drive {
                    drive_id: drive.id.clone(),
                    path_on_host: drive.path.clone(),
                    is_root_device: drive.is_root,
                    is_read_only: drive.read_only,
                })
                .await?;
        }

        if let Some(net) = &self.spec.net {
            self.api
                .add_network_interface(&NetworkInterface {
                    iface_id: "eth0".into(),
                    host_dev_name: net.tap.clone(),
                    guest_mac: net.guest_mac.clone(),
                })
                .await?;
        }

        if self.spec.vsock {
            self.api
                .set_vsock(&Vsock {
                    guest_cid: GUEST_CID,
                    uds_path: VSOCK_UDS.into(),
                })
                .await?;
        }

        Ok(())
    }

    pub fn api(&self) -> &FcApi {
        &self.api
    }

    pub fn spec(&self) -> &MicroVmSpec {
        &self.spec
    }

    pub fn pid(&self) -> Option<u32> {
        self.process.pid()
    }

    pub fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    /// Host CPU this VM has consumed, in microseconds. `None` when the VM runs
    /// under no cgroup, which is the same condition that leaves its cpu cap
    /// unenforced.
    pub fn cpu_usage_usec(&self) -> Option<u64> {
        self.cgroup.as_ref()?.cpu_usage_usec()
    }

    pub fn console_log_path(&self) -> &Path {
        self.process.console_log_path()
    }

    pub async fn console_tail(&self, lines: usize) -> String {
        self.process.console_tail(lines).await
    }

    /// Writes to the guest serial console (dev/rescue path; see
    /// [`FcProcess::console_write`]).
    pub async fn console_write(&mut self, input: &str) -> Result<()> {
        self.process.console_write(input).await
    }

    /// Waits for a marker string in the guest's serial output. Until the guest
    /// agent exists this is how we know a guest reached userspace.
    pub async fn wait_for_console(&self, marker: &str, timeout: Duration) -> Result<Duration> {
        self.process.wait_for_console(marker, timeout).await
    }

    pub async fn instance_info(&self) -> Result<InstanceInfo> {
        self.api.instance_info().await
    }

    /// Host-side Unix socket backing the guest's vsock device.
    pub fn vsock_uds_path(&self) -> PathBuf {
        self.spec.workdir.join(VSOCK_UDS)
    }

    /// Opens a connection to a guest vsock port. Reconnect after every resume;
    /// connections do not survive a pause.
    pub async fn connect_vsock(&self, port: u32) -> Result<tokio::net::UnixStream> {
        vsock::connect(&self.vsock_uds_path(), port).await
    }

    /// Waits for a guest vsock listener to accept, which is the agent's
    /// readiness signal (and far more precise than console scraping).
    pub async fn wait_for_vsock(&self, port: u32, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        let deadline = start + timeout;
        loop {
            if self.connect_vsock(port).await.is_ok() {
                return Ok(start.elapsed());
            }
            if Instant::now() >= deadline {
                return Err(VmmError::Timeout {
                    what: format!("guest vsock port {port}"),
                    timeout_ms: timeout.as_millis() as u64,
                });
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    pub async fn pause(&self) -> Result<()> {
        self.api.set_vm_state(VmState::Paused).await
    }

    pub async fn resume(&self) -> Result<()> {
        self.api.set_vm_state(VmState::Resumed).await
    }

    /// Snapshots a **paused** VM into `snapshot.vmstate` + `snapshot.mem` in
    /// the working directory.
    pub async fn snapshot(&self, kind: SnapshotType) -> Result<()> {
        self.snapshot_to(kind, SNAPSHOT_MEM_FILE).await
    }

    /// Snapshots a **paused** VM, writing memory to `mem_file`.
    ///
    /// A diff snapshot must go to its own file: it records only the pages
    /// touched since the last snapshot, so writing it over the base would
    /// destroy everything it does not contain.
    pub async fn snapshot_to(&self, kind: SnapshotType, mem_file: &str) -> Result<()> {
        // Only what is about to be written is unlinked. A diff is layered over
        // the memory file it was taken against, so removing that base, as
        // detaching everything would, leaves a chain pointing at nothing.
        detach_snapshot_targets(&self.spec.workdir, mem_file).await?;
        self.api
            .create_snapshot(&CreateSnapshot {
                snapshot_type: kind,
                snapshot_path: SNAPSHOT_FILE.into(),
                mem_file_path: mem_file.into(),
            })
            .await
    }

    /// Attaches a drive to a running VM.
    ///
    /// Only possible with `enable_pci`, and the guest sees nothing until it
    /// rescans its PCI bus: firecracker has no way to notify it. This is how a
    /// volume reaches a sandbox restored from a warm snapshot, which was
    /// captured without it.
    pub async fn attach_drive(&self, drive: &DriveSpec) -> Result<()> {
        self.api
            .add_drive(&Drive {
                drive_id: drive.id.clone(),
                path_on_host: drive.path.clone(),
                is_root_device: drive.is_root,
                is_read_only: drive.read_only,
            })
            .await
    }

    /// Starts a fresh VMM process and restores a snapshot from `workdir`
    /// instead of cold-booting. `spec` must describe the same resources
    /// (tap name, drive paths) as the snapshotted VM.
    pub async fn restore(spec: MicroVmSpec, resume: bool) -> Result<Self> {
        let start = Instant::now();
        clear_stale_sockets(&spec).await?;
        let process = FcProcess::spawn(
            &spec.firecracker_bin,
            &spec.vm_id,
            &spec.workdir,
            API_SOCK,
            spec.jail.as_ref(),
            spec.enable_pci,
        )
        .await?;
        let api = FcApi::new(spec.workdir.join(API_SOCK));

        let mut vm = Self {
            process,
            api,
            spec,
            boot_latency: Duration::ZERO,
            cgroup: None,
            #[cfg(target_os = "linux")]
            memory: None,
        };
        vm.cgroup = match apply_limits(&vm.spec, vm.process.pid()) {
            Ok(cgroup) => cgroup,
            Err(err) if !vm.spec.require_limits => {
                // Loud, because the sandbox is now running without the CPU cap
                // its policy asked for.
                tracing::error!(
                    vm_id = vm.spec.vm_id, %err,
                    "resource limits NOT enforced; sandbox can consume unbounded host cpu"
                );
                None
            }
            Err(err) => {
                let _ = vm.process.kill().await;
                return Err(err);
            }
        };
        // A chain has no single file for the kernel to map, so lazy memory is
        // not optional there. Started before `load_snapshot`, because
        // firecracker connects to it while handling that request and fails
        // outright if nothing is listening.
        let mem_backend = match vm.start_lazy_memory() {
            Ok(Some(backend_path)) => MemBackend {
                backend_type: "Uffd".into(),
                backend_path,
            },
            Ok(None) => MemBackend {
                backend_type: "File".into(),
                backend_path: SNAPSHOT_MEM_FILE.into(),
            },
            Err(err) => {
                let _ = vm.process.kill().await;
                return Err(err);
            }
        };
        let req = LoadSnapshot {
            snapshot_path: SNAPSHOT_FILE.into(),
            mem_backend,
            enable_diff_snapshots: vm.spec.track_dirty_pages,
            resume_vm: resume,
            // Point the snapshotted interface at this sandbox's own tap.
            network_overrides: vm
                .spec
                .net
                .as_ref()
                .map(|net| {
                    vec![NetworkOverride {
                        iface_id: "eth0".into(),
                        host_dev_name: net.tap.clone(),
                    }]
                })
                .unwrap_or_default(),
        };
        if let Err(err) = vm.api.load_snapshot(&req).await {
            let _ = vm.process.kill().await;
            return Err(err);
        }
        vm.boot_latency = start.elapsed();
        tracing::info!(
            vm_id = vm.spec.vm_id,
            latency_ms = vm.boot_latency.as_millis() as u64,
            lazy_memory = vm.lazy_memory_active(),
            "microvm restored from snapshot"
        );
        Ok(vm)
    }

    /// Brings up this VM's page-fault handler, returning the path firecracker
    /// should be pointed at.
    #[cfg(target_os = "linux")]
    fn start_lazy_memory(&mut self) -> Result<Option<String>> {
        let chained = self.spec.memory_chain.len() > 1;
        // A prefetch plan can only be served by the handler, so asking for one
        // is asking for lazy memory.
        let prefetching = self.spec.prefetch.is_some() || self.spec.record_prefetch.is_some();
        if !self.spec.lazy_memory && !chained && !prefetching {
            return Ok(None);
        }
        let chain: Vec<PathBuf> = if self.spec.memory_chain.is_empty() {
            vec![self.spec.workdir.join(SNAPSHOT_MEM_FILE)]
        } else {
            self.spec
                .memory_chain
                .iter()
                .map(|name| self.spec.workdir.join(name))
                .collect()
        };
        let backend = UffdBackend::start(
            &self.spec.workdir,
            &uffd::MemoryPlan {
                chain,
                owner: self.spec.jail.as_ref().map(|jail| (jail.uid, jail.gid)),
                prefetch: self
                    .spec
                    .prefetch
                    .as_ref()
                    .map(|name| self.spec.workdir.join(name)),
                record_to: self
                    .spec
                    .record_prefetch
                    .as_ref()
                    .map(|name| self.spec.workdir.join(name)),
            },
        )?;
        self.memory = Some(backend);
        Ok(Some(UffdBackend::backend_path().to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    fn start_lazy_memory(&mut self) -> Result<Option<String>> {
        Ok(None)
    }

    /// Whether this VM's memory is being served lazily.
    pub fn lazy_memory_active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.memory.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    pub async fn kill(mut self) -> Result<()> {
        let result = self.process.kill().await;
        // Strictly after the VMM is reaped: stopping the handler while a guest
        // is still running would stall it on its next fault rather than fail.
        #[cfg(target_os = "linux")]
        drop(self.memory.take());
        // Only removable once it holds no processes, so this must follow the
        // reap rather than accompany it.
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.remove();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A warm-created sandbox shares its snapshot files with the template by
    /// hard link. Writing a new snapshot through that link would publish the
    /// sandbox's memory as the template, so the link must be broken first.
    #[tokio::test]
    async fn snapshot_targets_are_detached_from_the_template() {
        let dir = std::env::temp_dir().join(format!("burrow-detach-{}", std::process::id()));
        let template = dir.join("template");
        tokio::fs::create_dir_all(&template).await.unwrap();

        let warm_mem = template.join("warm.mem");
        tokio::fs::write(&warm_mem, b"pristine template memory")
            .await
            .unwrap();
        tokio::fs::hard_link(&warm_mem, dir.join(SNAPSHOT_MEM_FILE))
            .await
            .unwrap();
        tokio::fs::write(dir.join(SNAPSHOT_FILE), b"state")
            .await
            .unwrap();

        detach_snapshot_targets(&dir, SNAPSHOT_MEM_FILE)
            .await
            .unwrap();

        // Firecracker now creates its own files; the template is untouched.
        assert!(
            !tokio::fs::try_exists(dir.join(SNAPSHOT_MEM_FILE))
                .await
                .unwrap()
        );
        assert!(
            !tokio::fs::try_exists(dir.join(SNAPSHOT_FILE))
                .await
                .unwrap()
        );
        assert_eq!(
            tokio::fs::read(&warm_mem).await.unwrap(),
            b"pristine template memory"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn detaching_a_workdir_with_no_snapshot_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("burrow-detach-empty-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        detach_snapshot_targets(&dir, SNAPSHOT_MEM_FILE)
            .await
            .unwrap();
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    /// A diff is layered over the memory file it was taken against, so that
    /// base must survive being written alongside.
    #[tokio::test]
    async fn writing_a_diff_leaves_the_base_it_layers_over() {
        let dir = std::env::temp_dir().join(format!("burrow-diff-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();

        tokio::fs::write(dir.join(SNAPSHOT_MEM_FILE), b"base memory")
            .await
            .unwrap();
        tokio::fs::write(dir.join(SNAPSHOT_FILE), b"state")
            .await
            .unwrap();
        tokio::fs::write(dir.join("snapshot.diff1.mem"), b"old diff")
            .await
            .unwrap();

        detach_snapshot_targets(&dir, "snapshot.diff1.mem")
            .await
            .unwrap();

        assert_eq!(
            tokio::fs::read(dir.join(SNAPSHOT_MEM_FILE)).await.unwrap(),
            b"base memory",
            "the base a diff layers over must not be removed"
        );
        // The vmstate is always rewritten, and the diff target is cleared.
        assert!(
            !tokio::fs::try_exists(dir.join(SNAPSHOT_FILE))
                .await
                .unwrap()
        );
        assert!(
            !tokio::fs::try_exists(dir.join("snapshot.diff1.mem"))
                .await
                .unwrap()
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
