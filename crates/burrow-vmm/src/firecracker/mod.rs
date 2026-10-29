//! Firecracker microVM supervision: spawn the VMM, configure it over its API
//! socket, boot it, and drive pause/resume/snapshot.

mod api;
mod model;
mod process;
#[cfg(target_os = "linux")]
pub mod uffd;
#[cfg(target_os = "linux")]
pub use uffd::data_extents;
pub mod vsock;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use api::FcApi;
pub use model::{InstanceInfo, NetworkOverride, SnapshotType, VmState};
pub use process::{FcProcess, Jail};
#[cfg(target_os = "linux")]
pub use uffd::{UffdBackend, merge_chain};

use crate::cgroup::{Cgroup, Limits};
use crate::error::Result;
use crate::{DriveSpec, NetSpec, VmSpec};
use model::*;

/// How this node runs Firecracker.
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub bin: PathBuf,
    /// Confines each VMM to a chroot under an unprivileged uid. `None` runs it
    /// as root with the whole host visible.
    pub jail: Option<Jail>,
}

/// The neutral spec, as Firecracker is configured from it. Firecracker boots
/// only a kernel.
pub(crate) fn spec(spec: VmSpec, config: FirecrackerConfig) -> crate::Result<MicroVmSpec> {
    let crate::Boot::Kernel { kernel, cmdline } = spec.boot else {
        return Err(crate::Error::Unsupported {
            hypervisor: crate::Hypervisor::Firecracker,
            what: "boot anything but a kernel",
        });
    };
    Ok(MicroVmSpec {
        vm_id: spec.vm_id,
        workdir: spec.workdir,
        firecracker_bin: config.bin,
        kernel,
        boot_args: cmdline,
        drives: spec.drives,
        is_pci_enabled: spec.is_pci_enabled,
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        net: spec.net,
        is_vsock_enabled: spec.is_vsock_enabled,
        is_dirty_pages_tracked: spec.is_dirty_pages_tracked,
        jail: config.jail,
        is_memory_lazy: spec.is_memory_lazy,
        memory_chain: spec.memory_chain,
        prefetch: spec.prefetch,
        record_prefetch: spec.record_prefetch,
        memory_source: spec.memory_source,
        limits: spec.limits,
        cgroup_root: spec.cgroup_root,
        is_limits_required: spec.is_limits_required,
    })
}

/// A memory file that is still being filled in while a guest runs from it.
///
/// The page-fault handler maps the file as usual, but a page may not have
/// arrived yet, so before serving one it asks the source to make it present.
/// Which ranges hold data comes from the source as well: a file being written
/// out of order has holes that are not yet data, and `SEEK_DATA` cannot tell
/// those apart from the guest's own zero pages.
pub trait PageSource: Send + Sync {
    /// Byte ranges of the finished file that hold data, sorted.
    fn extents(&self) -> Vec<(u64, u64)>;
    /// Blocks until `[offset, offset + len)` of the file holds its contents.
    fn ensure(&self, offset: u64, len: u64) -> std::io::Result<()>;
    /// Makes many pages present at once, before the guest runs. Fetching them
    /// one fault at a time would pay a round trip per page.
    fn ensure_all(&self, offsets: &[u64], page_size: u64) -> std::io::Result<()> {
        offsets
            .iter()
            .try_for_each(|&offset| self.ensure(offset, page_size))
    }
}

/// The source of a restore's base memory file, when it is still arriving.
#[derive(Clone)]
pub struct MemorySource(pub std::sync::Arc<dyn PageSource>);

impl std::fmt::Debug for MemorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemorySource")
    }
}

/// Conventional filenames inside a VM's working directory. Keeping these
/// identical for every sandbox is what makes snapshot restore portable across
/// sandboxes on a node.
pub const API_SOCK: &str = "fc.sock";
pub use crate::guest::VSOCK_UDS;
pub const SNAPSHOT_FILE: &str = "snapshot.vmstate";
pub const SNAPSHOT_MEM_FILE: &str = "snapshot.mem";

pub use crate::guest::GUEST_CID;

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
    pub is_pci_enabled: bool,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub net: Option<NetSpec>,
    /// Enable virtio-vsock, the transport the guest agent speaks.
    pub is_vsock_enabled: bool,
    /// Needed for diff snapshots.
    pub is_dirty_pages_tracked: bool,
    /// Confines firecracker to a chroot under an unprivileged uid. `None`
    /// runs it as root with the host filesystem visible.
    pub jail: Option<process::Jail>,
    /// Serve guest memory lazily on restore instead of letting the kernel page
    /// the whole memory file in. Ignored on a cold boot, which has no memory
    /// file to serve from.
    pub is_memory_lazy: bool,
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
    /// Where the base of `memory_chain` is still being filled in from. Forces
    /// the page-fault handler on, since the kernel would map the holes as
    /// zeroes.
    pub memory_source: Option<MemorySource>,
    /// Host resource caps. Applied to the VMM process, so they bound the guest
    /// and Firecracker's own overhead together.
    pub limits: Limits,
    /// cgroup2 mount point; `None` disables limit enforcement.
    pub cgroup_root: Option<PathBuf>,
    /// Whether a sandbox may run when its limits could not be applied. False
    /// keeps the stack usable where cgroups are unavailable, at the cost of
    /// unbounded CPU; true refuses to run an unbounded guest at all.
    pub is_limits_required: bool,
}

impl MicroVmSpec {
    pub fn new(vm_id: impl Into<String>, workdir: impl Into<PathBuf>) -> Self {
        Self {
            vm_id: vm_id.into(),
            workdir: workdir.into(),
            firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
            kernel: "vmlinux".into(),
            boot_args: crate::DEFAULT_BOOT_ARGS.into(),
            drives: Vec::new(),
            is_pci_enabled: false,
            vcpus: 1,
            mem_mib: 512,
            net: None,
            is_vsock_enabled: false,
            is_dirty_pages_tracked: false,
            prefetch: None,
            record_prefetch: None,
            memory_source: None,
            jail: None,
            is_memory_lazy: false,
            memory_chain: Vec::new(),
            limits: Limits::default(),
            cgroup_root: Some(PathBuf::from("/sys/fs/cgroup")),
            is_limits_required: false,
        }
    }
}

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

/// Starts the VMM inside the VM's cgroup, made first so the VMM joins it
/// before it execs and never runs outside its caps.
async fn spawn(spec: &MicroVmSpec) -> Result<(FcProcess, Option<Cgroup>)> {
    let cgroup = Cgroup::for_vm(
        spec.cgroup_root.as_deref(),
        &spec.vm_id,
        &spec.limits,
        spec.is_limits_required,
    )?;
    let process = FcProcess::spawn(
        &spec.firecracker_bin,
        &spec.vm_id,
        &spec.workdir,
        API_SOCK,
        spec.jail.as_ref(),
        spec.is_pci_enabled,
        cgroup.as_ref(),
    )
    .await;
    match process {
        Ok(process) => Ok((process, cgroup)),
        Err(err) => {
            if let Some(cgroup) = cgroup {
                cgroup.remove();
            }
            Err(err)
        }
    }
}

impl MicroVm {
    /// Spawns the VMM, applies the configuration, and starts the instance.
    pub async fn boot(spec: MicroVmSpec) -> Result<Self> {
        let start = Instant::now();
        if spec.is_vsock_enabled {
            crate::guest::clear_stale_sockets(&spec.workdir).await?;
        }
        let (process, cgroup) = spawn(&spec).await?;
        let api = FcApi::new(spec.workdir.join(API_SOCK));

        // Configure, then start. Any failure here kills the VMM so we never
        // leak a half-configured firecracker process.
        let mut vm = Self {
            process,
            api,
            spec,
            boot_latency: Duration::ZERO,
            cgroup,
            #[cfg(target_os = "linux")]
            memory: None,
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
                is_dirty_pages_tracked: self.spec.is_dirty_pages_tracked,
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
                    is_read_only: drive.is_read_only,
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

        if self.spec.is_vsock_enabled {
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
        crate::GuestAddr::in_workdir(&self.spec.workdir)
            .wait(port, timeout)
            .await
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
    /// Only possible with `is_pci_enabled`, and the guest sees nothing until it
    /// rescans its PCI bus: firecracker has no way to notify it. This is how a
    /// volume reaches a sandbox restored from a warm snapshot, which was
    /// captured without it.
    pub async fn attach_drive(&self, drive: &DriveSpec) -> Result<()> {
        self.api
            .add_drive(&Drive {
                drive_id: drive.id.clone(),
                path_on_host: drive.path.clone(),
                is_root_device: drive.is_root,
                is_read_only: drive.is_read_only,
            })
            .await
    }

    /// Starts a fresh VMM process and restores a snapshot from `workdir`
    /// instead of cold-booting. `spec` must describe the same resources
    /// (tap name, drive paths) as the snapshotted VM.
    pub async fn restore(spec: MicroVmSpec, resume: bool) -> Result<Self> {
        let start = Instant::now();
        if spec.is_vsock_enabled {
            crate::guest::clear_stale_sockets(&spec.workdir).await?;
        }
        let (process, cgroup) = spawn(&spec).await?;
        let api = FcApi::new(spec.workdir.join(API_SOCK));

        let mut vm = Self {
            process,
            api,
            spec,
            boot_latency: Duration::ZERO,
            cgroup,
            #[cfg(target_os = "linux")]
            memory: None,
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
            is_diff_snapshots_enabled: vm.spec.is_dirty_pages_tracked,
            is_vm_resumed: resume,
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
            lazy_memory = vm.is_lazy_memory_active(),
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
        if !self.spec.is_memory_lazy
            && !chained
            && !prefetching
            && self.spec.memory_source.is_none()
        {
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
                base_source: self.spec.memory_source.as_ref().map(|s| s.0.clone()),
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
    pub fn is_lazy_memory_active(&self) -> bool {
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
