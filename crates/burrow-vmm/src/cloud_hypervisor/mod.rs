//! Cloud Hypervisor as a [`crate::Vm`] backend.
//!
//! Driven the way Firecracker is: the VMM is started with only its API
//! socket, the machine is created and booted over the REST API, and pause,
//! resume, snapshot and hotplug are API calls too. The machine is the same one
//! Firecracker builds from a template (its kernel, its ext4 rootfs, virtio-blk
//! disks in the same order, the sandbox's own tap, hybrid vsock behind the same
//! socket name), so a Linux template boots under either backend unchanged.
//!
//! A snapshot is Cloud Hypervisor's own (`config.json`, `state.json` and
//! `memory-ranges`), packed into the two files of its [`crate::Layout`]: the
//! config and device state together as the state half, guest memory as the
//! other. A restore unpacks them into a directory of their own, points the
//! config at this sandbox's tap and starts a fresh VMM with `--restore`, which
//! copies guest memory in from the memory file.
//!
//! With a [`ChJail`] the VMM runs confined, as [`jail`] describes: it is
//! handed its tap as a descriptor rather than opening it by name, and a
//! jailed restore goes through the API for the same reason.

mod config;
pub mod jail;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::cgroup::Cgroup;
use crate::error::{Error, Result};
use crate::http::UnixHttp;
use crate::machine::Machine;
use crate::process::{Output, VmmProcess};
use crate::{DriveSpec, GuestOs, MachineSpec, VSOCK_UDS};

pub use jail::ChJail;

/// The VM's config and device state, as one JSON document.
pub const STATE_FILE: &str = "snapshot.ch-state";
/// Guest memory, Cloud Hypervisor's `memory-ranges` under the layout's name.
pub const MEMORY_FILE: &str = "snapshot.ch-memory";
const API_SOCK: &str = "ch.sock";
/// What the VMM writes the guest's console to: a FIFO the node copies into
/// the bounded console log.
const CONSOLE_PIPE: &str = "console.pipe";
/// Where an interactive console listens, in the working directory.
const CONSOLE_SOCK: &str = "console.sock";
/// The VMM's own log. Kept apart from the console, which the VMM opens and
/// writes itself.
const VMM_LOG: &str = "vmm.log";
/// Where a snapshot is written, and where one is unpacked to restore from.
/// Both are emptied before use and removed after.
const SNAPSHOT_DIR: &str = "snapshot.ch";
const RESTORE_DIR: &str = "restore.ch";

/// How long the VMM gets to open its API socket.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(2);
/// How long a `--restore` gets to load the VM's state: device state and a
/// copy of guest memory, about a second for 512 MiB.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(30);
/// Reads guest memory into anonymous RAM rather than mapping the memory file
/// copy-on-write. Mapped, every page the guest has not written since the
/// restore is reclaimable page cache of the snapshot file, and a guest doing a
/// few hundred MiB of I/O after a resume ended up reading corrupt memory: a
/// soft lockup in the slab allocator freeing a vsock buffer, the agent gone,
/// the guest spinning. Copied, guest memory is never reclaimed under it.
const MEMORY_RESTORE_MODE: &str = "copy";
/// The same, as the API's `vm.restore` spells it.
#[cfg(target_os = "linux")]
const MEMORY_RESTORE_MODE_API: &str = "Copy";
/// The host port Cloud Hypervisor gives the first host-initiated vsock
/// connection, and the next one each after it. A fresh VMM starts here again.
const FIRST_HOST_PORT: u32 = 1 << 30;

/// Cloud Hypervisor's edk2 build, where the node image installs it.
pub const DEFAULT_FIRMWARE: &str = "/usr/local/share/cloud-hypervisor/CLOUDHV_EFI.fd";

/// How this node runs Cloud Hypervisor.
#[derive(Debug, Clone)]
pub struct CloudHypervisorConfig {
    pub bin: PathBuf,
    /// The edk2 build a guest without a kernel boots, Windows included.
    pub firmware: PathBuf,
    /// Confines the VMM. `None` runs it as the daemon runs, root with the
    /// host's filesystem in view.
    pub jail: Option<ChJail>,
}

/// What a snapshot's state half holds.
#[derive(Serialize, Deserialize)]
struct Packed {
    config: Value,
    state: Value,
    /// The highest host port the VMM had handed out, or 0 if none was seen.
    last_host_port: u32,
}

/// A running (or paused) Cloud Hypervisor VM.
pub struct ChVm {
    process: VmmProcess,
    api: UnixHttp,
    workdir: PathBuf,
    /// [`Self::workdir`] as the VMM sees it.
    vmm_workdir: PathBuf,
    jail: Option<ChJail>,
    /// What [`config::disk`] opens a hotplugged drive for.
    guest_os: GuestOs,
    boot_latency: Duration,
    /// The input side of an interactive console.
    console_in: Option<tokio::net::unix::OwnedWriteHalf>,
    /// Copies the console into its log, until the VM is stopped.
    console: Option<crate::console::Capture>,
    /// The guest's TPM emulator, stopped with the VMM.
    tpm: Option<crate::TpmSpec>,
    /// The memory the guest booted with, in bytes, which the hotplug region
    /// sits above.
    boot_mem: u64,
}

impl Drop for ChVm {
    fn drop(&mut self) {
        if let Some(console) = &self.console {
            console.abort();
        }
        crate::vsock::untrack_ports(&self.workdir.join(VSOCK_UDS));
    }
}

impl ChVm {
    pub(crate) async fn boot(spec: MachineSpec, config: CloudHypervisorConfig) -> Result<Self> {
        let started = Instant::now();
        let mut vm_config = config::vm_config(&spec, &config, std::env::consts::ARCH)?;
        // A jailed VMM cannot open a tap, so its NICs are added once it
        // exists, each with the tap opened here.
        let nics = match &config.jail {
            Some(_) => {
                jail::set_landlock(&mut vm_config, true);
                vm_config
                    .as_object_mut()
                    .and_then(|vm| vm.remove("net"))
                    .and_then(|nics| nics.as_array().cloned())
                    .unwrap_or_default()
            }
            None => Vec::new(),
        };
        let read_only = jail::absolute_paths(&vm_config);
        if let Some(tpm) = &spec.devices.tpm {
            crate::swtpm::start(tpm, true).await?;
        }
        let spawned = Self::spawn(&spec, &config, &[], read_only).await;
        let mut vm = without_tpm_on_error(&spec, spawned).await?;
        let booted = async {
            vm.api.put("/api/v1/vm.create", &vm_config).await?;
            for nic in nics {
                vm.add_net(nic).await?;
            }
            vm.api.put_empty("/api/v1/vm.boot").await?;
            if spec.devices.console == crate::ConsoleSpec::Interactive {
                vm.attach_console().await?;
            }
            Ok(())
        }
        .await;
        if let Err(err) = booted {
            vm.stop().await;
            return Err(vm.explain(err).await);
        }
        vm.boot_latency = started.elapsed();
        tracing::info!(
            vm_id = spec.vm_id,
            pid = vm.pid(),
            latency_ms = vm.boot_latency.as_millis() as u64,
            "cloud hypervisor vm started"
        );
        Ok(vm)
    }

    pub(crate) async fn restore(
        spec: MachineSpec,
        config: CloudHypervisorConfig,
        resume: bool,
    ) -> Result<Self> {
        let started = Instant::now();
        let (restore_dir, vm_config, last_host_port) = unpack(&spec, config.jail.as_ref()).await?;
        let read_only = jail::absolute_paths(&vm_config);
        if let Some(tpm) = &spec.devices.tpm {
            crate::swtpm::start(tpm, false).await?;
        }
        let source = jail::vmm_workdir(&spec.workdir, config.jail.as_ref())?.join(RESTORE_DIR);
        let source_url = format!("file://{}", source.display());
        let spawned = match &config.jail {
            Some(_) => Self::spawn(&spec, &config, &[], read_only).await,
            None => {
                let source =
                    format!("source_url={source_url},memory_restore_mode={MEMORY_RESTORE_MODE}");
                Self::spawn(&spec, &config, &["--restore", &source], read_only).await
            }
        };
        let mut vm = without_tpm_on_error(&spec, spawned).await?;
        let loaded = async {
            if config.jail.is_some() {
                vm.restore_jailed(&source_url, &vm_config).await?;
            }
            vm.wait_until_loaded().await?;
            if spec.devices.console == crate::ConsoleSpec::Interactive {
                vm.attach_console().await?;
            }
            if resume {
                vm.resume().await?;
                crate::vsock::skip_stale_ports(
                    &spec.workdir.join(VSOCK_UDS),
                    FIRST_HOST_PORT,
                    last_host_port,
                )
                .await;
            }
            Ok::<_, Error>(())
        }
        .await;
        // Memory, config and state were all read in at startup, so nothing
        // here is needed any longer.
        let _ = tokio::fs::remove_dir_all(&restore_dir).await;
        if let Err(err) = loaded {
            vm.stop().await;
            return Err(vm.explain(err).await);
        }
        vm.boot_latency = started.elapsed();
        tracing::info!(
            vm_id = spec.vm_id,
            latency_ms = vm.boot_latency.as_millis() as u64,
            "cloud hypervisor vm restored from snapshot"
        );
        Ok(vm)
    }

    /// Starts the VMM with its API socket, inside the VM's cgroup from
    /// before it execs: the cgroup is made first and the child cloned into it,
    /// so the VMM (jailed, its helper, and the VMM that inherits it) never
    /// runs outside its caps. `read_only` are the host files the VM config names
    /// absolutely, which a jail has to bind in.
    async fn spawn(
        spec: &MachineSpec,
        config: &CloudHypervisorConfig,
        extra: &[&str],
        read_only: Vec<PathBuf>,
    ) -> Result<Self> {
        if !config.bin.exists() {
            return Err(Error::BinaryNotFound(config.bin.clone()));
        }
        tokio::fs::create_dir_all(&spec.workdir).await?;
        crate::guest::clear_stale_sockets(&spec.workdir).await?;
        remove_if_present(&spec.workdir.join(CONSOLE_SOCK)).await?;
        let console = capture_console(&spec.workdir, config.jail.as_ref()).await?;
        let socket = spec.workdir.join(API_SOCK);
        remove_if_present(&socket).await?;
        crate::vsock::track_ports(&spec.workdir.join(VSOCK_UDS), 0);

        let api_socket = format!("path={API_SOCK}");
        let vmm_args: Vec<String> = ["--api-socket", &api_socket]
            .iter()
            .chain(extra)
            .map(|arg| arg.to_string())
            .collect();
        let (program, args): (&Path, Vec<std::ffi::OsString>) = match &config.jail {
            None => (&config.bin, vmm_args.into_iter().map(Into::into).collect()),
            Some(jail) => (
                &jail.helper,
                jail::Plan {
                    workdir: std::path::absolute(&spec.workdir)?,
                    uid: jail.uid,
                    gid: jail.gid,
                    read_only,
                    program: config.bin.clone(),
                    args: vmm_args,
                }
                .helper_args(),
            ),
        };
        let cgroup = Cgroup::for_vm(
            spec.cgroup_root.as_deref(),
            &spec.vm_id,
            &spec.limits,
            spec.is_limits_required,
        )?;
        let log = spec.workdir.join(VMM_LOG);
        let spawned = crate::child::spawn_logged(
            program,
            &args,
            &spec.workdir,
            cgroup.as_ref().map(Cgroup::path),
            &log,
        )
        .await;
        let mut vm = Self {
            api: UnixHttp::new(socket.clone()),
            process: VmmProcess::new(spawned?, Output::Log(log), cgroup),
            workdir: spec.workdir.clone(),
            vmm_workdir: jail::vmm_workdir(&spec.workdir, config.jail.as_ref())?,
            jail: config.jail.clone(),
            guest_os: spec.guest_os,
            boot_latency: Duration::ZERO,
            console_in: None,
            console,
            tpm: spec.devices.tpm.clone(),
            boot_mem: u64::from(spec.memory.mib) * 1024 * 1024,
        };
        if let Err(err) = vm.process.wait_for_socket(&socket).await {
            vm.stop().await;
            return Err(err);
        }
        Ok(vm)
    }

    /// Kills the VMM and reaps it. A jailed one is asked through its helper,
    /// which kills and reaps the VMM before exiting itself: killing the
    /// helper outright would leave the VMM to be reaped by whatever adopts
    /// orphans, which in a container is burrowd, and it never would.
    async fn stop(&mut self) {
        if let Some(console) = &self.console {
            console.abort();
        }
        match (&self.jail, self.process.pid()) {
            (Some(_), Some(pid)) => {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGTERM,
                );
                let _ = self.process.wait().await;
            }
            _ => {
                let _ = self.process.kill().await;
            }
        }
        if let Some(tpm) = &self.tpm {
            crate::swtpm::stop(tpm, true).await;
        }
    }

    /// Adds a NIC to a VM that exists but has not booted, handing over its
    /// tap already open.
    #[cfg(target_os = "linux")]
    async fn add_net(&self, mut nic: Value) -> Result<()> {
        use std::os::fd::AsRawFd as _;
        let tap = nic
            .as_object_mut()
            .and_then(|nic| nic.remove("tap"))
            .and_then(|tap| tap.as_str().map(str::to_string))
            .unwrap_or_default();
        let fd = jail::open_tap(&tap)?;
        self.api
            .put_with_fds("/api/v1/vm.add-net", &nic, &[fd.as_raw_fd()])
            .await
    }

    /// Restores into a VMM started without `--restore`, handing it the taps
    /// the unpacked config's NICs name.
    #[cfg(target_os = "linux")]
    async fn restore_jailed(&self, source_url: &str, vm_config: &Value) -> Result<()> {
        use std::os::fd::AsRawFd as _;
        let nics: Vec<(String, std::os::fd::OwnedFd)> = taps(vm_config)
            .into_iter()
            .map(|(id, tap)| jail::open_tap(&tap).map(|fd| (id, fd)))
            .collect::<std::io::Result<_>>()?;
        let body = json!({
            "source_url": source_url,
            "memory_restore_mode": MEMORY_RESTORE_MODE_API,
            "net_fds": nics
                .iter()
                .map(|(id, _)| json!({ "id": id, "num_fds": 1 }))
                .collect::<Vec<_>>(),
        });
        let fds: Vec<_> = nics.iter().map(|(_, fd)| fd.as_raw_fd()).collect();
        self.api
            .put_with_fds("/api/v1/vm.restore", &body, &fds)
            .await
    }

    #[cfg(not(target_os = "linux"))]
    async fn add_net(&self, _nic: Value) -> Result<()> {
        Err(Error::Unsupported {
            hypervisor: crate::Hypervisor::CloudHypervisor,
            what: "run jailed off Linux",
        })
    }

    #[cfg(not(target_os = "linux"))]
    async fn restore_jailed(&self, _source_url: &str, _vm_config: &Value) -> Result<()> {
        self.add_net(Value::Null).await
    }

    /// Waits for a `--restore` to finish loading. The API answers once the
    /// VMM is up, and reports the VM paused once its state is in.
    async fn wait_until_loaded(&mut self) -> Result<()> {
        wait_until_loaded(&mut self.process, &self.api, RESTORE_TIMEOUT).await
    }

    /// An API failure with what the VMM logged about it, which is where Cloud
    /// Hypervisor says why.
    async fn explain(&self, err: Error) -> Error {
        match err {
            Error::Api {
                method,
                path,
                status,
                body,
            } => Error::Api {
                method,
                path,
                status,
                body: format!("{body}\n{}", self.process.output_tail(10).await),
            },
            err => err,
        }
    }

    /// Connects to an interactive console once the VMM listens on it, and
    /// copies what the guest writes there to the console log.
    async fn attach_console(&mut self) -> Result<()> {
        let path = self.workdir.join(CONSOLE_SOCK);
        let deadline = Instant::now() + SOCKET_TIMEOUT;
        let stream = loop {
            match tokio::net::UnixStream::connect(&path).await {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => tokio::time::sleep(POLL).await,
                Err(err) => return Err(err.into()),
            }
        };
        let (output, input) = stream.into_split();
        if let Some(console) = self.console.take() {
            console.abort();
        }
        self.console = Some(crate::console::capture(&self.workdir, vec![output])?);
        self.console_in = Some(input);
        Ok(())
    }
}

impl Machine for ChVm {
    fn hypervisor(&self) -> crate::Hypervisor {
        crate::Hypervisor::CloudHypervisor
    }

    fn workdir(&self) -> &Path {
        &self.workdir
    }

    fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    async fn pause(&self) -> Result<()> {
        self.api.put_empty("/api/v1/vm.pause").await
    }

    async fn resume(&self) -> Result<()> {
        self.api.put_empty("/api/v1/vm.resume").await
    }

    /// Snapshots the **paused** VM into its layout.
    ///
    /// Both files are replaced by rename rather than written in place, so a
    /// sandbox restored from a warm snapshot, which holds them as hard links
    /// to the template's, never writes through a link (see
    /// [`crate::snapfile`]).
    async fn snapshot(&self) -> Result<()> {
        let dir = self.workdir.join(SNAPSHOT_DIR);
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await?;
        if let Some(jail) = &self.jail {
            std::os::unix::fs::chown(&dir, Some(jail.uid), Some(jail.gid))?;
        }
        let destination = self.vmm_workdir.join(SNAPSHOT_DIR);
        self.api
            .put(
                "/api/v1/vm.snapshot",
                &json!({ "destination_url": format!("file://{}", destination.display()) }),
            )
            .await?;
        let packed = Packed {
            config: serde_json::from_slice(&tokio::fs::read(dir.join("config.json")).await?)?,
            state: serde_json::from_slice(&tokio::fs::read(dir.join("state.json")).await?)?,
            last_host_port: crate::vsock::highest_port(&self.workdir.join(VSOCK_UDS)),
        };
        let state = dir.join(STATE_FILE);
        tokio::fs::write(&state, serde_json::to_vec(&packed)?).await?;
        tokio::fs::rename(&state, self.workdir.join(STATE_FILE)).await?;
        tokio::fs::rename(dir.join("memory-ranges"), self.workdir.join(MEMORY_FILE)).await?;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        Ok(())
    }

    async fn kill(mut self) -> Result<()> {
        self.stop().await;
        let _ = tokio::fs::remove_file(self.workdir.join(API_SOCK)).await;
        // Only removable once it holds no processes, so this follows the reap.
        self.process.release_cgroup();
        Ok(())
    }

    async fn console_tail(&self, lines: usize) -> String {
        crate::console::tail(&self.workdir, lines).await
    }

    async fn console_write(&mut self, input: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let console = self.console_in.as_mut().ok_or(Error::ConsoleUnavailable)?;
        Ok(console.write_all(input.as_bytes()).await?)
    }

    /// Attaches a drive to the running guest, which sees it once it rescans
    /// its PCI bus.
    async fn attach_drive(&self, drive: &DriveSpec) -> Result<()> {
        self.api
            .call(
                Method::PUT,
                "/api/v1/vm.add-disk",
                Some(&config::disk(drive, self.guest_os)),
            )
            .await
            .map(|_| ())
    }

    /// Resizes a disk under the running guest, which Cloud Hypervisor tells
    /// it of with a config change.
    async fn resize_disk(&self, id: &str, bytes: u64) -> Result<()> {
        self.api
            .put(
                "/api/v1/vm.resize-disk",
                &json!({ "id": id, "desired_size": bytes }),
            )
            .await
    }

    /// Hotplugs or unplugs vCPUs.
    async fn resize_vcpus(&self, vcpus: u32) -> Result<()> {
        self.api
            .put("/api/v1/vm.resize", &json!({ "desired_vcpus": vcpus }))
            .await
    }

    /// Sets the guest's memory to its boot memory plus `plugged_mib`, which
    /// its virtio-mem driver then works towards; an ACPI hotplug adds it at
    /// once.
    async fn request_memory(&self, plugged_mib: u32) -> Result<()> {
        self.api
            .put(
                "/api/v1/vm.resize",
                &json!({ "desired_ram": self.boot_mem + u64::from(plugged_mib) * 1024 * 1024 }),
            )
            .await
    }

    /// `memory_actual_size` counts what the virtio-mem device has plugged,
    /// not what it was asked for. An ACPI hotplug moves the recorded memory
    /// size itself, which it counts.
    async fn plugged_memory(&self) -> Result<u32> {
        let info: Value = self.api.get_json("/api/v1/vm.info").await?;
        let actual = info["memory_actual_size"].as_u64().unwrap_or(self.boot_mem);
        Ok((actual.saturating_sub(self.boot_mem) / (1024 * 1024)) as u32)
    }

    fn process(&self) -> Option<&VmmProcess> {
        Some(&self.process)
    }

    fn process_mut(&mut self) -> Option<&mut VmmProcess> {
        Some(&mut self.process)
    }
}

/// Stops the TPM emulator started for a VMM that did not start, and moves
/// it into the cgroup of one that did.
async fn without_tpm_on_error(spec: &MachineSpec, spawned: Result<ChVm>) -> Result<ChVm> {
    let Some(tpm) = &spec.devices.tpm else {
        return spawned;
    };
    match &spawned {
        Err(_) => crate::swtpm::stop(tpm, false).await,
        Ok(vm) => {
            if let (Some(cgroup), Some(pid)) = (vm.process.cgroup(), crate::swtpm::pid(tpm))
                && let Err(err) = cgroup.add(pid)
            {
                tracing::warn!(%err, pid, "could not move swtpm into the VM's cgroup");
            }
        }
    }
    spawned
}

/// Lays a packed snapshot out the way a restore reads one, addressed to this
/// sandbox, and returns the directory, the config as written there and the
/// highest host port the snapshotted VMM used, open or not.
///
/// Landlock follows this VMM rather than the one snapshotted: its rules name
/// the jail's paths, which a VMM run unjailed does not have.
async fn unpack(spec: &MachineSpec, jail: Option<&ChJail>) -> Result<(PathBuf, Value, u32)> {
    let packed: Packed =
        serde_json::from_slice(&tokio::fs::read(spec.workdir.join(STATE_FILE)).await?)?;
    let last_host_port = last_host_port(&packed);
    let mut state = packed.state;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    restamp_clock(&mut state, now.map_or(0, |now| now.as_nanos() as u64));
    let mut vm_config = packed.config;
    config::retarget(&mut vm_config, spec)?;
    jail::set_landlock(&mut vm_config, jail.is_some());
    let mut written = vm_config.clone();
    jail::address_nics(&mut written, jail.is_some());
    let dir = spec.workdir.join(RESTORE_DIR);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::write(dir.join("config.json"), serde_json::to_vec(&written)?).await?;
    tokio::fs::write(dir.join("state.json"), serde_json::to_vec(&state)?).await?;
    // Linked: the VMM only reads it, so every sandbox of a warm template
    // restores from the one file.
    let memory = spec.workdir.join(MEMORY_FILE);
    tokio::fs::hard_link(&memory, dir.join("memory-ranges")).await?;
    // Cloud Hypervisor writes it 0600, so one written by a VMM running as
    // anyone else (an unjailed one, or the daemon staging it) is the jail
    // uid's to read only once it owns it. Every jailed VMM runs as that uid,
    // so this hands none of them anything another could not already open.
    if let Some(jail) = jail {
        std::os::unix::fs::chown(&memory, Some(jail.uid), Some(jail.gid))?;
    }
    Ok((dir, vm_config, last_host_port))
}

/// `KVM_CLOCK_REALTIME`, on the kvmclock an x86 snapshot saves.
const KVM_CLOCK_REALTIME: u32 = 1 << 2;

/// Stamps the guest clock a snapshot saved as taken at `now_ns`, so the guest
/// resumes with its clock where it stopped.
///
/// Cloud Hypervisor advances a restored guest's clock by the host wall time
/// since the snapshot: kvmclock through `KVM_CLOCK_REALTIME` on x86, the
/// virtual counter on aarch64. A warm snapshot restored hours after it was
/// built then jumps its guest's scheduler clock by hours under the running
/// task, and the EEVDF arithmetic of a 7.x guest kernel overflows on that
/// runtime and crashes in `pick_task_fair`. The handshake sets the wall clock.
fn restamp_clock(state: &mut Value, now_ns: u64) {
    let Some(text) = state["snapshot_data"]["state"].as_str() else {
        return;
    };
    let Ok(mut vm) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let Some(clock) = vm.get_mut("clock") else {
        return;
    };
    if let Some(bytes) = clock.get_mut("Kvm").and_then(Value::as_array_mut) {
        if bytes.len() < 24 {
            return;
        }
        let flags = (8..12).fold(0u32, |flags, i| {
            flags | ((bytes[i].as_u64().unwrap_or(0) as u32) << (8 * (i - 8)))
        });
        if flags & KVM_CLOCK_REALTIME == 0 {
            return;
        }
        for (byte, value) in bytes[16..24].iter_mut().zip(now_ns.to_le_bytes()) {
            *byte = value.into();
        }
    } else if let Some(stamp) = clock.get_mut("host_realtime_ns") {
        *stamp = now_ns.into();
    } else {
        return;
    }
    state["snapshot_data"]["state"] = vm.to_string().into();
}

/// The highest host port the snapshotted VMM was seen to hand out, or that a
/// connection still open in its state holds.
fn last_host_port(packed: &Packed) -> u32 {
    vsock_connections(&packed.state)
        .into_iter()
        .map(|(host, _)| host)
        .fold(packed.last_host_port, u32::max)
}

/// The (host port, guest port) of each vsock connection open when the state
/// was taken.
fn vsock_connections(state: &Value) -> Vec<(u32, u32)> {
    state["snapshots"]["device-manager"]["snapshots"]["vsock"]["snapshot_data"]["state"]
        .as_str()
        .and_then(|vsock| serde_json::from_str::<Value>(vsock).ok())
        .and_then(|vsock| serde_json::from_value(vsock["connections"].clone()).ok())
        .unwrap_or_default()
}

/// Each NIC's id and the tap it names.
#[cfg(target_os = "linux")]
fn taps(vm_config: &Value) -> Vec<(String, String)> {
    vm_config["net"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|nic| {
            Some((
                nic["id"].as_str()?.to_string(),
                nic["tap"].as_str()?.to_string(),
            ))
        })
        .collect()
}

/// Polls `vm.info` until the VM reports its state loaded, the VMM exits, or
/// `timeout` passes. A restore that stalls would otherwise hold the resume,
/// adopt, fork or warm create that asked for it forever; the caller kills the
/// VMM on any error.
async fn wait_until_loaded(
    process: &mut VmmProcess,
    api: &UnixHttp,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        process.check_running().await?;
        let last = match api.get_json::<Value>("/api/v1/vm.info").await {
            Ok(info) if matches!(info["state"].as_str(), Some("Paused" | "Running")) => {
                return Ok(());
            }
            Ok(info) => format!("the vm is {}", info["state"]),
            Err(err) => err.to_string(),
        };
        if Instant::now() >= deadline {
            return Err(Error::Timeout {
                what: format!("the restored vm to load (last vm.info: {last})"),
                timeout_ms: timeout.as_millis() as u64,
            });
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn remove_if_present(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}

/// Last `n` lines of a log, for diagnostics.
/// Makes the FIFO the VMM writes the guest's console to, owned by the jail
/// where there is one, and starts copying it into the console log. Opened for
/// writing too, so the copy does not end each time a VMM closes its end.
#[cfg(target_os = "linux")]
async fn capture_console(
    workdir: &Path,
    jail: Option<&ChJail>,
) -> Result<Option<crate::console::Capture>> {
    use std::os::unix::ffi::OsStrExt as _;
    let path = workdir.join(CONSOLE_PIPE);
    remove_if_present(&path).await?;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|err| Error::Io(std::io::Error::other(err)))?;
    // SAFETY: `name` is a valid NUL-terminated path.
    if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if let Some(jail) = jail {
        std::os::unix::fs::chown(&path, Some(jail.uid), Some(jail.gid))?;
    }
    let pipe = tokio::net::unix::pipe::OpenOptions::new()
        .read_write(true)
        .open_receiver(&path)?;
    Ok(Some(crate::console::capture(workdir, vec![pipe])?))
}

#[cfg(not(target_os = "linux"))]
async fn capture_console(
    _workdir: &Path,
    _jail: Option<&ChJail>,
) -> Result<Option<crate::console::Capture>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A guest restored over a copy-on-write mapping of its memory file read
    /// corrupt memory after a resume and heavy I/O. Both ways of restoring
    /// copy it in.
    #[test]
    fn a_restore_copies_guest_memory_in() {
        assert_eq!(MEMORY_RESTORE_MODE, "copy");
        #[cfg(target_os = "linux")]
        assert_eq!(MEMORY_RESTORE_MODE_API, "Copy");
    }

    #[test]
    fn the_connections_a_snapshot_held_are_read_from_its_vsock_state() {
        let vsock = json!({ "connections": [[FIRST_HOST_PORT, 1024]] }).to_string();
        let state = json!({ "snapshots": { "device-manager": { "snapshots": {
            "vsock": { "snapshot_data": { "state": vsock } }
        } } } });
        assert_eq!(vsock_connections(&state), [(FIRST_HOST_PORT, 1024)]);
        assert!(vsock_connections(&json!({})).is_empty());
    }

    fn vm_state(clock: Value) -> Value {
        let vm = json!({ "clock": clock, "common_cpuid": [] }).to_string();
        json!({ "snapshots": {}, "snapshot_data": { "state": vm } })
    }

    fn clock_of(state: &Value) -> Value {
        serde_json::from_str::<Value>(state["snapshot_data"]["state"].as_str().unwrap()).unwrap()
            ["clock"]
            .clone()
    }

    /// A kvmclock saved with the host's wall time is advanced by the wall time
    /// since on restore, which jumped a warm guest's clock by the hours since
    /// its snapshot was built. Its wall time becomes the restore's.
    #[test]
    fn a_restore_moves_the_saved_kvmclock_wall_time_to_now() {
        let mut saved = [0u8; 48];
        saved[..8].copy_from_slice(&5_000_000_000u64.to_le_bytes());
        saved[8..12].copy_from_slice(&(KVM_CLOCK_REALTIME | 1 << 3).to_le_bytes());
        saved[16..24].copy_from_slice(&1_000u64.to_le_bytes());
        let mut state = vm_state(json!({ "Kvm": saved.to_vec() }));
        let now = 1_795_165_474_106_746_855u64;
        restamp_clock(&mut state, now);
        let mut want = saved;
        want[16..24].copy_from_slice(&now.to_le_bytes());
        assert_eq!(clock_of(&state), json!({ "Kvm": want.to_vec() }));

        let mut unstamped = saved;
        unstamped[8..12].copy_from_slice(&0u32.to_le_bytes());
        let mut state = vm_state(json!({ "Kvm": unstamped.to_vec() }));
        restamp_clock(&mut state, now);
        assert_eq!(clock_of(&state), json!({ "Kvm": unstamped.to_vec() }));
    }

    #[test]
    fn a_restore_moves_the_saved_counter_wall_time_to_now() {
        let mut state = vm_state(json!({
            "cntvct": 123, "host_realtime_ns": 1_000, "cntfrq": 1_000_000_000
        }));
        restamp_clock(&mut state, 9_000);
        assert_eq!(
            clock_of(&state),
            json!({ "cntvct": 123, "host_realtime_ns": 9_000, "cntfrq": 1_000_000_000 })
        );
        let mut clockless = json!({ "snapshots": {} });
        restamp_clock(&mut clockless, 9_000);
        assert_eq!(clockless, json!({ "snapshots": {} }));
    }

    #[test]
    fn the_last_host_port_is_the_highest_used_open_or_closed() {
        let vsock = json!({ "connections": [[FIRST_HOST_PORT + 1, 1024]] }).to_string();
        let state = json!({ "snapshots": { "device-manager": { "snapshots": {
            "vsock": { "snapshot_data": { "state": vsock } }
        } } } });
        let packed: Packed = serde_json::from_value(json!({
            "config": {}, "state": state, "last_host_port": FIRST_HOST_PORT + 4
        }))
        .unwrap();
        assert_eq!(last_host_port(&packed), FIRST_HOST_PORT + 4);
        let packed: Packed = serde_json::from_value(json!({
            "config": {}, "state": state, "last_host_port": 0
        }))
        .unwrap();
        assert_eq!(last_host_port(&packed), FIRST_HOST_PORT + 1);
    }

    /// A restore whose VMM never reports the state loaded used to be polled
    /// forever. It gives up at the deadline and says what the VMM last said.
    #[tokio::test]
    async fn a_restore_that_never_loads_times_out_with_the_last_error() {
        let dir = std::env::temp_dir().join(format!("burrow-ch-wait-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let log = dir.join(VMM_LOG);
        let child =
            crate::child::spawn_logged(Path::new("/bin/sleep"), &["30".into()], &dir, None, &log)
                .await
                .unwrap();
        let mut process = VmmProcess::new(child, Output::Log(log), None);
        let api = UnixHttp::new(dir.join(API_SOCK));
        let err = wait_until_loaded(&mut process, &api, Duration::from_millis(50))
            .await
            .unwrap_err();
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let Error::Timeout { what, .. } = err else {
            panic!("expected a timeout, got {err}");
        };
        assert!(what.contains("last vm.info"), "{what}");
    }
}
