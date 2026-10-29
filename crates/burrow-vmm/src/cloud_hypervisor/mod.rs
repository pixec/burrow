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
//! maps the memory file copy-on-write rather than reading it in.
//!
//! With a [`ChJail`] the VMM runs confined, as [`jail`] describes: it is
//! handed its tap as a descriptor rather than opening it by name, and a
//! jailed restore goes through the API for the same reason.

mod config;
pub mod jail;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use hyper::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::process::{Child, Command};

use crate::cgroup::Cgroup;
use crate::error::{Error, Result};
use crate::http::UnixHttp;
use crate::{DriveSpec, VmSpec};

pub use jail::ChJail;

/// The VM's config and device state, as one JSON document.
pub const STATE_FILE: &str = "snapshot.ch-state";
/// Guest memory, Cloud Hypervisor's `memory-ranges` under the layout's name.
pub const MEMORY_FILE: &str = "snapshot.ch-memory";
const API_SOCK: &str = "ch.sock";
const CONSOLE_LOG: &str = "console.log";
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
/// How long a `--restore` gets to load the VM's state. Memory is mapped
/// rather than read, so this is device state and the mapping, which take well
/// under a second when nothing is wrong.
const RESTORE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maps the memory file privately, the way Firecracker's `File` backend does:
/// a restore costs a mapping rather than a copy of the guest, and sandboxes
/// restored from one warm snapshot share its page cache. Cloud Hypervisor
/// falls back to copying where the memory is not plain private RAM.
const MEMORY_RESTORE_MODE: &str = "copyonwrite";
/// The same, as the API's `vm.restore` spells it.
const MEMORY_RESTORE_MODE_API: &str = "CopyOnWrite";

/// How this node runs Cloud Hypervisor.
#[derive(Debug, Clone)]
pub struct CloudHypervisorConfig {
    pub bin: PathBuf,
    /// Booted instead of the template's own kernel, for a template whose
    /// kernel lacks what a PCI machine needs.
    pub kernel: Option<PathBuf>,
    /// Confines the VMM. `None` runs it as the daemon runs, root with the
    /// host's filesystem in view.
    pub jail: Option<ChJail>,
}

/// What a snapshot's state half holds.
#[derive(Serialize, Deserialize)]
struct Packed {
    config: Value,
    state: Value,
}

/// A running (or paused) Cloud Hypervisor VM.
pub struct ChVm {
    child: Child,
    api: UnixHttp,
    workdir: PathBuf,
    /// [`Self::workdir`] as the VMM sees it.
    vmm_workdir: PathBuf,
    jail: Option<ChJail>,
    boot_latency: Duration,
    /// Held for the VM's lifetime; removed once the process is reaped.
    cgroup: Option<Cgroup>,
}

impl ChVm {
    pub(crate) async fn boot(spec: VmSpec, config: CloudHypervisorConfig) -> Result<Self> {
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
        let mut vm = Self::spawn(&spec, &config, &[], read_only).await?;
        let booted = async {
            vm.api.put("/api/v1/vm.create", &vm_config).await?;
            for nic in nics {
                vm.add_net(nic).await?;
            }
            vm.api.put_empty("/api/v1/vm.boot").await
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
        spec: VmSpec,
        config: CloudHypervisorConfig,
        resume: bool,
    ) -> Result<Self> {
        let started = Instant::now();
        // A chain or a base still arriving needs burrow's page-fault handler,
        // which this VMM cannot be pointed at; the daemon only asks where it
        // can.
        if spec.memory_chain.len() > 1 || spec.memory_source.is_some() {
            return Err(Error::Unsupported {
                hypervisor: crate::Hypervisor::CloudHypervisor,
                what: "restore from a memory chain or from memory still arriving",
            });
        }
        let (restore_dir, vm_config) = unpack(&spec, config.jail.as_ref()).await?;
        let read_only = jail::absolute_paths(&vm_config);
        let source = jail::vmm_workdir(&spec.workdir, config.jail.as_ref())?.join(RESTORE_DIR);
        let source_url = format!("file://{}", source.display());
        let mut vm = match &config.jail {
            Some(_) => Self::spawn(&spec, &config, &[], read_only).await?,
            None => {
                let source =
                    format!("source_url={source_url},memory_restore_mode={MEMORY_RESTORE_MODE}");
                Self::spawn(&spec, &config, &["--restore", &source], read_only).await?
            }
        };
        let loaded = async {
            if config.jail.is_some() {
                vm.restore_jailed(&source_url, &vm_config).await?;
            }
            vm.wait_until_loaded().await?;
            if resume {
                vm.resume().await?;
            }
            Ok::<_, Error>(())
        }
        .await;
        // The mapping holds the memory file's inode, and the config and state
        // were read at startup, so nothing here is needed any longer.
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
    /// before it execs: the cgroup is made first and joined by the child, so
    /// the VMM (jailed, its helper, and the VMM that inherits it) never runs
    /// outside its caps. `read_only` are the host files the VM config names
    /// absolutely, which a jail has to bind in.
    async fn spawn(
        spec: &VmSpec,
        config: &CloudHypervisorConfig,
        extra: &[&str],
        read_only: Vec<PathBuf>,
    ) -> Result<Self> {
        if !config.bin.exists() {
            return Err(Error::BinaryNotFound(config.bin.clone()));
        }
        tokio::fs::create_dir_all(&spec.workdir).await?;
        crate::guest::clear_stale_sockets(&spec.workdir).await?;
        let socket = spec.workdir.join(API_SOCK);
        remove_if_present(&socket).await?;

        let api_socket = format!("path={API_SOCK}");
        let mut command = match &config.jail {
            None => {
                let mut command = Command::new(&config.bin);
                command
                    .current_dir(&spec.workdir)
                    .args(["--api-socket", &api_socket])
                    .args(extra);
                command
            }
            Some(jail) => jail::Plan {
                workdir: std::path::absolute(&spec.workdir)?,
                uid: jail.uid,
                gid: jail.gid,
                read_only,
                program: config.bin.clone(),
                args: ["--api-socket", &api_socket]
                    .iter()
                    .chain(extra)
                    .map(|arg| arg.to_string())
                    .collect(),
            }
            .command(jail),
        };
        let cgroup = Cgroup::for_vm(
            spec.cgroup_root.as_deref(),
            &spec.vm_id,
            &spec.limits,
            spec.is_limits_required,
        )?;
        let spawned = async {
            if let Some(cgroup) = &cgroup {
                cgroup.join_before_exec(&mut command)?;
            }
            let log = std::fs::File::create(spec.workdir.join(VMM_LOG))?;
            let log_err = log.try_clone()?;
            Ok::<_, Error>(
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log))
                    .stderr(Stdio::from(log_err))
                    .kill_on_drop(true)
                    .spawn()?,
            )
        }
        .await;
        let child = match spawned {
            Ok(child) => child,
            Err(err) => {
                if let Some(cgroup) = cgroup {
                    cgroup.remove();
                }
                return Err(err);
            }
        };
        let mut vm = Self {
            api: UnixHttp::new(socket.clone()),
            child,
            workdir: spec.workdir.clone(),
            vmm_workdir: jail::vmm_workdir(&spec.workdir, config.jail.as_ref())?,
            jail: config.jail.clone(),
            boot_latency: Duration::ZERO,
            cgroup,
        };
        if let Err(err) = wait_for_socket(&mut vm.child, &socket, &spec.workdir).await {
            vm.stop().await;
            if let Some(cgroup) = vm.cgroup.take() {
                cgroup.remove();
            }
            return Err(err);
        }
        Ok(vm)
    }

    /// Kills the VMM and reaps it. A jailed one is asked through its helper,
    /// which kills and reaps the VMM before exiting itself: killing the
    /// helper outright would leave the VMM to be reaped by whatever adopts
    /// orphans, which in a container is burrowd, and it never would.
    async fn stop(&mut self) {
        match (&self.jail, self.child.id()) {
            (Some(_), Some(pid)) => {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGTERM,
                );
                let _ = self.child.wait().await;
            }
            _ => {
                let _ = self.child.kill().await;
            }
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
        wait_until_loaded(&mut self.child, &self.api, &self.workdir, RESTORE_TIMEOUT).await
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
                body: format!("{body}\n{}", tail(&self.workdir.join(VMM_LOG), 10).await),
            },
            err => err,
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    pub fn cpu_usage_usec(&self) -> Option<u64> {
        self.cgroup.as_ref()?.cpu_usage_usec()
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub async fn console_tail(&self, lines: usize) -> String {
        tail(&self.workdir.join(CONSOLE_LOG), lines).await
    }

    pub async fn pause(&self) -> Result<()> {
        self.api.put_empty("/api/v1/vm.pause").await
    }

    pub async fn resume(&self) -> Result<()> {
        self.api.put_empty("/api/v1/vm.resume").await
    }

    /// Snapshots the **paused** VM into its layout.
    ///
    /// Both files are replaced by rename rather than written in place, for
    /// the reason Firecracker's are unlinked first: a sandbox restored from a
    /// warm snapshot holds them as hard links to the template's, and writing
    /// through a link would publish this guest's memory as the image every
    /// later sandbox restores.
    pub async fn snapshot(&self) -> Result<()> {
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
        };
        let state = dir.join(STATE_FILE);
        tokio::fs::write(&state, serde_json::to_vec(&packed)?).await?;
        tokio::fs::rename(&state, self.workdir.join(STATE_FILE)).await?;
        tokio::fs::rename(dir.join("memory-ranges"), self.workdir.join(MEMORY_FILE)).await?;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        Ok(())
    }

    /// Attaches a drive to the running guest, which sees it once it rescans
    /// its PCI bus.
    pub async fn attach_drive(&self, drive: &DriveSpec) -> Result<()> {
        self.api
            .call(
                Method::PUT,
                "/api/v1/vm.add-disk",
                Some(&json!({
                    "id": drive.id,
                    "path": drive.path,
                    "readonly": drive.is_read_only,
                    "image_type": "Raw",
                })),
            )
            .await
            .map(|_| ())
    }

    pub async fn kill(mut self) -> Result<()> {
        self.stop().await;
        let _ = tokio::fs::remove_file(self.workdir.join(API_SOCK)).await;
        // Only removable once it holds no processes, so this follows the reap.
        if let Some(cgroup) = self.cgroup.take() {
            cgroup.remove();
        }
        Ok(())
    }
}

/// Lays a packed snapshot out the way a restore reads one, addressed to this
/// sandbox, and returns the directory and the config as written there.
///
/// Landlock follows this VMM rather than the one snapshotted: its rules name
/// the jail's paths, which a VMM run unjailed does not have.
async fn unpack(spec: &VmSpec, jail: Option<&ChJail>) -> Result<(PathBuf, Value)> {
    let packed: Packed =
        serde_json::from_slice(&tokio::fs::read(spec.workdir.join(STATE_FILE)).await?)?;
    let mut vm_config = packed.config;
    config::retarget(&mut vm_config, spec)?;
    jail::set_landlock(&mut vm_config, jail.is_some());
    let mut written = vm_config.clone();
    jail::address_nics(&mut written, jail.is_some());
    let dir = spec.workdir.join(RESTORE_DIR);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::write(dir.join("config.json"), serde_json::to_vec(&written)?).await?;
    tokio::fs::write(dir.join("state.json"), serde_json::to_vec(&packed.state)?).await?;
    // Linked: the VMM maps it copy-on-write and never writes back, which is
    // what lets every sandbox of a warm template share the one file.
    let memory = spec.workdir.join(MEMORY_FILE);
    tokio::fs::hard_link(&memory, dir.join("memory-ranges")).await?;
    // Cloud Hypervisor writes it 0600, so one written by a VMM running as
    // anyone else (an unjailed one, or the daemon staging it) is the jail
    // uid's to read only once it owns it. Every jailed VMM runs as that uid,
    // so this hands none of them anything another could not already open.
    if let Some(jail) = jail {
        std::os::unix::fs::chown(&memory, Some(jail.uid), Some(jail.gid))?;
    }
    Ok((dir, vm_config))
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
    child: &mut Child,
    api: &UnixHttp,
    workdir: &Path,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Error::EarlyExit {
                status: status.to_string(),
                tail: tail(&workdir.join(VMM_LOG), 20).await,
            });
        }
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

async fn wait_for_socket(child: &mut Child, socket: &Path, workdir: &Path) -> Result<()> {
    let deadline = Instant::now() + SOCKET_TIMEOUT;
    loop {
        // Accepting, for the reason Firecracker's is waited for that way: the
        // file exists from bind, and a jailed restore's first call would be
        // refused if it landed before the listen.
        if tokio::net::UnixStream::connect(socket).await.is_ok() {
            return Ok(());
        }
        // A VMM that died on startup will never create the socket; surface
        // what it logged instead of waiting out the timeout.
        if let Some(status) = child.try_wait()? {
            return Err(Error::EarlyExit {
                status: status.to_string(),
                tail: tail(&workdir.join(VMM_LOG), 20).await,
            });
        }
        if Instant::now() >= deadline {
            return Err(Error::SocketTimeout {
                path: socket.to_path_buf(),
                timeout_ms: SOCKET_TIMEOUT.as_millis() as u64,
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
async fn tail(path: &Path, n: usize) -> String {
    let Ok(text) = tokio::fs::read_to_string(path).await else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A restore whose VMM never reports the state loaded used to be polled
    /// forever. It gives up at the deadline and says what the VMM last said.
    #[tokio::test]
    async fn a_restore_that_never_loads_times_out_with_the_last_error() {
        let dir = std::env::temp_dir().join(format!("burrow-ch-wait-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let mut child = Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let api = UnixHttp::new(dir.join(API_SOCK));
        let err = wait_until_loaded(&mut child, &api, &dir, Duration::from_millis(50))
            .await
            .unwrap_err();
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let Error::Timeout { what, .. } = err else {
            panic!("expected a timeout, got {err}");
        };
        assert!(what.contains("last vm.info"), "{what}");
    }

    /// The socket file exists from bind; an API call made before the VMM
    /// listens is refused, which failed restores with "Connection refused".
    #[tokio::test]
    async fn a_socket_is_ready_once_it_listens_not_once_it_exists() {
        use nix::sys::socket::{
            AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
        };
        use std::os::fd::AsRawFd as _;

        let dir = std::env::temp_dir().join(format!("burrow-ch-listen-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join(API_SOCK);
        let _ = tokio::fs::remove_file(&path).await;
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        bind(fd.as_raw_fd(), &UnixAddr::new(&path).unwrap()).unwrap();
        let mut child = Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let early = tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_socket(&mut child, &path, &dir),
        )
        .await;
        assert!(
            early.is_err(),
            "a bound socket that is not listening is not ready"
        );

        listen(&fd, Backlog::new(1).unwrap()).unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_socket(&mut child, &path, &dir),
        )
        .await
        .expect("ready once listening")
        .unwrap();
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
