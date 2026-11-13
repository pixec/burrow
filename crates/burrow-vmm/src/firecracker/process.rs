//! Spawning and supervising a `firecracker` process.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};

use crate::error::{Error, Result};

/// How long to wait for firecracker to create its API socket.
const SOCKET_TIMEOUT: Duration = Duration::from_millis(5_000);
const SOCKET_POLL: Duration = Duration::from_millis(2);

/// Firecracker accepts only alphanumerics and hyphens in `--id`, and panics
/// on anything else. Burrow's own ids use underscores (`sbx_1a2b…`), so they
/// are mapped here rather than constraining the id format everywhere else.
/// The value is only used in firecracker's own logs and metrics.
fn sanitize_vm_id(id: &str) -> String {
    let mapped: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(64)
        .collect();
    if mapped.is_empty() {
        "burrow-vm".to_string()
    } else {
        mapped
    }
}

/// Removes the device nodes the jailer creates.
///
/// The jailer `mknod`s `/dev/kvm` and `/dev/net/tun` inside the chroot
/// unconditionally and fails with `EEXIST` if they are already there. A chroot
/// is reused every time a sandbox resumes, so without this the first resume
/// after a suspend fails outright.
async fn clear_jail_devices(workdir: &Path) -> Result<()> {
    match tokio::fs::remove_dir_all(workdir.join("dev")).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// How firecracker is confined, if at all.
///
/// The jailer chroots the VMM into its own working directory and drops it to an
/// unprivileged uid, so a firecracker compromised out of its seccomp filter
/// still holds no root and can see no filesystem but the one sandbox's. Without
/// it firecracker runs as root with the whole host visible, which is a large
/// amount of trust to place in one process supervising untrusted guests.
#[derive(Debug, Clone)]
pub struct Jail {
    pub jailer: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// Every jailed VM's files are under `<base>/<hypervisor>/<id>/root`.
    pub chroot_base: PathBuf,
}

impl Jail {
    /// The chroot a VM under `hypervisor` runs in, which is also the working
    /// directory its files must be staged into.
    pub fn chroot_for(&self, hypervisor: crate::Hypervisor, vm_id: &str) -> PathBuf {
        self.dir_for(hypervisor, vm_id).join("root")
    }

    /// The directory one level above a VM's chroot.
    ///
    /// Firecracker's is the one its jailer builds, `<base>/<exec file
    /// name>/<id>`, and the binary is `firecracker`. Cloud Hypervisor's is
    /// laid out the same way under its own name.
    ///
    /// Named by the jailer's own sanitised id rather than the sandbox id: `_`
    /// is not alphanumeric, so `sbx_1234` lives in `sbx-1234`. Anything
    /// matching directories on this base against sandbox ids has to come
    /// through here, or it concludes that every jailed sandbox is an orphan.
    pub fn dir_for(&self, hypervisor: crate::Hypervisor, vm_id: &str) -> PathBuf {
        self.hypervisor_dir(hypervisor).join(sanitize_vm_id(vm_id))
    }

    /// Where every jailed VM under `hypervisor` has its directory.
    pub fn hypervisor_dir(&self, hypervisor: crate::Hypervisor) -> PathBuf {
        self.chroot_base.join(hypervisor.as_str())
    }

    /// What to remove to tear down the VM whose working directory is
    /// `workdir`: its whole directory when `workdir` is a chroot on this
    /// base, `workdir` alone otherwise. Decided on the path alone, so it
    /// never reaches outside the base or through a link.
    pub fn tree_of<'a>(&self, workdir: &'a Path) -> &'a Path {
        let is_chroot = workdir.strip_prefix(&self.chroot_base).is_ok_and(|rest| {
            let parts: Vec<_> = rest.components().collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
                && parts[2].as_os_str() == "root"
        });
        match workdir.parent() {
            Some(dir) if is_chroot => dir,
            _ => workdir,
        }
    }
}

pub struct FcProcess {
    child: Child,
    workdir: PathBuf,
    console_log: PathBuf,
    /// Firecracker's stdin is wired to the guest serial port, giving us a way
    /// to drive a guest that has no agent yet (dev and rescue only).
    console_in: Option<ChildStdin>,
}

impl FcProcess {
    /// Spawns firecracker with its working directory set to `workdir`, so
    /// every path handed to the API can stay relative, and in `cgroup` from
    /// before it execs.
    ///
    /// Guest serial output arrives on the process's stdout, so both stdout and
    /// stderr are captured to the bounded console log inside the workdir.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        binary: &Path,
        vm_id: &str,
        workdir: &Path,
        api_sock: &str,
        jail: Option<&Jail>,
        enable_pci: bool,
        cgroup: Option<&crate::cgroup::Cgroup>,
        phases: &mut crate::Phases,
    ) -> Result<Self> {
        if !binary.exists() {
            return Err(Error::BinaryNotFound(binary.to_path_buf()));
        }
        if let Some(jail) = jail
            && !jail.jailer.exists()
        {
            return Err(Error::BinaryNotFound(jail.jailer.clone()));
        }
        tokio::fs::create_dir_all(workdir).await?;

        // Firecracker refuses to start if the socket path already exists.
        let sock_path = workdir.join(api_sock);
        if tokio::fs::try_exists(&sock_path).await.unwrap_or(false) {
            tokio::fs::remove_file(&sock_path).await?;
        }

        let console_log = workdir.join(crate::console::LOG);

        if let Some(jail) = jail {
            clear_jail_devices(workdir).await?;
            // The jailer copies firecracker in each time; an existing copy is
            // simply overwritten, but a stale pid file confuses nothing and is
            // tidier gone.
            let _ = tokio::fs::remove_file(workdir.join("firecracker.pid")).await;
            let _ = jail;
        }

        phases.mark("prespawn");
        let id = sanitize_vm_id(vm_id);
        let mut command = match jail {
            None => {
                let mut command = Command::new(binary);
                command
                    .current_dir(workdir)
                    .args(["--api-sock", api_sock, "--id", &id]);
                if enable_pci {
                    command.arg("--enable-pci");
                }
                command
            }
            Some(jail) => {
                // Everything the VM needs is already inside the chroot, and
                // every path handed to the API is relative, so firecracker's
                // view of them is unchanged by the pivot.
                let mut command = Command::new(&jail.jailer);
                command.args([
                    "--id",
                    &id,
                    "--exec-file",
                    &binary.to_string_lossy(),
                    "--uid",
                    &jail.uid.to_string(),
                    "--gid",
                    &jail.gid.to_string(),
                    "--chroot-base-dir",
                    &jail.chroot_base.to_string_lossy(),
                    // v2 with no --cgroup means the jailer touches no cgroup at
                    // all, leaving the limits burrow applies by pid intact.
                    "--cgroup-version",
                    "2",
                    "--",
                    "--api-sock",
                    api_sock,
                ]);
                if enable_pci {
                    command.arg("--enable-pci");
                }
                command
            }
        };

        // The jailer execs firecracker in place, so what joins here before
        // the jailer runs is firecracker itself.
        if let Some(cgroup) = cgroup {
            cgroup.join_before_exec(&mut command)?;
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let outputs: Vec<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = vec![
            Box::new(child.stdout.take().expect("stdout is piped")),
            Box::new(child.stderr.take().expect("stderr is piped")),
        ];
        crate::console::capture(workdir, outputs)?;
        phases.mark("spawn");
        let console_in = child.stdin.take();
        let mut proc = Self {
            child,
            workdir: workdir.to_path_buf(),
            console_log,
            console_in,
        };
        proc.wait_for_socket(&sock_path).await?;
        phases.mark("api_ready");
        Ok(proc)
    }

    async fn wait_for_socket(&mut self, sock_path: &Path) -> Result<()> {
        let deadline = Instant::now() + SOCKET_TIMEOUT;
        loop {
            // Accepting, not merely present: the socket file appears at bind,
            // before firecracker listens, and an API call in that gap is
            // refused and fails the boot or restore it belongs to.
            if tokio::net::UnixStream::connect(sock_path).await.is_ok() {
                return Ok(());
            }
            // A firecracker that died on startup will never create the socket;
            // surface its console output instead of waiting out the timeout.
            if let Some(status) = self.child.try_wait()? {
                return Err(Error::EarlyExit {
                    status: status.to_string(),
                    tail: self.console_tail(20).await,
                });
            }
            if Instant::now() >= deadline {
                return Err(Error::SocketTimeout {
                    path: sock_path.to_path_buf(),
                    timeout_ms: SOCKET_TIMEOUT.as_millis() as u64,
                });
            }
            tokio::time::sleep(SOCKET_POLL).await;
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn has_exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub fn console_log_path(&self) -> &Path {
        &self.console_log
    }

    /// Writes to the guest serial console. Only useful for guests running a
    /// getty/shell on ttyS0; the supported control path is the guest agent.
    pub async fn console_write(&mut self, input: &str) -> Result<()> {
        let stdin = self.console_in.as_mut().ok_or(Error::ConsoleUnavailable)?;
        stdin.write_all(input.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    /// Last `n` lines of guest console output, for diagnostics.
    pub async fn console_tail(&self, n: usize) -> String {
        crate::console::tail(&self.workdir, n).await
    }

    /// How the process ended, once it has.
    pub fn exit_status(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Waits for `marker` to appear in the guest console output.
    pub async fn wait_for_console(&self, marker: &str, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        let deadline = start + timeout;
        loop {
            if let Ok(text) = tokio::fs::read_to_string(&self.console_log).await
                && text.contains(marker)
            {
                return Ok(start.elapsed());
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    what: format!("console marker {marker:?}"),
                    timeout_ms: timeout.as_millis() as u64,
                });
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// SIGKILLs the VMM and reaps it. Firecracker has no graceful shutdown
    /// path other than a guest-side reboot, so callers wanting a clean stop
    /// should snapshot first.
    pub async fn kill(&mut self) -> Result<()> {
        self.child.start_kill()?;
        self.child.wait().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_vm_id;

    #[test]
    fn maps_characters_firecracker_rejects() {
        assert_eq!(sanitize_vm_id("sbx_1a2b"), "sbx-1a2b");
        assert_eq!(sanitize_vm_id("a.b/c"), "a-b-c");
        assert_eq!(sanitize_vm_id("plain123"), "plain123");
    }

    #[test]
    fn always_produces_a_usable_id() {
        assert_eq!(sanitize_vm_id(""), "burrow-vm");
        assert_eq!(sanitize_vm_id(&"x".repeat(100)).len(), 64);
    }

    fn jail() -> super::Jail {
        super::Jail {
            jailer: "/usr/local/bin/jailer".into(),
            uid: 65534,
            gid: 65534,
            chroot_base: std::path::PathBuf::from("/var/lib/burrow/jail"),
        }
    }

    /// A jailed sandbox's directory is not named after its id, so anything
    /// looking one up by id finds nothing. That once made every live jailed
    /// sandbox read as an orphan, and its state was deleted on every restart.
    #[test]
    fn a_jail_directory_is_not_named_after_the_sandbox() {
        let jail = jail();
        let id = "sbx_1a2b";

        let dir = jail.dir_for(crate::Hypervisor::Firecracker, id);
        assert_eq!(
            dir,
            std::path::Path::new("/var/lib/burrow/jail/firecracker/sbx-1a2b")
        );
        assert_ne!(dir.file_name().unwrap(), id, "the id is not the directory");
        assert_eq!(
            jail.chroot_for(crate::Hypervisor::Firecracker, id),
            dir.join("root")
        );
        assert_eq!(
            jail.dir_for(crate::Hypervisor::CloudHypervisor, id),
            std::path::Path::new("/var/lib/burrow/jail/cloud-hypervisor/sbx-1a2b")
        );
    }

    /// Removing only the chroot left `<base>/<hypervisor>/<id>` behind empty
    /// for every VM the node ever ran.
    #[test]
    fn a_teardown_takes_the_vm_directory_and_nothing_above_it() {
        let jail = jail();
        let path = std::path::Path::new;
        for hypervisor in [
            crate::Hypervisor::Firecracker,
            crate::Hypervisor::CloudHypervisor,
        ] {
            let chroot = jail.chroot_for(hypervisor, "sbx_1");
            assert_eq!(jail.tree_of(&chroot), jail.dir_for(hypervisor, "sbx_1"));
        }
        for workdir in [
            "/var/lib/burrow/sandboxes/sbx_1",
            "/var/lib/burrow/jail/firecracker/root",
            "/var/lib/burrow/jail/firecracker/sbx-1/root/root",
            "/var/lib/burrow/jail/firecracker/sbx-1/other",
            "/var/lib/burrow/jail/../sandboxes/sbx-1/root",
            "/var/lib/burrow/jail/firecracker/../root",
        ] {
            assert_eq!(jail.tree_of(path(workdir)), path(workdir), "{workdir}");
        }
    }
}
