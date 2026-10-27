//! Spawning and supervising a `firecracker` process.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};

use crate::error::{Result, VmmError};

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
    /// The jailer builds `<base>/firecracker/<id>/root`; the caller must have
    /// staged the VM's files there already.
    pub chroot_base: PathBuf,
}

impl Jail {
    /// The chroot the jailer will build for `vm_id`, which is also the working
    /// directory the VM's files must be staged into.
    pub fn chroot_for(&self, vm_id: &str) -> PathBuf {
        self.dir_for(vm_id).join("root")
    }

    /// The directory the jailer builds for `vm_id`, one level above the chroot.
    ///
    /// Named by the jailer's own sanitised id rather than the sandbox id: `_`
    /// is not alphanumeric, so `sbx_1234` lives in `sbx-1234`. Anything
    /// matching directories on this base against sandbox ids has to come
    /// through here, or it concludes that every jailed sandbox is an orphan.
    pub fn dir_for(&self, vm_id: &str) -> PathBuf {
        self.chroot_base
            .join("firecracker")
            .join(sanitize_vm_id(vm_id))
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
    /// every path handed to the API can stay relative.
    ///
    /// Guest serial output arrives on the process's stdout, so both stdout and
    /// stderr are captured to `console.log` inside the workdir.
    pub async fn spawn(
        binary: &Path,
        vm_id: &str,
        workdir: &Path,
        api_sock: &str,
        jail: Option<&Jail>,
        enable_pci: bool,
    ) -> Result<Self> {
        if !binary.exists() {
            return Err(VmmError::BinaryNotFound(binary.to_path_buf()));
        }
        if let Some(jail) = jail
            && !jail.jailer.exists()
        {
            return Err(VmmError::BinaryNotFound(jail.jailer.clone()));
        }
        tokio::fs::create_dir_all(workdir).await?;

        // Firecracker refuses to start if the socket path already exists.
        let sock_path = workdir.join(api_sock);
        if tokio::fs::try_exists(&sock_path).await.unwrap_or(false) {
            tokio::fs::remove_file(&sock_path).await?;
        }

        let console_log = workdir.join("console.log");
        let console = std::fs::File::create(&console_log)?;
        let console_err = console.try_clone()?;

        if let Some(jail) = jail {
            clear_jail_devices(workdir).await?;
            // The jailer copies firecracker in each time; an existing copy is
            // simply overwritten, but a stale pid file confuses nothing and is
            // tidier gone.
            let _ = tokio::fs::remove_file(workdir.join("firecracker.pid")).await;
            let _ = jail;
        }

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

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::from(console))
            .stderr(Stdio::from(console_err))
            .kill_on_drop(true)
            .spawn()?;

        let console_in = child.stdin.take();
        let mut proc = Self {
            child,
            workdir: workdir.to_path_buf(),
            console_log,
            console_in,
        };
        proc.wait_for_socket(&sock_path).await?;
        Ok(proc)
    }

    async fn wait_for_socket(&mut self, sock_path: &Path) -> Result<()> {
        let deadline = Instant::now() + SOCKET_TIMEOUT;
        loop {
            if tokio::fs::try_exists(sock_path).await.unwrap_or(false) {
                return Ok(());
            }
            // A firecracker that died on startup will never create the socket;
            // surface its console output instead of waiting out the timeout.
            if let Some(status) = self.child.try_wait()? {
                return Err(VmmError::EarlyExit {
                    status: status.to_string(),
                    tail: self.console_tail(20).await,
                });
            }
            if Instant::now() >= deadline {
                return Err(VmmError::SocketTimeout {
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

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub fn console_log_path(&self) -> &Path {
        &self.console_log
    }

    /// Writes to the guest serial console. Only useful for guests running a
    /// getty/shell on ttyS0; the supported control path is the guest agent.
    pub async fn console_write(&mut self, input: &str) -> Result<()> {
        let stdin = self
            .console_in
            .as_mut()
            .ok_or(VmmError::ConsoleUnavailable)?;
        stdin.write_all(input.as_bytes()).await?;
        stdin.flush().await?;
        Ok(())
    }

    /// Last `n` lines of guest console output, for diagnostics.
    pub async fn console_tail(&self, n: usize) -> String {
        let Ok(text) = tokio::fs::read_to_string(&self.console_log).await else {
            return String::new();
        };
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
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
                return Err(VmmError::Timeout {
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

    /// A jailed sandbox's directory is not named after its id, so anything
    /// looking one up by id finds nothing. That once made every live jailed
    /// sandbox read as an orphan, and its state was deleted on every restart.
    #[test]
    fn a_jail_directory_is_not_named_after_the_sandbox() {
        let jail = super::Jail {
            jailer: "/usr/local/bin/jailer".into(),
            uid: 65534,
            gid: 65534,
            chroot_base: std::path::PathBuf::from("/var/lib/burrow/jail"),
        };
        let id = "sbx_1a2b";

        let dir = jail.dir_for(id);
        assert_eq!(
            dir,
            std::path::Path::new("/var/lib/burrow/jail/firecracker/sbx-1a2b")
        );
        assert_ne!(dir.file_name().unwrap(), id, "the id is not the directory");
        assert_eq!(jail.chroot_for(id), dir.join("root"));
    }
}
