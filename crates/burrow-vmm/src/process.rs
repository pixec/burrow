//! A Linux VMM process: Firecracker or Cloud Hypervisor, once spawned.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use crate::cgroup::Cgroup;
use crate::child::Child;
use crate::error::{Error, Result};

/// How long a VMM gets to listen on its API socket.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// A VMM listens a few milliseconds after it starts, and tokio's timer rounds
/// a sleep up to a whole millisecond, so the socket is polled from a blocking
/// thread, a slice at a time between checks that it still runs.
const SOCKET_POLL: Duration = Duration::from_micros(100);
const SOCKET_SLICE: Duration = Duration::from_millis(20);

/// Where a VMM's own output goes, which says why it exited.
pub(crate) enum Output {
    /// The guest console, which Firecracker's stdout is.
    Console(PathBuf),
    /// A log file of its own.
    Log(PathBuf),
}

/// A spawned VMM, with the cgroup it runs in, held until it is reaped.
pub(crate) struct VmmProcess {
    child: Child,
    output: Output,
    cgroup: Option<Cgroup>,
}

impl VmmProcess {
    pub(crate) fn new(child: Child, output: Output, cgroup: Option<Cgroup>) -> Self {
        Self {
            child,
            output,
            cgroup,
        }
    }

    /// Waits for the VMM to accept on `socket`. Accepting, not merely
    /// present: the socket file appears at bind, before the VMM listens, and
    /// an API call in that gap is refused and fails the boot or restore it
    /// belongs to.
    pub(crate) async fn wait_for_socket(&mut self, socket: &Path) -> Result<()> {
        let deadline = Instant::now() + SOCKET_TIMEOUT;
        loop {
            let path = socket.to_path_buf();
            let is_listening = tokio::task::spawn_blocking(move || {
                let slice = Instant::now() + SOCKET_SLICE;
                while Instant::now() < slice {
                    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                        return true;
                    }
                    std::thread::sleep(SOCKET_POLL);
                }
                false
            })
            .await
            .map_err(std::io::Error::other)?;
            if is_listening {
                return Ok(());
            }
            self.check_running().await?;
            if Instant::now() >= deadline {
                return Err(Error::SocketTimeout {
                    path: socket.to_path_buf(),
                    timeout_ms: SOCKET_TIMEOUT.as_millis() as u64,
                });
            }
        }
    }

    /// An error with what the VMM wrote, if it has exited.
    pub(crate) async fn check_running(&mut self) -> Result<()> {
        match self.child.try_wait()? {
            Some(status) => Err(Error::EarlyExit {
                status: status.to_string(),
                tail: self.output_tail(20).await,
            }),
            None => Ok(()),
        }
    }

    /// The last `lines` lines of what the VMM wrote.
    pub(crate) async fn output_tail(&self, lines: usize) -> String {
        match &self.output {
            Output::Console(workdir) => crate::console::tail(workdir, lines).await,
            Output::Log(path) => tail(path, lines).await,
        }
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub(crate) fn has_exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// How the process ended, once it has.
    pub(crate) fn exit_status(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    pub(crate) fn cgroup(&self) -> Option<&Cgroup> {
        self.cgroup.as_ref()
    }

    /// Host CPU the VMM has consumed, in microseconds. `None` when it runs
    /// under no cgroup, which is the same condition that leaves its cpu cap
    /// unenforced.
    pub(crate) fn cpu_usage_usec(&self) -> Option<u64> {
        self.cgroup.as_ref()?.cpu_usage_usec()
    }

    /// SIGKILLs the VMM and reaps it.
    pub(crate) async fn kill(&mut self) -> Result<()> {
        self.child.start_kill()?;
        self.child.wait().await?;
        Ok(())
    }

    /// Reaps a VMM that is exiting.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus> {
        Ok(self.child.wait().await?)
    }

    /// Removes the cgroup, which holds no processes once the VMM is reaped.
    pub(crate) fn release_cgroup(&mut self) {
        drop(self.cgroup.take());
    }
}

/// The last `n` lines of a log.
pub(crate) async fn tail(path: &Path, n: usize) -> String {
    let Ok(text) = tokio::fs::read_to_string(path).await else {
        return String::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket file exists from bind; an API call made before the VMM
    /// listens is refused, which failed restores with "Connection refused".
    #[tokio::test]
    async fn a_socket_is_ready_once_it_listens_not_once_it_exists() {
        use nix::sys::socket::{
            AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
        };
        use std::os::fd::AsRawFd as _;

        let dir = std::env::temp_dir().join(format!("burrow-vmm-listen-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("api.sock");
        let _ = tokio::fs::remove_file(&path).await;
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        bind(fd.as_raw_fd(), &UnixAddr::new(&path).unwrap()).unwrap();
        let log = dir.join("vmm.log");
        let child =
            crate::child::spawn_logged(Path::new("/bin/sleep"), &["30".into()], &dir, None, &log)
                .await
                .unwrap();
        let mut process = VmmProcess::new(child, Output::Log(log), None);

        let early =
            tokio::time::timeout(Duration::from_millis(100), process.wait_for_socket(&path)).await;
        assert!(
            early.is_err(),
            "a bound socket that is not listening is not ready"
        );

        listen(&fd, Backlog::new(8).unwrap()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), process.wait_for_socket(&path))
            .await
            .expect("ready once listening")
            .unwrap();
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
