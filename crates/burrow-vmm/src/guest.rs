//! Reaching a guest's vsock listeners from the host.
//!
//! Firecracker and Cloud Hypervisor both terminate the host side of vsock
//! themselves and expose it as a Unix socket in the VM's working directory,
//! with a text handshake naming the guest port (see
//! [`crate::firecracker::vsock`]). Each VM has a vsock device of its own
//! behind its own socket, so every guest can use the same CID and nothing on
//! the host has to hand them out.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::net::UnixStream;

use crate::error::{Error, Result};
use crate::firecracker::vsock;

/// The Unix socket backing a VM's vsock device, relative to its working
/// directory. Fixed, so a snapshot restored in another sandbox's directory
/// binds its own.
pub const VSOCK_UDS: &str = "vsock.sock";

/// The CID every guest is given: 0 to 2 are reserved, and with a device per
/// VM there is nothing for two guests to collide over.
pub const GUEST_CID: u32 = 3;

/// Where one guest's vsock listeners are reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAddr(PathBuf);

impl GuestAddr {
    /// The guest of the VM whose working directory is `workdir`.
    pub fn in_workdir(workdir: &Path) -> Self {
        Self(workdir.join(VSOCK_UDS))
    }

    pub fn socket_path(&self) -> &Path {
        &self.0
    }

    /// Opens a connection to a guest port. Reconnect after every resume:
    /// connections do not survive a pause.
    pub async fn connect(&self, port: u32) -> Result<UnixStream> {
        vsock::connect(&self.0, port).await
    }

    /// Waits for a guest listener to accept, which is the agent's readiness
    /// signal (and far more precise than console scraping).
    pub async fn wait(&self, port: u32, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        let deadline = start + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout {
                    what: format!("guest vsock port {port}"),
                    timeout_ms: timeout.as_millis() as u64,
                });
            }
            // Bound each attempt by what is left of the overall deadline, so
            // a guest that accepts and then goes quiet costs one attempt
            // rather than the whole wait.
            if vsock::connect_within(&self.0, port, deadline - now)
                .await
                .is_ok()
            {
                return Ok(start.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// Removes sockets left behind by a previous VM in the same working
/// directory. The VMM binds the vsock UDS itself and fails with EADDRINUSE if
/// the file already exists, so a reused workdir must be swept first. It also
/// creates one `<uds>_<port>` socket per guest-initiated connection, which are
/// stale for the same reason.
pub(crate) async fn clear_stale_sockets(workdir: &Path) -> Result<()> {
    let mut entries = match tokio::fs::read_dir(workdir).await {
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
