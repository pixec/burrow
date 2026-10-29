//! The macOS agent.
//!
//! A LaunchDaemon, run as root by launchd in a macOS guest under
//! Virtualization.framework, serving the node daemon over AF_VSOCK. Exec,
//! files, `Fs`, terminals and the reaper are `crate::unix`'s; what is here is
//! the daemon itself, its handshake, Open Directory accounts and vsock. See
//! the crate's README for what maps onto what.
//!
//! `burrow-guest install` installs it (see [`install`]); with no argument it
//! serves, as launchd runs it.

mod handshake;
mod install;
pub mod users;
mod vsock;

pub use crate::unix::{exec, files, fs};
pub use handshake::handshake;
pub use vsock::Arrival;

use std::os::unix::fs::PermissionsExt as _;

use tonic::{Status, transport::Server};

use burrow_proto::guest::v1 as guestpb;

use crate::commands;
use crate::unix::reaper;

/// What this agent does beyond the original protocol, for the health response.
pub fn features() -> Vec<String> {
    vec![
        files::FEATURE_FILES_AS_USER.to_string(),
        "attach-input".to_string(),
        "output-feed".to_string(),
        fs::FEATURE_FS.to_string(),
    ]
}

/// vsock port the node daemon dials. Free in a macOS guest: Apple's
/// `remoted` holds 1025 to 1033.
const AGENT_PORT: u32 = 1024;

/// The only peer the agent will talk to: the host, as Virtualization.framework
/// presents it. A process in the guest dialling its own cid arrives as
/// something else and is refused.
const HOST_CID: u32 = nix::libc::VMADDR_CID_HOST;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Set in the environment of an agent that replaced itself, so the new
/// process takes over the command table and open handles the old one left.
const REEXEC_MARK: &str = "BURROW_GUEST_REEXEC";
/// Where the finished-command table is handed across the re-exec.
const COMMANDS_STATE: &str = "/private/var/run/burrow-guest.commands";
/// Where open file handles are handed across the re-exec.
const FS_STATE: &str = "/private/var/run/burrow-guest.fs";

/// Linux's systemd namespaces, which a command there may be spawned into.
/// A macOS command starts in the agent's own context, so there never is one.
pub enum Namespaces {}

impl Namespaces {
    pub fn current() -> std::io::Result<Option<Self>> {
        Ok(None)
    }

    pub fn enter(&self, _: &mut std::process::Command, _: Option<&str>) -> std::io::Result<()> {
        match *self {}
    }

    pub fn spawn(&self, _: &mut std::process::Command) -> std::io::Result<std::process::Child> {
        match *self {}
    }
}

/// SHA-256 of the binary this process is running, as the host compares it.
/// Taken at start, before an upgrade can rename another binary over the path.
pub fn self_digest() -> &'static str {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(|| {
        use sha2::Digest as _;
        std::env::current_exe()
            .and_then(std::fs::read)
            .map(|bytes| hex_lower(&sha2::Sha256::digest(&bytes)))
            .unwrap_or_default()
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Replaces this agent with the binary streamed in.
///
/// Verified against the digest, renamed over the installed binary and
/// executed in place, as on Linux: the pid launchd watches stays the same, so
/// it neither restarts the daemon nor throttles it, and open `Fs` handles and
/// the command table carry over. The caller has refused it while a command is
/// running.
pub async fn upgrade(
    mut stream: tonic::Streaming<guestpb::UpgradeChunk>,
) -> Result<guestpb::UpgradeResponse, Status> {
    use sha2::Digest as _;
    use tokio::io::AsyncWriteExt as _;
    let exe =
        std::env::current_exe().map_err(|err| Status::internal(format!("own path: {err}")))?;
    // Before anything replaces the file it is read from.
    let current = self_digest();
    let temp = exe.with_extension(format!("{}.new", std::process::id()));
    let mut file = tokio::fs::File::create(&temp)
        .await
        .map_err(|err| Status::internal(format!("creating {}: {err}", temp.display())))?;
    let mut hasher = sha2::Sha256::new();
    let mut expected = String::new();
    let mut written = 0usize;
    while let Some(chunk) = stream.message().await? {
        if !chunk.digest.is_empty() {
            expected = chunk.digest;
        }
        hasher.update(&chunk.data);
        file.write_all(&chunk.data)
            .await
            .map_err(|err| Status::internal(format!("writing {}: {err}", temp.display())))?;
        written += chunk.data.len();
    }
    file.sync_all()
        .await
        .map_err(|err| Status::internal(format!("syncing {}: {err}", temp.display())))?;
    drop(file);
    let actual = hex_lower(&hasher.finalize());
    if written == 0 || expected.is_empty() || actual != expected {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(Status::invalid_argument(format!(
            "upgrade binary hashed as {actual}, expected {expected}"
        )));
    }
    if actual == current {
        let _ = tokio::fs::remove_file(&temp).await;
        return Ok(guestpb::UpgradeResponse {
            is_restarting: false,
        });
    }
    tokio::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
        .await
        .map_err(|err| Status::internal(format!("chmod {}: {err}", temp.display())))?;
    tokio::fs::rename(&temp, &exe)
        .await
        .map_err(|err| Status::internal(format!("installing {}: {err}", exe.display())))?;
    if let Err(err) = commands::save(COMMANDS_STATE) {
        tracing::warn!(%err, "command history will not survive the upgrade");
    }
    tracing::warn!(digest = actual, "agent upgrading; re-executing");
    // After the response has gone out, from a plain thread, for the same
    // reason as on Linux.
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let path =
            std::ffi::CString::new(exe.as_os_str().as_encoded_bytes()).expect("a path has no NUL");
        // SAFETY: setting an environment variable before exec, from a
        // thread that does nothing else.
        unsafe { std::env::set_var(REEXEC_MARK, "1") };
        if let Err(err) = fs::save(FS_STATE) {
            tracing::warn!(%err, "open file handles will not survive the upgrade");
        }
        let Err(err) = nix::unistd::execv(&path, &[path.as_c_str()]);
        tracing::error!(%err, "re-exec failed; the old agent keeps serving");
    });
    Ok(guestpb::UpgradeResponse {
        is_restarting: true,
    })
}

async fn serve() -> anyhow::Result<()> {
    let listener = vsock::Listener::bind(AGENT_PORT)?;
    tracing::debug!(
        port = AGENT_PORT,
        version = VERSION,
        "burrow-guest listening on vsock"
    );
    let incoming = async_stream::stream! {
        loop {
            let parked_since = std::time::Instant::now();
            match listener.accept().await {
                Ok((stream, cid)) if cid == HOST_CID => {
                    yield Ok::<_, std::io::Error>(vsock::VsockConn {
                        stream,
                        arrival: vsock::Arrival {
                            accepted_at: std::time::Instant::now(),
                            parked: parked_since.elapsed(),
                        },
                    })
                }
                // A process in this guest dialling the agent: its API runs
                // commands as root and is only meant for the host.
                Ok((_, cid)) => {
                    tracing::warn!(cid, "refusing a vsock connection that did not come from the host");
                }
                Err(err) => {
                    tracing::warn!(%err, "vsock accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    };
    Server::builder()
        .add_service(crate::agent::service())
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

pub fn main() {
    // launchd sends both streams to a log file, so no colour; `RUST_LOG` in
    // the plist raises the level.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    match std::env::args().nth(1).as_deref() {
        None => run(),
        Some("install") => {
            if let Err(err) = install::run() {
                eprintln!("burrow-guest install: {err:#}");
                std::process::exit(1);
            }
        }
        Some(other) => {
            eprintln!("usage: burrow-guest [install] (not {other:?})");
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn run() {
    self_digest();
    reaper::spawn();
    if std::env::var_os(REEXEC_MARK).is_some() {
        commands::restore(COMMANDS_STATE, exec::process_group);
        fs::restore(FS_STATE);
        tracing::warn!(
            version = VERSION,
            digest = self_digest(),
            "agent upgraded in place"
        );
    }
    tokio::spawn(fs::close_idle());
    // Exiting hands the restart to launchd's KeepAlive.
    if let Err(err) = serve().await {
        tracing::error!(%err, "agent server exited");
        std::process::exit(1);
    }
}
