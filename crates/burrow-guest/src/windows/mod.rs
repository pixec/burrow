//! The Windows agent.
//!
//! Runs as a Windows service, as LocalSystem, under QEMU with virtio-win's
//! drivers, and serves the node daemon over viosock. See the crate's
//! README for what maps onto what.

pub mod cmdline;
pub mod mode;
pub mod netcfg;

#[cfg(windows)]
pub mod exec;
#[cfg(windows)]
pub mod files;
#[cfg(windows)]
pub mod fs;
#[cfg(windows)]
mod handshake;
#[cfg(windows)]
mod nt;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod token;
#[cfg(windows)]
pub mod users;
#[cfg(windows)]
mod vsock;
#[cfg(windows)]
mod win;

#[cfg(windows)]
pub use handshake::handshake;
#[cfg(windows)]
pub use service::{main, upgrade};
#[cfg(windows)]
pub use vsock::Arrival;

/// What this agent does beyond the original protocol, for the health response.
#[cfg(windows)]
pub fn features() -> Vec<String> {
    vec![
        files::FEATURE_FILES_AS_USER.to_string(),
        "attach-input".to_string(),
        "output-feed".to_string(),
        fs::FEATURE_FS.to_string(),
    ]
}
