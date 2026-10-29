use std::path::PathBuf;

use crate::Hypervisor;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("vmm api transport error: {0}")]
    Transport(#[from] hyper::Error),

    #[error("malformed request: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The VMM's API answered with a non-2xx status.
    #[error("vmm api {method} {path} failed ({status}): {body}")]
    Api {
        method: String,
        path: String,
        status: u16,
        body: String,
    },

    /// A snapshot that cannot be restored as asked.
    #[error("snapshot: {0}")]
    Snapshot(String),

    #[error("hypervisor binary not found at {0}")]
    BinaryNotFound(PathBuf),

    #[error("the vmm did not create its control socket at {path} within {timeout_ms}ms")]
    SocketTimeout { path: PathBuf, timeout_ms: u64 },

    #[error("the vmm exited during startup ({status}); last console output:\n{tail}")]
    EarlyExit { status: String, tail: String },

    #[error("timed out after {timeout_ms}ms waiting for {what}")]
    Timeout { what: String, timeout_ms: u64 },

    #[error("guest serial console is not writable for this vm")]
    ConsoleUnavailable,

    #[error("resource limits cannot be enforced: {reason}")]
    CgroupUnavailable { reason: String },

    #[error("vsock connect to guest port {port} rejected: {response}")]
    VsockRejected { port: u32, response: String },

    /// Asked of a backend whose [`crate::Capabilities`] say it cannot. The
    /// daemon checks first, so reaching this is a bug on its side rather than
    /// anything the guest did.
    #[error("{hypervisor} cannot {what}")]
    Unsupported {
        hypervisor: Hypervisor,
        what: &'static str,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
