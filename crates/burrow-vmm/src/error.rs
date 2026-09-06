use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("firecracker api transport error: {0}")]
    Transport(#[from] hyper::Error),

    #[error("malformed request: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Firecracker answered with a non-2xx status.
    #[error("firecracker api {method} {path} failed ({status}): {body}")]
    Api {
        method: String,
        path: String,
        status: u16,
        body: String,
    },

    #[error("firecracker binary not found at {0}")]
    BinaryNotFound(PathBuf),

    #[error("firecracker did not create its api socket at {path} within {timeout_ms}ms")]
    SocketTimeout { path: PathBuf, timeout_ms: u64 },

    #[error("firecracker exited during startup ({status}); last console output:\n{tail}")]
    EarlyExit { status: String, tail: String },

    #[error("timed out after {timeout_ms}ms waiting for {what}")]
    Timeout { what: String, timeout_ms: u64 },

    #[error("guest serial console is not writable for this vm")]
    ConsoleUnavailable,

    #[error("resource limits cannot be enforced: {reason}")]
    CgroupUnavailable { reason: String },

    #[error("vsock connect to guest port {port} rejected: {response}")]
    VsockRejected { port: u32, response: String },
}

pub type Result<T> = std::result::Result<T, VmmError>;
