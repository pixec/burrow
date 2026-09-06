//! Host side of Firecracker's "hybrid" vsock.
//!
//! Firecracker does not expose a real `AF_VSOCK` socket to the host. Instead
//! the host connects to a Unix socket and speaks a short text handshake to say
//! which guest port it wants:
//!
//! ```text
//! host -> "CONNECT 1024\n"
//! guest <- "OK <assigned_host_port>\n"
//! ```
//!
//! After the `OK` line the stream is a plain byte pipe to the guest listener,
//! which is what gRPC runs over.
//!
//! Note that these connections do not survive a pause/snapshot cycle: always
//! reconnect after a resume rather than holding a channel across it.

use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::{Result, VmmError};

/// Generous bound on the `OK <port>` line; anything longer means the peer is
/// not speaking the handshake protocol.
const MAX_HANDSHAKE_LEN: usize = 64;

/// Connects through the hybrid vsock UDS to `port` inside the guest.
pub async fn connect(uds_path: &Path, port: u32) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(uds_path).await?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    stream.flush().await?;

    // Read the reply one byte at a time rather than through a BufReader.
    // The guest speaks first on this connection (a gRPC server emits its
    // HTTP/2 SETTINGS frame immediately), so any buffered read would swallow
    // the first frame of the real protocol and desynchronise the stream.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_HANDSHAKE_LEN {
            return Err(VmmError::VsockRejected {
                port,
                response: "handshake reply had no newline".into(),
            });
        }
    }

    let response = String::from_utf8_lossy(&line);
    let response = response.trim_end_matches('\r');
    if !response.starts_with("OK ") {
        return Err(VmmError::VsockRejected {
            port,
            response: response.to_string(),
        });
    }
    Ok(stream)
}
