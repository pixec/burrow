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
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::{Result, VmmError};

/// Generous bound on the `OK <port>` line; anything longer means the peer is
/// not speaking the handshake protocol.
const MAX_HANDSHAKE_LEN: usize = 64;

/// How long the guest gets to answer `CONNECT`.
///
/// Firecracker accepts the Unix socket the moment the VM is up, whether or not
/// anything inside the guest is listening, so a connect that succeeds proves
/// nothing until the reply arrives. A guest that accepts and then goes quiet
/// would otherwise park the caller on this read forever.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Connects through the hybrid vsock UDS to `port` inside the guest.
pub async fn connect(uds_path: &Path, port: u32) -> Result<UnixStream> {
    connect_within(uds_path, port, HANDSHAKE_TIMEOUT).await
}

/// [`connect`], with the handshake bounded by `timeout` rather than by
/// [`HANDSHAKE_TIMEOUT`].
pub async fn connect_within(uds_path: &Path, port: u32, timeout: Duration) -> Result<UnixStream> {
    tokio::time::timeout(timeout, handshake(uds_path, port))
        .await
        .map_err(|_| VmmError::Timeout {
            what: format!("guest vsock port {port} handshake"),
            timeout_ms: timeout.as_millis() as u64,
        })?
}

async fn handshake(uds_path: &Path, port: u32) -> Result<UnixStream> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Firecracker's UDS accepts before anything in the guest is listening, so
    /// a peer that accepts and then says nothing is the shape of a wedged
    /// guest. Without a bound on the reply this read never returns.
    #[tokio::test]
    async fn a_peer_that_never_speaks_does_not_wedge_the_caller() {
        let dir = std::env::temp_dir().join(format!("burrow-vsock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("silent.sock");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let _accepting = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let err = connect_within(&path, 1024, Duration::from_millis(50))
            .await
            .expect_err("a silent peer has to time out");
        assert!(
            matches!(err, VmmError::Timeout { .. }),
            "expected a timeout, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The stream is left positioned right after the `OK` line rather than
    /// having swallowed the guest's first protocol bytes.
    #[tokio::test]
    async fn a_handshake_that_answers_yields_the_stream() {
        let dir = std::env::temp_dir().join(format!("burrow-vsock-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ok.sock");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 13];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"OK 4242\nPAYLOAD").await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut stream = connect_within(&path, 1024, Duration::from_secs(5))
            .await
            .expect("the peer answered");
        let mut rest = [0u8; 7];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"PAYLOAD");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
