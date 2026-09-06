//! The node's half of the edge: accepts forwarded sandbox traffic and splices
//! it into a guest.
//!
//! Guest addresses live behind per-node taps, on a range only their own node
//! routes, so the edge resolves a sandbox to a node and forwards the connection
//! here for the last hop.
//!
//! Traffic is spliced rather than parsed. The edge has already read enough of
//! the request to route it, and re-parsing here would break WebSocket upgrades,
//! streaming responses and anything that is not HTTP at all.
//!
//! The connection opens with a one-line prelude naming the sandbox, the port,
//! and the cluster token:
//!
//! ```text
//! BURROW/1 <token> <sandbox-id> <port>\n
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use burrow_core::edge::Prelude;

use crate::sandbox::SandboxManager;

/// Longest acceptable prelude. Generous for a sandbox id and a port, small
/// enough that a client that never sends a newline cannot grow a buffer.
const MAX_PRELUDE: usize = 512;

/// A peer that connects and says nothing is holding a slot for nothing.
const PRELUDE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct SandboxProxy {
    pub sandboxes: SandboxManager,
    /// Required in the prelude. `None` accepts any, matching the rest of the
    /// node API when no key is configured.
    pub cluster_token: Option<String>,
}

impl SandboxProxy {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, from) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(%err, "sandbox proxy accept failed");
                    continue;
                }
            };
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(err) = proxy.handle(stream, from).await {
                    tracing::debug!(%from, %err, "forwarded connection ended");
                }
            });
        }
    }

    async fn handle(&self, mut stream: TcpStream, from: SocketAddr) -> std::io::Result<()> {
        let prelude = tokio::time::timeout(PRELUDE_TIMEOUT, read_prelude(&mut stream))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "prelude timed out")
            })??;

        let Some(request) = Prelude::parse(&prelude) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed prelude",
            ));
        };
        if !token_matches(self.cluster_token.as_deref(), request.token) {
            // Deliberately terse: an unauthenticated peer learns nothing about
            // whether the sandbox exists.
            tracing::warn!(%from, "forwarded connection presented the wrong token");
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "bad token",
            ));
        }

        let sandbox = self
            .sandboxes
            .get(request.sandbox_id)
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))?;

        // A sandbox id is not a secret (it appears in URLs, logs, API
        // responses), and unlike the edge this proxy is reached whether or
        // not a cluster token is configured. Without this, knowing an id
        // would be enough to reach every TCP service inside a sandbox, not
        // only the ones it published.
        let ports = self.sandboxes.list_ports(request.sandbox_id).await;
        if !crate::edge::port_is_published(&ports, request.port) {
            tracing::warn!(
                sandbox = request.sandbox_id,
                port = request.port,
                %from,
                "forwarded connection named a port that is not published"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "port is not published",
            ));
        }

        // Traffic is use: a sandbox serving requests must not be reclaimed as
        // idle underneath the person using it.
        sandbox.touch();
        let target = SocketAddr::from((sandbox.lease.guest_ip, request.port));

        let mut upstream = TcpStream::connect(target).await?;
        tracing::debug!(
            sandbox = request.sandbox_id,
            %target,
            "forwarding to guest"
        );
        tokio::io::copy_bidirectional(&mut stream, &mut upstream)
            .await
            .map(|_| ())
    }
}

/// Whether a presented token satisfies the configured one. `None` accepts any.
fn token_matches(expected: Option<&str>, presented: &str) -> bool {
    match expected {
        None => true,
        Some(expected) => {
            burrow_core::auth::constant_time_eq(expected.as_bytes(), presented.as_bytes())
        }
    }
}

/// Reads the prelude one byte at a time.
///
/// A buffered reader would swallow whatever the client sent after the newline,
/// usually the first bytes of its HTTP request, and there is nowhere to put
/// them once the stream is handed to `copy_bidirectional`.
async fn read_prelude(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the prelude ended",
            ));
        }
        if byte[0] == b'\n' {
            return String::from_utf8(line).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "prelude is not utf-8")
            });
        }
        line.push(byte[0]);
        if line.len() > MAX_PRELUDE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "prelude too long",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_checked_when_one_is_configured() {
        assert!(token_matches(Some("secret"), "secret"));
        assert!(!token_matches(Some("secret"), "wrong"));
        assert!(!token_matches(Some("secret"), ""));
        // Unauthenticated nodes accept anything, like the rest of the node API.
        assert!(token_matches(None, "anything"));
    }
}
