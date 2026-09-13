//! The node's own edge router: serves `<port>-<sandbox-id>.<domain>` for the
//! sandboxes this node holds, and nothing else.
//!
//! This is the only edge. Routing published-port traffic through the control
//! plane would make it a bandwidth bottleneck and a single point of failure for
//! traffic that is not control traffic.
//!
//! Sandboxes are node-pinned, so a node-scoped hostname stays correct for a
//! sandbox's whole life and a client that resolves it lands where the sandbox
//! already is. That is what makes this listener possible at all: there is no
//! registry lookup, no forwarding prelude and no second hop, and a request for
//! a sandbox this node does not hold is a 404. A node serving no edge has no
//! hostname routing, and its published ports are reachable at the node address
//! alone.
//!
//! A connection carries one request, because the hostname in that request is
//! what chose the sandbox; see [`relay`].
//!
//! Reading the head, validating it and rewriting it so a guest sees the real
//! client belong to [`burrow_core::edge`], whose tests check that faithfulness.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use burrow_core::edge::{Cidr, Exchange, Routed, Target, read_response_head, respond, route};
use burrow_proto::common::v1 as common;

use crate::sandbox::SandboxManager;

pub struct NodeEdge {
    pub sandboxes: SandboxManager,
    /// Suffix stripped from `Host` before parsing, e.g. `.node-a.example.com`.
    /// A node's own, not the orchestrator's: the record has to resolve to this
    /// node, so the name has to be one this node alone answers for.
    pub domain: String,
    /// Peers whose forwarding headers are believed. Empty trusts nothing, which
    /// is the only safe default: anything else has to be an operator saying
    /// that this edge is unreachable except through those addresses.
    pub trusted_proxies: Vec<Cidr>,
}

impl NodeEdge {
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(%err, "node edge accept failed");
                    continue;
                }
            };
            let edge = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(err) = edge.handle(stream, peer.ip()).await {
                    tracing::debug!(%err, "node edge connection ended");
                }
            });
        }
    }

    async fn handle(&self, mut client: TcpStream, peer: std::net::IpAddr) -> std::io::Result<()> {
        // Routed before the sandbox is looked up, so a head that cannot be
        // forwarded does not first wake a suspended sandbox.
        let forward = match route(&mut client, peer, &self.domain, &self.trusted_proxies).await? {
            Routed::Forward(forward) => forward,
            Routed::Refused { status, message } => {
                return respond(&mut client, status, message).await;
            }
        };

        let guest = match self.resolve(&forward.target).await {
            Ok(guest) => guest,
            Err(Refusal { status, message }) => {
                return respond(&mut client, status, &message).await;
            }
        };

        let mut upstream = TcpStream::connect(guest).await?;
        // No prelude: the sandbox proxy's one exists to name a sandbox to a
        // node that has not resolved it. This end already has the guest.
        upstream.write_all(&forward.head).await?;

        tracing::debug!(
            sandbox = forward.target.sandbox_id,
            %guest,
            "node edge forwarded a connection"
        );
        relay(&mut client, &mut upstream, &forward.exchange).await
    }

    /// The guest address to splice into, resuming a suspended sandbox first.
    async fn resolve(&self, target: &Target) -> Result<SocketAddr, Refusal> {
        // A sandbox this node does not hold is a 404 and stops here: the
        // hostname named this node, and this node is where it would be.
        let sandbox = self
            .sandboxes
            .get(&target.sandbox_id)
            .await
            .map_err(|_| Refusal::new(404, format!("no sandbox {} here", target.sandbox_id)))?;

        // The edge is documented as serving "a published guest port", not any
        // port the caller cares to name: a sandbox id is not a secret (it
        // appears in URLs, logs, API responses), so treating every guest port
        // as reachable this way would make "publish a port" decorative rather
        // than a boundary. Checked before the sandbox is woken, so naming an
        // unpublished port cannot be used to wake a parked tenant either.
        let ports = self.sandboxes.list_ports(&target.sandbox_id).await;
        if !port_is_published(&ports, target.port) {
            return Err(Refusal::new(
                404,
                format!(
                    "sandbox {} has no published port {}",
                    target.sandbox_id, target.port
                ),
            ));
        }

        if sandbox.record().state == common::SandboxState::Suspended as i32 {
            // Traffic for a parked sandbox is a request to wake it. Without
            // this, idle suspension would silently break every published port.
            tracing::info!(
                sandbox = sandbox.id(),
                "resuming a suspended sandbox for inbound traffic"
            );
            self.sandboxes
                .resume(&target.sandbox_id)
                .await
                .map_err(|err| {
                    Refusal::new(
                        502,
                        format!("could not resume {}: {}", target.sandbox_id, err.message()),
                    )
                })?;
        }

        // Traffic is use: a sandbox serving requests must not be reclaimed as
        // idle underneath the person using it.
        sandbox.touch();
        Ok(SocketAddr::from((sandbox.lease.guest_ip, target.port)))
    }
}

/// Relays one request and its answer, and nothing else.
///
/// A connection is routed by the hostname in its first request, so a second
/// request on the same connection would reach the sandbox the first one chose,
/// whatever hostname it carried. A reverse proxy in front pools connections per
/// upstream, so that second request is routinely another tenant's.
///
/// Two things keep it to one. The head carries `Connection: close`, so the guest
/// ends the connection after answering, and that close is what ends the copy of
/// the response: the edge never has to find a response boundary it does not
/// parse. And the client is read only as far as its own request body, so bytes
/// pipelined behind it are never delivered to a guest at all.
///
/// An upgrade is the exception, because a `101` is one request that never ends.
/// Only the guest can say whether it is one, and that answer cannot be read once
/// a blind copy is draining the same socket, so it is read here first.
async fn relay<C, U>(client: &mut C, upstream: &mut U, exchange: &Exchange) -> std::io::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    if exchange.upgrade {
        let (head, status) = read_response_head(&mut upstream_read).await?;
        client_write.write_all(&head).await?;
        if status != 101 {
            // Not an upgrade after all, so the connection is still a sequence
            // of requests and this one has had its answer. The write half is
            // closed so the guest finishes and lets go, since it was not told
            // to close; nothing further from the client goes upstream.
            let _ = upstream_write.shutdown().await;
            tokio::io::copy(&mut upstream_read, &mut client_write).await?;
            let _ = client_write.shutdown().await;
            return Ok(());
        }
    }

    // A tunnel's bytes are the one request that never ends. Anything past an
    // ordinary request's body is a second request, and this connection belongs
    // to the sandbox the first one named.
    let allowance = if exchange.upgrade {
        u64::MAX
    } else {
        exchange.body
    };
    let mut request = tokio::io::AsyncReadExt::take(client_read, allowance);

    let upward = async {
        let moved = tokio::io::copy(&mut request, &mut upstream_write).await;
        if exchange.upgrade {
            // The client half of a tunnel has ended, which the guest is
            // entitled to see. Not done for an ordinary request: a guest that
            // reads EOF before it has answered is entitled to abandon it.
            let _ = upstream_write.shutdown().await;
        }
        moved
    };
    let downward = async {
        let moved = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
        moved
    };
    let (up, down) = tokio::join!(upward, downward);
    up.and(down).map(|_| ())
}

/// Whether `guest_port` is one of a sandbox's published ports.
///
/// `ports` is `(host_port, guest_port)` pairs, exactly as
/// [`crate::sandbox::SandboxManager::list_ports`] returns them. Shared with
/// [`crate::sandboxproxy`], which forwards traffic too and needs the same
/// check.
pub(crate) fn port_is_published(ports: &[burrow_net::PortMap], guest_port: u16) -> bool {
    ports
        .iter()
        .any(|port| port.guest_port == guest_port && port.protocol == burrow_net::Protocol::Tcp)
}

/// An answer the edge gives instead of a guest.
struct Refusal {
    status: u16,
    message: String,
}

impl Refusal {
    fn new(status: u16, message: String) -> Self {
        Self { status, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A node edge serving no sandboxes: enough for the answers that never
    /// reach a guest.
    fn empty_edge(domain: &str) -> Arc<NodeEdge> {
        Arc::new(NodeEdge {
            sandboxes: crate::sandbox::tests::manager(),
            domain: domain.into(),
            trusted_proxies: Vec::new(),
        })
    }

    async fn ask(edge: Arc<NodeEdge>, host: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(edge.serve(listener));

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut answer = String::new();
        client.read_to_string(&mut answer).await.unwrap();
        answer
    }

    fn published(
        host_port: u16,
        guest_port: u16,
        protocol: burrow_net::Protocol,
    ) -> burrow_net::PortMap {
        burrow_net::PortMap {
            host_port,
            guest_port,
            protocol,
        }
    }

    /// The edge must not treat every guest port as reachable just because
    /// the hostname names it, only a port the sandbox actually published.
    /// A UDP mapping is not one of them: the edge carries HTTP, so routing to
    /// it would splice an HTTP request into a port serving datagrams.
    #[test]
    fn only_a_published_tcp_port_is_reachable() {
        use burrow_net::Protocol;
        let ports = [
            published(20005, 8080, Protocol::Tcp),
            published(20006, 22, Protocol::Tcp),
            published(20007, 5353, Protocol::Udp),
        ];
        assert!(port_is_published(&ports, 8080));
        assert!(port_is_published(&ports, 22));
        assert!(!port_is_published(&ports, 6379));
        assert!(!port_is_published(&ports, 5353));
        assert!(!port_is_published(&[], 8080));
    }

    /// The whole point of the node edge: it answers for its own sandboxes and
    /// does not go looking for anyone else's.
    #[tokio::test]
    async fn a_sandbox_this_node_does_not_hold_is_a_404() {
        let answer = ask(
            empty_edge("node-a.local"),
            "8000-sbx_elsewhere.node-a.local",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n"), "{answer}");
        assert!(answer.contains("no sandbox sbx_elsewhere here"), "{answer}");
    }

    #[tokio::test]
    async fn a_hostname_outside_the_domain_is_a_404() {
        let answer = ask(empty_edge("node-a.local"), "evil.example.com").await;
        assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n"), "{answer}");
    }

    /// A stand-in guest: answers with `answer` once it has a head, and reports
    /// everything it was sent.
    fn guest(answer: &'static str) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<String>) {
        let (mut guest, upstream) = tokio::io::duplex(16 * 1024);
        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                match guest.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => seen.extend_from_slice(&buf[..read]),
                }
            }
            let _ = guest.write_all(answer.as_bytes()).await;
            // Anything else the edge forwards has to be waited for, or a test
            // that asserts nothing followed would pass by racing.
            let more =
                tokio::time::timeout(std::time::Duration::from_millis(200), guest.read(&mut buf))
                    .await;
            if let Ok(Ok(read)) = more {
                seen.extend_from_slice(&buf[..read]);
            }
            drop(guest);
            String::from_utf8_lossy(&seen).into_owned()
        });
        (upstream, handle)
    }

    /// Relays as [`NodeEdge::handle`] does: the head is already forwarded, and
    /// `pending` is what the client had sent behind it.
    ///
    /// Returns what the guest saw and what the client was answered.
    async fn relayed(
        head: &'static str,
        pending: &'static str,
        exchange: Exchange,
        answer: &'static str,
    ) -> (String, String) {
        let (mut upstream, guest) = guest(answer);
        let (mut caller, mut client) = tokio::io::duplex(16 * 1024);
        upstream.write_all(head.as_bytes()).await.unwrap();
        caller.write_all(pending.as_bytes()).await.unwrap();

        let relaying = tokio::spawn(async move {
            let _ = relay(&mut client, &mut upstream, &exchange).await;
        });
        let mut answered = Vec::new();
        caller.read_to_end(&mut answered).await.unwrap();
        // The client half of a tunnel is the test itself, and a tunnel ends
        // when both halves do.
        drop(caller);
        relaying.await.unwrap();
        (
            guest.await.unwrap(),
            String::from_utf8_lossy(&answered).into_owned(),
        )
    }

    /// The cross-tenant bug: a second request on the connection names another
    /// sandbox, and the connection was routed by the first. It must not reach
    /// the guest the first one chose.
    #[tokio::test]
    async fn a_second_request_never_reaches_the_first_sandboxs_guest() {
        let (seen, answered) = relayed(
            "GET /a HTTP/1.1\r\nHost: 8000-sbx_a.node-a.local\r\nConnection: close\r\n\r\n",
            "GET /b HTTP/1.1\r\nHost: 8000-sbx_b.node-a.local\r\n\r\n",
            Exchange {
                body: 0,
                upgrade: false,
            },
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
        )
        .await;

        assert!(seen.contains("GET /a "), "{seen}");
        assert!(
            !seen.contains("sbx_b"),
            "the second request reached a guest:\n{seen}"
        );
        assert!(answered.starts_with("HTTP/1.1 200 OK\r\n"), "{answered}");
        assert!(answered.ends_with("\r\n\r\na"), "{answered}");
    }

    /// An ordinary request still works, body and all, and ends when the guest
    /// closes after answering it.
    #[tokio::test]
    async fn a_request_with_a_body_is_relayed_whole() {
        let (seen, answered) = relayed(
            "POST / HTTP/1.1\r\nHost: 8000-sbx_a.node-a.local\r\n\
             Content-Length: 5\r\nConnection: close\r\n\r\n",
            "hello",
            Exchange {
                body: 5,
                upgrade: false,
            },
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .await;

        assert!(seen.ends_with("hello"), "{seen}");
        assert!(answered.ends_with("\r\n\r\nok"), "{answered}");
    }

    /// A `101` is one request that never ends, so the tunnel keeps carrying
    /// bytes in both directions after it.
    #[tokio::test]
    async fn an_upgrade_still_tunnels_both_ways() {
        let (seen, answered) = relayed(
            "GET /ws HTTP/1.1\r\nHost: 8000-sbx_a.node-a.local\r\n\
             Upgrade: websocket\r\nConnection: upgrade\r\n\r\n",
            "FRAME",
            Exchange {
                body: 0,
                upgrade: true,
            },
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\n\r\n",
        )
        .await;

        assert!(
            answered.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "{answered}"
        );
        assert!(seen.ends_with("FRAME"), "{seen}");
    }

    /// A guest that declines the upgrade answered an ordinary request, so the
    /// connection is not a tunnel and carries nothing more.
    #[tokio::test]
    async fn a_declined_upgrade_carries_nothing_further() {
        let (seen, answered) = relayed(
            "GET /ws HTTP/1.1\r\nHost: 8000-sbx_a.node-a.local\r\n\
             Upgrade: websocket\r\nConnection: upgrade\r\n\r\n",
            "GET /b HTTP/1.1\r\nHost: 8000-sbx_b.node-a.local\r\n\r\n",
            Exchange {
                body: 0,
                upgrade: true,
            },
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nno",
        )
        .await;

        assert!(!seen.contains("sbx_b"), "{seen}");
        assert!(answered.starts_with("HTTP/1.1 200 OK\r\n"), "{answered}");
        assert!(answered.ends_with("no"), "{answered}");
    }
}
