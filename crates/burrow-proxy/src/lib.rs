//! Transparent egress proxy.
//!
//! Sandboxes in allowlist mode have their outbound TCP redirected here by
//! nftables. Because the redirect rewrites the destination, the original one
//! is recovered with `SO_ORIGINAL_DST`; the requested hostname comes from the
//! TLS SNI or the HTTP Host header. Only once both are known does the proxy
//! decide whether to open the upstream connection, so a denied request never
//! reaches its destination at all.
//!
//! TLS is not terminated by default: burrow sees the hostname, never the
//! payload. That keeps sandbox traffic private and avoids distributing a CA
//! into guests, at the cost of not seeing request bodies, nor a request that
//! names one host in its SNI and another inside the session. A sandbox may opt
//! in to inspection, which closes that gap by terminating TLS; see [`inspect`].

pub mod audit;
pub mod directory;
pub mod dns;
pub mod forward;
pub mod http;
pub mod http2;
pub mod inspect;
pub mod policy;
pub mod resolutions;
pub mod sni;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

pub use audit::{AuditLog, EgressEvent};
pub use dns::Resolver;
pub use policy::{Decision, NetworkMode, PolicyTable, SandboxPolicy};
pub use resolutions::{DeniedAddresses, Resolutions};

/// Longest first-flight read used to identify the destination. A ClientHello
/// is comfortably under this; anything larger is not something we can classify
/// anyway.
const PEEK_LIMIT: usize = 8 * 1024;
const PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// How many connections are relayed at once.
///
/// Each carries buffers and two sockets, and a sandbox can open them far
/// faster than it uses them. Beyond this the backlog waits in the kernel,
/// which is where an unserved connection is cheapest.
const MAX_CONNECTIONS: usize = 1024;
/// How many of those one sandbox may hold at once.
///
/// The global limit is shared, not divided: a single sandbox opening
/// connections in a loop would take every slot and the proxy would stop
/// serving its neighbours. Generous enough for a browser or a package manager
/// fanning out, and far below the global ceiling.
const MAX_CONNECTIONS_PER_SOURCE: usize = 96;

/// How long the upstream TCP connection may take to establish.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long the two TLS handshakes of an inspected session may take between
/// them.
///
/// One deadline covers both: the sandbox's handshake is not started until the
/// server's has finished, so a peer that stalls either half holds the same
/// task, the same two sockets and the same connection slot. Without it a
/// server that accepts and then says nothing pins those indefinitely, which a
/// sandbox can arrange by connecting to a host it controls.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-source connection counts, enforcing [`MAX_CONNECTIONS_PER_SOURCE`].
///
/// Keyed by source address, which under the transparent redirect is the guest
/// address and therefore the sandbox: it is assigned by burrow and anti-spoofed
/// in the firewall, so a guest cannot claim another sandbox's budget by forging
/// one.
#[derive(Default)]
struct SourceLimits {
    counts: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>,
}

impl SourceLimits {
    /// Claims a slot for `source`, or `None` if that sandbox is already at its
    /// limit.
    fn acquire(self: &Arc<Self>, source: std::net::IpAddr) -> Option<SourceSlot> {
        let mut counts = self.counts.lock().unwrap();
        let held = counts.entry(source).or_insert(0);
        if *held >= MAX_CONNECTIONS_PER_SOURCE {
            return None;
        }
        *held += 1;
        Some(SourceSlot {
            limits: Arc::clone(self),
            source,
        })
    }
}

/// Releases a source's slot when the connection ends, however it ends.
struct SourceSlot {
    limits: Arc<SourceLimits>,
    source: std::net::IpAddr,
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut counts = self.limits.counts.lock().unwrap();
        // The entry is removed at zero rather than left at zero, so a node
        // that has served many short-lived sandboxes does not accumulate a map
        // entry per recycled address.
        if let std::collections::hash_map::Entry::Occupied(mut entry) = counts.entry(self.source) {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }
}

pub struct Proxy {
    pub policies: Arc<PolicyTable>,
    pub audit: AuditLog,
    /// What the resolver told each sandbox. A hostname alone is a claim; this
    /// is what makes it checkable.
    pub resolutions: Arc<Resolutions>,
    /// Signs the certificates presented to sandboxes that opted in to having
    /// their TLS inspected. `None` disables inspection entirely.
    pub authority: Option<Arc<inspect::Authority>>,
    /// This deployment's control-plane addresses, which the firewall denies to
    /// every sandbox and the proxy must therefore deny too. Kept in step by
    /// the daemon, which renders the same set into the ruleset.
    pub denied: Arc<DeniedAddresses>,
}

impl Proxy {
    /// Serves until the listener fails. Each connection is handled
    /// independently; one sandbox's misbehaviour cannot stall another's.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        let per_source = Arc::new(SourceLimits::default());
        loop {
            // Claimed before accepting: at the limit new connections stay in
            // the listen backlog instead of becoming tasks holding buffers.
            let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
                return;
            };
            let (client, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(%err, "proxy accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            // Refused rather than queued: the sandbox is over its own budget,
            // and making it wait would hold the global slot it is not entitled
            // to. A source that cannot be attributed to a sandbox is dropped,
            // the same way `handle` refuses to serve one.
            // Counted against the unmapped address, so a sandbox cannot get
            // two budgets by reaching the proxy over both of its addresses.
            let Some(source_slot) = per_source.acquire(policy::unmap(peer.ip())) else {
                tracing::warn!(%peer, "refusing a connection: source is at its limit");
                continue;
            };
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                let _slot = slot;
                let _source_slot = source_slot;
                if let Err(err) = proxy.handle(client, peer).await {
                    tracing::debug!(%peer, %err, "proxy connection ended");
                }
            });
        }
    }

    async fn handle(&self, client: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        let original = original_dst(&client)?;
        // Read (without consuming) enough to identify the destination. A
        // client that says nothing, or too little, gets no route: we cannot
        // police what we cannot classify.
        let mut buf = vec![0u8; PEEK_LIMIT];
        let n = peek_head(&client, &mut buf, original.port()).await;
        self.relay(client, peer, original, &buf[..n]).await
    }

    /// Serves one connection that a userspace network stack terminated, whose
    /// destination it already knows.
    ///
    /// The same decision and relay as a redirected socket gets. There is no
    /// `peek` on an arbitrary stream, so the head is read off it and replayed
    /// ahead of the rest, which leaves the relay seeing the bytes a peek would
    /// have left in place. `peer` is the guest's address, which is how the
    /// sandbox is looked up in [`Self::policies`].
    pub async fn serve_stream<C>(
        &self,
        mut client: C,
        peer: SocketAddr,
        original: SocketAddr,
    ) -> std::io::Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let head = read_head(&mut client, original.port()).await;
        let client = Rewound {
            head: head.clone(),
            at: 0,
            inner: client,
        };
        self.relay(client, peer, original, &head).await
    }

    /// Decides one connection from `source_ip` to `original`, whose first
    /// bytes are `head`, before anything is dialled.
    ///
    /// Everything the proxy knows before the upstream connection exists is
    /// decided here: who the sandbox is, which host the connection names,
    /// whether it may go there at all, and whether its TLS is terminated.
    fn admit(&self, source_ip: std::net::IpAddr, original: SocketAddr, head: &[u8]) -> Admission {
        // ECH hides the real destination behind a cover name. Reading that
        // cover name and checking it against the allowlist is worse than
        // reading nothing, so it is tracked separately and refused below.
        let mut hides_destination = false;
        // What the sandbox is willing to speak, which is what an inspected
        // session negotiates upstream with.
        let mut offered: Vec<String> = Vec::new();
        let host = match original.port() {
            443 => match sni::parse_client_hello(head) {
                Some(hello) => {
                    hides_destination = hello.is_hello_encrypted;
                    offered = hello.alpn;
                    hello.server_name
                }
                None => None,
            },
            80 => sni::parse_http_host(head),
            _ => None,
        };

        let (policy, mut decision) = self.policies.decide(source_ip, host.as_deref());
        // `decide` already denied an unknown source; the default only stands
        // in so the checks below need not each handle its absence.
        let policy = policy.unwrap_or_default();
        // Checked on the address alone, before anything about the hostname:
        // the proxy runs on the host and so sits outside the sandbox chain
        // that denies these, and a connection here needs no name at all to
        // reach one. Ahead of the pinning check too, since a control-plane
        // address a sandbox was legitimately told about is still one it may
        // not reach.
        if self.denied.is_denied(original.ip()) {
            decision = Decision::Deny("destination is a control-plane address");
        }
        // The policy's own address-level denials, port and family, for the
        // same reason: they hold whatever name the connection carries. The
        // host firewall drops these everywhere it can; 80 and 443 in
        // allowlist mode reach here instead, and are refused and recorded.
        if let Some(reason) = policy.address_refusal(original) {
            decision = Decision::Deny(reason);
        }
        if hides_destination {
            // The visible name is a cover name, so there is nothing here an
            // allowlist can decide.
            decision = Decision::Deny("client hello encrypts its destination (ECH)");
        }
        // The outer name is checked and the address pinned, but neither sees
        // the host named *inside* the session. A sandbox that asked for
        // inspection has its TLS terminated here so that host is checked too.
        //
        // In open mode only the hosts its live rules name are inspected. The
        // node redirects nothing else here, but an address can serve more than
        // one name, and a rule can expire or be removed between the lookup
        // that set up the redirect and this connection: either way the
        // connection is open mode's ordinary egress, relayed without being
        // terminated.
        let is_open = policy.mode == NetworkMode::Open;
        let inspecting = original.port() == 443
            && self.authority.is_some()
            && host
                .as_deref()
                .is_some_and(|host| policy.is_inspected(host));
        // A bounded host is reachable only for the requests its rules admit,
        // and a connection nothing here will read carries requests nothing
        // here can judge. Refused rather than passed through blind.
        if decision.is_allowed()
            && let Some(host) = host.as_deref()
            && policy.is_bounded(host)
            && !inspecting
            && original.port() != 80
        {
            decision = Decision::Deny("bounded host requires inspection");
        }

        // A hostname is what the client says; the address is where it is
        // actually going. Allowing on the former while connecting to the
        // latter is what turns a domain allowlist into no restriction at all.
        //
        // Open mode pins only the sessions it inspects, which carry a
        // credential: those must go to an address the resolver gave this
        // sandbox for that name. A connection it merely relays is held to the
        // denials open mode always has and nothing more, as it would have been
        // had it never been redirected.
        if decision.is_allowed()
            && let Some(host) = host.as_deref()
            && (!is_open || inspecting)
        {
            let destination = policy::unmap(original.ip());
            // Deny beats every allowance, and it is checked against the address
            // rather than the name: an allowlisted domain that resolves into a
            // denied range must not be reachable through the proxy either, or
            // the nftables denial is only half a denial.
            if policy.is_denied(destination) {
                decision = Decision::Deny("destination is in a denied range");
            } else if resolutions::is_forbidden_destination(destination) {
                decision = Decision::Deny("destination is an internal or metadata address");
            } else if !self
                .resolutions
                .is_pinned(policy.sandbox_id.as_str(), host, destination)
            {
                decision = Decision::Deny("destination address is not pinned to this name");
            }
        }
        if decision.is_allowed() && is_open && !inspecting {
            let destination = policy::unmap(original.ip());
            if policy.is_denied(destination) {
                decision = Decision::Deny("destination is in a denied range");
            } else if resolutions::is_forbidden_destination(destination) {
                decision = Decision::Deny("destination is an internal or metadata address");
            }
        }

        Admission {
            policy,
            decision,
            host,
            offered,
            inspecting,
            is_open,
        }
    }

    async fn relay<C>(
        &self,
        mut client: C,
        peer: SocketAddr,
        original: SocketAddr,
        head: &[u8],
    ) -> std::io::Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Both families reach here now. A source is looked up as itself, and
        // an IPv4-mapped one as the v4 address it is, so a sandbox is the same
        // sandbox whichever shape its address arrives in.
        let source_ip = policy::unmap(peer.ip());
        let Admission {
            policy,
            decision,
            host,
            offered,
            inspecting,
            is_open,
        } = self.admit(source_ip, original, head);
        let sandbox_id = policy.sandbox_id.clone();

        if !decision.is_allowed() {
            self.audit.record(EgressEvent {
                at_ms: burrow_common::unix_now_ms(),
                sandbox_id,
                source_ip: source_ip.to_string(),
                destination: original.to_string(),
                host,
                port: original.port(),
                is_allowed: false,
                reason: decision.reason().to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                dropped_records: 0,
            });
            return Ok(());
        }

        // Bounded, because the connection slot and the sandbox's own budget
        // are held for as long as this takes: a destination that accepts SYNs
        // and never completes would otherwise hold both until the kernel gave
        // up, minutes later.
        let connected = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_marked(original, policy.egress_mark),
        )
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream did not answer in time",
            ))
        });
        let mut upstream = match connected {
            Ok(stream) => stream,
            Err(err) => {
                self.audit.record(EgressEvent {
                    at_ms: burrow_common::unix_now_ms(),
                    sandbox_id,
                    source_ip: source_ip.to_string(),
                    destination: original.to_string(),
                    host,
                    port: original.port(),
                    is_allowed: true,
                    reason: format!("upstream connect failed: {err}"),
                    bytes_sent: 0,
                    bytes_received: 0,
                    dropped_records: 0,
                });
                return Err(err);
            }
        };

        if inspecting && let Some(sni) = host.clone() {
            // An HTTP/2 session multiplexes requests that each name their own
            // host and each get their own decision, so each is recorded on its
            // own rather than summarised into the connection's record.
            let audit_stream = {
                let log = self.audit.clone();
                let sandbox_id = sandbox_id.clone();
                let source = source_ip.to_string();
                let destination = original.to_string();
                let port = original.port();
                Arc::new(move |outcome: http2::StreamOutcome| {
                    log.record(EgressEvent {
                        at_ms: burrow_common::unix_now_ms(),
                        sandbox_id: sandbox_id.clone(),
                        source_ip: source.clone(),
                        destination: destination.clone(),
                        host: outcome.host,
                        port,
                        is_allowed: outcome.is_allowed,
                        reason: outcome.reason,
                        bytes_sent: outcome.sent,
                        bytes_received: outcome.received,
                        dropped_records: 0,
                    });
                }) as Arc<dyn Fn(http2::StreamOutcome) + Send + Sync>
            };
            let outcome = self
                .inspect_tls(
                    client,
                    upstream,
                    Inspection {
                        sni: &sni,
                        policy: &policy,
                        sandbox_id: &sandbox_id,
                        offered: &offered,
                        audit_stream,
                    },
                )
                .await;
            // A refusal partway through a keep-alive session still moved the
            // bytes of the requests that came before it; reporting zero would
            // hide traffic that actually left.
            let (allowed_inner, reason, sent, received) = match outcome {
                Ok(relayed) => (
                    relayed.refusal.is_none(),
                    relayed
                        .refusal
                        .or(relayed.note)
                        .unwrap_or_else(|| "allowed (inspected)".to_string()),
                    relayed.sent,
                    relayed.received,
                ),
                Err(refusal) => (false, refusal, 0, 0),
            };
            self.audit.record(EgressEvent {
                at_ms: burrow_common::unix_now_ms(),
                sandbox_id,
                source_ip: source_ip.to_string(),
                destination: original.to_string(),
                host: Some(sni),
                port: original.port(),
                is_allowed: allowed_inner,
                reason,
                bytes_sent: sent,
                bytes_received: received,
                dropped_records: 0,
            });
            return Ok(());
        }

        // Plaintext HTTP gets the same treatment as an inspected session: a
        // keep-alive connection carries many requests, and checking only the
        // first would let the rest name any host the same server fronts.
        // Without TLS there is no session identity to pin them to, but every
        // request must still be allowlisted.
        if original.port() == 80 {
            let relayed = self
                .relay_http(
                    &mut client,
                    &mut upstream,
                    host.as_deref(),
                    &policy,
                    false,
                    false,
                )
                .await;
            self.audit.record(EgressEvent {
                at_ms: burrow_common::unix_now_ms(),
                sandbox_id,
                source_ip: source_ip.to_string(),
                destination: original.to_string(),
                host,
                port: original.port(),
                is_allowed: relayed.refusal.is_none(),
                reason: relayed.refusal.unwrap_or_else(|| "allowed".to_string()),
                bytes_sent: relayed.sent,
                bytes_received: relayed.received,
                dropped_records: 0,
            });
            return Ok(());
        }

        let (sent, received) = tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .unwrap_or((0, 0));

        self.audit.record(EgressEvent {
            at_ms: burrow_common::unix_now_ms(),
            sandbox_id,
            source_ip: source_ip.to_string(),
            destination: original.to_string(),
            host,
            port: original.port(),
            is_allowed: true,
            reason: if is_open {
                "allowed (not inspected: no live rule names this host)".into()
            } else {
                "allowed".into()
            },
            bytes_sent: sent,
            bytes_received: received,
            dropped_records: 0,
        });
        Ok(())
    }
}

impl Proxy {
    /// Relays HTTP, checking the host of **every** request on the connection.
    ///
    /// Keep-alive carries many requests down one connection, each naming its
    /// own host. Checking the first and splicing the rest would let a sandbox
    /// open a connection to an allowed host and then ask that same server for
    /// anything else it fronts.
    ///
    /// `require_match` additionally pins every request to the name the
    /// connection was opened for, which is what an inspected TLS session
    /// needs: two allowed names behind one address are still two names.
    ///
    /// `is_ruled` applies the policy's rules to a request that passed those
    /// checks. They are applied afterwards, so a rule can only change what a
    /// permitted request carries; it can never widen what is permitted. They
    /// are read afresh for every request, so a rule removed or expired while
    /// the connection is open stops applying at the next request on it.
    ///
    /// Only rules that leave the request pointed at the origin are relayable
    /// here. A session where any rule could divert one is served by
    /// [`Self::relay_diverted`] instead, because a response that comes from
    /// somewhere other than `upstream` cannot be written down a socket a blind
    /// copy is already draining.
    async fn relay_http<C, U>(
        &self,
        client: &mut C,
        upstream: &mut U,
        opened_for: Option<&str>,
        policy: &policy::SandboxPolicy,
        require_match: bool,
        is_ruled: bool,
    ) -> Relayed
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let (client_read, mut client_write) = tokio::io::split(client);
        let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
        // The buffers live here, spanning head parsing and body forwarding, so
        // bytes read while looking for the end of one are still there for the
        // other. Handing a raw half to a copy would lose them.
        let mut client_read = http::Buffered::new(client_read);
        let mut upstream_read = http::Buffered::new(upstream_read);

        let mut sent = 0u64;
        let mut received = 0u64;
        let mut refusal: Option<String> = None;
        let applied = std::sync::Mutex::new(Applied::default());
        let rules_now = || {
            if is_ruled {
                policy.current_rules()
            } else {
                Arc::new(Vec::new())
            }
        };

        // The first request is handled before anything copies the response
        // direction. An upgrade is only real once the server answers `101`, and
        // that answer cannot be read while a blind copy drains the same socket,
        // so before the response pump starts is the only place to judge one.
        let first = async {
            let Some(head) = client_read.read_head().await? else {
                return Ok(First::Closed);
            };
            let parsed = check_request(&head, policy, opened_for, require_match)?;
            let head = apply_rules(head, &parsed, &rules_now(), &applied)?;
            upstream_write
                .write_all(&head)
                .await
                .map_err(|err| format!("forwarding a request: {err}"))?;
            sent += head.len() as u64;
            // The body is forwarded by its ordinary framing whether or not an
            // upgrade was asked for. Letting `Upgrade` override the framing is
            // what let a `Content-Length` body be read as a second request.
            sent += client_read
                .forward_body(&mut upstream_write, &parsed.framing)
                .await?;
            if !parsed.is_upgrade_requested {
                return Ok(First::Continue);
            }

            let (response, status) = http::read_response_head(&mut upstream_read).await?;
            client_write
                .write_all(&response)
                .await
                .map_err(|err| format!("answering the sandbox: {err}"))?;
            received += response.len() as u64;
            // Only `101 Switching Protocols` actually leaves HTTP behind. Any
            // other status and this is still a sequence of requests, every one
            // of which still has to be checked.
            Ok(if status == 101 {
                First::Upgraded
            } else {
                First::Continue
            })
        }
        .await;

        match first {
            Err(reason) => {
                write_refusal(&mut client_write).await;
                refusal = Some(reason);
            }
            Ok(First::Closed) => {}
            Ok(First::Upgraded) => {
                // The server agreed to switch protocols, so nothing further
                // can be framed as a request. The one request that opened the
                // tunnel was checked, and the destination is fixed for the
                // rest of the connection.
                let upward = async {
                    let moved = client_read.copy_all(&mut upstream_write).await;
                    let _ = upstream_write.shutdown().await;
                    moved
                };
                let downward = async {
                    let moved = upstream_read.copy_all(&mut client_write).await;
                    let _ = client_write.shutdown().await;
                    moved
                };
                let (up, down) = tokio::join!(upward, downward);
                sent += up;
                received += down;
            }
            Ok(First::Continue) => {
                let requests = async {
                    let mut moved = 0u64;
                    let outcome = loop {
                        let head = match client_read.read_head().await {
                            Ok(Some(head)) => head,
                            Ok(None) => break Ok(()),
                            Err(err) => break Err(err),
                        };
                        let parsed = match check_request(&head, policy, opened_for, require_match) {
                            Ok(parsed) => parsed,
                            Err(reason) => break Err(reason),
                        };
                        // Upgrading here would mean judging the server's answer
                        // while the response direction is already being copied
                        // blind. Refused rather than tunnelled unchecked.
                        if parsed.is_upgrade_requested {
                            break Err(
                                "an upgrade after the first request is not relayed".to_string()
                            );
                        }
                        let head = match apply_rules(head, &parsed, &rules_now(), &applied) {
                            Ok(head) => head,
                            Err(reason) => break Err(reason),
                        };
                        if let Err(err) = upstream_write.write_all(&head).await {
                            break Err(format!("forwarding a request: {err}"));
                        }
                        moved += head.len() as u64;
                        match client_read
                            .forward_body(&mut upstream_write, &parsed.framing)
                            .await
                        {
                            Ok(body) => moved += body,
                            Err(err) => break Err(err),
                        }
                    };

                    // Closing the write half lets the server finish its
                    // response, which is what ends the copy running alongside
                    // this.
                    let _ = upstream_write.shutdown().await;
                    match outcome {
                        Ok(()) => Ok(moved),
                        Err(reason) => Err((moved, reason)),
                    }
                };

                // Responses need no inspection: policy is about where a request
                // goes. Run alongside rather than spawned, so neither half has
                // to outlive the borrowed streams.
                let downstream = upstream_read.copy_all(&mut client_write);

                let (outcome, moved) = tokio::join!(requests, downstream);
                match outcome {
                    Ok(body) => sent += body,
                    Err((body, reason)) => {
                        sent += body;
                        write_refusal(&mut client_write).await;
                        refusal = Some(reason);
                    }
                }
                received += moved;
            }
        }

        Relayed {
            sent,
            received,
            refusal,
            note: applied.into_inner().unwrap().note(),
        }
    }

    /// Terminates the sandbox's TLS, checks the inner host, and relays.
    ///
    /// Returns the bytes moved, or the reason the request was refused.
    async fn inspect_tls<C>(
        &self,
        client: C,
        upstream: TcpStream,
        session: Inspection<'_>,
    ) -> Result<Relayed, String>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let Inspection {
            sni,
            policy,
            sandbox_id,
            offered,
            audit_stream,
        } = session;
        // Rules go only down the inspected path: acting on a request means
        // reading it, and outside an inspected session there is no request to
        // read. Read here only to choose the relay; each request reads them
        // again.
        let rules = policy.current_rules();
        let authority = self
            .authority
            .as_ref()
            .ok_or("inspection is not configured")?;

        // Two independent TLS sessions: one to the sandbox using a certificate
        // burrow signed, one to the real server with ordinary verification. The
        // upstream half verifies for real, or inspecting would become a way to
        // accept certificates the sandbox would have rejected.
        //
        // Only the two protocols the relay can police are forwarded from the
        // sandbox's offer. A client that offered nothing gets HTTP/1.1.
        let mut alpn: Vec<Vec<u8>> = offered
            .iter()
            .filter(|name| name.as_str() == "h2" || name.as_str() == "http/1.1")
            .map(|name| name.as_bytes().to_vec())
            .collect();
        let unrestricted = alpn.is_empty();
        if unrestricted {
            alpn = vec![b"http/1.1".to_vec()];
        }

        // One deadline for both handshakes: they run one after the other on
        // this task, holding both sockets and the sandbox's connection budget,
        // so a peer that stalls either half costs the same either way.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

        let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
            .map_err(|err| format!("{sni} is not a usable server name: {err}"))?;
        let mut outer = tokio::time::timeout_at(
            deadline,
            tokio_rustls::TlsConnector::from(inspect::verified_client(alpn))
                .connect(server_name, upstream),
        )
        .await
        .map_err(|_| "tls handshake with the server timed out".to_string())?
        .map_err(|err| format!("tls handshake with the server failed: {err}"))?;

        let negotiated = outer.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let protocol = match negotiated.as_deref() {
            Some(b"h2") => inspect::Protocol::H2,
            Some(b"http/1.1") => inspect::Protocol::Http11,
            // An origin that ignored the extension entirely. Relayable only
            // where HTTP/1.1 is something the sandbox was willing to speak.
            None if unrestricted || offered.iter().any(|name| name == "http/1.1") => {
                inspect::Protocol::Http11
            }
            // Either a protocol nothing here can police, or none the sandbox
            // asked for. Refused rather than silently downgraded.
            _ => return Err("the server offers no protocol the sandbox can be relayed".into()),
        };

        let server_config = authority
            .server_config(sni, protocol)
            .map_err(|err| err.to_string())?;
        let mut inner = tokio::time::timeout_at(
            deadline,
            tokio_rustls::TlsAcceptor::from(server_config).accept(client),
        )
        .await
        .map_err(|_| "tls handshake with the sandbox timed out".to_string())?
        .map_err(|err| format!("tls handshake with the sandbox failed: {err}"))?;

        // Every request in the session is checked, not merely the first, and
        // each is pinned to the name the session was opened for.
        match protocol {
            // A session whose rules could take a request away from the origin
            // is served one request at a time: the answer may come from
            // somewhere `upstream` is not, and there is no writing that down a
            // socket a blind copy is already draining.
            inspect::Protocol::Http11 if rules.iter().any(policy::Rule::is_diverted) => Ok(self
                .relay_diverted(&mut inner, &mut outer, sni, policy, sandbox_id)
                .await),
            inspect::Protocol::Http11 => Ok(self
                .relay_http(&mut inner, &mut outer, Some(sni), policy, true, true)
                .await),
            inspect::Protocol::H2 => {
                http2::relay(inner, outer, sni, policy, sandbox_id, audit_stream).await
            }
        }
    }

    /// Relays one request on a session whose rules may divert it.
    ///
    /// Exactly one, and then the connection ends. The response direction of an
    /// ordinary relay is a blind copy from the origin, and a forwarded
    /// request's answer does not come from there, so the connection carries one
    /// request and the origin is asked to close after it. The cost is a
    /// connection per request for sandboxes whose policy forwards.
    async fn relay_diverted<C, U>(
        &self,
        client: &mut C,
        upstream: &mut U,
        opened_for: &str,
        policy: &policy::SandboxPolicy,
        sandbox_id: &str,
    ) -> Relayed
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let rules = policy.current_rules();
        let applied = std::sync::Mutex::new(Applied::default());

        let (client_read, mut client_write) = tokio::io::split(client);
        let (upstream_read, mut upstream_write) = tokio::io::split(upstream);
        let mut client_read = http::Buffered::new(client_read);
        let mut upstream_read = http::Buffered::new(upstream_read);

        let mut sent = 0u64;
        let mut received = 0u64;
        let mut note = None;

        let outcome = async {
            let Some(head) = client_read.read_head().await? else {
                return Ok(());
            };
            let parsed = check_request(&head, policy, Some(opened_for), true)?;
            // An upgrade leaves HTTP behind, and what follows could not be
            // matched against a rule that may forward it. Refused rather than
            // tunnelled past the rule.
            if parsed.is_upgrade_requested {
                return Err("an upgrade is not relayed on a connection that may forward".into());
            }
            let host = parsed.host.clone().unwrap_or_default();
            let facts = parsed.facts();

            match select_rule(&rules, &host, &facts) {
                Some(policy::Action::Refuse(reason)) => return Err(reason.clone()),
                Some(policy::Action::Forward(forward)) => {
                    let body = client_read
                        .read_body_whole(&parsed.framing, forward::MAX_BODY)
                        .await?;
                    sent += body.len() as u64;
                    let body = bytes::Bytes::from(body);
                    let answer = forward::send(
                        forward,
                        &parsed.method,
                        &parsed.headers,
                        body,
                        forward::Origin {
                            host: &host,
                            scheme: "https",
                            port: 443,
                            target: &parsed.origin_form(),
                            sandbox_id,
                        },
                    )
                    .await?;
                    note = Some(format!("forwarded to {}", forward.url));
                    received += write_forwarded(&mut client_write, answer).await?;
                    return Ok(());
                }
                Some(policy::Action::SetHeaders(_)) | None => {}
            }

            // Not diverted, so it goes to the origin, with the connection
            // closed after it so the blind copy of the response can end.
            let head = apply_rules(head, &parsed, &rules, &applied)?;
            let head =
                http::inject_headers(&head, &[("Connection", "close")]).map_err(str::to_string)?;
            upstream_write
                .write_all(&head)
                .await
                .map_err(|err| format!("forwarding a request: {err}"))?;
            sent += head.len() as u64;
            sent += client_read
                .forward_body(&mut upstream_write, &parsed.framing)
                .await?;
            // Not shut down first: closing the write half of a TLS session
            // sends close_notify, and an origin that reads it before it has
            // answered is entitled to stop. `Connection: close` is what ends
            // the copy below, and it is the origin's own decision.
            received += upstream_read.copy_all(&mut client_write).await;
            Ok(())
        }
        .await;

        if outcome.is_err() {
            write_refusal(&mut client_write).await;
        }
        let _ = client_write.shutdown().await;
        Relayed {
            sent,
            received,
            refusal: outcome.err(),
            note: note.or_else(|| applied.into_inner().unwrap().note()),
        }
    }
}

/// Answers a refused request with `403`, so the client learns the request was
/// refused rather than seeing its connection vanish. Nothing further is sent
/// on the connection, which is what `Connection: close` tells it.
async fn write_refusal<W>(to: &mut W)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let _ = to
        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
}

/// Writes a forwarded answer back to the sandbox as HTTP/1.1.
///
/// Framed by closing the connection: the body arrives decoded, so the origin's
/// own `Content-Length` and `Transfer-Encoding` describe bytes that are not
/// these, and re-deriving a length would mean buffering a response whole.
async fn write_forwarded<W>(to: &mut W, mut answer: forward::Answer) -> Result<u64, String>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let reason = answer.status.canonical_reason().unwrap_or("");
    let mut head = format!("HTTP/1.1 {} {reason}\r\n", answer.status.as_u16());
    for (name, value) in answer.headers.iter() {
        let name = name.as_str();
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    to.write_all(head.as_bytes())
        .await
        .map_err(|err| format!("answering the sandbox: {err}"))?;

    let mut moved = 0u64;
    while let Some(chunk) = forward::next_chunk(&mut answer.body).await? {
        moved += chunk.len() as u64;
        to.write_all(&chunk)
            .await
            .map_err(|err| format!("answering the sandbox: {err}"))?;
    }
    Ok(moved)
}

/// What one inspected session is judged against.
///
/// Gathered from the sandbox's policy at the point the connection was allowed,
/// so the relay decides against the policy that was in force when the session
/// opened rather than re-reading a table that may have changed underneath it.
struct Inspection<'a> {
    /// The name the session was opened for. Every request inside it must name
    /// this host: two allowed names behind one address are still two names.
    sni: &'a str,
    /// Also carries what happens to the requests inside the session, in
    /// policy order.
    policy: &'a policy::SandboxPolicy,
    /// Stamped onto forwarded requests, so the endpoint knows whose request it
    /// is looking at.
    sandbox_id: &'a str,
    /// The ALPN list the sandbox put in its ClientHello.
    ///
    /// The origin chooses from exactly this list and the sandbox is offered
    /// only what the origin chose, so both halves speak the same version of
    /// HTTP and no request is translated between HTTP/1.1 and HTTP/2 on the
    /// policy path. A sandbox that offered only `h2` to an origin that does not
    /// speak it is refused rather than silently downgraded.
    offered: &'a [String],
    /// Records one HTTP/2 stream. Unused on the HTTP/1.1 path, where the
    /// connection's own record already describes every request on it.
    audit_stream: Arc<dyn Fn(http2::StreamOutcome) + Send + Sync>,
}

/// What [`Proxy::admit`] decided about a connection.
struct Admission {
    policy: policy::SandboxPolicy,
    decision: Decision,
    /// The name the connection carries: the SNI on 443, `Host` on 80.
    host: Option<String>,
    /// The ALPN list the sandbox put in its ClientHello.
    offered: Vec<String>,
    /// Whether its TLS is terminated and its requests read.
    inspecting: bool,
    /// Whether the sandbox is in open mode, where a connection the proxy does
    /// not inspect is relayed as plain egress.
    is_open: bool,
}

/// What a relayed connection moved, and why it stopped if it was refused.
///
/// Byte counts are reported whether or not the connection ended in a refusal:
/// a session that carried three allowed requests and then asked for a fourth
/// host really did move those three requests' bytes.
struct Relayed {
    sent: u64,
    received: u64,
    refusal: Option<String>,
    /// What to record as the connection's reason when it was not refused.
    ///
    /// An HTTP/2 connection audits each stream separately, since they name
    /// their own hosts and get their own decisions, so its own record says how
    /// many there were rather than repeating one of them.
    note: Option<String>,
}

/// How the first request on a connection ended.
enum First {
    /// The client closed without sending one.
    Closed,
    /// The server answered `101`; the rest of the connection is not HTTP.
    Upgraded,
    /// Ordinary request; keep reading requests.
    Continue,
}

/// Parses a request head and checks the host it names against policy.
///
/// The one gate every request passes through, first or not, inspected or
/// plaintext.
fn check_request(
    head: &[u8],
    policy: &policy::SandboxPolicy,
    opened_for: Option<&str>,
    require_match: bool,
) -> Result<http::RequestHead, String> {
    let text = std::str::from_utf8(head).map_err(|_| "request head is not text".to_string())?;
    let parsed = http::parse_head(text).map_err(|err| err.to_string())?;
    let Some(host) = parsed.host.clone() else {
        return Err("request has no Host header".into());
    };
    // An absolute-form target names its own authority, which is what a
    // recipient fronting more than one name routes on, not necessarily the
    // `Host` header this function is about to check. Left unreconciled,
    // that's a second, unchecked place to send this request.
    if let Some(target_host) = http::target_authority(&parsed.target) {
        match target_host {
            Some(target_host) if target_host.eq_ignore_ascii_case(&host) => {}
            Some(target_host) => {
                return Err(format!(
                    "request-target authority does not match Host ({target_host} vs {host})"
                ));
            }
            None => return Err("malformed request-target authority".into()),
        }
    }
    let verdict = match opened_for {
        // An inspected session is pinned to the name it was opened for: two
        // allowed names behind one address are still two names.
        Some(name) if require_match => inspect::inner_host_allowed(name, &host, policy),
        _ => inspect::host_allowed(policy, &host),
    };
    verdict.map_err(|reason| format!("{reason} ({host})"))?;
    let (path, _) = parsed.path_and_query();
    policy.check_request(&host, &parsed.method, path)?;
    Ok(parsed)
}

/// Applies the rule that governs this request, if one does.
///
/// The host is the one [`check_request`] just validated, so a rule can never
/// widen access: it only decides what a permitted request carries.
fn apply_rules(
    head: Vec<u8>,
    parsed: &http::RequestHead,
    rules: &[policy::Rule],
    applied: &std::sync::Mutex<Applied>,
) -> Result<Vec<u8>, String> {
    // The target's authority was checked against Host in `check_request`, but
    // an upstream that honours absolute-form still routes on it, not on
    // `Host`, so it's rewritten to origin-form regardless of whether any
    // rule matches, not only on the branches that happen to rebuild the head.
    let head = if http::target_authority(&parsed.target).is_some() {
        http::normalize_absolute_target(&head, &parsed.origin_form()).map_err(str::to_string)?
    } else {
        head
    };
    if rules.is_empty() {
        return Ok(head);
    }
    let host = parsed.host.as_deref().unwrap_or_default();
    let facts = parsed.facts();
    let selected = select_rule_at(rules, host, &facts, policy::now_unix_ms());
    applied.lock().unwrap().request(selected);
    match selected.map(|(_, rule)| &rule.action) {
        // Matching nothing is not a refusal. The request goes as it was
        // written (origin-form normalization above aside), which is the
        // whole difference between a matcher and a filter.
        None => Ok(head),
        Some(policy::Action::SetHeaders(headers)) => {
            let set: Vec<(&str, &str)> = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            http::inject_headers(&head, &set).map_err(|err| err.to_string())
        }
        // This relay has no second destination to write to. Reached only when a
        // request names a host the session was not opened for, which the
        // inspected path already refuses; refused here too rather than sent to
        // the origin the rule said it must not reach.
        Some(policy::Action::Forward(forward)) => Err(format!(
            "a request that must be forwarded to {} cannot be relayed on this connection",
            forward.url
        )),
        Some(policy::Action::Refuse(reason)) => Err(reason.clone()),
    }
}

/// The action for one request, or nothing if no rule claims it.
pub(crate) fn select_rule<'a>(
    rules: &'a [policy::Rule],
    host: &str,
    facts: &policy::Request<'_>,
) -> Option<&'a policy::Action> {
    select_rule_at(rules, host, facts, policy::now_unix_ms()).map(|(_, rule)| &rule.action)
}

/// The rule that claims one request at `now_ms`, with its position in the
/// policy. An expired rule claims nothing, so the next one that matches does.
pub(crate) fn select_rule_at<'a>(
    rules: &'a [policy::Rule],
    host: &str,
    facts: &policy::Request<'_>,
    now_ms: u64,
) -> Option<(usize, &'a policy::Rule)> {
    rules.iter().enumerate().find(|(_, rule)| {
        rule.is_live_at(now_ms)
            && burrow_common::glob::is_host_match(&rule.domain, host)
            && rule
                .matcher
                .as_ref()
                .is_none_or(|matcher| matcher.is_match(facts))
    })
}

/// Which rules set headers on how many of a connection's requests, for its
/// audit record. A brokered credential is the one thing the proxy adds to
/// traffic, so where it went has to be visible afterwards.
#[derive(Default)]
struct Applied {
    requests: u64,
    /// Rule position, its domain, and how many requests it set headers on.
    by_rule: Vec<(usize, String, u64)>,
}

impl Applied {
    fn request(&mut self, selected: Option<(usize, &policy::Rule)>) {
        self.requests += 1;
        let Some((index, rule)) = selected else {
            return;
        };
        if !matches!(rule.action, policy::Action::SetHeaders(_)) {
            return;
        }
        match self.by_rule.iter_mut().find(|(at, _, _)| *at == index) {
            Some((_, _, count)) => *count += 1,
            None => self.by_rule.push((index, rule.domain.clone(), 1)),
        }
    }

    fn note(&self) -> Option<String> {
        if self.by_rule.is_empty() {
            return None;
        }
        let rules: Vec<String> = self
            .by_rule
            .iter()
            .map(|(index, domain, count)| format!("rule {index} ({domain}) on {count}"))
            .collect();
        Some(format!(
            "allowed (inspected); headers set by {} of {} requests",
            rules.join(", "),
            self.requests
        ))
    }
}

/// The audit note for one HTTP/2 stream a rule set headers on.
pub(crate) fn applied_note(index: usize, rule: &policy::Rule) -> String {
    format!(
        "allowed (inspected); headers set by rule {index} ({})",
        rule.domain
    )
}

/// Peeks until there is enough to classify the connection, or [`PEEK_TIMEOUT`]
/// runs out.
///
/// One read is not enough: a ClientHello or a request head can arrive split
/// across segments, and classifying half of one means missing the name it
/// carries. Returns how many bytes are buffered, which may be too few to
/// classify, and that is a denial rather than a guess.
async fn peek_head(client: &TcpStream, buf: &mut [u8], port: u16) -> usize {
    let deadline = tokio::time::Instant::now() + PEEK_TIMEOUT;
    let mut backoff = std::time::Duration::from_millis(2);
    let mut best = 0;
    loop {
        match tokio::time::timeout_at(deadline, client.peek(buf)).await {
            Ok(Ok(0)) => return best,
            Ok(Ok(n)) => {
                best = n;
                if n == buf.len() || is_classifiable(port, &buf[..n]) {
                    return n;
                }
            }
            _ => return best,
        }
        // `peek` returns whatever has already arrived rather than waiting for
        // more, so the only way to let the rest turn up is to come back for it.
        if tokio::time::timeout_at(deadline, tokio::time::sleep(backoff))
            .await
            .is_err()
        {
            return best;
        }
        backoff = (backoff * 2).min(std::time::Duration::from_millis(50));
    }
}

/// [`peek_head`] for a stream that cannot be peeked: reads until there is
/// enough to classify, or [`PEEK_TIMEOUT`] runs out, and returns what it read.
async fn read_head<C>(client: &mut C, port: u16) -> Vec<u8>
where
    C: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let deadline = tokio::time::Instant::now() + PEEK_TIMEOUT;
    let mut head = Vec::with_capacity(PEEK_LIMIT);
    let mut chunk = [0u8; 2048];
    // Nothing read is not a verdict, whatever the parser makes of no bytes.
    while head.len() < PEEK_LIMIT && (head.is_empty() || !is_classifiable(port, &head)) {
        let room = (PEEK_LIMIT - head.len()).min(chunk.len());
        match tokio::time::timeout_at(deadline, client.read(&mut chunk[..room])).await {
            Ok(Ok(n)) if n > 0 => head.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    head
}

/// A stream with bytes already read off it put back in front.
struct Rewound<C> {
    head: Vec<u8>,
    at: usize,
    inner: C,
}

impl<C: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Rewound<C> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.at < self.head.len() {
            let n = (self.head.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.head[at..at + n]);
            self.at += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<C: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Rewound<C> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Whether `head` holds enough for the parser on this port to reach a verdict.
fn is_classifiable(port: u16, head: &[u8]) -> bool {
    match port {
        443 => {
            // The whole ClientHello, not merely the first record: a hello may
            // be split across records, and stopping at the end of the first
            // one would classify a fragment whose extensions had not arrived,
            // which is a split the sandbox chooses.
            //
            // `Malformed` counts as classifiable: no amount of waiting turns
            // it into a hello, and the parser will refuse it.
            !matches!(sni::reassemble_handshake(head), sni::Handshake::Incomplete)
        }
        80 => head.windows(4).any(|window| window == b"\r\n\r\n"),
        _ => !head.is_empty(),
    }
}

/// `SOL_IP`, which libc does not re-export on every target.
const SOL_IP: nix::libc::c_int = 0;
/// Linux's `SO_ORIGINAL_DST`: netfilter stashes the pre-redirect destination
/// here. Not in libc for all targets, so it is spelled out.
const SO_ORIGINAL_DST: nix::libc::c_int = 80;
/// `SOL_IPV6`, and netfilter's v6 spelling of the same option. The number is
/// shared with the v4 one but the level is not, and asking the wrong level
/// returns the wrong answer rather than an error.
const SOL_IPV6: nix::libc::c_int = 41;
const IP6T_SO_ORIGINAL_DST: nix::libc::c_int = 80;

/// Recovers the address the client was originally connecting to, before
/// nftables redirected the connection here.
fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    // The option is per family and the kernel answers only the one the socket
    // belongs to, so which to ask is decided by the connection, not guessed.
    if is_ipv4_request(stream.local_addr()?) {
        original_dst_v4(stream)
    } else {
        original_dst_v6(stream)
    }
}

/// Whether a connection whose local address is `local` carries its original
/// destination under the IPv4 option.
///
/// The listener is dual stack, so an IPv4 connection arrives on an IPv6 socket
/// and reports a v4-mapped local address. The kernel answers only the option
/// for the family the packet was really in: asking IPv6 for a mapped
/// connection fails, and the connection then dies before any policy decision
/// is made or audited, which reads as the destination being unreachable.
fn is_ipv4_request(local: SocketAddr) -> bool {
    match local {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(local) => local.ip().to_ipv4_mapped().is_some(),
    }
}

fn original_dst_v4(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut addr: nix::libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<nix::libc::sockaddr_in>() as nix::libc::socklen_t;

    // SAFETY: `addr` and `len` are correctly sized for SO_ORIGINAL_DST on an
    // IPv4 socket, and `fd` is owned by the live `stream`.
    let rc = unsafe {
        nix::libc::getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            (&raw mut addr).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SocketAddr::from((
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    )))
}

fn original_dst_v6(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut addr: nix::libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<nix::libc::sockaddr_in6>() as nix::libc::socklen_t;

    // SAFETY: as above, sized for the v6 option on an IPv6 socket.
    let rc = unsafe {
        nix::libc::getsockopt(
            fd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            (&raw mut addr).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SocketAddr::from((
        std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
        u16::from_be(addr.sin6_port),
    )))
}

/// Dials `address`, marking the socket first when `mark` is set: a sandbox
/// with a public address has its upstream connections translated to it by
/// the node, which knows them by the mark.
async fn connect_marked(address: SocketAddr, mark: u32) -> std::io::Result<TcpStream> {
    if mark == 0 {
        return TcpStream::connect(address).await;
    }
    let socket = match address {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    #[cfg(target_os = "linux")]
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::Mark, &mark)
        .map_err(std::io::Error::from)?;
    socket.connect(address).await
}

pub fn unix_now_ms() -> i64 {
    burrow_common::unix_now_ms()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn proxy() -> Proxy {
        Proxy {
            policies: Arc::new(PolicyTable::default()),
            audit: AuditLog::new(
                std::env::temp_dir().join("burrow-proxy-test-audit.jsonl"),
                None,
            ),
            resolutions: Arc::new(resolutions::Resolutions::default()),
            authority: None,
            denied: Arc::new(DeniedAddresses::default()),
        }
    }

    /// Relays `request` as an inspected session would and returns what the
    /// upstream server received.
    async fn relayed(request: &[u8], rules: Vec<policy::Rule>) -> String {
        let (mut sandbox, client) = tokio::io::duplex(8 * 1024);
        let (mut server, mut upstream) = tokio::io::duplex(8 * 1024);
        sandbox.write_all(request).await.unwrap();
        sandbox.shutdown().await.unwrap();

        let mut client = client;
        let allowed = policy::SandboxPolicy {
            rules: Arc::new(rules),
            ..policy::SandboxPolicy::allowing(&["api.example.com", "other.example"])
        };
        let relay = tokio::spawn(async move {
            let proxy = proxy();
            proxy
                .relay_http(
                    &mut client,
                    &mut upstream,
                    Some("api.example.com"),
                    &allowed,
                    false,
                    true,
                )
                .await
        });

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        drop(server);
        let outcome = relay.await.unwrap();
        assert!(outcome.refusal.is_none(), "{:?}", outcome.refusal);
        String::from_utf8(received).unwrap()
    }

    fn rule(domain: &str, name: &str, value: &str) -> policy::Rule {
        policy::Rule {
            domain: domain.into(),
            expires_at_unix_ms: 0,
            matcher: None,
            action: policy::Action::SetHeaders(vec![(name.to_string(), value.to_string())]),
        }
    }

    /// The same rule, narrowed to the requests a matcher selects.
    fn matched(
        domain: &str,
        name: &str,
        value: &str,
        matcher: policy::RequestMatch,
    ) -> policy::Rule {
        policy::Rule {
            domain: domain.into(),
            expires_at_unix_ms: 0,
            matcher: Some(matcher),
            action: policy::Action::SetHeaders(vec![(name.to_string(), value.to_string())]),
        }
    }

    /// The credential is added on the way out and the guest's own attempt at
    /// the same header does not survive, so sandbox code can neither read the
    /// secret nor forge it.
    #[tokio::test]
    async fn a_matching_request_carries_the_brokered_credential() {
        let request =
            b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer forged\r\n\r\n";
        let seen = relayed(
            request,
            vec![rule("api.example.com", "Authorization", "Bearer real")],
        )
        .await;

        assert!(seen.contains("Authorization: Bearer real\r\n"));
        assert!(!seen.contains("forged"));
        assert!(seen.contains("Host: api.example.com\r\n"));
    }

    /// An absolute-form target whose authority disagrees with `Host` is a
    /// routing split waiting to happen on any recipient that honours
    /// absolute-form: refused rather than forwarded on the strength of
    /// `Host` alone.
    #[test]
    fn absolute_form_authority_disagreeing_with_host_is_refused() {
        let head = b"GET http://evil.example/path HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let allowed = policy::SandboxPolicy::allowing(&["api.example.com"]);
        let err = check_request(head, &allowed, None, false).unwrap_err();
        assert!(err.contains("does not match Host"), "{err}");
    }

    /// An absolute-form target that does agree with `Host` is allowed, but
    /// rewritten to origin-form before it reaches the upstream: the upstream
    /// must not be handed a second authority to route on, even one that
    /// matched.
    #[tokio::test]
    async fn matching_absolute_form_target_is_normalized_before_forwarding() {
        let request =
            b"GET http://api.example.com/v1?a=1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let seen = relayed(request, vec![]).await;
        assert!(seen.starts_with("GET /v1?a=1 HTTP/1.1\r\n"), "{seen}");
        assert!(!seen.contains("http://"), "{seen}");
    }

    /// The point of a matcher: the credential goes on the requests the rule
    /// selected and on no others, and the others still succeed.
    #[tokio::test]
    async fn a_matcher_narrows_which_requests_carry_the_credential() {
        let matcher = policy::RequestMatch {
            path: Some(policy::Match::compile(policy::MatchOp::StartsWith, "/v1/").unwrap()),
            methods: vec!["GET".into()],
            ..Default::default()
        };
        let requests = concat!(
            "GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            "GET /v2/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            "POST /v1/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
        );
        let seen = relayed(
            requests.as_bytes(),
            vec![matched(
                "api.example.com",
                "Authorization",
                "Bearer real",
                matcher,
            )],
        )
        .await;

        // Only the one request the matcher selected carries it, and the two it
        // did not select were relayed unchanged rather than refused.
        assert_eq!(seen.matches("Authorization: Bearer real").count(), 1);
        let heads: Vec<&str> = seen.split("\r\n\r\n").collect();
        assert!(heads[0].contains("/v1/users") && heads[0].contains("Authorization"));
        assert!(heads[1].contains("/v2/users") && !heads[1].contains("Authorization"));
        assert!(heads[2].contains("POST") && !heads[2].contains("Authorization"));
    }

    /// A rule with no matcher matches everything, so nothing after it for the
    /// same domain is ever reached.
    #[tokio::test]
    async fn a_rule_without_a_matcher_shadows_the_rules_after_it() {
        let narrow = policy::RequestMatch {
            path: Some(policy::Match::compile(policy::MatchOp::Exact, "/v1").unwrap()),
            ..Default::default()
        };
        let seen = relayed(
            b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            vec![
                rule("api.example.com", "X-Wide", "wide"),
                matched("api.example.com", "X-Narrow", "narrow", narrow),
            ],
        )
        .await;
        assert!(seen.contains("X-Wide: wide"));
        assert!(!seen.contains("X-Narrow"));
    }

    /// An endpoint that answers one forwarded request and reports its head.
    async fn forward_endpoint() -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = socket.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..read]);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Gate: yes\r\n\r\nok")
                .await
                .unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        (address, handle)
    }

    /// The forwarded request reaches the operator's endpoint, carrying where it
    /// came from and never reaching the origin the sandbox named.
    #[tokio::test]
    async fn a_forwarded_request_arrives_stamped_with_where_it_came_from() {
        let (address, endpoint) = forward_endpoint().await;
        let url = format!("http://127.0.0.1:{}/gate", address.port());
        let forward = policy::Rule {
            domain: "api.example.com".into(),
            expires_at_unix_ms: 0,
            matcher: None,
            action: policy::Action::Forward(policy::Forward {
                target: policy::ForwardTarget::parse(&url).unwrap(),
                url: url.clone(),
                secret: "shared".into(),
            }),
        };

        let (mut sandbox, mut client) = tokio::io::duplex(8 * 1024);
        let (mut origin, mut upstream) = tokio::io::duplex(8 * 1024);
        // A header in the reserved prefix, forged by the guest.
        sandbox
            .write_all(
                b"GET /v1/users?a=1 HTTP/1.1\r\nHost: api.example.com\r\n\
                  burrow-forwarded-sandbox: someone-else\r\n\r\n",
            )
            .await
            .unwrap();

        let policy = policy::SandboxPolicy {
            rules: Arc::new(vec![forward]),
            ..policy::SandboxPolicy::allowing(&["api.example.com"])
        };
        let relay = tokio::spawn(async move {
            proxy()
                .relay_diverted(
                    &mut client,
                    &mut upstream,
                    "api.example.com",
                    &policy,
                    "sbx-1",
                )
                .await
        });

        let mut answer = Vec::new();
        sandbox.read_to_end(&mut answer).await.unwrap();
        let answer = String::from_utf8(answer).unwrap();
        let outcome = relay.await.unwrap();
        assert!(outcome.refusal.is_none(), "{:?}", outcome.refusal);
        assert_eq!(outcome.note, Some(format!("forwarded to {url}")));

        let seen = endpoint.await.unwrap();
        assert!(
            seen.starts_with("GET /gate/v1/users?a=1 HTTP/1.1\r\n"),
            "{seen}"
        );
        assert!(
            seen.contains("burrow-forwarded-host: api.example.com\r\n"),
            "{seen}"
        );
        assert!(seen.contains("burrow-forwarded-scheme: https\r\n"));
        assert!(seen.contains("burrow-forwarded-port: 443\r\n"));
        assert!(seen.contains("burrow-forwarded-path: /v1/users?a=1\r\n"));
        assert!(seen.contains("burrow-forwarded-secret: shared\r\n"));
        // The guest's forged claim did not survive.
        assert!(
            seen.contains("burrow-forwarded-sandbox: sbx-1\r\n"),
            "{seen}"
        );
        assert!(!seen.contains("someone-else"));

        // The endpoint's answer is what the sandbox sees, and nothing was
        // written to the origin.
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.contains("x-gate: yes") || answer.contains("X-Gate: yes"));
        assert!(answer.ends_with("\r\n\r\nok"));
        let mut to_origin = Vec::new();
        origin.read_to_end(&mut to_origin).await.unwrap();
        assert!(to_origin.is_empty(), "nothing may reach the origin");
    }

    #[tokio::test]
    async fn a_request_to_another_host_is_untouched() {
        let request =
            b"GET / HTTP/1.1\r\nHost: other.example\r\nAuthorization: Bearer mine\r\n\r\n";
        let seen = relayed(
            request,
            vec![rule("api.example.com", "Authorization", "Bearer real")],
        )
        .await;

        assert_eq!(seen, String::from_utf8_lossy(request));
    }

    /// The global limit is shared, so a sandbox opening connections in a loop
    /// would take every slot. Each source gets its own budget on top.
    /// A refused request is answered, not dropped: the client sees a `403`
    /// naming the refusal instead of a connection that vanished.
    #[tokio::test]
    async fn a_request_refused_by_an_http_rule_is_answered_with_403() {
        let (mut sandbox, mut client) = tokio::io::duplex(8 * 1024);
        let (_origin, mut upstream) = tokio::io::duplex(8 * 1024);
        sandbox
            .write_all(b"POST /repos/o/r HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .await
            .unwrap();
        sandbox.shutdown().await.unwrap();

        let policy = policy::SandboxPolicy {
            http_rules: Arc::new(vec![policy::HttpRule {
                hosts: vec!["api.example.com".into()],
                methods: vec!["GET".into()],
                paths: vec!["/repos/**".into()],
                is_denying: false,
            }]),
            ..Default::default()
        };
        let relay = tokio::spawn(async move {
            proxy()
                .relay_http(
                    &mut client,
                    &mut upstream,
                    Some("api.example.com"),
                    &policy,
                    true,
                    false,
                )
                .await
        });

        let mut answer = Vec::new();
        sandbox.read_to_end(&mut answer).await.unwrap();
        let answer = String::from_utf8(answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer}");
        let outcome = relay.await.unwrap();
        let refusal = outcome.refusal.unwrap();
        assert!(refusal.contains("no http rule admits POST"), "{refusal}");
    }

    #[test]
    fn a_mapped_connection_asks_for_its_original_destination_as_ipv4() {
        assert!(is_ipv4_request("10.99.4.1:3128".parse().unwrap()));
        // What a dual-stack listener reports for an IPv4 client.
        assert!(is_ipv4_request("[::ffff:10.99.4.1]:3128".parse().unwrap()));
        assert!(!is_ipv4_request(
            "[fd99:b070:0:100::1]:3128".parse().unwrap()
        ));
    }

    #[test]
    fn one_source_cannot_take_more_than_its_share_of_connections() {
        let limits = Arc::new(SourceLimits::default());
        let noisy = IpAddr::from([10, 99, 0, 6]);
        let quiet = IpAddr::from([10, 99, 0, 10]);

        let held: Vec<_> = (0..MAX_CONNECTIONS_PER_SOURCE)
            .map(|n| {
                limits
                    .acquire(noisy)
                    .unwrap_or_else(|| panic!("connection {n} is within the budget"))
            })
            .collect();
        assert!(
            limits.acquire(noisy).is_none(),
            "a sandbox past its budget must be refused"
        );
        // And the neighbour is unaffected, which is the whole point.
        assert!(limits.acquire(quiet).is_some());

        // A finished connection gives its slot back.
        drop(held);
        assert!(limits.acquire(noisy).is_some());
    }

    /// The map is keyed by a recycled address, so an entry that outlived its
    /// connections would accumulate one per sandbox the node has run.
    #[test]
    fn a_sources_entry_is_forgotten_once_it_holds_nothing() {
        let limits = Arc::new(SourceLimits::default());
        let source = IpAddr::from([10, 99, 0, 6]);
        let a = limits.acquire(source).unwrap();
        let b = limits.acquire(source).unwrap();
        assert_eq!(limits.counts.lock().unwrap().get(&source), Some(&2));
        drop(a);
        assert_eq!(limits.counts.lock().unwrap().get(&source), Some(&1));
        drop(b);
        assert!(limits.counts.lock().unwrap().is_empty());
    }

    /// The client chooses the record boundaries, so classifying the first
    /// record alone would let a sandbox make its destination unreadable by
    /// splitting the hello.
    #[test]
    fn a_fragmented_client_hello_is_not_classifiable_until_it_is_whole() {
        // A minimal hello, refragmented one byte per record.
        let mut whole = vec![0x16, 0x03, 0x01];
        let handshake = {
            let mut body = Vec::new();
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[0u8; 32]);
            body.push(0);
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x13, 0x01]);
            body.push(1);
            body.push(0);
            body.extend_from_slice(&0u16.to_be_bytes()); // no extensions
            let mut handshake = vec![0x01];
            handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            handshake.extend_from_slice(&body);
            handshake
        };
        whole.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        whole.extend_from_slice(&handshake);

        let mut split = Vec::new();
        for byte in &handshake {
            split.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x01, *byte]);
        }

        assert!(is_classifiable(443, &whole));
        assert!(is_classifiable(443, &split));
        // Every prefix of the fragmented form is still arriving.
        for cut in 0..split.len() {
            assert!(
                !is_classifiable(443, &split[..cut]),
                "{cut} bytes of a fragmented hello must not be classified"
            );
        }
        // Something that is not TLS at all needs no waiting.
        assert!(is_classifiable(443, b"GET / HTTP/1.1\r\n\r\n"));
    }

    /// A rule past its expiry claims nothing: the request leaves as the guest
    /// wrote it, and an unexpired rule after it is the one that applies.
    #[tokio::test]
    async fn an_expired_rule_sets_nothing() {
        let request = b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let expired = policy::Rule {
            expires_at_unix_ms: 1,
            ..rule("api.example.com", "Authorization", "Bearer old")
        };
        let seen = relayed(request, vec![expired.clone()]).await;
        assert!(!seen.contains("Authorization"), "{seen}");

        let later = policy::Rule {
            expires_at_unix_ms: policy::now_unix_ms() + 60_000,
            ..rule("api.example.com", "Authorization", "Bearer new")
        };
        let seen = relayed(request, vec![expired, later]).await;
        assert!(seen.contains("Authorization: Bearer new\r\n"), "{seen}");
    }

    /// Where a credential went is in the connection's audit record.
    #[tokio::test]
    async fn a_connection_records_which_rule_set_headers_on_how_many_requests() {
        let (mut sandbox, mut client) = tokio::io::duplex(8 * 1024);
        let (mut server, mut upstream) = tokio::io::duplex(8 * 1024);
        sandbox
            .write_all(
                b"GET /a HTTP/1.1\r\nHost: api.example.com\r\n\r\n\
                  GET /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .await
            .unwrap();
        sandbox.shutdown().await.unwrap();
        let policy = policy::SandboxPolicy {
            rules: Arc::new(vec![matched(
                "api.example.com",
                "Authorization",
                "Bearer t",
                policy::RequestMatch {
                    path: Some(policy::Match::Exact("/a".into())),
                    ..Default::default()
                },
            )]),
            ..policy::SandboxPolicy::allowing(&["api.example.com"])
        };
        let relay = tokio::spawn(async move {
            proxy()
                .relay_http(
                    &mut client,
                    &mut upstream,
                    Some("api.example.com"),
                    &policy,
                    true,
                    true,
                )
                .await
        });
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        drop(server);
        let outcome = relay.await.unwrap();
        assert_eq!(
            outcome.note.as_deref(),
            Some("allowed (inspected); headers set by rule 0 (api.example.com) on 1 of 2 requests")
        );
    }

    /// Revoking a credential reaches a session that is already open: the next
    /// request on it goes without, rather than the credential lasting as long
    /// as the client keeps its connection alive.
    #[tokio::test]
    async fn a_rule_removed_while_a_session_is_open_stops_at_its_next_request() {
        let table = PolicyTable::default();
        let source = IpAddr::from([10, 99, 0, 6]);
        let granted = policy::SandboxPolicy {
            sandbox_id: "sbx".into(),
            rules: Arc::new(vec![rule("api.example.com", "Authorization", "Bearer t")]),
            ..policy::SandboxPolicy::allowing(&["api.example.com"])
        };
        table.replace([(source, granted.clone())].into());
        let session = table.get(source).unwrap();

        let (mut sandbox, mut client) = tokio::io::duplex(8 * 1024);
        let (mut server, mut upstream) = tokio::io::duplex(8 * 1024);
        let relay = tokio::spawn(async move {
            proxy()
                .relay_http(
                    &mut client,
                    &mut upstream,
                    Some("api.example.com"),
                    &session,
                    true,
                    true,
                )
                .await
        });

        sandbox
            .write_all(b"GET /1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .await
            .unwrap();
        let mut first = vec![0u8; 4096];
        let n = server.read(&mut first).await.unwrap();
        let first = String::from_utf8_lossy(&first[..n]).into_owned();
        assert!(first.contains("Authorization: Bearer t\r\n"), "{first}");

        table.replace(
            [(
                source,
                policy::SandboxPolicy {
                    rules: Arc::new(Vec::new()),
                    ..granted
                },
            )]
            .into(),
        );
        sandbox
            .write_all(b"GET /2 HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .await
            .unwrap();
        sandbox.shutdown().await.unwrap();
        let mut rest = Vec::new();
        server.read_to_end(&mut rest).await.unwrap();
        drop(server);
        let rest = String::from_utf8(rest).unwrap();
        assert!(rest.starts_with("GET /2 "), "{rest}");
        assert!(!rest.contains("Authorization"), "{rest}");
        relay.await.unwrap();
    }

    fn open_policy(rules: Vec<policy::Rule>) -> policy::SandboxPolicy {
        policy::SandboxPolicy {
            sandbox_id: "sbx".into(),
            mode: NetworkMode::Open,
            is_tls_inspected: true,
            rules: Arc::new(rules),
            ..Default::default()
        }
    }

    /// A proxy that can inspect, holding `policy` for one sandbox.
    fn inspecting_proxy(policy: policy::SandboxPolicy) -> (Proxy, IpAddr) {
        // One directory per call: tests run in parallel, and two creating
        // an authority in the same place race on its files.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "burrow-open-inspection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut proxy = proxy();
        proxy.authority = Some(Arc::new(inspect::Authority::load_or_create(&dir).unwrap()));
        let source = IpAddr::from([10, 99, 0, 6]);
        proxy.policies.replace([(source, policy)].into());
        (proxy, source)
    }

    const ORIGIN: &str = "93.184.216.34:443";

    /// Open mode inspects exactly the hosts its live rules name. A connection
    /// for any other name, which reaches the proxy only because it shares an
    /// address with an inspected host, is relayed as open mode's ordinary
    /// egress: allowed, unpinned, untouched.
    #[tokio::test]
    async fn open_mode_inspects_only_the_hosts_its_rules_name() {
        let (proxy, source) = inspecting_proxy(open_policy(vec![rule(
            "api.example.com",
            "Authorization",
            "Bearer t",
        )]));
        let origin: SocketAddr = ORIGIN.parse().unwrap();
        proxy.resolutions.record(
            "sbx",
            "api.example.com",
            vec![origin.ip()],
            std::time::Duration::from_secs(300),
        );

        let inspected = proxy.admit(source, origin, &sni::tests::client_hello("api.example.com"));
        assert!(inspected.decision.is_allowed(), "{:?}", inspected.decision);
        assert!(inspected.inspecting);

        let other = proxy.admit(source, origin, &sni::tests::client_hello("www.example.com"));
        assert!(other.decision.is_allowed(), "{:?}", other.decision);
        assert!(!other.inspecting, "a host no rule names is not terminated");
    }

    /// The credential only ever goes to an address the resolver gave this
    /// sandbox for that name. Unpinned, the inspected connection is refused,
    /// not relayed without its credential.
    #[tokio::test]
    async fn an_inspected_open_mode_host_must_be_pinned() {
        let (proxy, source) = inspecting_proxy(open_policy(vec![rule(
            "api.example.com",
            "Authorization",
            "Bearer t",
        )]));
        let admitted = proxy.admit(
            source,
            ORIGIN.parse().unwrap(),
            &sni::tests::client_hello("api.example.com"),
        );
        assert_eq!(
            admitted.decision,
            Decision::Deny("destination address is not pinned to this name")
        );
    }

    /// What cannot be identified is refused, as in allowlist mode: no SNI,
    /// or an encrypted ClientHello whose visible name is a cover.
    #[tokio::test]
    async fn open_mode_inspection_fails_closed_on_what_it_cannot_name() {
        let (proxy, source) = inspecting_proxy(open_policy(vec![rule(
            "api.example.com",
            "Authorization",
            "Bearer t",
        )]));
        let origin: SocketAddr = ORIGIN.parse().unwrap();
        proxy.resolutions.record(
            "sbx",
            "api.example.com",
            vec![origin.ip()],
            std::time::Duration::from_secs(300),
        );

        let nameless = proxy.admit(source, origin, b"\x16\x03\x01\x00\x05hello");
        assert!(!nameless.decision.is_allowed());

        let ech = sni::tests::client_hello_with(&[
            (0x0000, sni::tests::server_name_extension("api.example.com")),
            (0xfe0d, vec![0x01]),
        ]);
        let hidden = proxy.admit(source, origin, &ech);
        assert_eq!(
            hidden.decision,
            Decision::Deny("client hello encrypts its destination (ECH)")
        );
    }

    /// Open mode's denials still hold on a connection the proxy merely relays,
    /// since the redirect took it out of the path the ruleset enforces them on.
    #[tokio::test]
    async fn a_relayed_open_mode_connection_keeps_its_denials() {
        let (proxy, source) = inspecting_proxy(policy::SandboxPolicy {
            deny_cidrs: vec!["93.184.216.0/24".into()],
            deny_domains: vec!["blocked.example".into()],
            ..open_policy(vec![rule("api.example.com", "Authorization", "Bearer t")])
        });
        let origin: SocketAddr = ORIGIN.parse().unwrap();
        let denied_range =
            proxy.admit(source, origin, &sni::tests::client_hello("www.example.com"));
        assert_eq!(
            denied_range.decision,
            Decision::Deny("destination is in a denied range")
        );
        let denied_name = proxy.admit(
            source,
            "93.184.217.1:443".parse().unwrap(),
            &sni::tests::client_hello("blocked.example"),
        );
        assert!(!denied_name.decision.is_allowed());
    }

    /// An expired rule takes its host out of inspection with it.
    #[tokio::test]
    async fn an_expired_open_mode_rule_stops_its_host_being_inspected() {
        let expired = policy::Rule {
            expires_at_unix_ms: 1,
            ..rule("api.example.com", "Authorization", "Bearer t")
        };
        let (proxy, source) = inspecting_proxy(open_policy(vec![expired]));
        let admitted = proxy.admit(
            source,
            ORIGIN.parse().unwrap(),
            &sni::tests::client_hello("api.example.com"),
        );
        assert!(admitted.decision.is_allowed());
        assert!(!admitted.inspecting);
    }
}
