//! The transport under the tunnel: WireGuard over the relay and, once disco
//! has found one, over a direct UDP path.
//!
//! This is the small corner of magicsock that tailcat needs. Every client
//! that meows becomes a WireGuard peer (a boringtun tunnel) whose packets
//! can arrive from the relay, tagged with its node key, or from any UDP
//! address, in which case the WireGuard receiver index (or, for a handshake
//! initiation, the static key inside it) says which tunnel they belong to.
//!
//! Path selection is deliberately simple. We learn our own endpoints from
//! STUN and the local interfaces and advertise them in a call-me-maybe
//! whenever a client registers or they change. Candidates for a client come
//! from its call-me-maybe and from wherever its disco pings arrive; we ping
//! them, and a pong promotes its address to the direct path, trusted for a
//! few seconds at a time and kept alive by a heartbeat. Without a recent
//! pong, sends fall back to the relay. The stock client runs the full
//! magicsock state machine on its side and needs nothing more from us than
//! prompt pongs and an honest call-me-maybe.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::derp::{self, DerpClient};
use crate::derpmap::DerpRegion;
use crate::disco::{self, Message, TxId};
use crate::key::{DiscoPrivate, DiscoPublic, DiscoShared, NodePrivate, NodePublic, PresharedKey};
use crate::meow;
use crate::netstack::Netstack;
use crate::stun;

const WG_TIMER_TICK: Duration = Duration::from_millis(250);
const TICKS_PER_HEARTBEAT: u64 = 12;
const TICKS_PER_STUN: u64 = 120;
/// How often a candidate is pinged while no direct path is trusted.
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);
/// How long a pong keeps a direct path trusted. Tailscale's figure.
const TRUST_UDP_ADDR: Duration = Duration::from_millis(6500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// A peer with no tunnel traffic for this long stops being probed.
const SESSION_ACTIVE: Duration = Duration::from_secs(120);
/// Endpoints older than this are refreshed before being advertised to a new
/// client.
const ENDPOINTS_FRESH: Duration = Duration::from_secs(20);
const MAPPED_TTL: Duration = Duration::from_secs(90);
const CALL_ME_MAYBE_INTERVAL: Duration = Duration::from_secs(30);
/// Tailscale's placeholder address for "the relay" in disco pongs.
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);
const BUF: usize = 2048;

pub struct Config {
    pub key: NodePrivate,
    pub preshared_key: Option<PresharedKey>,
    pub region: DerpRegion,
    /// `None` admits every client.
    pub allowed_clients: Option<HashSet<NodePublic>>,
    pub derp: derp::Options,
}

/// A client as the transport sees it.
#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub key: NodePublic,
    pub addr: Ipv6Addr,
    /// The UDP address currently trusted for sending, if any.
    pub direct: Option<SocketAddr>,
    /// Last UDP address a disco pong authenticated. Kept after the sending
    /// path falls back to DERP, so a share can still spoof that public IP.
    pub last_udp: Option<SocketAddr>,
    pub idle: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Path {
    Derp,
    Udp(SocketAddr),
}

#[derive(Default)]
struct Candidate {
    from_call_me_maybe: bool,
    last_ping: Option<Instant>,
}

struct Direct {
    addr: SocketAddr,
    latency: Duration,
    trust_until: Instant,
    last_pong: Instant,
}

struct Peer {
    key: NodePublic,
    shared: DiscoShared,
    tunn: Tunn,
    addr: Ipv6Addr,
    direct: Option<Direct>,
    /// Last pong-verified UDP address, independent of whether it is still
    /// trusted for sending.
    last_udp: Option<SocketAddr>,
    candidates: HashMap<SocketAddr, Candidate>,
    sent_pings: HashMap<TxId, (SocketAddr, Instant)>,
    last_activity: Instant,
    last_call_me_maybe: Option<Instant>,
}

impl Peer {
    fn direct_path(&self, now: Instant) -> Option<SocketAddr> {
        self.direct
            .as_ref()
            .filter(|d| now < d.trust_until)
            .map(|d| d.addr)
    }
}

/// Sends go through plain non-blocking sockets rather than tokio's, so they
/// work from under the state lock and from the first tick, before the
/// reactor has observed the sockets as writable.
struct Io {
    udp4: Option<std::net::UdpSocket>,
    udp6: Option<std::net::UdpSocket>,
    derp: DerpClient,
}

impl Io {
    fn send_udp(&self, addr: SocketAddr, pkt: &[u8]) -> bool {
        let sock = match addr {
            SocketAddr::V4(_) => &self.udp4,
            SocketAddr::V6(_) => &self.udp6,
        };
        sock.as_ref().is_some_and(|s| s.send_to(pkt, addr).is_ok())
    }

    fn send_peer(&self, peer: &Peer, now: Instant, pkt: &[u8]) {
        match peer.direct_path(now) {
            Some(addr) if self.send_udp(addr, pkt) => {}
            _ => {
                self.derp.send(&peer.key, pkt);
            }
        }
    }

    fn send_disco(&self, from: &DiscoPublic, peer: &Peer, path: Path, msg: &Message) {
        let pkt = disco::seal(&peer.shared, from, msg);
        match path {
            Path::Udp(addr) => {
                self.send_udp(addr, &pkt);
            }
            Path::Derp => {
                self.derp.send(&peer.key, &pkt);
            }
        }
    }
}

struct State {
    key: NodePrivate,
    public: NodePublic,
    disco_priv: DiscoPrivate,
    disco_pub: DiscoPublic,
    psk: Option<[u8; 32]>,
    region: DerpRegion,
    io: Io,
    peers: HashMap<NodePublic, Peer>,
    by_index: HashMap<u32, NodePublic>,
    by_addr: HashMap<Ipv6Addr, NodePublic>,
    by_disco: HashMap<DiscoPublic, NodePublic>,
    allowed: Option<HashSet<NodePublic>>,
    next_index: u32,
    stun_sent: HashMap<stun::TxId, (SocketAddr, Instant)>,
    mapped: HashMap<SocketAddr, (SocketAddr, Instant)>,
    endpoints: Vec<SocketAddr>,
    last_stun: Option<Instant>,
    stun_wanted: bool,
}

impl State {
    fn handle_derp_packet(
        &mut self,
        src: NodePublic,
        data: &[u8],
        now: Instant,
        out: &mut Vec<Vec<u8>>,
    ) {
        if disco::looks_like_disco(data) {
            self.handle_disco(data, Path::Derp, Some(src), now);
        } else if meow::is_meow(data) {
            if let Some((_, disco_pub)) = meow::parse_ping(data) {
                self.on_meow(src, disco_pub, now);
            }
        } else if let Some(peer) = self.peers.get_mut(&src) {
            decapsulate(&self.io, peer, None, data, now, out);
        }
    }

    fn handle_udp_packet(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
        out: &mut Vec<Vec<u8>>,
    ) {
        if let Some((tx, mapped)) = stun::parse_response(data) {
            self.on_stun(tx, mapped, now);
            return;
        }
        if disco::looks_like_disco(data) {
            self.handle_disco(data, Path::Udp(from), None, now);
            return;
        }
        let Some(key) = self.peer_for_wg(data) else {
            return;
        };
        if let Some(peer) = self.peers.get_mut(&key) {
            decapsulate(&self.io, peer, Some(from.ip()), data, now, out);
        }
    }

    /// Which tunnel a WireGuard packet from an arbitrary UDP source belongs
    /// to. Every message but a handshake initiation names our session index,
    /// whose high bits are the peer's; an initiation is decrypted far enough
    /// to read the initiator's static key.
    fn peer_for_wg(&self, data: &[u8]) -> Option<NodePublic> {
        match Tunn::parse_incoming_packet(data).ok()? {
            Packet::HandshakeInit(init) => {
                let half =
                    parse_handshake_anon(&self.key.static_secret(), &self.public.x25519(), &init)
                        .ok()?;
                Some(NodePublic::from_raw(half.peer_static_public))
            }
            Packet::HandshakeResponse(p) => self.by_index.get(&(p.receiver_idx >> 8)).copied(),
            Packet::PacketCookieReply(p) => self.by_index.get(&(p.receiver_idx >> 8)).copied(),
            Packet::PacketData(p) => self.by_index.get(&(p.receiver_idx >> 8)).copied(),
        }
    }

    fn on_meow(&mut self, src: NodePublic, disco_pub: DiscoPublic, now: Instant) {
        if self.allowed.as_ref().is_some_and(|a| !a.contains(&src)) {
            tracing::info!(client = %src.short(), "ignoring meow: not an allowed client");
            return;
        }
        if !self.peers.contains_key(&src) {
            let index = self.next_index;
            self.next_index += 1;
            let tunn = Tunn::new(
                self.key.static_secret(),
                src.x25519(),
                self.psk,
                None,
                index,
                None,
            );
            let addr = src.addr();
            self.peers.insert(
                src,
                Peer {
                    key: src,
                    shared: self.disco_priv.shared(&disco_pub),
                    tunn,
                    addr,
                    direct: None,
                    last_udp: None,
                    candidates: HashMap::new(),
                    sent_pings: HashMap::new(),
                    last_activity: now,
                    last_call_me_maybe: None,
                },
            );
            self.by_index.insert(index, src);
            self.by_addr.insert(addr, src);
            self.by_disco.insert(disco_pub, src);
            tracing::info!(client = %src.short(), %addr, "client registered");
        }
        // Sent last, and only here: a client reads the reply as permission to
        // dial, which is a lie unless its tunnel already exists.
        self.io.derp.send(&src, &meow::encode_meowed());
        if self
            .last_stun
            .is_none_or(|t| now.duration_since(t) > ENDPOINTS_FRESH)
        {
            self.stun_wanted = true;
        }
        let peer = self.peers.get_mut(&src).expect("just inserted");
        send_call_me_maybe(&self.io, &self.disco_pub, &self.endpoints, peer, now);
    }

    fn handle_disco(
        &mut self,
        data: &[u8],
        path: Path,
        derp_src: Option<NodePublic>,
        now: Instant,
    ) {
        let Some(sender) = disco::sender(data) else {
            return;
        };
        let Some(key) = self.by_disco.get(&sender).copied() else {
            return;
        };
        let peer = self.peers.get_mut(&key).expect("indexed peer exists");
        let Some(msg) = disco::open(&peer.shared, data) else {
            return;
        };
        match msg {
            Message::Ping { tx_id, .. } => {
                let src = match path {
                    Path::Udp(addr) => addr,
                    Path::Derp => {
                        SocketAddr::new(DERP_MAGIC_IP.into(), self.region.region_id as u16)
                    }
                };
                self.io
                    .send_disco(&self.disco_pub, peer, path, &Message::Pong { tx_id, src });
                if let Path::Udp(addr) = path
                    && !peer.candidates.contains_key(&addr)
                {
                    peer.candidates.insert(addr, Candidate::default());
                    ping(&self.io, &self.disco_pub, &self.public, peer, addr, now);
                }
            }
            Message::Pong { tx_id, .. } => {
                let Some((to, at)) = peer.sent_pings.remove(&tx_id) else {
                    return;
                };
                let Path::Udp(_) = path else {
                    return;
                };
                let latency = now.duration_since(at);
                let better = match &peer.direct {
                    Some(d) if d.addr == to => false,
                    Some(d) => now > d.trust_until || latency < d.latency,
                    None => true,
                };
                match &mut peer.direct {
                    Some(d) if !better => {
                        if d.addr == to {
                            d.latency = latency;
                            d.last_pong = now;
                            d.trust_until = now + TRUST_UDP_ADDR;
                            peer.last_udp = Some(to);
                        }
                    }
                    slot => {
                        tracing::info!(client = %peer.key.short(), %to, ?latency, "using direct path");
                        *slot = Some(Direct {
                            addr: to,
                            latency,
                            trust_until: now + TRUST_UDP_ADDR,
                            last_pong: now,
                        });
                        peer.last_udp = Some(to);
                    }
                }
            }
            Message::CallMeMaybe { endpoints } => {
                if path != Path::Derp || derp_src != Some(peer.key) {
                    return;
                }
                peer.candidates
                    .retain(|addr, c| !c.from_call_me_maybe || endpoints.contains(addr));
                for ep in endpoints {
                    if let IpAddr::V6(v6) = ep.ip()
                        && v6.is_unicast_link_local()
                    {
                        continue;
                    }
                    peer.candidates.entry(ep).or_default().from_call_me_maybe = true;
                }
                let addrs: Vec<SocketAddr> = peer.candidates.keys().copied().collect();
                tracing::debug!(client = %peer.key.short(), ?addrs, "call-me-maybe");
                for addr in addrs {
                    ping(&self.io, &self.disco_pub, &self.public, peer, addr, now);
                }
            }
            Message::Other(_) => {}
        }
    }

    fn send_ip(&mut self, pkt: &[u8], now: Instant) {
        if pkt.len() < 40 {
            return;
        }
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
        let Some(key) = self.by_addr.get(&dst) else {
            return;
        };
        let peer = self.peers.get_mut(key).expect("indexed peer exists");
        peer.last_activity = now;
        let mut buf = [0u8; BUF];
        match peer.tunn.encapsulate(pkt, &mut buf) {
            TunnResult::WriteToNetwork(out) => self.io.send_peer(peer, now, out),
            TunnResult::Err(err) => {
                tracing::debug!(client = %peer.key.short(), ?err, "encapsulate")
            }
            _ => {}
        }
    }

    fn tick(&mut self, n: u64, now: Instant) {
        let mut buf = [0u8; BUF];
        for peer in self.peers.values_mut() {
            match peer.tunn.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(out) => self.io.send_peer(peer, now, out),
                TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired) => {}
                TunnResult::Err(err) => {
                    tracing::debug!(client = %peer.key.short(), ?err, "wireguard timers")
                }
                _ => {}
            }
        }
        if n.is_multiple_of(TICKS_PER_HEARTBEAT) {
            for peer in self.peers.values_mut() {
                heartbeat(
                    &self.io,
                    &self.disco_pub,
                    &self.public,
                    &self.endpoints,
                    peer,
                    now,
                );
            }
        }
        if n.is_multiple_of(TICKS_PER_STUN) || self.stun_wanted {
            self.stun_wanted = false;
            self.stun_probe(now);
            self.update_endpoints(now);
        }
    }

    fn stun_probe(&mut self, now: Instant) {
        self.stun_sent
            .retain(|_, (_, at)| now.duration_since(*at) < PING_TIMEOUT);
        for node in &self.region.nodes {
            let Some(port) = node.stun_port() else {
                continue;
            };
            for ip in node.ip_addrs() {
                let server = SocketAddr::new(ip, port);
                let tx = stun::TxId::random();
                if self.io.send_udp(server, &stun::request(tx)) {
                    self.stun_sent.insert(tx, (server, now));
                }
            }
        }
        self.last_stun = Some(now);
    }

    fn on_stun(&mut self, tx: stun::TxId, mapped: SocketAddr, now: Instant) {
        let Some((server, _)) = self.stun_sent.remove(&tx) else {
            return;
        };
        self.mapped.insert(server, (mapped, now));
        self.update_endpoints(now);
    }

    /// Recomputes what we advertise: every interface address with the
    /// matching socket's port, plus whatever STUN has recently reported. A
    /// change is sent to every client, which is what lets a client behind a
    /// NAT find a path to us: magicsock never probes a peer it has no
    /// endpoints for.
    fn update_endpoints(&mut self, now: Instant) {
        self.mapped
            .retain(|_, (_, at)| now.duration_since(*at) < MAPPED_TTL);
        let port4 = self
            .io
            .udp4
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port());
        let port6 = self
            .io
            .udp6
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port());
        let mut eps = local_endpoints(port4, port6);
        eps.extend(self.mapped.values().map(|(a, _)| *a));
        eps.sort();
        eps.dedup();
        if eps == self.endpoints {
            return;
        }
        tracing::debug!(endpoints = ?eps, "endpoints changed");
        self.endpoints = eps;
        for peer in self.peers.values_mut() {
            peer.last_call_me_maybe = None;
            send_call_me_maybe(&self.io, &self.disco_pub, &self.endpoints, peer, now);
        }
    }
}

fn decapsulate(
    io: &Io,
    peer: &mut Peer,
    src_ip: Option<IpAddr>,
    data: &[u8],
    now: Instant,
    out: &mut Vec<Vec<u8>>,
) {
    let mut buf = [0u8; BUF];
    let mut datagram = data;
    loop {
        match peer.tunn.decapsulate(src_ip, datagram, &mut buf) {
            TunnResult::WriteToNetwork(pkt) => {
                io.send_peer(peer, now, pkt);
                // Repeating with an empty datagram flushes packets that
                // were queued behind the handshake that just completed.
                datagram = &[];
            }
            TunnResult::WriteToTunnelV6(pkt, src) => {
                // AllowedIPs: a client may only source packets from its own
                // tunnel address, which is enforced here rather than by a
                // filter that could be misordered.
                if src == peer.addr {
                    peer.last_activity = now;
                    out.push(pkt.to_vec());
                } else {
                    tracing::debug!(client = %peer.key.short(), %src, "dropping packet from disallowed source");
                }
                return;
            }
            TunnResult::WriteToTunnelV4(..) | TunnResult::Done => return,
            TunnResult::Err(err) => {
                tracing::trace!(client = %peer.key.short(), ?err, "decapsulate");
                return;
            }
        }
    }
}

fn ping(
    io: &Io,
    disco_pub: &DiscoPublic,
    node: &NodePublic,
    peer: &mut Peer,
    addr: SocketAddr,
    now: Instant,
) {
    let tx_id = TxId::random();
    peer.sent_pings.insert(tx_id, (addr, now));
    if let Some(c) = peer.candidates.get_mut(&addr) {
        c.last_ping = Some(now);
    }
    io.send_disco(
        disco_pub,
        peer,
        Path::Udp(addr),
        &Message::Ping {
            tx_id,
            node_key: Some(*node),
        },
    );
}

fn send_call_me_maybe(
    io: &Io,
    disco_pub: &DiscoPublic,
    endpoints: &[SocketAddr],
    peer: &mut Peer,
    now: Instant,
) {
    if endpoints.is_empty() {
        return;
    }
    peer.last_call_me_maybe = Some(now);
    io.send_disco(
        disco_pub,
        peer,
        Path::Derp,
        &Message::CallMeMaybe {
            endpoints: endpoints.to_vec(),
        },
    );
}

fn heartbeat(
    io: &Io,
    disco_pub: &DiscoPublic,
    node: &NodePublic,
    endpoints: &[SocketAddr],
    peer: &mut Peer,
    now: Instant,
) {
    peer.sent_pings
        .retain(|_, (_, at)| now.duration_since(*at) < PING_TIMEOUT);
    if now.duration_since(peer.last_activity) > SESSION_ACTIVE {
        return;
    }
    if let Some(d) = &peer.direct {
        if now.duration_since(d.last_pong) > TRUST_UDP_ADDR + PING_TIMEOUT {
            tracing::info!(client = %peer.key.short(), addr = %d.addr, "direct path lost, using relay");
            peer.direct = None;
        } else {
            let addr = d.addr;
            ping(io, disco_pub, node, peer, addr, now);
            return;
        }
    }
    let due: Vec<SocketAddr> = peer
        .candidates
        .iter()
        .filter(|(_, c)| {
            c.last_ping
                .is_none_or(|t| now.duration_since(t) >= DISCO_PING_INTERVAL)
        })
        .map(|(a, _)| *a)
        .collect();
    for addr in due {
        ping(io, disco_pub, node, peer, addr, now);
    }
    if peer.candidates.is_empty()
        && peer
            .last_call_me_maybe
            .is_none_or(|t| now.duration_since(t) >= CALL_ME_MAYBE_INTERVAL)
    {
        send_call_me_maybe(io, disco_pub, endpoints, peer, now);
    }
}

/// The addresses of this host's interfaces, with the port of the socket
/// for each family. Loopback is advertised only when nothing else is,
/// matching what magicsock does.
fn local_endpoints(port4: Option<u16>, port6: Option<u16>) -> Vec<SocketAddr> {
    use nix::net::if_::InterfaceFlags;
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut regular = Vec::new();
    let mut loopback = Vec::new();
    for ifa in addrs {
        if !ifa.flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        let Some(sa) = ifa.address else {
            continue;
        };
        let (ip, port) = if let Some(v4) = sa.as_sockaddr_in() {
            (IpAddr::V4(v4.ip()), port4)
        } else if let Some(v6) = sa.as_sockaddr_in6() {
            (IpAddr::V6(v6.ip()), port6)
        } else {
            continue;
        };
        let Some(port) = port else {
            continue;
        };
        let usable = match ip {
            IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_unspecified(),
            IpAddr::V6(v6) => !v6.is_unicast_link_local() && !v6.is_unspecified(),
        };
        if !usable {
            continue;
        }
        let ep = SocketAddr::new(ip, port);
        if ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK) || ip.is_loopback() {
            loopback.push(ep);
        } else {
            regular.push(ep);
        }
    }
    if regular.is_empty() {
        loopback
    } else {
        regular
    }
}

/// Binds a UDP socket for receiving through tokio and a clone of it for
/// sending directly. A family that cannot be bound is simply not used.
fn bind_udp(addr: &str) -> std::io::Result<(Option<UdpSocket>, Option<std::net::UdpSocket>)> {
    let Ok(sock) = std::net::UdpSocket::bind(addr) else {
        return Ok((None, None));
    };
    sock.set_nonblocking(true)?;
    let sender = sock.try_clone()?;
    Ok((Some(UdpSocket::from_std(sock)?), Some(sender)))
}

/// The running transport. Dropping it stops every task.
pub struct Transport {
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Transport {
    pub fn start(
        cfg: Config,
        netstack: Arc<Netstack>,
        mut egress: mpsc::Receiver<Vec<u8>>,
    ) -> std::io::Result<Transport> {
        let (udp4, send4) = bind_udp("0.0.0.0:0")?;
        let (udp6, send6) = bind_udp("[::]:0")?;
        if udp4.is_none() && udp6.is_none() {
            return Err(std::io::Error::other("could not bind a UDP socket"));
        }
        let (derp, mut packets) =
            DerpClient::connect(cfg.region.clone(), cfg.key.clone(), cfg.derp);
        let disco_priv = cfg.key.disco();
        let state = Arc::new(Mutex::new(State {
            public: cfg.key.public(),
            disco_pub: disco_priv.public(),
            disco_priv,
            key: cfg.key,
            psk: cfg.preshared_key.map(|k| *k.as_bytes()),
            region: cfg.region,
            io: Io {
                udp4: send4,
                udp6: send6,
                derp,
            },
            peers: HashMap::new(),
            by_index: HashMap::new(),
            by_addr: HashMap::new(),
            by_disco: HashMap::new(),
            allowed: cfg.allowed_clients,
            next_index: 1,
            stun_sent: HashMap::new(),
            mapped: HashMap::new(),
            endpoints: Vec::new(),
            last_stun: None,
            stun_wanted: false,
        }));

        let mut tasks = Vec::new();
        {
            let state = state.clone();
            let netstack = netstack.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(derp::Packet { src, data }) = packets.recv().await {
                    let mut out = Vec::new();
                    state
                        .lock()
                        .unwrap()
                        .handle_derp_packet(src, &data, Instant::now(), &mut out);
                    for pkt in out {
                        netstack.inject(pkt);
                    }
                }
            }));
        }
        for sock in [udp4, udp6].into_iter().flatten() {
            let sock = Arc::new(sock);
            let state = state.clone();
            let netstack = netstack.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                        continue;
                    };
                    let mut out = Vec::new();
                    state.lock().unwrap().handle_udp_packet(
                        from,
                        &buf[..n],
                        Instant::now(),
                        &mut out,
                    );
                    for pkt in out {
                        netstack.inject(pkt);
                    }
                }
            }));
        }
        {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                while let Some(pkt) = egress.recv().await {
                    state.lock().unwrap().send_ip(&pkt, Instant::now());
                }
            }));
        }
        {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(WG_TIMER_TICK);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let mut n = 0u64;
                loop {
                    interval.tick().await;
                    state.lock().unwrap().tick(n, Instant::now());
                    n += 1;
                }
            }));
        }
        Ok(Transport { state, tasks })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub fn peer_for_addr(&self, addr: Ipv6Addr) -> Option<NodePublic> {
        self.lock().by_addr.get(&addr).copied()
    }

    pub fn add_allowed_client(&self, key: NodePublic) {
        self.lock()
            .allowed
            .get_or_insert_with(HashSet::new)
            .insert(key);
    }

    pub fn peers(&self) -> Vec<PeerStatus> {
        let st = self.lock();
        let now = Instant::now();
        st.peers
            .values()
            .map(|p| PeerStatus {
                key: p.key,
                addr: p.addr,
                direct: p.direct_path(now),
                last_udp: p.last_udp,
                idle: now.duration_since(p.last_activity),
            })
            .collect()
    }

    pub fn close(&self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.close();
    }
}
