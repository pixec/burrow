//! Private networks between sandboxes on a node with no ruleset.
//!
//! Every sandbox's stack hands the router the IP packets its guest sends to
//! another sandbox's address, and the router delivers them, unterminated, to
//! the stack serving that address, or over the mesh to the node holding it.
//! No host socket is involved and nothing is proxied: the two guests speak TCP
//! to each other as they would across a Linux node's forward chain.
//!
//! Each new flow is decided once, by [`policy::decide_peer`] over the
//! sender's own decision and the receiver's rules, and then tracked in both
//! directions, as conntrack does: a reply is never decided again. A policy
//! change re-decides every tracked flow, and one it now denies is cut, its TCP
//! ends reset. Only addresses in the sandbox pool are ever forwarded.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Message, Icmpv4Packet, IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
};

use super::Flow;
use super::stack::Shared;
use crate::policy::{self, SANDBOX_POOL, Transport, Verdict};

/// How long a tracked flow outlives its last packet. An established TCP flow
/// lasts as long as conntrack would plausibly keep it; one that has seen a
/// FIN or a reset only long enough to finish closing.
const TCP_IDLE: Duration = Duration::from_secs(2 * 60 * 60);
const CLOSING_IDLE: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(60);
const ICMP_IDLE: Duration = Duration::from_secs(30);
/// Flows the node tracks at once. Past it a new flow is dropped.
const MAX_FLOWS: usize = 16384;
const SWEEP_EVERY: Duration = Duration::from_secs(5);
/// The largest TCP segment that crosses the mesh unfragmented: a 1420-byte
/// WireGuard MTU, as Linux gives its interface, less the TCP and IP headers.
pub const MESH_MSS: u16 = 1380;

/// What carries packets to sandboxes on other nodes.
pub trait Uplink: Send + Sync {
    /// Whether a peer node holds `address`.
    fn routes(&self, address: Ipv4Addr) -> bool;
    /// Sends one IP packet to the node holding its destination.
    fn send(&self, packet: &[u8]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    protocol: u8,
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

impl Key {
    fn reversed(self) -> Self {
        Self {
            protocol: self.protocol,
            src: self.dst,
            dst: self.src,
        }
    }

    fn transport(self) -> Transport {
        match IpProtocol::from(self.protocol) {
            IpProtocol::Tcp => Transport::Tcp,
            IpProtocol::Udp => Transport::Udp,
            _ => Transport::Icmp,
        }
    }

    /// The port a policy decides by: none for ICMP, whose key carries the
    /// echo identifier.
    fn port(self) -> u16 {
        match self.transport() {
            Transport::Icmp => 0,
            _ => self.dst.1,
        }
    }
}

/// What the router reads of one packet.
struct Parsed {
    key: Key,
    /// Whether this packet may open a flow: anything but an echo reply.
    is_opening: bool,
    tcp: Option<Segment>,
}

#[derive(Clone, Copy)]
struct Segment {
    ack: Option<u32>,
    is_closing: bool,
    is_syn: bool,
}

fn parse(packet: &[u8]) -> Option<Parsed> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    if ip.more_frags() || ip.frag_offset() != 0 {
        return None;
    }
    let (src, dst) = (ip.src_addr(), ip.dst_addr());
    let protocol = ip.next_header();
    let key = |sport, dport| Key {
        protocol: protocol.into(),
        src: (src, sport),
        dst: (dst, dport),
    };
    match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            Some(Parsed {
                key: key(tcp.src_port(), tcp.dst_port()),
                is_opening: true,
                tcp: Some(Segment {
                    ack: tcp.ack().then(|| tcp.ack_number().0 as u32),
                    is_closing: tcp.fin() || tcp.rst(),
                    is_syn: tcp.syn(),
                }),
            })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(Parsed {
                key: key(udp.src_port(), udp.dst_port()),
                is_opening: true,
                tcp: None,
            })
        }
        IpProtocol::Icmp => {
            let icmp = Icmpv4Packet::new_checked(ip.payload()).ok()?;
            let is_opening = match icmp.msg_type() {
                Icmpv4Message::EchoRequest => true,
                Icmpv4Message::EchoReply => false,
                _ => return None,
            };
            let ident = icmp.echo_ident();
            Some(Parsed {
                key: key(ident, ident),
                is_opening,
                tcp: None,
            })
        }
        _ => None,
    }
}

struct Tracked {
    last: Instant,
    is_closing: bool,
    /// The last acknowledgement each end sent, initiator first: where a reset
    /// cutting the flow has to start for that end to accept it.
    acks: [Option<u32>; 2],
    /// Bytes each end sent, initiator first.
    bytes: [u64; 2],
}

impl Tracked {
    fn idle(&self, key: Key) -> Duration {
        match key.transport() {
            Transport::Tcp if self.is_closing => CLOSING_IDLE,
            Transport::Tcp => TCP_IDLE,
            Transport::Udp => UDP_IDLE,
            Transport::Icmp => ICMP_IDLE,
        }
    }
}

#[derive(Default)]
struct Table {
    /// Keyed by the initiator's direction.
    flows: HashMap<Key, Tracked>,
}

impl Table {
    /// The flow a packet belongs to, and whether it travels as the
    /// initiator's.
    fn find(&mut self, key: Key) -> Option<(Key, &mut Tracked, bool)> {
        if self.flows.contains_key(&key) {
            return Some((key, self.flows.get_mut(&key)?, true));
        }
        let reversed = key.reversed();
        Some((reversed, self.flows.get_mut(&reversed)?, false))
    }
}

/// Where a packet is handed next.
enum Hop {
    Link(Arc<Shared>),
    Mesh(Arc<dyn Uplink>),
}

/// The node's forwarding between sandbox stacks, and onto the mesh.
#[derive(Default)]
pub struct Router {
    links: RwLock<HashMap<Ipv4Addr, Weak<Shared>>>,
    table: Mutex<Table>,
    uplink: RwLock<Option<Weak<dyn Uplink>>>,
    is_sweeping: AtomicBool,
}

impl Router {
    /// Carries packets for addresses no stack here serves over `uplink`.
    pub fn set_uplink(&self, uplink: Weak<dyn Uplink>) {
        *self.uplink.write().unwrap() = Some(uplink);
    }

    /// Whether the router, rather than the stack, handles a packet from a
    /// guest to `address`.
    pub(super) fn is_routed(address: Ipv4Addr) -> bool {
        SANDBOX_POOL.contains(std::net::IpAddr::V4(address))
    }

    pub(super) fn attach(self: &Arc<Self>, address: Ipv4Addr, link: Weak<Shared>) {
        if !self.is_sweeping.swap(true, Ordering::Relaxed) {
            tokio::spawn(sweep(Arc::downgrade(self)));
        }
        self.links.write().unwrap().insert(address, link);
    }

    /// Forgets `link`'s address, unless a newer stack already serves it.
    pub(super) fn detach(&self, address: Ipv4Addr, link: &Shared) {
        {
            let mut links = self.links.write().unwrap();
            if links
                .get(&address)
                .is_some_and(|held| std::ptr::eq(held.as_ptr(), link))
            {
                links.remove(&address);
            }
        }
        self.cut(|key| key.src.0 == address || key.dst.0 == address);
    }

    fn link(&self, address: Ipv4Addr) -> Option<Arc<Shared>> {
        self.links.read().unwrap().get(&address)?.upgrade()
    }

    fn mesh_for(&self, address: Ipv4Addr) -> Option<Arc<dyn Uplink>> {
        let uplink = self.uplink.read().unwrap().as_ref()?.upgrade()?;
        uplink.routes(address).then_some(uplink)
    }

    fn hop(&self, address: Ipv4Addr) -> Option<Hop> {
        match self.link(address) {
            Some(link) => Some(Hop::Link(link)),
            None => self.mesh_for(address).map(Hop::Mesh),
        }
    }

    /// Takes a packet a guest sent to another sandbox's address. Returns
    /// false when the sender's own policy does not send it to a peer, for the
    /// stack to proxy or refuse as it would any other destination.
    pub(super) fn forward(&self, from: &Shared, packet: &[u8]) -> bool {
        let Some(parsed) = parse(packet) else {
            return true;
        };
        let key = parsed.key;
        if self.track(&parsed, packet.len()) {
            if let Some(hop) = self.hop(key.dst.0) {
                deliver(&hop, packet, parsed.tcp, false);
            }
            return true;
        }
        if !parsed.is_opening {
            return true;
        }
        let sent = from.decide(IpAddr::V4(key.dst.0), key.transport(), key.port());
        if sent != Verdict::Direct {
            return false;
        }
        let hop = self.hop(key.dst.0);
        let verdict = match &hop {
            Some(Hop::Link(to)) => {
                policy::decide_peer(Some(sent), Some(&to.policy.borrow().rules), key.src.0)
            }
            Some(Hop::Mesh(_)) => sent,
            None => Verdict::Deny("no node holds this address"),
        };
        match (verdict, hop) {
            (Verdict::Direct, Some(hop)) if self.open(&parsed, packet.len()) => {
                deliver(&hop, packet, parsed.tcp, false);
            }
            (Verdict::Direct, _) => {}
            (Verdict::Deny(reason), _) => refuse(from, key, reason),
            _ => {}
        }
        true
    }

    /// Takes a packet that arrived over the mesh, already admitted by the
    /// sender's node.
    pub fn from_mesh(&self, packet: &[u8]) {
        let Some(parsed) = parse(packet) else {
            return;
        };
        let key = parsed.key;
        if !Self::is_routed(key.src.0) {
            return;
        }
        let Some(to) = self.link(key.dst.0) else {
            return;
        };
        if self.track(&parsed, packet.len()) {
            deliver(&Hop::Link(to), packet, parsed.tcp, true);
            return;
        }
        if !parsed.is_opening {
            return;
        }
        let verdict = policy::decide_peer(None, Some(&to.policy.borrow().rules), key.src.0);
        match verdict {
            Verdict::Direct if self.open(&parsed, packet.len()) => {
                deliver(&Hop::Link(to), packet, parsed.tcp, true);
            }
            Verdict::Deny(reason) => refuse(&to, key, reason),
            _ => {}
        }
    }

    /// Counts a packet against the flow it belongs to, if one is tracked.
    fn track(&self, parsed: &Parsed, len: usize) -> bool {
        let mut table = self.table.lock().unwrap();
        let Some((_, tracked, is_initiator)) = table.find(parsed.key) else {
            return false;
        };
        let side = usize::from(!is_initiator);
        tracked.last = Instant::now();
        tracked.bytes[side] += len as u64;
        if let Some(segment) = parsed.tcp {
            if segment.ack.is_some() {
                tracked.acks[side] = segment.ack;
            }
            tracked.is_closing |= segment.is_closing;
        }
        true
    }

    /// Starts tracking a flow just admitted. False when the table is full.
    fn open(&self, parsed: &Parsed, len: usize) -> bool {
        let mut table = self.table.lock().unwrap();
        if table.flows.len() >= MAX_FLOWS {
            tracing::warn!("dropping a flow between sandboxes: the node tracks too many");
            return false;
        }
        table.flows.insert(
            parsed.key,
            Tracked {
                last: Instant::now(),
                is_closing: parsed.tcp.is_some_and(|s| s.is_closing),
                acks: [parsed.tcp.and_then(|s| s.ack), None],
                bytes: [len as u64, 0],
            },
        );
        true
    }

    /// Decides every tracked flow again under the policies in force now, and
    /// cuts those that are no longer allowed.
    pub(super) fn reapply(&self) {
        let flows: Vec<Key> = self.table.lock().unwrap().flows.keys().copied().collect();
        let denied: Vec<Key> = flows
            .into_iter()
            .filter(|&key| self.decide_again(key) != Verdict::Direct)
            .collect();
        if !denied.is_empty() {
            self.cut(|key| denied.contains(key));
        }
    }

    fn decide_again(&self, key: Key) -> Verdict {
        let sender = self.link(key.src.0);
        let receiver = self.link(key.dst.0);
        let sent = sender
            .as_ref()
            .map(|from| from.decide(IpAddr::V4(key.dst.0), key.transport(), key.port()));
        match &receiver {
            Some(to) => policy::decide_peer(sent, Some(&to.policy.borrow().rules), key.src.0),
            None => policy::decide_peer(sent, None, key.src.0),
        }
    }

    /// Stops tracking the flows `which` picks, resetting their TCP ends, and
    /// records each as cut.
    fn cut(&self, which: impl Fn(&Key) -> bool) {
        let cut: Vec<(Key, Tracked)> = {
            let mut table = self.table.lock().unwrap();
            let keys: Vec<Key> = table.flows.keys().copied().filter(|k| which(k)).collect();
            keys.into_iter()
                .filter_map(|key| Some((key, table.flows.remove(&key)?)))
                .collect()
        };
        for (key, tracked) in cut {
            if key.transport() == Transport::Tcp && !tracked.is_closing {
                for (to, from, ack) in [
                    (key.src, key.dst, tracked.acks[0]),
                    (key.dst, key.src, tracked.acks[1]),
                ] {
                    if let (Some(ack), Some(hop)) = (ack, self.hop(to.0)) {
                        deliver(&hop, &reset(from, to, ack), None, false);
                    }
                }
            }
            self.record(
                key,
                &tracked,
                false,
                "connection reset: the policy now denies this peer",
            );
        }
    }

    /// Forgets flows that have gone quiet, recording each.
    fn expire(&self, now: Instant) {
        let expired: Vec<(Key, Tracked)> = {
            let mut table = self.table.lock().unwrap();
            let keys: Vec<Key> = table
                .flows
                .iter()
                .filter(|(key, tracked)| now.duration_since(tracked.last) > tracked.idle(**key))
                .map(|(key, _)| *key)
                .collect();
            keys.into_iter()
                .filter_map(|key| Some((key, table.flows.remove(&key)?)))
                .collect()
        };
        for (key, tracked) in expired {
            self.record(key, &tracked, true, "allowed (peer)");
        }
    }

    /// One record per flow, by whichever end is on this node, the initiator
    /// first.
    fn record(&self, key: Key, tracked: &Tracked, is_allowed: bool, reason: &str) {
        let Some(link) = self.link(key.src.0).or_else(|| self.link(key.dst.0)) else {
            return;
        };
        Flow {
            sandbox_id: &link.sandbox_id(),
            source: key.src.0,
            destination: SocketAddr::new(IpAddr::V4(key.dst.0), key.port()),
            is_allowed,
            reason: reason.to_string(),
            sent: tracked.bytes[0],
            received: tracked.bytes[1],
        }
        .record(&link.node.audit);
    }

    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.table.lock().unwrap().flows.len()
    }
}

/// Expires quiet flows for as long as the router is in use.
async fn sweep(router: Weak<Router>) {
    loop {
        tokio::time::sleep(SWEEP_EVERY).await;
        let Some(router) = router.upgrade() else {
            return;
        };
        router.expire(Instant::now());
    }
}

/// Audits a flow refused here rather than by the sender's own stack.
fn refuse(at: &Shared, key: Key, reason: &str) {
    Flow {
        sandbox_id: &at.sandbox_id(),
        source: key.src.0,
        destination: SocketAddr::new(IpAddr::V4(key.dst.0), key.port()),
        is_allowed: false,
        reason: reason.to_string(),
        sent: 0,
        received: 0,
    }
    .record(&at.node.audit);
}

/// Hands one packet on, a hop further: its TTL spent, and a SYN crossing
/// the mesh, either way, clamped to what the mesh carries whole.
fn deliver(hop: &Hop, packet: &[u8], tcp: Option<Segment>, is_from_mesh: bool) {
    let mut packet = packet.to_vec();
    let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
    if ip.hop_limit() <= 1 {
        return;
    }
    ip.set_hop_limit(ip.hop_limit() - 1);
    ip.fill_checksum();
    let crosses_mesh = is_from_mesh || matches!(hop, Hop::Mesh(_));
    if crosses_mesh && tcp.is_some_and(|s| s.is_syn) {
        clamp_mss(&mut packet, MESH_MSS);
    }
    match hop {
        Hop::Link(link) => link.route_in(&packet),
        Hop::Mesh(uplink) => uplink.send(&packet),
    }
}

/// Lowers a SYN's MSS option to `mss`, keeping its checksum right.
fn clamp_mss(packet: &mut [u8], mss: u16) {
    let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
    let (src, dst) = (ip.src_addr(), ip.dst_addr());
    let mut tcp = TcpPacket::new_unchecked(ip.payload_mut());
    let options = tcp.options_mut();
    let mut at = 0;
    let mut is_changed = false;
    while at < options.len() {
        match options[at] {
            0 => break,
            1 => at += 1,
            kind => {
                let Some(&len) = options.get(at + 1) else {
                    break;
                };
                let len = usize::from(len);
                if len < 2 || at + len > options.len() {
                    break;
                }
                if kind == 2 && len == 4 {
                    let offered = u16::from_be_bytes([options[at + 2], options[at + 3]]);
                    if offered > mss {
                        options[at + 2..at + 4].copy_from_slice(&mss.to_be_bytes());
                        is_changed = true;
                    }
                }
                at += len;
            }
        }
    }
    if is_changed {
        tcp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
    }
}

/// A reset from `from` that `to` accepts, starting where `to` last
/// acknowledged.
fn reset(from: (Ipv4Addr, u16), to: (Ipv4Addr, u16), seq: u32) -> Vec<u8> {
    let tcp = TcpRepr {
        src_port: from.1,
        dst_port: to.1,
        control: TcpControl::Rst,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: None,
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let ip = Ipv4Repr {
        src_addr: from.0,
        dst_addr: to.0,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let mut packet = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
    let caps = ChecksumCapabilities::default();
    let mut header = Ipv4Packet::new_unchecked(&mut packet[..]);
    ip.emit(&mut header, &caps);
    tcp.emit(
        &mut TcpPacket::new_unchecked(header.payload_mut()),
        &IpAddress::Ipv4(from.0),
        &IpAddress::Ipv4(to.0),
        &caps,
    );
    packet
}
