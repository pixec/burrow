//! The node mesh in userspace, for a node with no kernel WireGuard.
//!
//! One UDP socket and a boringtun tunnel per peer node, speaking the same
//! protocol as the Linux nodes' `burrow-wg` interface, configured from the
//! same peer list ([`crate::mesh::Peer`]) with the same validation. A peer's
//! slice is its `AllowedIPs` both ways: a packet goes to the peer whose slice
//! holds its destination, and a packet from a peer is dropped unless its
//! source is in that peer's slice.
//!
//! A peer's configured endpoint is used when it resolves here; otherwise, or
//! once the peer is heard from somewhere else, replies go to wherever its
//! last authenticated packet came from, as WireGuard's roaming does. A node
//! behind NAT, or whose peers advertise names only their own network
//! resolves, is reachable as soon as each peer has sent its first keepalive.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

use super::Router;
use super::router::Uplink;
use crate::mesh::Peer;
use crate::policy::{Cidr, parse_cidr};

/// Large enough for any datagram, and for boringtun's own minimum.
const BUF: usize = 65536 + 64;
/// How often each tunnel's timers run: handshake retries, keepalives,
/// rekeying.
const TICK: Duration = Duration::from_millis(250);
/// Linux's mesh sets the same, so a NAT between nodes stays open.
const KEEPALIVE_SECS: u16 = 25;
/// How long one endpoint gets to resolve.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// A private key as `wg genkey` writes it.
pub(crate) fn secret(private_key: &str) -> Option<StaticSecret> {
    Some(StaticSecret::from(decode_key(private_key)?))
}

fn decode_key(key: &str) -> Option<[u8; 32]> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .ok()?
        .try_into()
        .ok()
}

struct PeerState {
    node_id: String,
    public_key: [u8; 32],
    subnet: Cidr,
    tunn: Tunn,
    /// This end's index for the peer's sessions, which every message but an
    /// initiation names.
    index: u32,
    /// Where the peer's packets go: its configured endpoint, or where it was
    /// last heard from.
    endpoint: Option<SocketAddr>,
}

#[derive(Default)]
struct Peers {
    list: Vec<PeerState>,
    next_index: u32,
}

/// The node's end of the mesh.
pub struct Mesh {
    socket: UdpSocket,
    secret: StaticSecret,
    public: PublicKey,
    peers: Mutex<Peers>,
    router: Arc<Router>,
}

impl Mesh {
    /// Listens on `listen` with the node's mesh key, and makes this the
    /// router's way to other nodes.
    pub async fn start(
        listen: SocketAddr,
        private_key: &str,
        router: Arc<Router>,
    ) -> std::io::Result<Arc<Self>> {
        let secret = secret(private_key)
            .ok_or_else(|| std::io::Error::other("the mesh key is not 32 bytes of base64"))?;
        let socket = UdpSocket::bind(listen).await?;
        let mesh = Arc::new(Self {
            socket,
            public: PublicKey::from(&secret),
            secret,
            peers: Mutex::default(),
            router: Arc::clone(&router),
        });
        let uplink: Arc<dyn Uplink> = mesh.clone();
        router.set_uplink(Arc::downgrade(&uplink));
        tokio::spawn(receive(Arc::downgrade(&mesh)));
        tokio::spawn(tick(Arc::downgrade(&mesh)));
        tracing::info!(listen = %mesh.socket.local_addr()?, "mesh listening");
        Ok(mesh)
    }

    /// The address the socket is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Replaces the peer set. A peer already known keeps its tunnel, so a
    /// heartbeat restating the fleet does not renegotiate every session.
    pub async fn configure(&self, peers: &[Peer]) {
        let mut wanted = Vec::new();
        for peer in peers.iter().filter(|peer| crate::mesh::is_valid_peer(peer)) {
            let (Some(public_key), Some(subnet)) =
                (decode_key(&peer.public_key), parse_cidr(&peer.subnet))
            else {
                continue;
            };
            wanted.push((peer, public_key, subnet, resolve(&peer.endpoint).await));
        }
        let mut held = self.peers.lock().unwrap();
        let mut old = std::mem::take(&mut held.list);
        for (peer, public_key, subnet, endpoint) in wanted {
            let state = match old.iter().position(|p| p.public_key == public_key) {
                Some(at) => {
                    let mut state = old.swap_remove(at);
                    state.node_id = peer.node_id.clone();
                    state.subnet = subnet;
                    state.endpoint = endpoint.or(state.endpoint);
                    state
                }
                None => {
                    held.next_index = (held.next_index + 1) & 0x00ff_ffff;
                    let index = held.next_index;
                    PeerState {
                        node_id: peer.node_id.clone(),
                        public_key,
                        subnet,
                        tunn: Tunn::new(
                            self.secret.clone(),
                            PublicKey::from(public_key),
                            None,
                            Some(KEEPALIVE_SECS),
                            index,
                            None,
                        ),
                        index,
                        endpoint,
                    }
                }
            };
            held.list.push(state);
        }
        tracing::info!(peers = held.list.len(), "mesh configured");
    }

    /// Which peer a datagram is from: an initiation names its sender's
    /// static key, everything else this end's index for the session.
    fn peer_of(&self, peers: &Peers, data: &[u8]) -> Option<usize> {
        let index = match Tunn::parse_incoming_packet(data).ok()? {
            Packet::HandshakeInit(init) => {
                let half = parse_handshake_anon(&self.secret, &self.public, &init).ok()?;
                return peers
                    .list
                    .iter()
                    .position(|p| p.public_key == half.peer_static_public);
            }
            Packet::HandshakeResponse(p) => p.receiver_idx,
            Packet::PacketCookieReply(p) => p.receiver_idx,
            Packet::PacketData(p) => p.receiver_idx,
        };
        peers.list.iter().position(|p| p.index == index >> 8)
    }

    /// Decrypts one datagram from `from`, answering whatever the protocol
    /// asks to be answered, and returns the packets it carried.
    fn open(&self, data: &[u8], from: SocketAddr) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut peers = self.peers.lock().unwrap();
        let Some(at) = self.peer_of(&peers, data) else {
            return packets;
        };
        let peer = &mut peers.list[at];
        // A keepalive is a data message carrying nothing, authenticated all
        // the same.
        let is_data = data.first() == Some(&4);
        let mut buf = vec![0u8; BUF];
        let mut datagram = data;
        loop {
            match peer.tunn.decapsulate(Some(from.ip()), datagram, &mut buf) {
                TunnResult::WriteToNetwork(reply) => {
                    peer.endpoint = Some(from);
                    let _ = self.socket.try_send_to(reply, from);
                    // An empty datagram flushes what queued behind the
                    // handshake that just completed.
                    datagram = &[];
                }
                TunnResult::WriteToTunnelV4(packet, source) => {
                    peer.endpoint = Some(from);
                    if peer.subnet.contains(std::net::IpAddr::V4(source)) {
                        packets.push(packet.to_vec());
                    } else {
                        tracing::debug!(node = peer.node_id, %source, "dropping a mesh packet from outside the peer's slice");
                    }
                    break;
                }
                TunnResult::Done => {
                    if is_data {
                        peer.endpoint = Some(from);
                    }
                    break;
                }
                TunnResult::WriteToTunnelV6(..) => break,
                TunnResult::Err(err) => {
                    tracing::trace!(node = peer.node_id, ?err, "mesh datagram refused");
                    break;
                }
            }
        }
        packets
    }

    /// Runs every tunnel's timers once.
    fn tick(&self) {
        let mut peers = self.peers.lock().unwrap();
        let mut buf = vec![0u8; BUF];
        for peer in &mut peers.list {
            match peer.tunn.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(out) => {
                    if let Some(endpoint) = peer.endpoint {
                        let _ = self.socket.try_send_to(out, endpoint);
                    }
                }
                TunnResult::Err(WireGuardError::ConnectionExpired) => {}
                TunnResult::Err(err) => {
                    tracing::trace!(node = peer.node_id, ?err, "mesh timers");
                }
                _ => {}
            }
        }
    }
}

impl Uplink for Mesh {
    fn routes(&self, address: Ipv4Addr) -> bool {
        self.peers
            .lock()
            .unwrap()
            .list
            .iter()
            .any(|peer| peer.subnet.contains(std::net::IpAddr::V4(address)))
    }

    fn send(&self, packet: &[u8]) {
        let Ok(ip) = smoltcp::wire::Ipv4Packet::new_checked(packet) else {
            return;
        };
        let destination = ip.dst_addr();
        let mut peers = self.peers.lock().unwrap();
        let Some(peer) = peers
            .list
            .iter_mut()
            .find(|peer| peer.subnet.contains(std::net::IpAddr::V4(destination)))
        else {
            return;
        };
        let mut buf = vec![0u8; packet.len() + 148];
        // Without a session the packet is queued and an initiation comes
        // out instead, which goes to the same endpoint.
        if let TunnResult::WriteToNetwork(out) = peer.tunn.encapsulate(packet, &mut buf)
            && let Some(endpoint) = peer.endpoint
        {
            let _ = self.socket.try_send_to(out, endpoint);
        }
    }
}

/// Resolves a peer's advertised endpoint, if it resolves from here.
async fn resolve(endpoint: &str) -> Option<SocketAddr> {
    if endpoint.is_empty() {
        return None;
    }
    let found = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(endpoint)).await;
    match found {
        Ok(Ok(mut addresses)) => addresses.find(SocketAddr::is_ipv4),
        _ => {
            tracing::debug!(
                endpoint,
                "a mesh peer's endpoint does not resolve here; waiting to hear from it"
            );
            None
        }
    }
}

async fn receive(mesh: Weak<Mesh>) {
    let mut buf = vec![0u8; BUF];
    loop {
        let Some(held) = mesh.upgrade() else {
            return;
        };
        let received = held.socket.recv_from(&mut buf).await;
        let (n, from) = match received {
            Ok(received) => received,
            Err(err) => {
                tracing::debug!(%err, "mesh socket");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        for packet in held.open(&buf[..n], from) {
            held.router.from_mesh(&packet);
        }
    }
}

async fn tick(mesh: Weak<Mesh>) {
    loop {
        tokio::time::sleep(TICK).await;
        let Some(mesh) = mesh.upgrade() else {
            return;
        };
        mesh.tick();
    }
}
