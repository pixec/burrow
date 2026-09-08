//! The userspace TCP/UDP stack that terminates tunnel traffic.
//!
//! Decrypted IPv6 packets from peers are fed into a smoltcp interface; what
//! it wants to transmit comes back out to be encrypted. There is no TUN
//! device: the stack owns the server's tunnel address (and, when
//! forwarding is enabled, answers for any address) entirely in memory.
//!
//! Listeners are created on demand. Every inbound SYN is inspected before
//! the stack sees it: if the port policy admits it, a listening socket for
//! that exact address and port exists by the time the packet is processed,
//! so the connection completes and is handed out as a [`TcpConn`]. A SYN
//! the policy refuses is dropped before the stack, so the client sees a
//! timeout rather than a refusal, as with the stock server's filter. UDP
//! datagrams likewise conjure a socket per destination and are demuxed per
//! source into [`UdpFlow`]s that time out when idle.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

use crate::key::NodePublic;

/// The tunnel MTU. WireGuard over IPv6 with room to spare, and what the
/// stock client assumes.
pub const MTU: usize = 1280;
const TCP_BUFFER: usize = 128 * 1024;
const UDP_PACKETS: usize = 128;
const UDP_BUFFER: usize = 256 * 1024;
const FLOW_QUEUE: usize = 64;
const ACCEPT_QUEUE: usize = 256;
const EGRESS_QUEUE: usize = 512;
/// A connection whose peer stops acknowledging is torn down after this,
/// so a client that vanished mid-transfer does not pin a socket forever.
const TCP_TIMEOUT: Duration = Duration::from_secs(90);

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// The NAT64 well-known prefix, `64:ff9b::/96`. Clients map IPv4
/// destinations into it, since the tunnel carries only IPv6.
const NAT64_PREFIX: [u8; 12] = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];

/// Which ports on the server's own address admit new connections or flows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ports {
    All,
    Ranges(Vec<RangeInclusive<u16>>),
}

impl Ports {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Ports::All => true,
            Ports::Ranges(ranges) => ranges.iter().any(|r| r.contains(&port)),
        }
    }

    pub fn list(ports: impl IntoIterator<Item = u16>) -> Self {
        Ports::Ranges(ports.into_iter().map(|p| p..=p).collect())
    }
}

/// What the stack admits from the tunnel.
#[derive(Clone, Debug)]
pub struct Policy {
    pub self_addr: Ipv6Addr,
    pub tcp_ports: Ports,
    /// `None` means no UDP is served at all.
    pub udp_ports: Option<Ports>,
    /// Also admit TCP aimed past us, which is what makes an exit node.
    pub forward_tcp: bool,
    pub forward_udp: bool,
    pub udp_idle_timeout: Duration,
}

/// Maps a NAT64-embedded IPv4 address back out; other addresses pass.
pub fn unmap_nat64(ip: Ipv6Addr) -> IpAddr {
    let o = ip.octets();
    if o[..12] == NAT64_PREFIX {
        IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else {
        IpAddr::V6(ip)
    }
}

struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct RxToken(Vec<u8>);

impl phy::RxToken for RxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct TxToken<'a>(&'a mut Vec<Vec<u8>>);

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for Queues {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(RxToken, TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxToken(pkt), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

type FlowKey = (SocketAddrV6, SocketAddrV6);

struct Flow {
    tx: mpsc::Sender<Vec<u8>>,
    last_activity: Instant,
    shared: Arc<FlowShared>,
}

struct FlowShared {
    closed: AtomicBool,
}

struct Accepted {
    handle: SocketHandle,
    local: SocketAddrV6,
    remote: SocketAddrV6,
}

struct NewFlow {
    key: FlowKey,
    rx: mpsc::Receiver<Vec<u8>>,
    shared: Arc<FlowShared>,
}

struct Inner {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: Queues,
    policy: Policy,
    /// Sockets in `Listen` or `SynReceived` for each local endpoint. A SYN
    /// only creates a new listener when none of them is still listening.
    listeners: HashMap<(Ipv6Addr, u16), Vec<SocketHandle>>,
    /// Handed-out sockets whose [`TcpConn`] is gone, removed once closed.
    closing: Vec<SocketHandle>,
    udp_sockets: HashMap<(Ipv6Addr, u16), SocketHandle>,
    flows: HashMap<FlowKey, Flow>,
    closed: bool,
}

fn endpoint_v6(ep: IpEndpoint) -> SocketAddrV6 {
    match SocketAddr::from(ep) {
        SocketAddr::V6(a) => a,
        SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
    }
}

impl Inner {
    fn admit(&mut self, pkt: &[u8]) -> bool {
        if pkt.len() < 40 || pkt[0] >> 4 != 6 {
            return false;
        }
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).unwrap());
        let to_self = dst == self.policy.self_addr;
        let payload = &pkt[40..];
        match pkt[6] {
            IPPROTO_TCP => {
                if payload.len() < 20 {
                    return false;
                }
                let port = u16::from_be_bytes([payload[2], payload[3]]);
                let admitted = if to_self {
                    self.policy.tcp_ports.contains(port)
                } else {
                    self.policy.forward_tcp
                };
                if !admitted {
                    return false;
                }
                let flags = payload[13];
                if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
                    self.ensure_listener(dst, port);
                }
                true
            }
            IPPROTO_UDP => {
                if payload.len() < 8 {
                    return false;
                }
                let port = u16::from_be_bytes([payload[2], payload[3]]);
                let admitted = if to_self {
                    self.policy
                        .udp_ports
                        .as_ref()
                        .is_some_and(|p| p.contains(port))
                } else {
                    self.policy.forward_udp
                };
                if !admitted {
                    return false;
                }
                self.ensure_udp_socket(dst, port);
                true
            }
            IPPROTO_ICMPV6 => to_self,
            _ => false,
        }
    }

    fn ensure_listener(&mut self, addr: Ipv6Addr, port: u16) {
        let handles = self.listeners.entry((addr, port)).or_default();
        if handles
            .iter()
            .any(|h| self.sockets.get::<tcp::Socket>(*h).state() == tcp::State::Listen)
        {
            return;
        }
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        sock.set_nagle_enabled(false);
        sock.set_timeout(Some(TCP_TIMEOUT.into()));
        sock.listen(IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(addr)),
            port,
        })
        .expect("fresh socket listens");
        handles.push(self.sockets.add(sock));
    }

    fn ensure_udp_socket(&mut self, addr: Ipv6Addr, port: u16) -> SocketHandle {
        if let Some(h) = self.udp_sockets.get(&(addr, port)) {
            return *h;
        }
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_BUFFER],
            )
        };
        let mut sock = udp::Socket::new(buffer(), buffer());
        sock.bind(IpListenEndpoint {
            addr: Some(IpAddress::Ipv6(addr)),
            port,
        })
        .expect("fresh socket binds");
        let h = self.sockets.add(sock);
        self.udp_sockets.insert((addr, port), h);
        h
    }

    fn poll(
        &mut self,
        now: Instant,
    ) -> (Vec<Vec<u8>>, Vec<Accepted>, Vec<NewFlow>, Option<Duration>) {
        let ts = smol_now_from(now);
        self.iface.poll(ts, &mut self.device, &mut self.sockets);

        let mut accepted = Vec::new();
        let sockets = &mut self.sockets;
        self.listeners.retain(|_, handles| {
            handles.retain(|h| {
                let sock = sockets.get::<tcp::Socket>(*h);
                match sock.state() {
                    tcp::State::Listen | tcp::State::SynReceived => true,
                    tcp::State::Closed => {
                        sockets.remove(*h);
                        false
                    }
                    _ => {
                        if let (Some(local), Some(remote)) =
                            (sock.local_endpoint(), sock.remote_endpoint())
                        {
                            accepted.push(Accepted {
                                handle: *h,
                                local: endpoint_v6(local),
                                remote: endpoint_v6(remote),
                            });
                        } else {
                            sockets.remove(*h);
                        }
                        false
                    }
                }
            });
            !handles.is_empty()
        });

        self.closing.retain(|h| {
            if sockets.get::<tcp::Socket>(*h).state() == tcp::State::Closed {
                sockets.remove(*h);
                false
            } else {
                true
            }
        });

        let mut new_flows = Vec::new();
        for (&(addr, port), &h) in &self.udp_sockets {
            let sock = sockets.get_mut::<udp::Socket>(h);
            while let Ok((data, meta)) = sock.recv() {
                let local = SocketAddrV6::new(addr, port, 0, 0);
                let key = (local, endpoint_v6(meta.endpoint));
                let data = data.to_vec();
                let flow = self.flows.entry(key).or_insert_with(|| {
                    let (tx, rx) = mpsc::channel(FLOW_QUEUE);
                    let shared = Arc::new(FlowShared {
                        closed: AtomicBool::new(false),
                    });
                    new_flows.push(NewFlow {
                        key,
                        rx,
                        shared: shared.clone(),
                    });
                    Flow {
                        tx,
                        last_activity: now,
                        shared,
                    }
                });
                flow.last_activity = now;
                let _ = flow.tx.try_send(data);
            }
        }

        let idle = self.policy.udp_idle_timeout;
        self.flows.retain(|_, flow| {
            let keep = now.duration_since(flow.last_activity) < idle;
            if !keep {
                flow.shared.closed.store(true, Ordering::Relaxed);
            }
            keep
        });

        let egress = std::mem::take(&mut self.device.tx);
        let delay = self
            .iface
            .poll_delay(ts, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()));
        (egress, accepted, new_flows, delay)
    }

    fn abort_all(&mut self) {
        for (_, sock) in self.sockets.iter_mut() {
            if let smoltcp::socket::Socket::Tcp(sock) = sock {
                sock.abort();
            }
        }
    }
}

fn smol_now_from(now: Instant) -> SmolInstant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    SmolInstant::from_micros(now.saturating_duration_since(epoch).as_micros() as i64)
}

/// The stack and the task that drives it.
pub struct Netstack {
    inner: Arc<Mutex<Inner>>,
    wake: Arc<Notify>,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// The receiving ends a [`Netstack`] delivers into.
pub struct Outputs {
    /// IPv6 packets the stack wants sent to peers.
    pub egress: mpsc::Receiver<Vec<u8>>,
    pub tcp: mpsc::Receiver<TcpConn>,
    pub udp: mpsc::Receiver<UdpFlow>,
}

impl Netstack {
    pub fn start(policy: Policy) -> (Arc<Netstack>, Outputs) {
        let mut device = Queues {
            rx: VecDeque::new(),
            tx: Vec::new(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let now = Instant::now();
        let mut iface = Interface::new(config, &mut device, smol_now_from(now));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(policy.self_addr), 128))
                .expect("one address fits");
        });
        iface.set_any_ip(policy.forward_tcp || policy.forward_udp);

        let inner = Arc::new(Mutex::new(Inner {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            policy,
            listeners: HashMap::new(),
            closing: Vec::new(),
            udp_sockets: HashMap::new(),
            flows: HashMap::new(),
            closed: false,
        }));
        let wake = Arc::new(Notify::new());
        let (egress_tx, egress_rx) = mpsc::channel(EGRESS_QUEUE);
        let (tcp_tx, tcp_rx) = mpsc::channel(ACCEPT_QUEUE);
        let (udp_tx, udp_rx) = mpsc::channel(ACCEPT_QUEUE);
        let ns = Arc::new(Netstack {
            inner,
            wake,
            task: Mutex::new(None),
        });
        let task = tokio::spawn(ns.clone().run(egress_tx, tcp_tx, udp_tx));
        *ns.task.lock().unwrap() = Some(task);
        (
            ns,
            Outputs {
                egress: egress_rx,
                tcp: tcp_rx,
                udp: udp_rx,
            },
        )
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    /// Feeds one decrypted IPv6 packet from a peer into the stack.
    pub fn inject(&self, pkt: Vec<u8>) {
        let mut inner = self.lock();
        if inner.closed || !inner.admit(&pkt) {
            return;
        }
        inner.device.rx.push_back(pkt);
        drop(inner);
        self.wake.notify_one();
    }

    pub fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.abort_all();
        for flow in inner.flows.values() {
            flow.shared.closed.store(true, Ordering::Relaxed);
        }
        inner.flows.clear();
        drop(inner);
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }

    async fn run(
        self: Arc<Self>,
        egress: mpsc::Sender<Vec<u8>>,
        tcp_tx: mpsc::Sender<TcpConn>,
        udp_tx: mpsc::Sender<UdpFlow>,
    ) {
        loop {
            let (out, accepted, new_flows, delay) = {
                let mut inner = self.lock();
                if inner.closed {
                    return;
                }
                inner.poll(Instant::now())
            };
            for pkt in out {
                if egress.send(pkt).await.is_err() {
                    return;
                }
            }
            for a in accepted {
                let conn = TcpConn {
                    inner: self.inner.clone(),
                    wake: self.wake.clone(),
                    handle: a.handle,
                    local: a.local,
                    remote: a.remote,
                    peer_key: None,
                };
                if tcp_tx.send(conn).await.is_err() {
                    self.lock().sockets.get_mut::<tcp::Socket>(a.handle).abort();
                }
            }
            for f in new_flows {
                let flow = UdpFlow {
                    inner: self.inner.clone(),
                    wake: self.wake.clone(),
                    key: f.key,
                    rx: f.rx,
                    shared: f.shared,
                    peer_key: None,
                };
                let _ = udp_tx.send(flow).await;
            }
            let delay = delay.unwrap_or(Duration::from_secs(1));
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }
}

impl Drop for Netstack {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

/// A TCP connection a client opened through the tunnel.
///
/// Dropping it closes the connection gracefully; use
/// [`AsyncWriteExt::shutdown`](tokio::io::AsyncWriteExt::shutdown) for a
/// half-close that still reads.
pub struct TcpConn {
    inner: Arc<Mutex<Inner>>,
    wake: Arc<Notify>,
    handle: SocketHandle,
    local: SocketAddrV6,
    remote: SocketAddrV6,
    pub(crate) peer_key: Option<NodePublic>,
}

impl TcpConn {
    /// The address the client dialed. An IPv4 destination that arrived
    /// through NAT64 is reported as IPv4.
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(unmap_nat64(*self.local.ip()), self.local.port())
    }

    /// The client's tunnel address and source port.
    pub fn remote_addr(&self) -> SocketAddrV6 {
        self.remote
    }

    /// The node key of the client, which is what its tunnel address was
    /// derived from.
    pub fn peer_key(&self) -> Option<NodePublic> {
        self.peer_key
    }

    /// Whether the client dialed somewhere other than the server itself.
    pub fn is_forward(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        *self.local.ip() != inner.policy.self_addr
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        let sock = inner.sockets.get_mut::<tcp::Socket>(self.handle);
        if sock.can_recv() {
            let n = sock
                .recv_slice(buf.initialize_unfilled())
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            buf.advance(n);
            drop(inner);
            self.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if !sock.may_recv() {
            return Poll::Ready(Ok(()));
        }
        sock.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut inner = self.inner.lock().unwrap();
        let sock = inner.sockets.get_mut::<tcp::Socket>(self.handle);
        if !sock.may_send() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        if sock.can_send() {
            let n = sock
                .send_slice(data)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            drop(inner);
            self.wake.notify_one();
            return Poll::Ready(Ok(n));
        }
        sock.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        inner.sockets.get_mut::<tcp::Socket>(self.handle).close();
        drop(inner);
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        inner.sockets.get_mut::<tcp::Socket>(self.handle).close();
        inner.closing.push(self.handle);
        drop(inner);
        self.wake.notify_one();
    }
}

/// One client's UDP flow to one destination: every datagram from a given
/// source address and port to a given local address and port.
///
/// Datagram boundaries are preserved. A flow ends when it has been idle
/// for the configured timeout, after which [`recv`](Self::recv) returns
/// `None` and sends fail.
pub struct UdpFlow {
    inner: Arc<Mutex<Inner>>,
    wake: Arc<Notify>,
    key: FlowKey,
    rx: mpsc::Receiver<Vec<u8>>,
    shared: Arc<FlowShared>,
    pub(crate) peer_key: Option<NodePublic>,
}

impl UdpFlow {
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(unmap_nat64(*self.key.0.ip()), self.key.0.port())
    }

    pub fn remote_addr(&self) -> SocketAddrV6 {
        self.key.1
    }

    pub fn peer_key(&self) -> Option<NodePublic> {
        self.peer_key
    }

    pub fn is_forward(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        *self.key.0.ip() != inner.policy.self_addr
    }

    /// The next datagram, or `None` once the flow has ended.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Sends one datagram back to the client. Like any UDP send it may be
    /// dropped silently if the stack's buffer is full.
    pub fn send(&self, data: &[u8]) -> std::io::Result<()> {
        if self.shared.closed.load(Ordering::Relaxed) {
            return Err(std::io::ErrorKind::NotConnected.into());
        }
        let mut inner = self.inner.lock().unwrap();
        let (local, remote) = self.key;
        let Some(&handle) = inner.udp_sockets.get(&(*local.ip(), local.port())) else {
            return Err(std::io::ErrorKind::NotConnected.into());
        };
        let meta = udp::UdpMetadata {
            endpoint: IpEndpoint::from(SocketAddr::V6(remote)),
            local_address: Some(IpAddress::Ipv6(*local.ip())),
            meta: Default::default(),
        };
        match inner
            .sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(data, meta)
        {
            Ok(()) | Err(udp::SendError::BufferFull) => {}
            Err(udp::SendError::Unaddressable) => {
                return Err(std::io::ErrorKind::AddrNotAvailable.into());
            }
        }
        if let Some(flow) = inner.flows.get_mut(&self.key) {
            flow.last_activity = Instant::now();
        }
        drop(inner);
        self.wake.notify_one();
        Ok(())
    }
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Relaxed);
        self.inner.lock().unwrap().flows.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpProtocol, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
        UdpRepr,
    };
    use tokio::time::timeout;

    const SELF: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1);
    const CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 2);
    const WAIT: Duration = Duration::from_secs(2);

    fn policy(tcp_ports: Ports, udp_ports: Option<Ports>) -> Policy {
        Policy {
            self_addr: SELF,
            tcp_ports,
            udp_ports,
            forward_tcp: false,
            forward_udp: false,
            udp_idle_timeout: Duration::from_secs(60),
        }
    }

    fn ipv6(next_header: IpProtocol, payload_len: usize) -> (Vec<u8>, Ipv6Repr) {
        let ip = Ipv6Repr {
            src_addr: CLIENT,
            dst_addr: SELF,
            next_header,
            payload_len,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + payload_len];
        ip.emit(&mut Ipv6Packet::new_unchecked(&mut buf));
        (buf, ip)
    }

    fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp = UdpRepr { src_port, dst_port };
        let (mut buf, ip) = ipv6(IpProtocol::Udp, udp.header_len() + payload.len());
        let mut pkt = Ipv6Packet::new_unchecked(&mut buf);
        udp.emit(
            &mut UdpPacket::new_unchecked(pkt.payload_mut()),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    fn syn(src_port: u16, dst_port: u16) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port,
            dst_port,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1220),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let (mut buf, ip) = ipv6(IpProtocol::Tcp, tcp.buffer_len());
        let mut pkt = Ipv6Packet::new_unchecked(&mut buf);
        tcp.emit(
            &mut TcpPacket::new_unchecked(pkt.payload_mut()),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    #[tokio::test]
    async fn udp_flow_round_trips() {
        let (ns, mut out) = Netstack::start(policy(Ports::All, Some(Ports::All)));
        ns.inject(udp(5000, 7777, b"ping"));
        let mut flow = timeout(WAIT, out.udp.recv()).await.unwrap().unwrap();
        assert_eq!(flow.local_addr(), SocketAddr::new(SELF.into(), 7777));
        assert_eq!(flow.remote_addr(), SocketAddrV6::new(CLIENT, 5000, 0, 0));
        assert!(!flow.is_forward());
        assert_eq!(flow.recv().await.unwrap(), b"ping");

        flow.send(b"pong").unwrap();
        let pkt = timeout(WAIT, out.egress.recv()).await.unwrap().unwrap();
        let ip = Ipv6Packet::new_checked(&pkt).unwrap();
        assert_eq!(ip.dst_addr(), CLIENT);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!((udp.src_port(), udp.dst_port()), (7777, 5000));
        assert_eq!(udp.payload(), b"pong");
        ns.close();
    }

    #[tokio::test]
    async fn udp_outside_policy_is_dropped() {
        let (ns, mut out) = Netstack::start(policy(Ports::All, Some(Ports::list([53]))));
        ns.inject(udp(5000, 54, b"nope"));
        assert!(
            timeout(Duration::from_millis(300), out.udp.recv())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(300), out.egress.recv())
                .await
                .is_err()
        );
        ns.close();
    }

    #[tokio::test]
    async fn tcp_policy_gates_syns() {
        let (ns, mut out) = Netstack::start(policy(Ports::list([80]), None));
        ns.inject(syn(40000, 81));
        assert!(
            timeout(Duration::from_millis(300), out.egress.recv())
                .await
                .is_err()
        );

        ns.inject(syn(40001, 80));
        let pkt = timeout(WAIT, out.egress.recv()).await.unwrap().unwrap();
        let ip = Ipv6Packet::new_checked(&pkt).unwrap();
        assert_eq!(ip.dst_addr(), CLIENT);
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack());
        assert_eq!((tcp.src_port(), tcp.dst_port()), (80, 40001));
        ns.close();
    }

    #[test]
    fn nat64_unmaps() {
        let mapped: Ipv6Addr = "64:ff9b::c000:201".parse().unwrap();
        assert_eq!(unmap_nat64(mapped), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(unmap_nat64(SELF), IpAddr::V6(SELF));
    }
}
