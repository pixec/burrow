//! The per-sandbox stack: the frame filter in front of smoltcp, the task that
//! drives it, and the decision each new TCP flow gets.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr, IpListenEndpoint,
    IpProtocol, Ipv4Packet, TcpPacket, UdpPacket,
};
use tokio::net::{TcpListener, UnixDatagram};
use tokio::sync::{Notify, watch};
use tokio::task::{AbortHandle, JoinHandle};

use super::conn::{self, GuestConn};
use super::{Flow, Node, Policy, SandboxNet, Services, udp, wire};
use crate::policy::{self, NodeDenials, Transport, Verdict};

/// Per direction. Large enough that one flow can fill a fast upstream: the
/// receive buffer is the window the guest is offered.
const TCP_BUFFER: usize = 512 * 1024;
/// A connection whose peer stops acknowledging is torn down after this,
/// so a guest that vanished mid-transfer does not pin a socket forever.
const TCP_TIMEOUT: Duration = Duration::from_secs(90);
/// TCP flows one sandbox may hold at once, the proxy's own per-source budget
/// several times over. Past it a SYN is reset rather than queued.
const MAX_TCP_FLOWS: usize = 512;
/// How long an upstream connect may take, the proxy's own bound.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Frames read per pass before smoltcp is polled, so a guest flooding the
/// link cannot starve its own timers.
const RX_BATCH: usize = 256;
/// Ephemeral ports on the gateway for connections into the guest.
const INBOUND_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;

/// Guest source port and destination.
pub(super) type FlowKey = (u16, SocketAddr);

struct Queues {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    mtu: usize,
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
        let packet = self.rx.pop_front()?;
        Some((RxToken(packet), TxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<TxToken<'_>> {
        Some(TxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub(crate) struct Inner {
    iface: Interface,
    pub(super) sockets: SocketSet<'static>,
    device: Queues,
    /// Frames built outside smoltcp, waiting to be sent.
    pub(super) frames: Vec<Vec<u8>>,
    flows: HashMap<FlowKey, SocketHandle>,
    /// SYNs that made a socket, waiting for their flow to be decided.
    pending: Vec<(FlowKey, SocketHandle)>,
    /// Sockets nothing holds any more, removed once they reach `Closed`.
    pub(super) released: HashSet<SocketHandle>,
    /// Direct TCP flows, re-decided when the policy changes.
    direct: HashMap<SocketHandle, SocketAddr>,
    pub(super) udp: udp::Flows,
    tasks: Vec<AbortHandle>,
    ident: u16,
    next_port: u16,
    pub(super) is_closed: bool,
    is_leased: bool,
}

impl Inner {
    /// An IPv4 identification for a packet built outside smoltcp.
    pub(super) fn ident(&mut self) -> u16 {
        self.ident = self.ident.wrapping_add(1);
        self.ident
    }

    pub(super) fn track(&mut self, task: AbortHandle) {
        if self.tasks.len() >= 64 {
            self.tasks.retain(|task| !task.is_finished());
        }
        self.tasks.push(task);
    }
}

/// Everything a sandbox's flows share with the task that drives the stack.
pub(crate) struct Shared {
    pub(super) inner: Mutex<Inner>,
    pub(super) wake: Notify,
    pub(super) net: SandboxNet,
    pub(super) node: Arc<Node>,
    pub(super) services: Services,
    pub(super) budget: burrow_proxy::dns::Budget,
    pub(super) policy: watch::Receiver<Policy>,
    epoch: Instant,
    /// Where tests really dial a destination the guest names, since nothing
    /// a test can listen on is reachable through the policy: every address
    /// it could bind is the node's own.
    #[cfg(test)]
    pub(super) dial: Mutex<HashMap<SocketAddr, SocketAddr>>,
}

impl Shared {
    pub(super) fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    /// The address a flow to `destination` is actually dialled at.
    pub(super) fn dial_address(&self, destination: SocketAddr) -> SocketAddr {
        #[cfg(test)]
        if let Some(&to) = self.dial.lock().unwrap().get(&destination) {
            return to;
        }
        destination
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.epoch.elapsed().as_micros() as i64)
    }

    pub(super) fn sandbox_id(&self) -> String {
        self.policy.borrow().proxy.sandbox_id.clone()
    }

    /// Decides a new flow from the guest against the policy in force now.
    pub(super) fn decide(&self, destination: IpAddr, transport: Transport, port: u16) -> Verdict {
        let policy = self.policy.borrow();
        self.decide_with(&policy, destination, transport, port)
    }

    pub(super) fn decide_with(
        &self,
        policy: &Policy,
        destination: IpAddr,
        transport: Transport,
        port: u16,
    ) -> Verdict {
        let node = NodeDenials {
            control_plane: self.node.denied.addresses(),
            node: super::node_addresses(),
        };
        // The resolver may be given an address of its own, but it is the
        // gateway's service all the same.
        let destination = match destination {
            IpAddr::V4(v4) if v4 == self.net.dns_ip => IpAddr::V4(self.net.gateway_ip),
            other => other,
        };
        policy::decide(
            &policy.rules,
            self.net.gateway_ip,
            &node,
            destination,
            transport,
            port,
        )
    }

    /// Records a flow this stack decided.
    pub(super) fn record(
        &self,
        destination: SocketAddr,
        is_allowed: bool,
        reason: String,
        (sent, received): (u64, u64),
    ) {
        Flow {
            sandbox_id: &self.sandbox_id(),
            source: self.net.guest_ip,
            destination,
            is_allowed,
            reason,
            sent,
            received,
        }
        .record(&self.node.audit);
    }

    /// Queues frames for the guest and wakes the driver to send them.
    pub(super) fn send_frames(&self, frames: Vec<Vec<u8>>) {
        let mut inner = self.lock();
        if inner.is_closed {
            return;
        }
        inner.frames.extend(frames);
        drop(inner);
        self.wake.notify_one();
    }

    /// One frame from the guest: answered here, handed to smoltcp, or
    /// dropped.
    fn ingest(self: &Arc<Self>, inner: &mut Inner, frame: &[u8]) {
        let Ok(eth) = EthernetFrame::new_checked(frame) else {
            return;
        };
        // The link has one guest on it; anything claiming another source
        // was forged inside it.
        if eth.src_addr().0 != self.net.mac {
            return;
        }
        let dst = eth.dst_addr();
        if dst.0 != wire::GATEWAY_MAC && !dst.is_broadcast() {
            return;
        }
        match eth.ethertype() {
            EthernetProtocol::Arp => {
                let owned = [self.net.gateway_ip, self.net.dns_ip];
                if let Some(reply) = wire::arp_reply(&self.net, eth.payload(), &owned) {
                    inner.frames.push(reply);
                }
            }
            EthernetProtocol::Ipv4 => self.ingest_ipv4(inner, eth.payload()),
            _ => {}
        }
    }

    fn ingest_ipv4(self: &Arc<Self>, inner: &mut Inner, packet: &[u8]) {
        let Ok(ip) = Ipv4Packet::new_checked(packet) else {
            return;
        };
        let packet = &packet[..usize::from(ip.total_len())];
        if ip.more_frags() || ip.frag_offset() != 0 {
            return;
        }
        let (src, dst) = (ip.src_addr(), ip.dst_addr());
        let payload = ip.payload();

        if ip.next_header() == IpProtocol::Udp
            && let Ok(datagram) = UdpPacket::new_checked(payload)
        {
            // The only traffic allowed from an address the guest does not
            // have yet is asking for one.
            if datagram.dst_port() == 67 && (src == self.net.guest_ip || src.is_unspecified()) {
                let ident = inner.ident();
                if let Some(reply) = wire::dhcp_reply(&self.net, ident, datagram.payload()) {
                    inner.is_leased |= reply.iter().any(|frame| wire::is_lease_ack(frame));
                    inner.frames.extend(reply);
                }
                return;
            }
        }
        if src != self.net.guest_ip {
            return;
        }

        match ip.next_header() {
            IpProtocol::Udp => {
                if let Ok(datagram) = UdpPacket::new_checked(payload) {
                    udp::ingest(self, inner, dst, &datagram);
                }
            }
            IpProtocol::Icmp => {
                if (dst == self.net.gateway_ip || dst == self.net.dns_ip)
                    && let Some(reply) = wire::echo_reply(&self.net, inner.ident(), &ip)
                {
                    inner.frames.push(reply);
                }
            }
            IpProtocol::Tcp => {
                let Ok(segment) = TcpPacket::new_checked(payload) else {
                    return;
                };
                if segment.syn() && !segment.ack() {
                    let key = (
                        segment.src_port(),
                        SocketAddr::new(IpAddr::V4(dst), segment.dst_port()),
                    );
                    if !self.admit_syn(inner, key) {
                        return;
                    }
                }
                inner.device.rx.push_back(packet.to_vec());
            }
            _ => {}
        }
    }

    /// Makes sure a socket is waiting for this SYN, with its SYN-ACK held
    /// back until the flow is decided. Returns whether the SYN goes on to
    /// smoltcp at all.
    fn admit_syn(&self, inner: &mut Inner, key: FlowKey) -> bool {
        if let Some(&handle) = inner.flows.get(&key) {
            let state = inner.sockets.get::<tcp::Socket>(handle).state();
            // A retransmission for a flow already being decided, or a socket
            // something still holds, which only smoltcp may answer.
            if !matches!(state, tcp::State::TimeWait | tcp::State::Closed)
                || !inner.released.contains(&handle)
            {
                return true;
            }
            // The guest is reusing a port whose last connection is over.
            inner.flows.remove(&key);
            inner.released.remove(&handle);
            inner.direct.remove(&handle);
            inner.sockets.remove(handle);
        }
        // Addressed to the gateway, a SYN only ever meets a reset: the
        // gateway runs no TCP service a guest may reach.
        if key.1.ip() == IpAddr::V4(self.net.gateway_ip) {
            return true;
        }
        if inner.flows.len() >= MAX_TCP_FLOWS {
            tracing::warn!(
                sandbox = self.sandbox_id(),
                "refusing a connection: sandbox is at its limit"
            );
            return true;
        }
        let SocketAddr::V4(to) = key.1 else {
            return false;
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        socket.set_nagle_enabled(false);
        socket.set_timeout(Some(TCP_TIMEOUT.into()));
        socket.pause_synack(true);
        socket
            .listen(IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(*to.ip())),
                port: to.port(),
            })
            .expect("a fresh socket listens");
        let handle = inner.sockets.add(socket);
        inner.flows.insert(key, handle);
        inner.pending.push((key, handle));
        true
    }

    /// Polls smoltcp, decides the flows whose SYNs just arrived, and returns
    /// every frame ready for the guest with how long smoltcp can wait.
    fn poll(self: &Arc<Self>) -> (Vec<Vec<u8>>, Option<Duration>) {
        let mut inner = self.lock();
        let inner = &mut *inner;
        let now = self.now();
        inner.iface.poll(now, &mut inner.device, &mut inner.sockets);

        let pending = std::mem::take(&mut inner.pending);
        for (key, handle) in pending {
            self.dispatch(inner, key, handle);
        }
        if !inner.device.rx.is_empty() || !inner.released.is_empty() {
            inner.iface.poll(now, &mut inner.device, &mut inner.sockets);
        }

        let sockets = &mut inner.sockets;
        let flows = &mut inner.flows;
        inner.released.retain(|&handle| {
            if sockets.get::<tcp::Socket>(handle).state() != tcp::State::Closed {
                return true;
            }
            sockets.remove(handle);
            flows.retain(|_, held| *held != handle);
            false
        });
        udp::expire(inner, Instant::now());

        let mut out = std::mem::take(&mut inner.frames);
        for packet in inner.device.tx.drain(..) {
            out.push(wire::ethernet(&self.net, EthernetProtocol::Ipv4, &packet));
        }
        let delay = inner
            .iface
            .poll_delay(now, &inner.sockets)
            .map(|d| Duration::from_micros(d.total_micros()));
        (out, delay)
    }

    /// Decides one new TCP flow and starts whatever carries it.
    fn dispatch(self: &Arc<Self>, inner: &mut Inner, key: FlowKey, handle: SocketHandle) {
        let (guest_port, destination) = key;
        let verdict = self.decide(destination.ip(), Transport::Tcp, destination.port());
        let peer = SocketAddr::new(IpAddr::V4(self.net.guest_ip), guest_port);
        match verdict {
            Verdict::Proxy => {
                inner
                    .sockets
                    .get_mut::<tcp::Socket>(handle)
                    .pause_synack(false);
                let conn = GuestConn::new(Arc::clone(self), handle);
                let shared = Arc::clone(self);
                let task = tokio::spawn(async move {
                    if let Err(err) = shared
                        .services
                        .proxy
                        .serve_stream(conn, peer, destination)
                        .await
                    {
                        tracing::debug!(%peer, %err, "proxied connection ended");
                    }
                });
                inner.track(task.abort_handle());
            }
            Verdict::Direct => {
                let shared = Arc::clone(self);
                let task = tokio::spawn(async move { shared.direct(handle, destination).await });
                inner.direct.insert(handle, destination);
                inner.track(task.abort_handle());
            }
            Verdict::Host | Verdict::Deny(_) => {
                inner.sockets.get_mut::<tcp::Socket>(handle).abort();
                inner.released.insert(handle);
                let reason = match verdict {
                    Verdict::Deny(reason) => reason,
                    _ => "destination is this node",
                };
                self.record(destination, false, reason.to_string(), (0, 0));
            }
        }
    }

    /// Dials a destination the policy allows directly, and only then lets
    /// the guest's handshake complete.
    async fn direct(self: Arc<Self>, handle: SocketHandle, destination: SocketAddr) {
        let connected = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(self.dial_address(destination)),
        )
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream did not answer in time",
            ))
        });
        let upstream = match connected {
            Ok(stream) => stream,
            Err(err) => {
                {
                    let mut inner = self.lock();
                    inner.direct.remove(&handle);
                    if !inner.is_closed {
                        inner.sockets.get_mut::<tcp::Socket>(handle).abort();
                        inner.released.insert(handle);
                    }
                }
                self.wake.notify_one();
                self.record(
                    destination,
                    true,
                    format!("upstream connect failed: {err}"),
                    (0, 0),
                );
                return;
            }
        };
        let _ = upstream.set_nodelay(true);
        {
            let mut inner = self.lock();
            if inner.is_closed {
                return;
            }
            inner
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .pause_synack(false);
        }
        self.wake.notify_one();

        let guest = GuestConn::new(Arc::clone(&self), handle);
        let moved = conn::splice(guest, upstream).await;
        let is_cut = self.lock().direct.remove(&handle).is_none();
        if is_cut {
            self.record(
                destination,
                false,
                "connection reset: the policy now denies this destination".into(),
                moved,
            );
        } else {
            self.record(destination, true, "allowed (direct)".into(), moved);
        }
    }

    /// Applies a new policy to flows already running: a direct flow whose
    /// destination it denies is reset.
    fn reapply(&self, policy: &Policy) {
        let mut inner = self.lock();
        let denied: Vec<_> = inner
            .direct
            .iter()
            .filter(|(_, destination)| {
                !matches!(
                    self.decide_with(policy, destination.ip(), Transport::Tcp, destination.port()),
                    Verdict::Direct
                )
            })
            .map(|(&handle, _)| handle)
            .collect();
        for handle in denied {
            // The reset ends the splice, which resets the upstream side too
            // and records the flow with what it moved before the change.
            if inner.direct.remove(&handle).is_some() {
                inner.sockets.get_mut::<tcp::Socket>(handle).abort();
            }
        }
        udp::reapply(self, &mut inner, policy);
        drop(inner);
        self.wake.notify_one();
    }

    /// Opens a connection from the gateway to `port` in the guest.
    async fn connect(self: &Arc<Self>, port: u16) -> std::io::Result<GuestConn> {
        let handle = {
            let mut inner = self.lock();
            let inner = &mut *inner;
            if inner.is_closed {
                return Err(std::io::ErrorKind::NotConnected.into());
            }
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            );
            socket.set_nagle_enabled(false);
            socket.set_timeout(Some(TCP_TIMEOUT.into()));
            let local = inner.next_port;
            inner.next_port = if local == *INBOUND_PORTS.end() {
                *INBOUND_PORTS.start()
            } else {
                local + 1
            };
            socket
                .connect(
                    inner.iface.context(),
                    (IpAddress::from(self.net.guest_ip), port),
                    (IpAddress::from(self.net.gateway_ip), local),
                )
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            inner.sockets.add(socket)
        };
        self.wake.notify_one();
        let conn = GuestConn::new(Arc::clone(self), handle);
        conn.established().await?;
        Ok(conn)
    }

    fn close(&self) {
        let mut inner = self.lock();
        inner.is_closed = true;
        // Every socket in the set is TCP; UDP never enters smoltcp. Matched
        // all the same: another crate in a build (tailcat) can turn on
        // smoltcp's other socket kinds.
        for (_, socket) in inner.sockets.iter_mut() {
            if let smoltcp::socket::Socket::Tcp(socket) = socket {
                socket.abort();
            }
        }
        for task in inner.tasks.drain(..) {
            task.abort();
        }
        udp::close(&mut inner);
    }
}

/// A running stack. Dropping it detaches the guest: every flow is reset and
/// every task stopped.
pub struct Handle {
    pub(super) shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl Handle {
    /// Whether the guest has been acknowledged a DHCP lease.
    pub fn is_leased(&self) -> bool {
        self.shared.lock().is_leased
    }

    /// Opens a TCP connection to `port` in the guest, from the gateway.
    pub async fn connect(&self, port: u16) -> std::io::Result<GuestConn> {
        self.shared.connect(port).await
    }

    /// Forwards every connection `listener` accepts to `guest_port` in the
    /// guest, for as long as the stack runs: a published port. Inbound is not
    /// egress, so no policy applies, as on Linux where a published port is
    /// open in every mode.
    pub fn publish(&self, listener: TcpListener, guest_port: u16) {
        let shared = Arc::clone(&self.shared);
        let task = tokio::spawn(async move {
            loop {
                let Ok((client, peer)) = listener.accept().await else {
                    return;
                };
                let flow = Arc::clone(&shared);
                let task = tokio::spawn(async move {
                    match flow.connect(guest_port).await {
                        Ok(guest) => {
                            let _ = client.set_nodelay(true);
                            conn::splice(guest, client).await;
                        }
                        Err(err) => {
                            tracing::debug!(%peer, guest_port, %err, "published port refused")
                        }
                    }
                });
                shared.lock().track(task.abort_handle());
            }
        });
        self.shared.lock().track(task.abort_handle());
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shared.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub(super) fn attach(
    fd: OwnedFd,
    net: SandboxNet,
    policy: watch::Receiver<Policy>,
    node: Arc<Node>,
) -> std::io::Result<Handle> {
    let socket = std::os::unix::net::UnixDatagram::from(fd);
    socket.set_nonblocking(true)?;
    // Apple's guidance for this attachment, mirrored on this end: a send
    // buffer of at least the largest frame and a receive buffer several
    // times that, or a burst from the guest is dropped in the kernel.
    let sock = socket2::SockRef::from(&socket);
    let _ = sock.set_send_buffer_size(1 << 20);
    let _ = sock.set_recv_buffer_size(4 << 20);
    let socket = UnixDatagram::from_std(socket)?;

    let epoch = Instant::now();
    let mut device = Queues {
        rx: VecDeque::new(),
        tx: Vec::new(),
        mtu: usize::from(net.mtu),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = u64::from(std::process::id()) ^ epoch.elapsed().as_nanos() as u64;
    let mut iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::from(net.gateway_ip), net.prefix))
            .expect("one address fits");
    });
    // Every destination is answered here: a flow is terminated in the stack
    // and carried onward by a host socket, whatever address the guest used.
    iface.set_any_ip(true);

    let policies = Arc::new(burrow_proxy::PolicyTable::default());
    let current = policy.borrow().proxy.clone();
    policies.replace(HashMap::from([(IpAddr::V4(net.guest_ip), current)]));
    let shared = Arc::new(Shared {
        inner: Mutex::new(Inner {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            frames: Vec::new(),
            flows: HashMap::new(),
            pending: Vec::new(),
            released: HashSet::new(),
            direct: HashMap::new(),
            udp: udp::Flows::default(),
            tasks: Vec::new(),
            ident: 0,
            next_port: *INBOUND_PORTS.start(),
            is_closed: false,
            is_leased: false,
        }),
        wake: Notify::new(),
        net,
        services: Services::new(&node, Arc::clone(&policies)),
        node,
        budget: burrow_proxy::dns::Budget::default(),
        policy: policy.clone(),
        epoch,
        #[cfg(test)]
        dial: Mutex::new(HashMap::new()),
    });

    let driver = tokio::spawn(drive(Arc::clone(&shared), socket));
    let watcher = tokio::spawn(watch_policy(
        Arc::clone(&shared),
        policy,
        policies,
        net.guest_ip,
    ));
    Ok(Handle {
        shared,
        tasks: vec![driver, watcher],
    })
}

async fn watch_policy(
    shared: Arc<Shared>,
    mut policy: watch::Receiver<Policy>,
    policies: Arc<burrow_proxy::PolicyTable>,
    guest_ip: Ipv4Addr,
) {
    while policy.changed().await.is_ok() {
        let current = policy.borrow_and_update().clone();
        policies.replace(HashMap::from([(
            IpAddr::V4(guest_ip),
            current.proxy.clone(),
        )]));
        shared.reapply(&current);
    }
}

/// Moves frames between the socket pair and the stack until either end
/// goes away.
async fn drive(shared: Arc<Shared>, socket: UnixDatagram) {
    let mut buf = vec![0u8; 65536];
    loop {
        {
            let mut inner = shared.lock();
            if inner.is_closed {
                return;
            }
            for _ in 0..RX_BATCH {
                match socket.try_recv(&mut buf) {
                    // The guest's end closed: the machine is gone.
                    Ok(0) => return,
                    Ok(n) => shared.ingest(&mut inner, &buf[..n]),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) => {
                        tracing::warn!(%err, "guest link failed");
                        return;
                    }
                }
            }
        }
        let (out, delay) = shared.poll();
        for frame in out {
            if send(&socket, &frame).await.is_err() {
                return;
            }
        }
        // Never zero: a socket whose SYN-ACK is held back asks to be polled
        // now on every pass until its flow is decided, and spinning on that
        // would starve the very task deciding it.
        let delay = delay
            .unwrap_or(Duration::from_secs(1))
            .max(Duration::from_millis(1));
        tokio::select! {
            ready = socket.readable() => if ready.is_err() { return },
            _ = shared.wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// Sends one frame, waiting out a full socket buffer.
///
/// A datagram socket reports a full buffer as `ENOBUFS` on macOS rather than
/// as would-block, and readiness says nothing about it, so the wait is a
/// short sleep. A frame that still does not fit is dropped, which TCP
/// recovers from and UDP is allowed to suffer.
async fn send(socket: &UnixDatagram, frame: &[u8]) -> std::io::Result<()> {
    for _ in 0..64 {
        match socket.try_send(frame) {
            Ok(_) => return Ok(()),
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.raw_os_error() == Some(libc::ENOBUFS) =>
            {
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}
