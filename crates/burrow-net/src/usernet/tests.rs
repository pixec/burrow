//! A fake guest on the far end of the socket pair, driving raw frames.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use burrow_proxy::policy::NetworkMode;
use burrow_proxy::{AuditLog, EgressEvent, SandboxPolicy};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, DhcpMessageType, DhcpPacket, DhcpRepr, EthernetAddress,
    EthernetFrame, EthernetProtocol, Icmpv4Packet, Icmpv4Repr, IpProtocol, Ipv4Packet, Ipv4Repr,
    TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixDatagram;
use tokio::sync::watch;

use super::*;

const MAC: [u8; 6] = [0x02, 0x00, 0x0a, 0x63, 0x00, 0x06];
const GUEST: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 6);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 5);
/// Where tests pretend the internet is. Dialled at a local listener instead.
const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(300);

fn net() -> SandboxNet {
    SandboxNet {
        mac: MAC,
        guest_ip: GUEST,
        gateway_ip: GATEWAY,
        prefix: 30,
        dns_ip: GATEWAY,
        mtu: 1500,
    }
}

fn policy(mode: NetworkMode, domains: &[&str], allow_cidrs: &[&str], ports: &[u32]) -> Policy {
    Policy::new(
        SandboxPolicy {
            sandbox_id: "sbx_test".into(),
            mode,
            allow_domains: domains.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        },
        &allow_cidrs
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>(),
        ports,
        &[],
        &[],
    )
}

/// A node for tests, and every audit record it writes.
async fn test_node() -> (Arc<Node>, Arc<Mutex<Vec<EgressEvent>>>) {
    let audit = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&audit);
    let dir = std::env::temp_dir().join(format!("burrow-usernet-{}", std::process::id()));
    let node = Arc::new(Node {
        audit: AuditLog::new(dir.join("egress.jsonl"), None).observed(Arc::new(
            move |event: &EgressEvent| seen.lock().unwrap().push(event.clone()),
        )),
        resolutions: Arc::default(),
        denied: Arc::default(),
        authority: None,
        directory: Arc::default(),
        dns_upstream: fake_upstream().await,
        router: Arc::default(),
    });
    (node, audit)
}

/// An upstream resolver that answers every A query with `REMOTE`.
async fn fake_upstream() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let mut reply = buf[..n].to_vec();
            reply[2] |= 0x80;
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            reply.extend_from_slice(&REMOTE.octets());
            let _ = socket.send_to(&reply, from).await;
        }
    });
    address
}

struct Guest {
    net: SandboxNet,
    link: UnixDatagram,
    handle: Handle,
    policy: watch::Sender<Policy>,
    audit: Arc<Mutex<Vec<EgressEvent>>>,
    meter: Arc<Meter>,
    ident: u16,
}

impl Guest {
    async fn attach(policy: Policy) -> Self {
        let (node, audit) = test_node().await;
        Self::attach_to(&node, audit, net(), policy)
    }

    /// A guest on `node`, alongside whatever else is attached to it.
    fn attach_to(
        node: &Arc<Node>,
        audit: Arc<Mutex<Vec<EgressEvent>>>,
        net: SandboxNet,
        policy: Policy,
    ) -> Self {
        let (link, theirs) = UnixDatagram::pair().unwrap();
        let theirs = OwnedFd::from(theirs.into_std().unwrap());
        let (tx, rx) = watch::channel(policy);
        let meter = Arc::new(Meter::default());
        let handle =
            UserNet::attach(theirs, net, rx, Arc::clone(node), Arc::clone(&meter)).unwrap();
        Self {
            net,
            link,
            handle,
            policy: tx,
            audit,
            meter,
            ident: 0,
        }
    }

    /// Makes `destination` really reach `at`.
    fn route(&self, destination: SocketAddr, at: SocketAddr) {
        self.handle
            .shared
            .dial
            .lock()
            .unwrap()
            .insert(destination, at);
    }

    fn frame(&self, src_mac: [u8; 6], ethertype: EthernetProtocol, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + payload.len()];
        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        eth.set_src_addr(EthernetAddress(src_mac));
        eth.set_dst_addr(EthernetAddress(GATEWAY_MAC));
        eth.set_ethertype(ethertype);
        eth.payload_mut().copy_from_slice(payload);
        frame
    }

    async fn send_ip(&mut self, src: Ipv4Addr, dst: Ipv4Addr, protocol: IpProtocol, body: &[u8]) {
        self.send_ip_as(self.net.mac, src, dst, protocol, body)
            .await;
    }

    async fn send_ip_as(
        &mut self,
        mac: [u8; 6],
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: IpProtocol,
        body: &[u8],
    ) {
        self.ident += 1;
        let repr = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: protocol,
            payload_len: body.len(),
            hop_limit: 64,
        };
        let mut packet = vec![0u8; 20 + body.len()];
        let mut ip = Ipv4Packet::new_unchecked(&mut packet);
        repr.emit(&mut ip, &ChecksumCapabilities::default());
        ip.payload_mut().copy_from_slice(body);
        let frame = self.frame(mac, EthernetProtocol::Ipv4, &packet);
        self.link.send(&frame).await.unwrap();
    }

    async fn send_udp(&mut self, src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), data: &[u8]) {
        let repr = UdpRepr {
            src_port: src.1,
            dst_port: dst.1,
        };
        let mut body = vec![0u8; 8 + data.len()];
        repr.emit(
            &mut UdpPacket::new_unchecked(&mut body),
            &src.0.into(),
            &dst.0.into(),
            data.len(),
            |p| p.copy_from_slice(data),
            &ChecksumCapabilities::default(),
        );
        self.send_ip(src.0, dst.0, IpProtocol::Udp, &body).await;
    }

    async fn send_tcp(&mut self, src: Ipv4Addr, dst: SocketAddr, segment: Segment<'_>) {
        let SocketAddr::V4(dst) = dst else {
            unreachable!()
        };
        let repr = TcpRepr {
            src_port: segment.port,
            dst_port: dst.port(),
            control: segment.control,
            seq_number: TcpSeqNumber(segment.seq as i32),
            ack_number: segment.ack.map(|a| TcpSeqNumber(a as i32)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: (segment.control == TcpControl::Syn).then_some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: segment.payload,
        };
        let mut body = vec![0u8; repr.buffer_len()];
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut body),
            &src.into(),
            &(*dst.ip()).into(),
            &ChecksumCapabilities::default(),
        );
        self.send_ip(src, *dst.ip(), IpProtocol::Tcp, &body).await;
    }

    /// The next frame from the stack, or `None` if it stays quiet for `wait`.
    async fn recv(&self, wait: Duration) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(wait, self.link.recv(&mut buf))
            .await
            .ok()?
            .unwrap();
        buf.truncate(n);
        Some(buf)
    }

    /// The next IPv4 packet carrying `protocol`, skipping anything else.
    async fn recv_ip(&self, protocol: IpProtocol, wait: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = self.recv(left).await?;
            let eth = EthernetFrame::new_checked(&frame[..]).unwrap();
            assert_eq!(eth.src_addr().0, GATEWAY_MAC);
            assert_eq!(eth.dst_addr().0, self.net.mac);
            if eth.ethertype() != EthernetProtocol::Ipv4 {
                continue;
            }
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            if ip.next_header() == protocol {
                return Some(eth.payload()[..usize::from(ip.total_len())].to_vec());
            }
        }
    }

    async fn recv_tcp(&self, wait: Duration) -> Option<Received> {
        let packet = self.recv_ip(IpProtocol::Tcp, wait).await?;
        let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        Some(Received {
            from: SocketAddr::new(IpAddr::V4(ip.src_addr()), tcp.src_port()),
            port: tcp.dst_port(),
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            seq: tcp.seq_number().0 as u32,
            payload: tcp.payload().to_vec(),
        })
    }

    async fn recv_udp(&self, wait: Duration) -> Option<(SocketAddr, u16, Vec<u8>)> {
        let packet = self.recv_ip(IpProtocol::Udp, wait).await?;
        let ip = Ipv4Packet::new_checked(&packet[..]).unwrap();
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        Some((
            SocketAddr::new(IpAddr::V4(ip.src_addr()), udp.src_port()),
            udp.dst_port(),
            udp.payload().to_vec(),
        ))
    }

    /// Opens a connection to `dst` and completes the handshake.
    async fn connect(&mut self, port: u16, dst: SocketAddr) -> Tcp {
        let guest = self.net.guest_ip;
        self.send_tcp(guest, dst, Segment::syn(port, 1000)).await;
        let reply = loop {
            let reply = self.recv_tcp(WAIT).await.expect("a syn-ack");
            if reply.port == port {
                break reply;
            }
        };
        assert!(reply.syn && reply.ack, "expected a syn-ack, got {reply:?}");
        let mut tcp = Tcp {
            port,
            dst,
            seq: 1001,
            ack: reply.seq.wrapping_add(1),
        };
        self.send_tcp(guest, dst, tcp.segment(TcpControl::None, &[]))
            .await;
        tcp.seq = 1001;
        tcp
    }

    /// Reads from the connection until `want` bytes have arrived, acking
    /// each segment.
    async fn read(&mut self, tcp: &mut Tcp, want: usize) -> Vec<u8> {
        let mut data = Vec::new();
        while data.len() < want {
            let segment = self.recv_tcp(WAIT).await.expect("data");
            assert!(!segment.rst, "reset while reading");
            if segment.payload.is_empty() {
                continue;
            }
            tcp.ack = segment.seq.wrapping_add(segment.payload.len() as u32);
            data.extend_from_slice(&segment.payload);
            let guest = self.net.guest_ip;
            self.send_tcp(guest, tcp.dst, tcp.segment(TcpControl::None, &[]))
                .await;
        }
        data
    }

    async fn write(&mut self, tcp: &mut Tcp, data: &[u8]) {
        let segment = tcp.segment(TcpControl::Psh, data);
        let guest = self.net.guest_ip;
        self.send_tcp(guest, tcp.dst, segment).await;
        tcp.seq = tcp.seq.wrapping_add(data.len() as u32);
    }

    /// Waits for an audit record matching `want`.
    async fn audited(&self, want: impl Fn(&EgressEvent) -> bool) -> EgressEvent {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            if let Some(event) = self.audit.lock().unwrap().iter().find(|e| want(e)) {
                return event.clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no matching audit record in {:?}",
                self.audit.lock().unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

struct Segment<'a> {
    port: u16,
    control: TcpControl,
    seq: u32,
    ack: Option<u32>,
    payload: &'a [u8],
}

impl Segment<'_> {
    fn syn(port: u16, seq: u32) -> Self {
        Segment {
            port,
            control: TcpControl::Syn,
            seq,
            ack: None,
            payload: &[],
        }
    }
}

struct Tcp {
    port: u16,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
}

impl Tcp {
    fn segment<'a>(&self, control: TcpControl, payload: &'a [u8]) -> Segment<'a> {
        Segment {
            port: self.port,
            control,
            seq: self.seq,
            ack: Some(self.ack),
            payload,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct Received {
    from: SocketAddr,
    port: u16,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    seq: u32,
    payload: Vec<u8>,
}

fn dhcp(message_type: DhcpMessageType, requested: Option<Ipv4Addr>) -> Vec<u8> {
    let repr = DhcpRepr {
        message_type,
        transaction_id: 0x1234,
        secs: 0,
        client_hardware_address: EthernetAddress(MAC),
        client_ip: Ipv4Addr::UNSPECIFIED,
        your_ip: Ipv4Addr::UNSPECIFIED,
        server_ip: Ipv4Addr::UNSPECIFIED,
        router: None,
        subnet_mask: None,
        relay_agent_ip: Ipv4Addr::UNSPECIFIED,
        broadcast: false,
        requested_ip: requested,
        client_identifier: Some(EthernetAddress(MAC)),
        server_identifier: None,
        parameter_request_list: Some(&[1, 3, 6, 26]),
        dns_servers: None,
        max_size: None,
        lease_duration: None,
        renew_duration: None,
        rebind_duration: None,
        additional_options: &[],
    };
    let mut body = vec![0u8; repr.buffer_len()];
    repr.emit(&mut DhcpPacket::new_unchecked(&mut body))
        .unwrap();
    body
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut query = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

/// A ClientHello carrying `name` as its SNI and nothing the proxy would
/// refuse it for.
fn client_hello(name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);

    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[7u8; 32]);
    hello.push(0);
    hello.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![1];
    handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A TCP server that echoes back what it reads, then closes.
async fn echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

fn remote(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(REMOTE), port)
}

#[tokio::test]
async fn dhcp_hands_out_the_sandbox_address() {
    let mut guest = Guest::attach(policy(NetworkMode::None, &[], &[], &[])).await;
    let any = (Ipv4Addr::UNSPECIFIED, 68);
    let everyone = (Ipv4Addr::BROADCAST, 67);

    guest
        .send_udp(any, everyone, &dhcp(DhcpMessageType::Discover, None))
        .await;
    let (from, port, offer) = guest.recv_udp(WAIT).await.expect("an offer");
    assert_eq!((from, port), (SocketAddr::from((GATEWAY, 67)), 68));
    let offer = DhcpPacket::new_checked(&offer[..]).unwrap();
    let offer = DhcpRepr::parse(&offer).unwrap();
    assert_eq!(offer.message_type, DhcpMessageType::Offer);
    assert_eq!(offer.your_ip, GUEST);
    assert_eq!(offer.router, Some(GATEWAY));
    assert_eq!(offer.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 252)));
    assert_eq!(offer.server_identifier, Some(GATEWAY));
    assert!(!guest.handle.is_leased());

    guest
        .send_udp(any, everyone, &dhcp(DhcpMessageType::Request, Some(GUEST)))
        .await;
    let (_, _, ack) = guest.recv_udp(WAIT).await.expect("an ack");
    let ack = DhcpPacket::new_checked(&ack[..]).unwrap();
    let ack = DhcpRepr::parse(&ack).unwrap();
    assert_eq!(ack.message_type, DhcpMessageType::Ack);
    assert_eq!(ack.your_ip, GUEST);
    assert!(guest.handle.is_leased());

    // A lease from some other network is refused, so the guest lets go.
    guest
        .send_udp(
            any,
            everyone,
            &dhcp(
                DhcpMessageType::Request,
                Some(Ipv4Addr::new(192, 168, 1, 9)),
            ),
        )
        .await;
    let (_, _, nak) = guest.recv_udp(WAIT).await.expect("a nak");
    let nak = DhcpPacket::new_checked(&nak[..]).unwrap();
    let nak = DhcpRepr::parse(&nak).unwrap();
    assert_eq!(nak.message_type, DhcpMessageType::Nak);
}

#[tokio::test]
async fn arp_is_answered_for_the_gateway_only() {
    let guest = Guest::attach(policy(NetworkMode::None, &[], &[], &[])).await;
    let request = |sender_mac: [u8; 6], target: Ipv4Addr| {
        let repr = ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress(sender_mac),
            source_protocol_addr: GUEST,
            target_hardware_addr: EthernetAddress([0; 6]),
            target_protocol_addr: target,
        };
        let mut body = vec![0u8; repr.buffer_len()];
        repr.emit(&mut ArpPacket::new_unchecked(&mut body));
        guest.frame(sender_mac, EthernetProtocol::Arp, &body)
    };

    guest.link.send(&request(MAC, GATEWAY)).await.unwrap();
    let reply = guest.recv(WAIT).await.expect("an arp reply");
    let eth = EthernetFrame::new_checked(&reply[..]).unwrap();
    assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
    let ArpRepr::EthernetIpv4 {
        operation,
        source_hardware_addr,
        source_protocol_addr,
        ..
    } = ArpRepr::parse(&ArpPacket::new_checked(eth.payload()).unwrap()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(operation, ArpOperation::Reply);
    assert_eq!(source_hardware_addr.0, GATEWAY_MAC);
    assert_eq!(source_protocol_addr, GATEWAY);

    // Its own address (a conflict probe), anyone else's, and a forged MAC.
    guest.link.send(&request(MAC, GUEST)).await.unwrap();
    guest.link.send(&request(MAC, REMOTE)).await.unwrap();
    let forged = [0x02, 0, 0, 0, 0, 0x99];
    guest.link.send(&request(forged, GATEWAY)).await.unwrap();
    assert!(guest.recv(QUIET).await.is_none());
}

#[tokio::test]
async fn ping_reaches_the_gateway() {
    let mut guest = Guest::attach(policy(NetworkMode::None, &[], &[], &[])).await;
    let echo = Icmpv4Repr::EchoRequest {
        ident: 7,
        seq_no: 1,
        data: b"ping",
    };
    let mut body = vec![0u8; echo.buffer_len()];
    echo.emit(
        &mut Icmpv4Packet::new_unchecked(&mut body[..]),
        &ChecksumCapabilities::default(),
    );
    guest.send_ip(GUEST, GATEWAY, IpProtocol::Icmp, &body).await;
    let reply = guest
        .recv_ip(IpProtocol::Icmp, WAIT)
        .await
        .expect("a reply");
    let ip = Ipv4Packet::new_checked(&reply[..]).unwrap();
    assert_eq!((ip.src_addr(), ip.dst_addr()), (GATEWAY, GUEST));
    let icmp = Icmpv4Repr::parse(
        &Icmpv4Packet::new_checked(ip.payload()).unwrap(),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    assert!(matches!(
        icmp,
        Icmpv4Repr::EchoReply {
            ident: 7,
            seq_no: 1,
            data: b"ping"
        }
    ));

    // Anywhere else, nothing: echo is not relayed.
    guest.send_ip(GUEST, REMOTE, IpProtocol::Icmp, &body).await;
    assert!(guest.recv(QUIET).await.is_none());
}

/// IP bytes are counted both ways, the guest's whether or not policy lets
/// them anywhere, and frames that are not IP are not counted at all.
#[tokio::test]
async fn the_meter_counts_ip_bytes_ahead_of_policy() {
    let mut guest = Guest::attach(policy(NetworkMode::None, &[], &[], &[])).await;
    let echo = Icmpv4Repr::EchoRequest {
        ident: 7,
        seq_no: 1,
        data: b"ping",
    };
    let mut body = vec![0u8; echo.buffer_len()];
    echo.emit(
        &mut Icmpv4Packet::new_unchecked(&mut body[..]),
        &ChecksumCapabilities::default(),
    );
    let packet = (20 + body.len()) as u64;
    guest.send_ip(GUEST, GATEWAY, IpProtocol::Icmp, &body).await;
    guest
        .recv_ip(IpProtocol::Icmp, WAIT)
        .await
        .expect("a reply");
    // Denied in `none` mode, counted all the same.
    guest
        .send_udp((GUEST, 40000), (REMOTE, 9), b"dropped")
        .await;
    let arp = guest.frame(MAC, EthernetProtocol::Arp, &[0u8; 28]);
    guest.link.send(&arp).await.unwrap();
    assert!(guest.recv(QUIET).await.is_none());
    let traffic = guest.meter.traffic();
    assert_eq!(traffic.tx_bytes, packet + 20 + 8 + 7);
    assert_eq!(traffic.rx_bytes, packet);
}

#[tokio::test]
async fn an_allowed_connection_is_spliced_and_audited() {
    let mut guest = Guest::attach(policy(NetworkMode::Open, &[], &[], &[])).await;
    guest.route(remote(7), echo_server().await);

    let mut tcp = guest.connect(40000, remote(7)).await;
    guest.write(&mut tcp, b"hello through the stack").await;
    let echoed = guest.read(&mut tcp, 23).await;
    assert_eq!(echoed, b"hello through the stack");

    // Half-close from the guest: the echo server sees EOF and closes, and
    // its FIN comes back as ours.
    guest
        .send_tcp(GUEST, remote(7), tcp.segment(TcpControl::Fin, &[]))
        .await;
    tcp.seq += 1;
    let fin = loop {
        let segment = guest.recv_tcp(WAIT).await.expect("a fin");
        if segment.fin {
            break segment;
        }
    };
    assert!(!fin.rst);
    tcp.ack = fin.seq.wrapping_add(1);
    guest
        .send_tcp(GUEST, remote(7), tcp.segment(TcpControl::None, &[]))
        .await;

    let event = guest
        .audited(|e| e.destination == remote(7).to_string() && e.is_allowed)
        .await;
    assert_eq!(event.sandbox_id, "sbx_test");
    assert_eq!(event.source_ip, GUEST.to_string());
    assert_eq!((event.bytes_sent, event.bytes_received), (23, 23));
}

#[tokio::test]
async fn a_denied_connection_is_reset_and_audited() {
    let mut open = policy(NetworkMode::Open, &[], &[], &[]);
    open.proxy.deny_cidrs = vec!["198.51.100.0/24".into()];
    let open = Policy::new(open.proxy, &[], &[], &[], &[]);
    let mut guest = Guest::attach(open).await;
    guest.route(remote(7), echo_server().await);

    guest
        .send_tcp(GUEST, remote(7), Segment::syn(40001, 5))
        .await;
    let reply = guest.recv_tcp(WAIT).await.expect("a reset");
    assert!(reply.rst && !reply.syn, "expected a reset, got {reply:?}");
    let event = guest.audited(|e| !e.is_allowed).await;
    assert_eq!(event.reason, "destination is in a denied range");
    assert_eq!(event.port, 7);
}

#[tokio::test]
async fn a_denied_port_is_reset_and_audited_in_open_mode() {
    let open = policy(NetworkMode::Open, &[], &[], &[]);
    let open = Policy::new(
        open.proxy,
        &[],
        &[],
        &[crate::policy::PortDenial {
            protocol: Some(crate::firewall::Protocol::Tcp),
            first: 7,
            ..Default::default()
        }],
        &[],
    );
    let mut guest = Guest::attach(open).await;
    guest.route(remote(7), echo_server().await);

    guest
        .send_tcp(GUEST, remote(7), Segment::syn(40004, 5))
        .await;
    let reply = guest.recv_tcp(WAIT).await.expect("a reset");
    assert!(reply.rst && !reply.syn, "expected a reset, got {reply:?}");
    let event = guest.audited(|e| !e.is_allowed).await;
    assert_eq!(event.reason, "destination port is denied");
    assert_eq!(event.port, 7);
}

#[tokio::test]
async fn a_denied_web_port_is_refused_by_the_proxy_in_allowlist_mode() {
    let mut allow = policy(NetworkMode::Allowlist, &["allowed.test"], &[], &[]);
    allow.proxy.deny_ports = vec![burrow_proxy::policy::DeniedPorts {
        first: 443,
        last: 443,
        cidrs: vec![],
    }];
    let allow = Policy::new(
        allow.proxy,
        &[],
        &[],
        &[crate::policy::PortDenial {
            protocol: Some(crate::firewall::Protocol::Tcp),
            first: 443,
            ..Default::default()
        }],
        &[],
    );
    let mut guest = Guest::attach(allow).await;

    let mut tcp = guest.connect(40012, remote(443)).await;
    guest.write(&mut tcp, &client_hello("allowed.test")).await;
    let event = guest
        .audited(|e| e.host.as_deref() == Some("allowed.test"))
        .await;
    assert!(!event.is_allowed);
    assert_eq!(event.reason, "destination port is denied");
}

#[tokio::test]
async fn none_mode_and_the_node_itself_are_refused() {
    let mut guest = Guest::attach(policy(NetworkMode::None, &[], &[], &[])).await;
    guest.route(remote(7), echo_server().await);
    guest
        .send_tcp(GUEST, remote(7), Segment::syn(40002, 5))
        .await;
    assert!(guest.recv_tcp(WAIT).await.unwrap().rst);
    guest.audited(|e| e.reason == "sandbox has no egress").await;

    guest
        .policy
        .send_replace(policy(NetworkMode::Open, &[], &[], &[]));
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 22));
    guest
        .send_tcp(GUEST, loopback, Segment::syn(40003, 5))
        .await;
    assert!(guest.recv_tcp(WAIT).await.unwrap().rst);
    guest
        .audited(|e| e.reason == "destination is this node")
        .await;
}

#[tokio::test]
async fn an_unreachable_destination_is_reset() {
    let mut guest = Guest::attach(policy(NetworkMode::Open, &[], &[], &[])).await;
    // Bound and closed again: nothing listens there now.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    guest.route(remote(9), closed);
    guest
        .send_tcp(GUEST, remote(9), Segment::syn(40004, 5))
        .await;
    let reply = guest.recv_tcp(WAIT).await.expect("a reset");
    assert!(reply.rst && !reply.syn);
    let event = guest
        .audited(|e| e.reason.starts_with("upstream connect failed"))
        .await;
    assert!(event.is_allowed);
}

#[tokio::test]
async fn spoofed_sources_are_dropped() {
    let mut guest = Guest::attach(policy(NetworkMode::Open, &[], &[], &[])).await;
    guest.route(remote(7), echo_server().await);
    let other = Ipv4Addr::new(10, 99, 0, 10);
    guest
        .send_tcp(other, remote(7), Segment::syn(40005, 5))
        .await;
    assert!(guest.recv(QUIET).await.is_none());

    let syn = TcpRepr {
        src_port: 40006,
        dst_port: 7,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(5),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let mut body = vec![0u8; syn.buffer_len()];
    syn.emit(
        &mut TcpPacket::new_unchecked(&mut body),
        &GUEST.into(),
        &REMOTE.into(),
        &ChecksumCapabilities::default(),
    );
    guest
        .send_ip_as(
            [0x02, 0, 0, 0, 0, 0x99],
            GUEST,
            REMOTE,
            IpProtocol::Tcp,
            &body,
        )
        .await;
    assert!(guest.recv(QUIET).await.is_none());
    assert!(guest.audit.lock().unwrap().is_empty());
}

#[tokio::test]
async fn dns_answers_only_what_the_policy_allows() {
    let mut guest =
        Guest::attach(policy(NetworkMode::Allowlist, &["allowed.test"], &[], &[])).await;
    let client = (GUEST, 5353);

    guest
        .send_udp(client, (GATEWAY, 53), &dns_query("allowed.test"))
        .await;
    let (from, port, answer) = guest.recv_udp(WAIT).await.expect("an answer");
    assert_eq!((from, port), (SocketAddr::from((GATEWAY, 53)), 5353));
    assert_eq!(answer[3] & 0x0f, 0, "NOERROR");
    assert_eq!(&answer[answer.len() - 4..], &REMOTE.octets());

    guest
        .send_udp(client, (GATEWAY, 53), &dns_query("denied.test"))
        .await;
    let (_, _, refused) = guest.recv_udp(WAIT).await.expect("a refusal");
    assert_eq!(refused[3] & 0x0f, 5, "REFUSED");
    guest
        .audited(|e| e.host.as_deref() == Some("denied.test") && !e.is_allowed)
        .await;

    // In mode none the resolver is not reachable at all, as on Linux.
    guest
        .policy
        .send_replace(policy(NetworkMode::None, &[], &[], &[]));
    guest
        .send_udp(client, (GATEWAY, 53), &dns_query("allowed.test"))
        .await;
    assert!(guest.recv(QUIET).await.is_none());
}

#[tokio::test]
async fn allowlist_web_traffic_goes_through_the_proxy() {
    let mut guest =
        Guest::attach(policy(NetworkMode::Allowlist, &["allowed.test"], &[], &[])).await;

    let mut tcp = guest.connect(40010, remote(443)).await;
    guest.write(&mut tcp, &client_hello("denied.test")).await;
    let event = guest
        .audited(|e| e.host.as_deref() == Some("denied.test"))
        .await;
    assert!(!event.is_allowed);
    assert_eq!(event.reason, "host not in allowlist");
    assert_eq!(event.destination, remote(443).to_string());

    // An allowed name the resolver never gave this address for is refused
    // by the pin check, which is the proxy's own and is reached only past
    // the allowlist.
    let mut tcp = guest.connect(40011, remote(443)).await;
    guest.write(&mut tcp, &client_hello("allowed.test")).await;
    let event = guest
        .audited(|e| e.host.as_deref() == Some("allowed.test"))
        .await;
    assert_eq!(
        event.reason,
        "destination address is not pinned to this name"
    );
}

#[tokio::test]
async fn a_policy_change_resets_flows_it_now_denies() {
    let mut guest = Guest::attach(policy(NetworkMode::Open, &[], &[], &[])).await;
    guest.route(remote(7), echo_server().await);
    let mut tcp = guest.connect(40020, remote(7)).await;
    guest.write(&mut tcp, b"before").await;
    assert_eq!(guest.read(&mut tcp, 6).await, b"before");

    let mut locked = policy(NetworkMode::Open, &[], &[], &[]);
    locked.proxy.deny_cidrs = vec!["198.51.100.10/32".into()];
    guest
        .policy
        .send_replace(Policy::new(locked.proxy, &[], &[], &[], &[]));
    let reset = loop {
        let segment = guest.recv_tcp(WAIT).await.expect("a reset");
        if segment.rst {
            break segment;
        }
    };
    assert_eq!(reset.from, remote(7));
    let event = guest
        .audited(|e| e.reason.starts_with("connection reset"))
        .await;
    assert!(!event.is_allowed);
    assert_eq!((event.bytes_sent, event.bytes_received), (6, 6));

    guest
        .send_tcp(GUEST, remote(7), Segment::syn(40021, 5))
        .await;
    assert!(guest.recv_tcp(WAIT).await.unwrap().rst);
}

#[tokio::test]
async fn udp_follows_the_cidr_allowance() {
    let mut guest = Guest::attach(policy(
        NetworkMode::Allowlist,
        &[],
        &["198.51.100.0/24"],
        &[9999],
    ))
    .await;
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    guest.route(remote(9999), echo.local_addr().unwrap());
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], from).await;
        }
    });

    guest
        .send_udp((GUEST, 6000), (REMOTE, 9999), b"datagram")
        .await;
    let (from, port, data) = guest.recv_udp(WAIT).await.expect("an echo");
    assert_eq!(
        (from, port, data.as_slice()),
        (remote(9999), 6000, &b"datagram"[..])
    );

    guest.send_udp((GUEST, 6001), (REMOTE, 9998), b"nope").await;
    assert!(guest.recv(QUIET).await.is_none());
    let event = guest.audited(|e| e.port == 9998).await;
    assert!(!event.is_allowed);
}

#[tokio::test]
async fn a_published_port_reaches_the_guest() {
    let mut guest = Guest::attach(policy(NetworkMode::None, &[], &[], &[])).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let published = listener.local_addr().unwrap();
    guest.handle.publish(listener, 8080);

    let client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(published).await.unwrap();
        stream.write_all(b"GET /").await.unwrap();
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await.unwrap();
        reply
    });

    let syn = guest.recv_tcp(WAIT).await.expect("a syn into the guest");
    assert!(syn.syn && !syn.ack);
    assert_eq!((syn.from.ip(), syn.port), (IpAddr::V4(GATEWAY), 8080));
    let gateway = syn.from;
    let mut tcp = Tcp {
        port: 8080,
        dst: gateway,
        seq: 7000,
        ack: syn.seq.wrapping_add(1),
    };
    guest
        .send_tcp(GUEST, gateway, tcp.segment(TcpControl::Syn, &[]))
        .await;
    tcp.seq += 1;
    assert_eq!(guest.read(&mut tcp, 5).await, b"GET /");
    guest.write(&mut tcp, b"ok").await;
    assert_eq!(
        &tokio::time::timeout(WAIT, client).await.unwrap().unwrap(),
        b"ok"
    );
}

/// Another guest's link, at `.{guest}` with its gateway one below.
fn net_at(guest: u8) -> SandboxNet {
    SandboxNet {
        mac: [0x02, 0x00, 10, 99, 0, guest],
        guest_ip: Ipv4Addr::new(10, 99, 0, guest),
        gateway_ip: Ipv4Addr::new(10, 99, 0, guest - 1),
        prefix: 30,
        dns_ip: Ipv4Addr::new(10, 99, 0, guest - 1),
        mtu: 1500,
    }
}

fn member(id: &str, mode: NetworkMode, peers: &[Ipv4Addr]) -> Policy {
    Policy::new(
        SandboxPolicy {
            sandbox_id: id.into(),
            mode,
            ..Default::default()
        },
        &[],
        &[],
        &[],
        peers,
    )
}

/// Two members of one network on one node, and a third sandbox on no
/// network at all.
async fn trio(mode: NetworkMode) -> (Guest, Guest, Guest, Arc<Node>) {
    let (node, audit) = test_node().await;
    let (a, b, c) = (net_at(6), net_at(10), net_at(14));
    let alpha = Guest::attach_to(
        &node,
        Arc::clone(&audit),
        a,
        member("sbx_a", mode, &[b.guest_ip]),
    );
    let beta = Guest::attach_to(
        &node,
        Arc::clone(&audit),
        b,
        member("sbx_b", mode, &[a.guest_ip]),
    );
    let outsider = Guest::attach_to(&node, audit, c, member("sbx_c", NetworkMode::Open, &[]));
    (alpha, beta, outsider, node)
}

/// The TCP header of a packet, and the packet's TTL.
fn tcp_of(packet: &[u8]) -> (Received, u8, Option<u16>) {
    let ip = Ipv4Packet::new_checked(packet).unwrap();
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    let repr = TcpRepr::parse(
        &tcp,
        &ip.src_addr().into(),
        &ip.dst_addr().into(),
        &ChecksumCapabilities::default(),
    )
    .expect("a valid segment");
    (
        Received {
            from: SocketAddr::new(IpAddr::V4(ip.src_addr()), tcp.src_port()),
            port: tcp.dst_port(),
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            seq: tcp.seq_number().0 as u32,
            payload: tcp.payload().to_vec(),
        },
        ip.hop_limit(),
        repr.max_seg_size,
    )
}

#[tokio::test]
async fn peers_reach_each_other_unterminated() {
    let (mut alpha, mut beta, _outsider, node) = trio(NetworkMode::None).await;
    let (a, b) = (alpha.net.guest_ip, beta.net.guest_ip);
    let to_b = SocketAddr::from((b, 8080));

    alpha.send_tcp(a, to_b, Segment::syn(40100, 1000)).await;
    let syn = beta.recv_ip(IpProtocol::Tcp, WAIT).await.expect("the syn");
    let (syn, ttl, mss) = tcp_of(&syn);
    // The guest's own segment, a hop on: nothing in between answered it.
    assert!(syn.syn && !syn.ack);
    assert_eq!(
        (syn.from, syn.port, syn.seq),
        (SocketAddr::from((a, 40100)), 8080, 1000)
    );
    assert_eq!(ttl, 63);
    assert_eq!(mss, Some(1460), "a flow on one node keeps its MSS");
    assert!(
        alpha.recv(QUIET).await.is_none(),
        "the sender is not answered for"
    );

    let synack = Segment {
        port: 8080,
        control: TcpControl::Syn,
        seq: 5000,
        ack: Some(1001),
        payload: &[],
    };
    beta.send_tcp(b, SocketAddr::from((a, 40100)), synack).await;
    let reply = alpha.recv_tcp(WAIT).await.expect("the syn-ack");
    assert!(reply.syn && reply.ack);
    assert_eq!((reply.from, reply.seq), (to_b, 5000));

    let mut tcp = Tcp {
        port: 40100,
        dst: to_b,
        seq: 1001,
        ack: 5001,
    };
    alpha.write(&mut tcp, b"hello").await;
    let data = beta.recv_tcp(WAIT).await.expect("data");
    assert_eq!(data.payload, b"hello");
    assert_eq!(node.router.tracked(), 1);
}

#[tokio::test]
async fn a_non_member_is_refused_and_never_delivered() {
    let (_alpha, mut beta, mut outsider, node) = trio(NetworkMode::Open).await;
    let (b, c) = (beta.net.guest_ip, outsider.net.guest_ip);

    outsider
        .send_tcp(c, SocketAddr::from((b, 8080)), Segment::syn(40110, 1))
        .await;
    let refused = outsider.recv_tcp(WAIT).await.expect("a reset");
    assert!(refused.rst);
    outsider
        .audited(|e| e.reason == "destination is another sandbox" && !e.is_allowed)
        .await;
    outsider.send_udp((c, 5000), (b, 5000), b"hi").await;
    assert!(beta.recv(QUIET).await.is_none());
    assert_eq!(node.router.tracked(), 0);

    // Nor can a member reach out to it.
    beta.send_tcp(b, SocketAddr::from((c, 22)), Segment::syn(40111, 1))
        .await;
    assert!(beta.recv_tcp(WAIT).await.unwrap().rst);
    assert!(outsider.recv(QUIET).await.is_none());
}

#[tokio::test]
async fn the_receiver_has_to_admit_the_sender() {
    let (node, audit) = test_node().await;
    let (a, b) = (net_at(6), net_at(10));
    let mut alpha = Guest::attach_to(
        &node,
        Arc::clone(&audit),
        a,
        member("sbx_a", NetworkMode::None, &[b.guest_ip]),
    );
    let beta = Guest::attach_to(&node, audit, b, member("sbx_b", NetworkMode::None, &[]));

    alpha
        .send_tcp(
            a.guest_ip,
            SocketAddr::from((b.guest_ip, 8080)),
            Segment::syn(40120, 1),
        )
        .await;
    assert!(beta.recv(QUIET).await.is_none());
    let event = alpha
        .audited(|e| e.reason == "source shares no private network with this sandbox")
        .await;
    assert_eq!(event.sandbox_id, "sbx_a");
}

#[tokio::test]
async fn allowlist_traffic_to_a_peer_skips_the_proxy() {
    let (mut alpha, beta, _outsider, _node) = trio(NetworkMode::Allowlist).await;
    let (a, b) = (alpha.net.guest_ip, beta.net.guest_ip);
    alpha
        .send_tcp(a, SocketAddr::from((b, 443)), Segment::syn(40130, 7))
        .await;
    let syn = beta.recv_tcp(WAIT).await.expect("the syn, not the proxy");
    assert!(syn.syn && syn.seq == 7);
    assert!(alpha.recv(QUIET).await.is_none());
}

/// A denied port is egress like any other, so the router holds a sandbox
/// to its own `deny_ports` towards a peer, as the Linux sandbox chain does.
#[tokio::test]
async fn a_denied_port_holds_towards_a_peer() {
    let (node, audit) = test_node().await;
    let (a, b) = (net_at(6), net_at(10));
    let denied = member("sbx_a", NetworkMode::Open, &[b.guest_ip]);
    let denied = Policy::new(
        denied.proxy,
        &[],
        &[],
        &[crate::policy::PortDenial {
            protocol: Some(crate::firewall::Protocol::Tcp),
            first: 8080,
            ..Default::default()
        }],
        &[b.guest_ip],
    );
    let mut alpha = Guest::attach_to(&node, Arc::clone(&audit), a, denied);
    let beta = Guest::attach_to(
        &node,
        audit,
        b,
        member("sbx_b", NetworkMode::Open, &[a.guest_ip]),
    );

    alpha
        .send_tcp(
            a.guest_ip,
            SocketAddr::from((b.guest_ip, 8080)),
            Segment::syn(40140, 1),
        )
        .await;
    assert!(
        beta.recv(QUIET).await.is_none(),
        "a denied port is never delivered"
    );
    let event = alpha
        .audited(|e| e.reason == "destination port is denied" && !e.is_allowed)
        .await;
    assert_eq!((event.sandbox_id.as_str(), event.port), ("sbx_a", 8080));

    alpha
        .send_tcp(
            a.guest_ip,
            SocketAddr::from((b.guest_ip, 8081)),
            Segment::syn(40141, 1),
        )
        .await;
    let syn = beta
        .recv_tcp(WAIT)
        .await
        .expect("another port still reaches the peer");
    assert!(syn.syn && syn.port == 8081);
}

#[tokio::test]
async fn a_policy_change_cuts_flows_between_peers() {
    let (mut alpha, mut beta, _outsider, node) = trio(NetworkMode::Open).await;
    let (a, b) = (alpha.net.guest_ip, beta.net.guest_ip);
    let to_b = SocketAddr::from((b, 8080));
    alpha.send_tcp(a, to_b, Segment::syn(40140, 1000)).await;
    beta.recv_tcp(WAIT).await.expect("the syn");
    let synack = Segment {
        port: 8080,
        control: TcpControl::Syn,
        seq: 5000,
        ack: Some(1001),
        payload: &[],
    };
    beta.send_tcp(b, SocketAddr::from((a, 40140)), synack).await;
    alpha.recv_tcp(WAIT).await.expect("the syn-ack");
    let mut tcp = Tcp {
        port: 40140,
        dst: to_b,
        seq: 1001,
        ack: 5001,
    };
    alpha.write(&mut tcp, b"x").await;
    beta.recv_tcp(WAIT).await.expect("data");

    // The network is left.
    alpha
        .policy
        .send_replace(member("sbx_a", NetworkMode::Open, &[]));
    let to_alpha = alpha.recv_tcp(WAIT).await.expect("a reset for the sender");
    assert!(to_alpha.rst);
    assert_eq!((to_alpha.from, to_alpha.seq), (to_b, 5001));
    let to_beta = beta.recv_tcp(WAIT).await.expect("a reset for the receiver");
    assert!(to_beta.rst);
    assert_eq!(to_beta.from, SocketAddr::from((a, 40140)));
    assert_eq!(node.router.tracked(), 0);
    alpha
        .audited(|e| e.reason == "connection reset: the policy now denies this peer")
        .await;

    // And nothing more of it gets through.
    alpha.write(&mut tcp, b"y").await;
    assert!(beta.recv(QUIET).await.is_none());
}

#[tokio::test]
async fn icmp_and_udp_reach_a_peer() {
    let (mut alpha, mut beta, _outsider, _node) = trio(NetworkMode::None).await;
    let (a, b) = (alpha.net.guest_ip, beta.net.guest_ip);
    alpha.send_udp((a, 6000), (b, 7000), b"ping").await;
    let (from, port, data) = beta.recv_udp(WAIT).await.expect("the datagram");
    assert_eq!(
        (from, port, data.as_slice()),
        (SocketAddr::from((a, 6000)), 7000, &b"ping"[..])
    );
    beta.send_udp((b, 7000), (a, 6000), b"pong").await;
    let (_, _, data) = alpha.recv_udp(WAIT).await.expect("the reply");
    assert_eq!(data, b"pong");

    let echo = Icmpv4Repr::EchoRequest {
        ident: 9,
        seq_no: 1,
        data: b"abc",
    };
    let mut body = vec![0u8; echo.buffer_len()];
    echo.emit(
        &mut Icmpv4Packet::new_unchecked(&mut body),
        &ChecksumCapabilities::default(),
    );
    alpha.send_ip(a, b, IpProtocol::Icmp, &body).await;
    let request = beta
        .recv_ip(IpProtocol::Icmp, WAIT)
        .await
        .expect("the echo request");
    let ip = Ipv4Packet::new_checked(&request[..]).unwrap();
    assert_eq!(ip.src_addr(), a);
}

/// Stands in for the WireGuard mesh: the node at 10.99.4.0/22.
#[derive(Default)]
struct FakeMesh {
    sent: Mutex<Vec<Vec<u8>>>,
}

impl Uplink for FakeMesh {
    fn routes(&self, address: Ipv4Addr) -> bool {
        address.octets()[..2] == [10, 99] && (4..8).contains(&address.octets()[2])
    }

    fn send(&self, packet: &[u8]) {
        self.sent.lock().unwrap().push(packet.to_vec());
    }
}

#[tokio::test]
async fn the_mesh_carries_peers_on_other_nodes_and_nothing_else() {
    let remote_peer = Ipv4Addr::new(10, 99, 4, 6);
    let (node, audit) = test_node().await;
    let mesh = Arc::new(FakeMesh::default());
    let uplink: Arc<dyn Uplink> = mesh.clone();
    node.router.set_uplink(Arc::downgrade(&uplink));
    let a = net_at(6);
    let mut alpha = Guest::attach_to(
        &node,
        audit,
        a,
        member("sbx_a", NetworkMode::Open, &[remote_peer]),
    );

    alpha
        .send_tcp(
            a.guest_ip,
            SocketAddr::from((remote_peer, 5432)),
            Segment::syn(40150, 1),
        )
        .await;
    let sent = tokio::time::timeout(WAIT, async {
        loop {
            if let Some(packet) = mesh.sent.lock().unwrap().first().cloned() {
                return packet;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the syn on the mesh");
    let (syn, ttl, mss) = tcp_of(&sent);
    assert!(syn.syn && ttl == 63);
    assert_eq!(mss, Some(MESH_MSS), "clamped to what the mesh carries");

    // The peer's syn-ack comes back over the mesh.
    let reply = {
        let repr = TcpRepr {
            src_port: 5432,
            dst_port: 40150,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(900),
            ack_number: Some(TcpSeqNumber(2)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: remote_peer,
            dst_addr: a.guest_ip,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        };
        let mut packet = vec![0u8; 20 + repr.buffer_len()];
        let mut header = Ipv4Packet::new_unchecked(&mut packet[..]);
        ip.emit(&mut header, &ChecksumCapabilities::default());
        repr.emit(
            &mut TcpPacket::new_unchecked(header.payload_mut()),
            &remote_peer.into(),
            &a.guest_ip.into(),
            &ChecksumCapabilities::default(),
        );
        packet
    };
    node.router.from_mesh(&reply);
    let got = alpha
        .recv_ip(IpProtocol::Tcp, WAIT)
        .await
        .expect("the syn-ack");
    let (synack, _, mss) = tcp_of(&got);
    assert!(synack.syn && synack.ack && synack.seq == 900);
    assert_eq!(mss, Some(MESH_MSS));

    // An unsolicited packet from a node's sandbox that is no member is not
    // delivered, and neither is one claiming a source outside the pool.
    let mut stranger = reply.clone();
    Ipv4Packet::new_unchecked(&mut stranger[..]).set_src_addr(Ipv4Addr::new(10, 99, 4, 7));
    node.router.from_mesh(&stranger);
    let mut outside = reply;
    Ipv4Packet::new_unchecked(&mut outside[..]).set_src_addr(REMOTE);
    node.router.from_mesh(&outside);
    assert!(alpha.recv(QUIET).await.is_none());

    // Open-mode egress outside the pool never touches the mesh.
    let before = mesh.sent.lock().unwrap().len();
    alpha.route(remote(7), echo_server().await);
    alpha.connect(40151, remote(7)).await;
    assert_eq!(mesh.sent.lock().unwrap().len(), before);
}

#[tokio::test]
async fn internal_names_resolve_for_members_only() {
    use burrow_proxy::directory::Member;
    let (alpha, mut beta, mut outsider, node) = trio(NetworkMode::Allowlist).await;
    let (a, b, c) = (alpha.net.guest_ip, beta.net.guest_ip, outsider.net.guest_ip);
    node.directory.replace(
        [(
            "team".to_string(),
            vec![
                Member {
                    sandbox_id: "sbx_a".into(),
                    alias: "api".into(),
                    address: a,
                },
                Member {
                    sandbox_id: "sbx_b".into(),
                    alias: "worker".into(),
                    address: b,
                },
            ],
        )]
        .into(),
    );
    let resolver = beta.net.dns_ip;
    beta.send_udp((b, 5353), (resolver, 53), &dns_query("api.team.internal"))
        .await;
    let (_, _, answer) = beta.recv_udp(WAIT).await.expect("an answer");
    assert_eq!(answer[3] & 0x0f, 0, "NOERROR");
    assert_eq!(&answer[answer.len() - 4..], &a.octets());

    let resolver = outsider.net.dns_ip;
    outsider
        .send_udp((c, 5353), (resolver, 53), &dns_query("api.team.internal"))
        .await;
    let (_, _, answer) = outsider.recv_udp(WAIT).await.expect("an answer");
    assert_eq!(answer[3] & 0x0f, 3, "NXDOMAIN");
}

fn mesh_key() -> (String, String) {
    use base64::Engine as _;
    let secret = x25519_dalek::StaticSecret::random();
    let public = x25519_dalek::PublicKey::from(&secret);
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    (encode(&secret.to_bytes()), encode(public.as_bytes()))
}

/// Two nodes' userspace meshes over loopback. The second is told no
/// endpoint for the first, as a Mac is not for a Linux node whose name only
/// its own network resolves, and answers wherever the first is heard from.
#[tokio::test]
async fn sandboxes_on_two_nodes_reach_each_other_over_the_mesh() {
    let (here, here_audit) = test_node().await;
    let (there, there_audit) = test_node().await;
    let (here_private, here_public) = mesh_key();
    let (there_private, there_public) = mesh_key();
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let here_mesh = Mesh::start(loopback, &here_private, Arc::clone(&here.router))
        .await
        .unwrap();
    let there_mesh = Mesh::start(loopback, &there_private, Arc::clone(&there.router))
        .await
        .unwrap();
    here_mesh
        .configure(&[crate::mesh::Peer {
            node_id: "there".into(),
            public_key: there_public,
            endpoint: there_mesh.local_addr().unwrap().to_string(),
            subnet: "10.99.4.0/22".into(),
        }])
        .await;
    there_mesh
        .configure(&[crate::mesh::Peer {
            node_id: "here".into(),
            public_key: here_public,
            endpoint: "node-here.invalid:51820".into(),
            subnet: "10.99.0.0/22".into(),
        }])
        .await;

    let a = net_at(6);
    let b = SandboxNet {
        mac: [0x02, 0x00, 10, 99, 4, 6],
        guest_ip: Ipv4Addr::new(10, 99, 4, 6),
        gateway_ip: Ipv4Addr::new(10, 99, 4, 5),
        prefix: 30,
        dns_ip: Ipv4Addr::new(10, 99, 4, 5),
        mtu: 1500,
    };
    let mut alpha = Guest::attach_to(
        &here,
        here_audit,
        a,
        member("sbx_a", NetworkMode::None, &[b.guest_ip]),
    );
    let mut beta = Guest::attach_to(
        &there,
        there_audit,
        b,
        member("sbx_b", NetworkMode::None, &[a.guest_ip]),
    );

    alpha
        .send_udp((a.guest_ip, 6000), (b.guest_ip, 7000), b"across")
        .await;
    let (from, port, data) = beta.recv_udp(WAIT).await.expect("the datagram, decrypted");
    assert_eq!((from, port), (SocketAddr::from((a.guest_ip, 6000)), 7000));
    assert_eq!(data, b"across");
    beta.send_udp((b.guest_ip, 7000), (a.guest_ip, 6000), b"back")
        .await;
    let (_, _, data) = alpha.recv_udp(WAIT).await.expect("the reply");
    assert_eq!(data, b"back");

    // And a flow opened from the far side, which knows the way now.
    beta.send_tcp(
        b.guest_ip,
        SocketAddr::from((a.guest_ip, 22)),
        Segment::syn(40160, 3),
    )
    .await;
    let syn = alpha.recv_tcp(WAIT).await.expect("the syn");
    assert!(syn.syn && syn.seq == 3);
}
