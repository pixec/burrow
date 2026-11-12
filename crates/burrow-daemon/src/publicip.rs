//! Public addresses on this node: the global IPv6 address each sandbox is
//! given from the node's routed prefix, the dedicated addresses attached to
//! it, waking a suspended holder on its first admitted packet, and an audit
//! record for every connection those addresses carry.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use burrow_net::ipam::BLOCKS_PER_NODE;
use burrow_proto::common::v1 as common;

/// How this node gives sandboxes public addresses.
#[derive(Debug, Clone, Default)]
pub struct PublicConfig {
    /// The routed prefix each sandbox's global IPv6 address comes from.
    pub ipv6_prefix: Option<(Ipv6Addr, u8)>,
    /// The prefix each sandbox is routed out of it.
    pub ipv6_per_sandbox: u8,
    /// Answer NDP on the uplink for each sandbox's v6 prefix, when the
    /// upstream looks it up there rather than routing it to the node.
    pub is_ipv6_on_link: bool,
    /// The uplink public addresses arrive on, when it is not the interface
    /// the node reaches a pool's gateway through.
    pub interface: Option<String>,
    /// New inbound connections per second to one sandbox's public addresses,
    /// and inbound kilobytes per second; 0 is unlimited.
    pub new_per_sec: u32,
    pub kbytes_per_sec: u32,
    pub(crate) uplinks: Arc<std::sync::Mutex<HashMap<IpAddr, String>>>,
}

impl PublicConfig {
    /// Checks a prefix and share size against the node's 256 sandboxes.
    pub fn with_ipv6(
        mut self,
        prefix: &str,
        per_sandbox: u8,
        is_on_link: bool,
    ) -> anyhow::Result<Self> {
        let (address, len) = prefix
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("--ipv6-prefix {prefix:?} is not address/len"))?;
        let address: Ipv6Addr = address.parse()?;
        let len: u8 = len.parse()?;
        let slots = BLOCKS_PER_NODE.trailing_zeros() as u8;
        if per_sandbox > 128 || u16::from(len) + u16::from(slots) > u16::from(per_sandbox) {
            anyhow::bail!(
                "--ipv6-prefix /{len} cannot hold {BLOCKS_PER_NODE} sandboxes of /{per_sandbox}; \
                 give a prefix at most /{} or a smaller --ipv6-per-sandbox",
                per_sandbox.saturating_sub(slots)
            );
        }
        self.ipv6_prefix = Some((address, len));
        self.ipv6_per_sandbox = per_sandbox;
        self.is_ipv6_on_link = is_on_link;
        Ok(self)
    }

    /// The global address of the sandbox on lease block `block`, and the
    /// prefix routed to it, indexed by the block within this node's slice.
    pub fn ipv6_for(&self, block: u32) -> Option<(Ipv6Addr, u8)> {
        let (base, len) = self.ipv6_prefix?;
        let per = self.ipv6_per_sandbox;
        let mask = match len {
            0 => 0,
            bits => u128::MAX << (128 - u32::from(bits)),
        };
        let index = u128::from(block % BLOCKS_PER_NODE);
        let subnet = (u128::from(base) & mask) | (index << (128 - u32::from(per)));
        let address = if per < 128 { subnet | 1 } else { subnet };
        Some((Ipv6Addr::from(address), per))
    }

    /// The address sandbox `sandbox_id` on lease block `block` takes from
    /// this node's IPv6 prefix, as a public IP of the node's own pool.
    pub fn node_ip(&self, node_id: &str, sandbox_id: &str, block: u32) -> Option<common::PublicIp> {
        let (address, prefix) = self.ipv6_for(block)?;
        Some(common::PublicIp {
            address: address.to_string(),
            family: 6,
            prefix_len: u32::from(prefix),
            pool: node_pool(node_id),
            sandbox_id: sandbox_id.to_string(),
            node_id: node_id.to_string(),
            allocated_at_unix_ms: burrow_common::unix_now_ms(),
            attached_at_unix_ms: burrow_common::unix_now_ms(),
            is_on_link: self.is_ipv6_on_link,
            state: common::PublicIpState::Allocated as i32,
            is_node_prefix: true,
            ..Default::default()
        })
    }

    /// The interface the node reaches `toward` through.
    pub async fn uplink(&self, toward: IpAddr) -> Option<String> {
        if let Some(interface) = &self.interface {
            return Some(interface.clone());
        }
        if let Some(dev) = self.uplinks.lock().unwrap().get(&toward) {
            return Some(dev.clone());
        }
        let dev = burrow_net::public::uplink_for(toward).await?;
        self.uplinks.lock().unwrap().insert(toward, dev.clone());
        Some(dev)
    }
}

/// The name of the pool a node's IPv6 prefix forms.
pub fn node_pool(node_id: &str) -> String {
    format!("node:{node_id}")
}

/// Which sandbox holds each public address, and whether it wakes on traffic.
#[derive(Debug, Default)]
pub struct PublicIndex(std::sync::RwLock<Vec<Holder>>);

#[derive(Debug, Clone)]
pub struct Holder {
    pub address: IpAddr,
    pub prefix: u8,
    pub sandbox_id: String,
    pub is_waking: bool,
}

impl Holder {
    fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = match self.prefix {
                    0 => 0,
                    bits => u32::MAX << (32 - u32::from(bits.min(32))),
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = match self.prefix {
                    0 => 0,
                    bits => u128::MAX << (128 - u32::from(bits.min(128))),
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl PublicIndex {
    pub fn replace(&self, holders: Vec<Holder>) {
        *self.0.write().unwrap() = holders;
    }

    pub fn holder(&self, address: IpAddr) -> Option<Holder> {
        self.0
            .read()
            .unwrap()
            .iter()
            .find(|holder| holder.contains(address))
            .cloned()
    }
}

/// The addresses a sandbox's record holds, as the guest configures them.
pub fn guest_addresses(
    ips: &[common::PublicIp],
    ipv6: Option<(Ipv6Addr, u8)>,
) -> Vec<burrow_proto::guest::v1::PublicAddress> {
    let mut out: Vec<_> = ips
        .iter()
        .filter_map(|ip| {
            let address: IpAddr = ip.address.parse().ok()?;
            Some(burrow_proto::guest::v1::PublicAddress {
                address: address.to_string(),
                prefix_len: if address.is_ipv4() { 32 } else { 128 },
            })
        })
        .collect();
    if let Some((address, _)) = ipv6 {
        out.push(burrow_proto::guest::v1::PublicAddress {
            address: address.to_string(),
            prefix_len: 128,
        });
    }
    out
}

/// Holds packets the wake queue was given until their sandbox is up.
#[cfg(target_os = "linux")]
pub fn spawn_wake(manager: crate::sandbox::SandboxManager) {
    use std::os::fd::AsRawFd as _;

    let (arrived, mut arrivals) = tokio::sync::mpsc::unbounded_channel::<IpAddr>();
    let (release, releases) = std::sync::mpsc::channel::<(Vec<IpAddr>, bool)>();
    std::thread::Builder::new()
        .name("burrow-wake".into())
        .spawn(move || {
            let mut queue = match nfq::Queue::open() {
                Ok(queue) => queue,
                Err(err) => {
                    tracing::warn!(%err, "no netfilter queue; wake-on-traffic delivers to a sleeping sandbox instead");
                    return;
                }
            };
            if let Err(err) = queue.bind(burrow_net::firewall::WAKE_QUEUE) {
                tracing::warn!(%err, "could not bind the wake queue");
                return;
            }
            let _ = queue.set_copy_range(burrow_net::firewall::WAKE_QUEUE, 64);
            queue.set_nonblocking(true);
            let mut held: Vec<(IpAddr, std::time::Instant, nfq::Message)> = Vec::new();
            loop {
                while let Ok((addresses, is_accepted)) = releases.try_recv() {
                    let (go, keep): (Vec<_>, Vec<_>) = held
                        .drain(..)
                        .partition(|(address, _, _)| addresses.contains(address));
                    held = keep;
                    for (_, _, mut message) in go {
                        message.set_verdict(if is_accepted {
                            nfq::Verdict::Accept
                        } else {
                            nfq::Verdict::Drop
                        });
                        let _ = queue.verdict(message);
                    }
                }
                // A resume that never reports back does not pin the packets.
                let (stale, keep): (Vec<_>, Vec<_>) = held
                    .drain(..)
                    .partition(|(_, at, _)| at.elapsed() > std::time::Duration::from_secs(30));
                held = keep;
                for (_, _, mut message) in stale {
                    message.set_verdict(nfq::Verdict::Drop);
                    let _ = queue.verdict(message);
                }
                match queue.recv() {
                    Ok(mut message) => match destination(message.get_payload()) {
                        Some(address) if held.len() < 1024 => {
                            let _ = arrived.send(address);
                            held.push((address, std::time::Instant::now(), message));
                        }
                        _ => {
                            message.set_verdict(nfq::Verdict::Drop);
                            let _ = queue.verdict(message);
                        }
                    },
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        let mut poll = libc::pollfd {
                            fd: queue.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        // SAFETY: one pollfd for a socket this thread owns.
                        unsafe { libc::poll(&mut poll, 1, 50) };
                    }
                    Err(err) => {
                        tracing::warn!(%err, "wake queue read failed");
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        })
        .expect("spawning the wake thread");

    tokio::spawn(async move {
        let waking: Arc<tokio::sync::Mutex<HashMap<String, Vec<IpAddr>>>> = Arc::default();
        while let Some(address) = arrivals.recv().await {
            let Some(holder) = manager
                .public_index()
                .holder(address)
                .filter(|holder| holder.is_waking)
            else {
                let _ = release.send((vec![address], false));
                continue;
            };
            let mut pending = waking.lock().await;
            if let Some(addresses) = pending.get_mut(&holder.sandbox_id) {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                continue;
            }
            pending.insert(holder.sandbox_id.clone(), vec![address]);
            drop(pending);
            let (manager, waking, release) =
                (manager.clone(), Arc::clone(&waking), release.clone());
            tokio::spawn(async move {
                let id = holder.sandbox_id;
                let outcome = manager.resume(&id).await;
                if let Err(err) = &outcome {
                    tracing::warn!(
                        sandbox = id,
                        err = err.message(),
                        "could not wake a sandbox on traffic"
                    );
                } else {
                    tracing::info!(sandbox = id, %address, "woke a suspended sandbox on traffic");
                }
                let addresses = waking.lock().await.remove(&id).unwrap_or_default();
                let _ = release.send((addresses, outcome.is_ok()));
            });
        }
    });
}

/// The destination of an IP packet.
fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let octets: [u8; 4] = packet[16..20].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        6 if packet.len() >= 40 => {
            let octets: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

/// One new connection, from a conntrack event line.
#[derive(Debug, PartialEq, Eq)]
struct Connection {
    protocol: String,
    source: IpAddr,
    destination: IpAddr,
    sport: u16,
    dport: u16,
}

/// Reads `[NEW] tcp 6 120 SYN_SENT src=a dst=b sport=x dport=y ...`, taking
/// the original direction only.
fn parse_event(line: &str) -> Option<Connection> {
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "[NEW]" {
        return None;
    }
    let protocol = tokens.next()?.to_string();
    let mut source = None;
    let mut destination = None;
    let mut sport = 0;
    let mut dport = 0;
    for token in tokens {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "src" if source.is_none() => source = value.parse().ok(),
            "dst" if destination.is_none() => destination = value.parse().ok(),
            "sport" if sport == 0 => sport = value.parse().unwrap_or(0),
            "dport" if dport == 0 => dport = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some(Connection {
        protocol,
        source: source?,
        destination: destination?,
        sport,
        dport,
    })
}

/// Records every connection opened to or from a public address, from the
/// kernel's conntrack events. The proxy's upstream connections are its own
/// records already, and leave from the node's address before translation, so
/// they are not counted twice.
#[cfg(target_os = "linux")]
pub fn spawn_audit(manager: crate::sandbox::SandboxManager) {
    use tokio::io::AsyncBufReadExt as _;

    tokio::spawn(async move {
        loop {
            let child = tokio::process::Command::new("conntrack")
                .args(["-E", "-e", "NEW"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn();
            let mut child = match child {
                Ok(child) => child,
                Err(err) => {
                    tracing::warn!(%err, "no conntrack events; connections on public addresses go unaudited");
                    return;
                }
            };
            let Some(stdout) = child.stdout.take() else {
                return;
            };
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Some(connection) = parse_event(&line) else {
                    continue;
                };
                let index = manager.public_index();
                let (holder, reason, port) = match (
                    index.holder(connection.destination),
                    index.holder(connection.source),
                ) {
                    (Some(holder), _) => (holder, "inbound to a public address", connection.dport),
                    (None, Some(holder)) => {
                        (holder, "outbound from a public address", connection.dport)
                    }
                    (None, None) => continue,
                };
                manager.audit_public(burrow_proxy::EgressEvent {
                    at_ms: burrow_proxy::unix_now_ms(),
                    sandbox_id: holder.sandbox_id,
                    source_ip: connection.source.to_string(),
                    destination: format!(
                        "{}",
                        std::net::SocketAddr::new(connection.destination, connection.dport)
                    ),
                    host: None,
                    port,
                    is_allowed: true,
                    reason: format!(
                        "{reason} ({}, from port {})",
                        connection.protocol, connection.sport
                    ),
                    bytes_sent: 0,
                    bytes_received: 0,
                    dropped_records: 0,
                });
            }
            let _ = child.wait().await;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(prefix: &str, per: u8) -> PublicConfig {
        PublicConfig::default()
            .with_ipv6(prefix, per, false)
            .unwrap()
    }

    #[test]
    fn each_block_gets_its_own_share_of_the_prefix() {
        let config = config("2001:db8:100::/56", 64);
        assert_eq!(
            config.ipv6_for(1),
            Some(("2001:db8:100:1::1".parse().unwrap(), 64))
        );
        // A node's blocks start past its slice's base, and index within it.
        assert_eq!(
            config.ipv6_for(BLOCKS_PER_NODE + 5),
            Some(("2001:db8:100:5::1".parse().unwrap(), 64))
        );
        let config = super::tests::config("2001:db8:100::/112", 128);
        assert_eq!(
            config.ipv6_for(7),
            Some(("2001:db8:100::7".parse().unwrap(), 128))
        );
    }

    #[test]
    fn a_sandboxs_node_address_is_a_public_ip_of_the_nodes_pool() {
        let config = config("2001:db8:100::/56", 64);
        let ip = config.node_ip("node-a", "sbx_a", 3).unwrap();
        assert_eq!(ip.address, "2001:db8:100:3::1");
        assert_eq!((ip.family, ip.prefix_len), (6, 64));
        assert_eq!(ip.pool, "node:node-a");
        assert!(ip.is_node_prefix && !ip.is_smtp_allowed);
        assert_eq!(ip.sandbox_id, "sbx_a");
        assert!(
            PublicConfig::default()
                .node_ip("node-a", "sbx_a", 3)
                .is_none()
        );
    }

    #[test]
    fn a_prefix_too_small_for_the_node_is_refused() {
        assert!(
            PublicConfig::default()
                .with_ipv6("2001:db8::/60", 64, false)
                .is_err()
        );
        assert!(
            PublicConfig::default()
                .with_ipv6("2001:db8::/121", 128, false)
                .is_err()
        );
        assert!(
            PublicConfig::default()
                .with_ipv6("nonsense", 64, false)
                .is_err()
        );
    }

    #[test]
    fn a_holder_covers_its_prefix() {
        let index = PublicIndex::default();
        index.replace(vec![Holder {
            address: "2001:db8:100:5::1".parse().unwrap(),
            prefix: 64,
            sandbox_id: "sbx_a".into(),
            is_waking: true,
        }]);
        assert_eq!(
            index
                .holder("2001:db8:100:5::99".parse().unwrap())
                .unwrap()
                .sandbox_id,
            "sbx_a"
        );
        assert!(index.holder("2001:db8:100:6::1".parse().unwrap()).is_none());
    }

    #[test]
    fn a_conntrack_event_is_read_in_its_original_direction() {
        let line = "    [NEW] tcp      6 120 SYN_SENT src=198.51.100.9 dst=203.0.113.17 sport=40000 \
                    dport=22 [UNREPLIED] src=203.0.113.17 dst=198.51.100.9 sport=22 dport=40000";
        assert_eq!(
            parse_event(line),
            Some(Connection {
                protocol: "tcp".into(),
                source: "198.51.100.9".parse().unwrap(),
                destination: "203.0.113.17".parse().unwrap(),
                sport: 40000,
                dport: 22,
            })
        );
        assert_eq!(parse_event("[DESTROY] tcp 6 src=1.1.1.1 dst=2.2.2.2"), None);
    }

    #[test]
    fn a_packet_names_its_destination() {
        let mut v4 = vec![0x45u8; 20];
        v4[16..20].copy_from_slice(&[203, 0, 113, 17]);
        assert_eq!(destination(&v4), Some("203.0.113.17".parse().unwrap()));
        let mut v6 = vec![0x60u8; 40];
        v6[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(destination(&v6), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(destination(&[0x45]), None);
    }
}
