//! Tailcat shares: a sandbox's ports reachable through a WireGuard tunnel
//! bootstrapped over a DERP relay.
//!
//! A share is one tailcat server per sandbox, owned by burrowd. The address
//! it hands out is the credential, scoped to that one sandbox, so revoking a
//! share is dropping its server and rotating it is issuing new keys. Servers
//! are created on demand rather than for every sandbox: each holds a relay
//! connection open for as long as it exists.
//!
//! Connections terminate here and are dialed into the guest the way the edge
//! does, which is what makes a share wake a suspended sandbox, and what keeps
//! the guest unable to reach the tunnel sockets: a guest cannot initiate a
//! connection to the host at all, so a share is not a way to reach a
//! neighbour. The client's identity travels only as far as the guest asks
//! for it, as a PROXY protocol header.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tonic::Status;

use burrow_proto::common::v1 as common;
use burrow_store::ShareRow;
use tailcat_rs::{
    Config, ConnInfo, DerpRegion, ExpandOptions, NodePrivate, NodePublic, Ports, PresharedKey,
    Region, Server, TcpConn, UdpFlow,
};

use crate::sandbox::SandboxManager;

/// Where the relay region a node listens through is remembered.
///
/// Addresses embed the relay's details, so the region has to be the same
/// one after a restart for the addresses to stay valid, even if the DERP map
/// has since changed.
const REGION_FILE: &str = "tailcat-region.json";
const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct ShareOptions {
    pub enabled: bool,
    /// The DERP region to listen through, or the nearest when unset.
    pub region: Option<i64>,
    pub derp_map_url: Option<String>,
}

/// What a share admits: everything about it but its keys.
#[derive(Clone, Debug, Default)]
pub struct ShareShape {
    /// Guest TCP ports; empty means every port.
    pub ports: Vec<u16>,
    pub allowed_clients: Vec<String>,
    pub proxy_protocol: bool,
    /// Guest UDP ports; none unless listed or `all_udp`.
    pub udp_ports: Vec<u16>,
    pub all_udp: bool,
}

impl ShareShape {
    /// Applies this shape to a share, keeping its keys.
    pub fn onto(self, existing: ShareRow) -> ShareRow {
        ShareRow {
            ports: self.ports,
            allowed_clients: self.allowed_clients,
            proxy_protocol: self.proxy_protocol,
            udp_ports: self.udp_ports,
            all_udp: self.all_udp,
            ..existing
        }
    }
}

/// A share as reported to callers.
#[derive(Clone, Debug)]
pub struct ShareInfo {
    pub address: String,
    pub spec: ShareRow,
}

struct Active {
    spec: ShareRow,
    server: Arc<Server>,
    task: JoinHandle<()>,
    /// Connections currently relayed into the guest. A sandbox with any is in
    /// use, whatever its idle clock says.
    open: Arc<AtomicU32>,
}

impl Drop for Active {
    fn drop(&mut self) {
        self.task.abort();
        self.server.close();
    }
}

pub struct Shares {
    options: ShareOptions,
    data_dir: PathBuf,
    region: tokio::sync::OnceCell<DerpRegion>,
    active: Mutex<HashMap<String, Active>>,
}

fn parse_key<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, Status> {
    s.parse()
        .map_err(|_| Status::internal(format!("stored share has an invalid {what}")))
}

impl Shares {
    pub fn new(options: ShareOptions, data_dir: &Path) -> Self {
        Self {
            options,
            data_dir: data_dir.to_path_buf(),
            region: tokio::sync::OnceCell::new(),
            active: Mutex::new(HashMap::new()),
        }
    }

    /// New keys for a share: a fresh address nobody has been given yet.
    pub fn new_spec(shape: ShareShape) -> ShareRow {
        ShareRow {
            key: NodePrivate::generate().to_string(),
            preshared_key: PresharedKey::generate().to_string(),
            ports: shape.ports,
            allowed_clients: shape.allowed_clients,
            proxy_protocol: shape.proxy_protocol,
            created_at: burrow_core::unix_now(),
            udp_ports: shape.udp_ports,
            all_udp: shape.all_udp,
        }
    }

    /// The relay region every share on this node listens through, resolved
    /// once and then read back from disk.
    async fn region(&self) -> Result<DerpRegion, Status> {
        self.region
            .get_or_try_init(|| async {
                let path = self.data_dir.join(REGION_FILE);
                if let Ok(text) = tokio::fs::read_to_string(&path).await
                    && let Ok(region) = serde_json::from_str::<DerpRegion>(&text)
                    && self
                        .options
                        .region
                        .is_none_or(|want| want == region.region_id)
                {
                    return Ok(region);
                }
                let mut ci = ConnInfo {
                    region_id: self.options.region.unwrap_or(-1),
                    ..Default::default()
                };
                ci.expand(&ExpandOptions {
                    derp_map_url: self.options.derp_map_url.clone(),
                    derp_map: None,
                    for_server: true,
                })
                .await
                .map_err(|err| Status::unavailable(format!("cannot pick a DERP region: {err}")))?;
                let region = ci
                    .region
                    .into_iter()
                    .next()
                    .ok_or_else(|| Status::unavailable("no DERP region available"))?;
                if let Err(err) =
                    tokio::fs::write(&path, serde_json::to_vec_pretty(&region).unwrap()).await
                {
                    tracing::warn!(path = %path.display(), %err, "could not persist the DERP region");
                }
                tracing::info!(
                    region = region.region_id,
                    code = region.region_code,
                    "tailcat shares will listen through this DERP region"
                );
                Ok(region)
            })
            .await
            .cloned()
    }

    /// Starts serving `spec` for `id`, replacing any server already doing so.
    pub async fn start(
        &self,
        manager: &SandboxManager,
        id: &str,
        spec: ShareRow,
    ) -> Result<ShareInfo, Status> {
        if !self.options.enabled {
            return Err(Status::failed_precondition(
                "tailcat shares are disabled on this node",
            ));
        }
        let region = self.region().await?;
        let key: NodePrivate = parse_key(&spec.key, "key")?;
        let preshared_key: PresharedKey = parse_key(&spec.preshared_key, "pre-shared key")?;
        let allowed_clients = spec
            .allowed_clients
            .iter()
            .map(|k| parse_key::<NodePublic>(k, "client key"))
            .collect::<Result<Vec<_>, _>>()?;
        let server = Server::start(Config {
            key: Some(key),
            preshared_key: Some(preshared_key),
            region: Region::Embedded(region),
            allowed_clients: (!allowed_clients.is_empty()).then_some(allowed_clients),
            tcp_ports: if spec.ports.is_empty() {
                Ports::All
            } else {
                Ports::list(spec.ports.iter().copied())
            },
            udp_ports: if spec.all_udp {
                Some(Ports::All)
            } else if spec.udp_ports.is_empty() {
                None
            } else {
                Some(Ports::list(spec.udp_ports.iter().copied()))
            },
            ..Default::default()
        })
        .await
        .map_err(|err| Status::unavailable(format!("cannot start tailcat server: {err}")))?;
        let server = Arc::new(server);
        let address = server.tailcat_addr().to_string();
        let open = Arc::new(AtomicU32::new(0));
        let task = tokio::spawn(serve(
            manager.clone(),
            id.to_string(),
            server.clone(),
            spec.proxy_protocol,
            open.clone(),
        ));
        self.active.lock().await.insert(
            id.to_string(),
            Active {
                spec: spec.clone(),
                server,
                task,
                open,
            },
        );
        tracing::info!(sandbox = id, "sandbox shared");
        Ok(ShareInfo { address, spec })
    }

    pub async fn stop(&self, id: &str) -> bool {
        self.active.lock().await.remove(id).is_some()
    }

    pub async fn get(&self, id: &str) -> Option<ShareInfo> {
        self.active.lock().await.get(id).map(|a| ShareInfo {
            address: a.server.tailcat_addr().to_string(),
            spec: a.spec.clone(),
        })
    }

    pub async fn spec(&self, id: &str) -> Option<ShareRow> {
        self.active.lock().await.get(id).map(|a| a.spec.clone())
    }

    pub async fn open_connections(&self, id: &str) -> u32 {
        match self.active.lock().await.get(id) {
            Some(a) => a.open.load(Ordering::Relaxed),
            None => 0,
        }
    }
}

async fn serve(
    manager: SandboxManager,
    id: String,
    server: Arc<Server>,
    proxy_protocol: bool,
    open: Arc<AtomicU32>,
) {
    loop {
        tokio::select! {
            conn = server.accept_tcp() => {
                let Some(conn) = conn else { return };
                let (manager, id, server, open) = (manager.clone(), id.clone(), server.clone(), open.clone());
                tokio::spawn(async move {
                    if let Err(err) = relay(&manager, &id, &server, conn, proxy_protocol, &open).await {
                        tracing::debug!(sandbox = id, %err, "share connection ended");
                    }
                });
            }
            flow = server.accept_udp() => {
                let Some(flow) = flow else { return };
                let (manager, id, open) = (manager.clone(), id.clone(), open.clone());
                tokio::spawn(async move {
                    if let Err(err) = relay_udp(&manager, &id, flow, &open).await {
                        tracing::debug!(sandbox = id, %err, "share flow ended");
                    }
                });
            }
        }
    }
}

/// Wakes the sandbox for a connection and marks it in use for as long as
/// the returned guard lives.
async fn admit<'a>(
    manager: &SandboxManager,
    id: &str,
    open: &'a AtomicU32,
) -> Result<(Arc<crate::sandbox::RunningSandbox>, OpenGuard<'a>), String> {
    let sandbox = manager
        .get(id)
        .await
        .map_err(|err| err.message().to_string())?;
    if sandbox.record().state == common::SandboxState::Suspended as i32 {
        tracing::info!(
            sandbox = id,
            "resuming a suspended sandbox for a shared connection"
        );
        manager
            .resume(id)
            .await
            .map_err(|err| format!("could not resume: {}", err.message()))?;
    }
    // Held for the connection's life, and the sandbox is touched again when
    // it ends, so idle suspension neither reclaims a sandbox mid-session nor
    // counts the session's length against what follows it.
    open.fetch_add(1, Ordering::Relaxed);
    let guard = OpenGuard {
        open,
        sandbox: sandbox.clone(),
    };
    sandbox.touch();
    Ok((sandbox, guard))
}

/// Pumps one UDP flow between the client and the guest. It ends when the
/// tunnel side times the flow out for inactivity, which is the only end a
/// datagram exchange has.
async fn relay_udp(
    manager: &SandboxManager,
    id: &str,
    mut flow: UdpFlow,
    open: &AtomicU32,
) -> Result<(), String> {
    let (sandbox, _guard) = admit(manager, id, open).await?;
    let guest = SocketAddr::from((sandbox.lease.guest_ip, flow.local_addr().port()));
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|err| format!("bind: {err}"))?;
    sock.connect(guest)
        .await
        .map_err(|err| format!("connect to {guest}: {err}"))?;
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            datagram = flow.recv() => {
                let Some(datagram) = datagram else { return Ok(()) };
                let _ = sock.send(&datagram).await;
            }
            received = sock.recv(&mut buf) => {
                let n = received.map_err(|err| format!("recv from {guest}: {err}"))?;
                if flow.send(&buf[..n]).is_err() {
                    return Ok(());
                }
            }
        }
    }
}

async fn relay(
    manager: &SandboxManager,
    id: &str,
    server: &Server,
    mut conn: TcpConn,
    proxy_protocol: bool,
    open: &AtomicU32,
) -> Result<(), String> {
    let (sandbox, _guard) = admit(manager, id, open).await?;
    let guest = SocketAddr::from((sandbox.lease.guest_ip, conn.local_addr().port()));
    let mut upstream = tokio::time::timeout(GUEST_CONNECT_TIMEOUT, TcpStream::connect(guest))
        .await
        .map_err(|_| format!("connect to {guest} timed out"))?
        .map_err(|err| format!("connect to {guest}: {err}"))?;
    if proxy_protocol {
        // Only a direct path's address is the client's real one: those
        // packets authenticated under its key, and nothing it merely claimed
        // about itself did.
        let public = conn
            .peer_key()
            .and_then(|k| server.peer(&k))
            .and_then(|p| p.direct);
        let header = proxy_header(
            conn.remote_addr(),
            SocketAddrV6::new(server.addr(), conn.local_addr().port(), 0, 0),
            guest,
            public,
            conn.peer_key(),
        );
        upstream
            .write_all(&header)
            .await
            .map_err(|err| format!("write PROXY header: {err}"))?;
    }
    let _ = tokio::io::copy_bidirectional(&mut conn, &mut upstream).await;
    Ok(())
}

struct OpenGuard<'a> {
    open: &'a AtomicU32,
    sandbox: Arc<crate::sandbox::RunningSandbox>,
}

impl Drop for OpenGuard<'_> {
    fn drop(&mut self) {
        self.open.fetch_sub(1, Ordering::Relaxed);
        self.sandbox.touch();
    }
}

const PP2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
const PP2_VERSION_PROXY: u8 = 0x21;
const PP2_TCP4: u8 = 0x11;
const PP2_TCP6: u8 = 0x21;
/// Custom TLVs, in the range the spec reserves for applications.
const PP2_TYPE_TUNNEL_ADDR: u8 = 0xe0;
const PP2_TYPE_NODE_KEY: u8 = 0xe1;

/// A PROXY protocol v2 header describing one shared connection.
///
/// The source is the client's public address when the tunnel has a verified
/// direct path to it, with the guest as destination, so a service that logs
/// or rate-limits by source sees what it would see on the open internet.
/// Otherwise the source is the client's tunnel address, an IPv6 derived from
/// its key, with the share's own tunnel address as destination. The tunnel
/// address and node key always travel as TLVs, so a service can key on the
/// identity that does not change when the client moves networks.
fn proxy_header(
    tunnel_src: SocketAddrV6,
    tunnel_dst: SocketAddrV6,
    guest: SocketAddr,
    public: Option<SocketAddr>,
    node_key: Option<NodePublic>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    let family = match public {
        Some(SocketAddr::V4(src)) => {
            body.extend_from_slice(&src.ip().octets());
            match guest.ip() {
                IpAddr::V4(dst) => body.extend_from_slice(&dst.octets()),
                IpAddr::V6(dst) => body.extend_from_slice(&dst.octets()[12..]),
            }
            body.extend_from_slice(&src.port().to_be_bytes());
            body.extend_from_slice(&guest.port().to_be_bytes());
            PP2_TCP4
        }
        Some(SocketAddr::V6(src)) => {
            body.extend_from_slice(&src.ip().octets());
            body.extend_from_slice(&tunnel_dst.ip().octets());
            body.extend_from_slice(&src.port().to_be_bytes());
            body.extend_from_slice(&tunnel_dst.port().to_be_bytes());
            PP2_TCP6
        }
        None => {
            body.extend_from_slice(&tunnel_src.ip().octets());
            body.extend_from_slice(&tunnel_dst.ip().octets());
            body.extend_from_slice(&tunnel_src.port().to_be_bytes());
            body.extend_from_slice(&tunnel_dst.port().to_be_bytes());
            PP2_TCP6
        }
    };
    let mut tlv = |typ: u8, value: &[u8]| {
        body.push(typ);
        body.extend_from_slice(&(value.len() as u16).to_be_bytes());
        body.extend_from_slice(value);
    };
    tlv(PP2_TYPE_TUNNEL_ADDR, tunnel_src.to_string().as_bytes());
    if let Some(key) = node_key {
        tlv(PP2_TYPE_NODE_KEY, key.to_string().as_bytes());
    }

    let mut header = Vec::with_capacity(16 + body.len());
    header.extend_from_slice(&PP2_SIGNATURE);
    header.push(PP2_VERSION_PROXY);
    header.push(family);
    header.extend_from_slice(&(body.len() as u16).to_be_bytes());
    header.extend_from_slice(&body);
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel(last: u16, port: u16) -> SocketAddrV6 {
        SocketAddrV6::new(
            std::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, last),
            port,
            0,
            0,
        )
    }

    #[test]
    fn header_without_a_public_address_names_the_tunnel() {
        let key = NodePrivate::generate().public();
        let h = proxy_header(
            tunnel(2, 40000),
            tunnel(1, 8080),
            "10.99.0.2:8080".parse().unwrap(),
            None,
            Some(key),
        );
        assert_eq!(&h[..12], &PP2_SIGNATURE);
        assert_eq!((h[12], h[13]), (PP2_VERSION_PROXY, PP2_TCP6));
        let len = u16::from_be_bytes([h[14], h[15]]) as usize;
        assert_eq!(h.len(), 16 + len);
        assert_eq!(&h[16..32], &tunnel(2, 40000).ip().octets());
        assert_eq!(&h[32..48], &tunnel(1, 8080).ip().octets());
        assert_eq!(&h[48..52], &[0x9c, 0x40, 0x1f, 0x90]);
        // First TLV: the tunnel address as text.
        assert_eq!(h[52], PP2_TYPE_TUNNEL_ADDR);
        let tlv_len = u16::from_be_bytes([h[53], h[54]]) as usize;
        assert_eq!(
            &h[55..55 + tlv_len],
            tunnel(2, 40000).to_string().as_bytes()
        );
        assert_eq!(h[55 + tlv_len], PP2_TYPE_NODE_KEY);
        assert!(h.ends_with(key.to_string().as_bytes()));
    }

    #[test]
    fn header_with_a_public_address_is_ipv4_to_the_guest() {
        let h = proxy_header(
            tunnel(2, 40000),
            tunnel(1, 22),
            "10.99.0.2:22".parse().unwrap(),
            Some("203.0.113.9:4444".parse().unwrap()),
            None,
        );
        assert_eq!((h[12], h[13]), (PP2_VERSION_PROXY, PP2_TCP4));
        assert_eq!(&h[16..20], &[203, 0, 113, 9]);
        assert_eq!(&h[20..24], &[10, 99, 0, 2]);
        assert_eq!(&h[24..28], &[0x11, 0x5c, 0, 22]);
        assert_eq!(h[28], PP2_TYPE_TUNNEL_ADDR);
    }
}
