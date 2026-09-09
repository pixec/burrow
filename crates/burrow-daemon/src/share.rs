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
//! neighbour. With `--transparent-ip`, each connection is sourced from the
//! last disco-pong-verified public IPv4, so the guest sees that address on
//! the packet. A client that has never hole-punched has no such address and
//! is sourced from the gateway.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

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
    /// Whether shares here may source connections from the client's own
    /// address. Off makes every share on this node use the gateway.
    pub transparent: bool,
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
    /// Guest UDP ports; none unless listed or `all_udp`.
    pub udp_ports: Vec<u16>,
    pub all_udp: bool,
    /// Source each connection from the last pong-verified public IPv4.
    pub transparent_ip: bool,
}

impl ShareShape {
    /// Applies this shape to a share, keeping its keys.
    pub fn onto(self, existing: ShareRow) -> ShareRow {
        ShareRow {
            ports: self.ports,
            allowed_clients: self.allowed_clients,
            udp_ports: self.udp_ports,
            all_udp: self.all_udp,
            transparent_ip: self.transparent_ip,
            ..existing
        }
    }
}

/// A share as reported to callers.
#[derive(Clone, Debug)]
pub struct ShareInfo {
    pub address: String,
    pub spec: ShareRow,
    /// Whether connections really are sourced from the client's address.
    pub transparent_ip: bool,
}

struct Active {
    spec: ShareRow,
    /// What the share ended up doing, which is what a caller is told: a node
    /// that could not install the reply path serves from the gateway.
    transparent_ip: bool,
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
    /// Reply-path host setup, installed once the first share needs it. Left
    /// empty on failure so the next share retries.
    transparent_ready: tokio::sync::OnceCell<()>,
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
            transparent_ready: tokio::sync::OnceCell::new(),
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
            created_at: burrow_core::unix_now(),
            udp_ports: shape.udp_ports,
            all_udp: shape.all_udp,
            transparent_ip: shape.transparent_ip,
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
        let transparent_ip = spec.transparent_ip && self.transparent_ready().await;
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
            Dial { transparent_ip },
            open.clone(),
        ));
        self.active.lock().await.insert(
            id.to_string(),
            Active {
                spec: spec.clone(),
                transparent_ip,
                server,
                task,
                open,
            },
        );
        tracing::info!(sandbox = id, transparent_ip, "sandbox shared");
        Ok(ShareInfo {
            address,
            spec,
            transparent_ip,
        })
    }

    pub async fn stop(&self, id: &str) -> bool {
        self.active.lock().await.remove(id).is_some()
    }

    pub async fn get(&self, id: &str) -> Option<ShareInfo> {
        self.active.lock().await.get(id).map(|a| ShareInfo {
            address: a.server.tailcat_addr().to_string(),
            spec: a.spec.clone(),
            transparent_ip: a.transparent_ip,
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

    /// Whether this node can source a connection from the client's own
    /// address, installing the reply path the first time it is asked.
    ///
    /// A node whose kernel or privileges cannot carry it still serves the
    /// share, from the gateway: losing the client's address is a worse guest
    /// experience, but refusing to share at all is a worse outage, and the
    /// same call is what brings persisted shares back after a restart.
    async fn transparent_ready(&self) -> bool {
        if !self.options.transparent {
            return false;
        }
        match self
            .transparent_ready
            .get_or_try_init(burrow_net::transparent::install)
            .await
        {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(
                    %err,
                    "cannot install the reply path for client source addresses; \
                     shares on this node will be sourced from the gateway"
                );
                false
            }
        }
    }
}

/// How a share dials the guest for one connection or flow.
#[derive(Clone, Copy)]
struct Dial {
    transparent_ip: bool,
}

async fn serve(
    manager: SandboxManager,
    id: String,
    server: Arc<Server>,
    dial: Dial,
    open: Arc<AtomicU32>,
) {
    loop {
        tokio::select! {
            conn = server.accept_tcp() => {
                let Some(conn) = conn else { return };
                let (manager, id, server, open) = (manager.clone(), id.clone(), server.clone(), open.clone());
                tokio::spawn(async move {
                    if let Err(err) = relay(&manager, &id, &server, conn, dial, &open).await {
                        tracing::debug!(sandbox = id, %err, "share connection ended");
                    }
                });
            }
            flow = server.accept_udp() => {
                let Some(flow) = flow else { return };
                let (manager, id, server, open) = (manager.clone(), id.clone(), server.clone(), open.clone());
                tokio::spawn(async move {
                    if let Err(err) = relay_udp(&manager, &id, &server, flow, dial, &open).await {
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
    server: &Server,
    mut flow: UdpFlow,
    dial: Dial,
    open: &AtomicU32,
) -> Result<(), String> {
    let (sandbox, _guard) = admit(manager, id, open).await?;
    let guest = SocketAddr::from((sandbox.lease.guest_ip, flow.local_addr().port()));
    let public = flow
        .peer_key()
        .and_then(|k| server.peer(&k))
        .and_then(|p| p.last_udp);
    let from = client_src(dial, public);
    if let Some(src) = from {
        tracing::debug!(
            sandbox = id,
            client = %flow.peer_key().map(|k| k.short()).unwrap_or_default(),
            %src,
            %guest,
            "share flow from client public address"
        );
    }
    let sock = match from {
        Some(src) => {
            let std = burrow_net::transparent::bind_udp(src)
                .map_err(|err| format!("bind {src}: {err}"))?;
            UdpSocket::from_std(std).map_err(|err| format!("bind {src}: {err}"))?
        }
        None => UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .await
            .map_err(|err| format!("bind: {err}"))?,
    };
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
    dial: Dial,
    open: &AtomicU32,
) -> Result<(), String> {
    let (sandbox, _guard) = admit(manager, id, open).await?;
    let guest = SocketAddr::from((sandbox.lease.guest_ip, conn.local_addr().port()));
    let public = conn
        .peer_key()
        .and_then(|k| server.peer(&k))
        .and_then(|p| p.last_udp);
    let from = client_src(dial, public);
    if let Some(src) = from {
        tracing::debug!(
            sandbox = id,
            client = %conn.peer_key().map(|k| k.short()).unwrap_or_default(),
            %src,
            %guest,
            "share connection from client public address"
        );
    }
    let mut upstream = dial_guest(guest, from).await?;
    let _ = tokio::io::copy_bidirectional(&mut conn, &mut upstream).await;
    Ok(())
}

/// The client's last pong-verified IPv4, or `None` to use the gateway.
fn client_src(dial: Dial, public: Option<SocketAddr>) -> Option<Ipv4Addr> {
    if !dial.transparent_ip {
        return None;
    }
    match public {
        Some(SocketAddr::V4(src)) => Some(*src.ip()),
        _ => None,
    }
}

async fn dial_guest(guest: SocketAddr, from: Option<Ipv4Addr>) -> Result<TcpStream, String> {
    let connecting = async {
        match from {
            None => TcpStream::connect(guest).await,
            Some(src) => {
                let sock = tokio::net::TcpSocket::new_v4()?;
                burrow_net::transparent::enable_socket(&sock)?;
                sock.bind(SocketAddr::from((src, 0)))?;
                sock.connect(guest).await
            }
        }
    };
    tokio::time::timeout(GUEST_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| format!("connect to {guest} timed out"))?
        .map_err(|err| match from {
            Some(src) => format!("connect to {guest} from {src}: {err}"),
            None => format!("connect to {guest}: {err}"),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_ip_is_only_the_verified_public_ipv4() {
        let dial = Dial {
            transparent_ip: true,
        };
        let public: SocketAddr = "203.0.113.9:4444".parse().unwrap();
        assert_eq!(
            client_src(dial, Some(public)),
            Some("203.0.113.9".parse().unwrap())
        );
        // No address, or IPv6-only, means the gateway: we do not invent one.
        assert_eq!(client_src(dial, None), None);
        let v6: SocketAddr = "[2001:db8::1]:4444".parse().unwrap();
        assert_eq!(client_src(dial, Some(v6)), None);
        let off = Dial {
            transparent_ip: false,
        };
        assert_eq!(client_src(off, Some(public)), None);
    }

    #[tokio::test]
    async fn dial_guest_binds_the_requested_source() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _client = dial_guest(addr, Some(Ipv4Addr::LOCALHOST)).await.unwrap();
        let (_, peer) = accept.await.unwrap();
        assert_eq!(peer.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
