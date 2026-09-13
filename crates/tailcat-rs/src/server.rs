//! The server: configuration, startup, and the accept queues.

use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};

use crate::addr::{Addr, ConnInfo};
use crate::derp;
use crate::derpmap::{DerpRegion, ExpandOptions};
use crate::error::{Error, Result};
use crate::key::{NodePrivate, NodePublic, PresharedKey};
use crate::netstack::{Netstack, Policy, Ports, TcpConn, UdpFlow};
use crate::transport::{self, PeerStatus, Transport};

/// How long an inbound UDP flow with no traffic stays open.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// What the relay is told we are. The stock server's name, so relay operators
/// see one kind of tailcat server, which is what this is on the wire.
const DERP_APP_NAME: &str = "tailcat-server";

/// The relay a server listens through.
#[derive(Clone, Debug)]
pub enum Region {
    /// Fetch the DERP map and pick the lowest-latency region.
    Nearest,
    /// Fetch the DERP map and use this region.
    Id(i64),
    /// Use this region as is, without fetching anything.
    Embedded(DerpRegion),
}

/// Server configuration. [`Config::default`] is a usable server: an
/// ephemeral key, a fresh pre-shared key, the nearest public relay, every
/// client admitted, every TCP port on the server's address served, no UDP
/// and no forwarding.
#[derive(Clone, Debug)]
pub struct Config {
    /// The node identity. `None` generates an ephemeral one, which means a
    /// new address on every start.
    pub key: Option<NodePrivate>,
    /// The pre-shared key clients must know. `None` generates one. A
    /// persistent server restores this along with `key` so its address
    /// stays valid.
    pub preshared_key: Option<PresharedKey>,
    /// Drop the pre-shared-key layer for shorter addresses that clients
    /// before tailcat v0.6 accept. Not recommended.
    pub disable_preshared_key: bool,
    pub region: Region,
    /// Where to fetch the DERP map from, when a region has to be looked up.
    pub derp_map_url: Option<String>,
    /// Client node keys admitted, or `None` for all. Others are ignored
    /// silently. See [`Server::add_allowed_client`] to add more at runtime.
    pub allowed_clients: Option<Vec<NodePublic>>,
    /// Which of our own ports admit a connection.
    pub tcp_ports: Ports,
    /// Which of our own ports admit a datagram flow. `None` serves no UDP.
    pub udp_ports: Option<Ports>,
    /// Also accept TCP addressed to any other destination, exit-node style.
    /// Such connections report the dialed address through
    /// [`TcpConn::local_addr`].
    pub forward_tcp: bool,
    pub forward_udp: bool,
    /// Zero means [`DEFAULT_UDP_IDLE_TIMEOUT`].
    pub udp_idle_timeout: Duration,
    /// Speak plaintext HTTP to the relay, for a `derper --dev`. Never for a
    /// real relay.
    pub insecure_derp_http: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            key: None,
            preshared_key: None,
            disable_preshared_key: false,
            region: Region::Nearest,
            derp_map_url: None,
            allowed_clients: None,
            tcp_ports: Ports::All,
            udp_ports: None,
            forward_tcp: false,
            forward_udp: false,
            udp_idle_timeout: Duration::ZERO,
            insecure_derp_http: false,
        }
    }
}

/// A running tailcat server.
pub struct Server {
    transport: Transport,
    netstack: Arc<Netstack>,
    tcp: Mutex<mpsc::Receiver<TcpConn>>,
    udp: Mutex<mpsc::Receiver<UdpFlow>>,
    public: NodePublic,
    addr: Addr,
    region: DerpRegion,
}

async fn expand_region(region_id: i64, url: Option<String>) -> Result<DerpRegion> {
    let mut ci = ConnInfo {
        region_id,
        ..Default::default()
    };
    ci.expand(&ExpandOptions {
        derp_map_url: url,
        derp_map: None,
        for_server: true,
    })
    .await?;
    ci.region
        .into_iter()
        .next()
        .ok_or_else(|| Error::DerpMap("no region resolved".into()))
}

impl Server {
    /// Resolves the relay, connects to it, and starts accepting clients.
    pub async fn start(config: Config) -> Result<Server> {
        let key = config.key.unwrap_or_else(NodePrivate::generate);
        let preshared_key = if config.disable_preshared_key {
            None
        } else {
            Some(config.preshared_key.unwrap_or_else(PresharedKey::generate))
        };
        let region = match config.region {
            Region::Embedded(r) => r,
            Region::Id(id) => expand_region(id, config.derp_map_url).await?,
            Region::Nearest => expand_region(-1, config.derp_map_url).await?,
        };
        if region.region_id == 0 {
            return Err(Error::Config("missing RegionID in DERP region".into()));
        }

        let public = key.public();
        let self_addr = public.addr();
        let (netstack, outputs) = Netstack::start(Policy {
            self_addr,
            tcp_ports: config.tcp_ports,
            udp_ports: config.udp_ports,
            forward_tcp: config.forward_tcp,
            forward_udp: config.forward_udp,
            udp_idle_timeout: if config.udp_idle_timeout.is_zero() {
                DEFAULT_UDP_IDLE_TIMEOUT
            } else {
                config.udp_idle_timeout
            },
        });
        let transport = Transport::start(
            transport::Config {
                key: key.clone(),
                preshared_key,
                region: region.clone(),
                allowed_clients: config.allowed_clients.map(HashSet::from_iter),
                derp: derp::Options {
                    plaintext_http: config.insecure_derp_http,
                    app_name: DERP_APP_NAME.into(),
                },
            },
            netstack.clone(),
            outputs.egress,
        )?;

        let addr = ConnInfo {
            server_public: public,
            server_disco_public: Some(key.disco().public()),
            preshared_key,
            region: vec![region.clone()],
            region_id: 0,
        }
        .addr();
        tracing::info!(%self_addr, region = region.region_id, "tailcat server started");

        Ok(Server {
            transport,
            netstack,
            tcp: Mutex::new(outputs.tcp),
            udp: Mutex::new(outputs.udp),
            public,
            addr,
            region,
        })
    }

    /// The address clients connect with. It embeds the relay's details, so
    /// clients need no DERP map fetch, and it contains the pre-shared key,
    /// so it is a secret.
    pub fn tailcat_addr(&self) -> Addr {
        self.addr.clone()
    }

    /// The server's tunnel address, derived from its public key.
    pub fn addr(&self) -> Ipv6Addr {
        self.public.addr()
    }

    pub fn region(&self) -> &DerpRegion {
        &self.region
    }

    /// Admits `key`. Until any key is allowed, here or in
    /// [`Config::allowed_clients`], every client is.
    pub fn add_allowed_client(&self, key: NodePublic) {
        self.transport.add_allowed_client(key);
    }

    /// The next TCP connection a client opened, or `None` once the server
    /// is closed.
    pub async fn accept_tcp(&self) -> Option<TcpConn> {
        let mut conn = self.tcp.lock().await.recv().await?;
        conn.peer_key = self.transport.peer_for_addr(*conn.remote_addr().ip());
        Some(conn)
    }

    /// The next UDP flow a client started, or `None` once the server is
    /// closed.
    pub async fn accept_udp(&self) -> Option<UdpFlow> {
        let mut flow = self.udp.lock().await.recv().await?;
        flow.peer_key = self.transport.peer_for_addr(*flow.remote_addr().ip());
        Some(flow)
    }

    /// The registered clients and the path each currently uses.
    pub fn peers(&self) -> Vec<PeerStatus> {
        self.transport.peers()
    }

    pub fn peer(&self, key: &NodePublic) -> Option<PeerStatus> {
        self.transport.peers().into_iter().find(|p| p.key == *key)
    }

    /// Stops the server, aborting open connections and the relay session.
    pub fn close(&self) {
        self.netstack.close();
        self.transport.close();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close();
    }
}
