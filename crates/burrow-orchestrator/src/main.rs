mod admission;
mod api;
mod builds;
mod cluster;
mod collect;
mod events;
mod leader;
mod ledger;
mod registry;
mod sandboxes;
mod secrets;
mod snapshots;
mod volumes;

use std::sync::Arc;

use anyhow::Context as _;

use clap::Parser;
use tonic::{Request, Response, Status, transport::Server};

use burrow_proto::api::v1::burrow_server::BurrowServer;
use burrow_proto::node::v1 as nodepb;
use burrow_proto::node::v1::node_registry_server::{NodeRegistry, NodeRegistryServer};
use registry::HEARTBEAT_INTERVAL;

#[derive(Parser)]
#[command(name = "burrow-orchestrator", about = "Burrow control plane")]
struct Args {
    /// Address to serve the public + node gRPC APIs on.
    #[arg(
        long,
        default_value = "127.0.0.1:7070",
        env = "BURROW_ORCHESTRATOR_LISTEN"
    )]
    listen: std::net::SocketAddr,
    /// Bearer token clients must present. Prefer --api-key-file: a token on
    /// the command line is visible in `ps` to every user on the host.
    #[arg(long, env = "BURROW_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
    /// File of accepted tokens, one per line; `#` comments allowed. Multiple
    /// tokens let a key be rotated without downtime.
    #[arg(long, env = "BURROW_API_KEY_FILE")]
    api_key_file: Option<std::path::PathBuf>,
    /// File of operator tokens, one per line. Only these may create, change
    /// and remove public IP pools, and they are accepted as API keys too.
    /// Unset, every API key is an operator's.
    #[arg(long, env = "BURROW_OPERATOR_KEY_FILE")]
    operator_key_file: Option<std::path::PathBuf>,
    /// Public IPs one credential may hold at once. Operators are not limited.
    #[arg(long, default_value_t = 4, env = "BURROW_IP_QUOTA")]
    ip_quota: u32,
    /// Seconds a released public IP waits before it is allocated again, so it
    /// does not inherit its last holder's blocklist entries at once. A pool
    /// may set its own.
    #[arg(long, default_value_t = 86_400, env = "BURROW_IP_QUARANTINE_SECS")]
    ip_quarantine_secs: i64,
    /// The node-facing secret, shared with every node's --node-token.
    ///
    /// Used in both directions: nodes present it to register and heartbeat,
    /// and this orchestrator presents it when calling nodes. Distinct from
    /// --api-key because registration decides where exec and logs are routed,
    /// and because a client key should not drive a node directly. Unset falls
    /// back to the api key, which the startup warning calls out.
    #[arg(long, env = "BURROW_NODE_TOKEN", hide_env_values = true)]
    node_token: Option<String>,
    /// File of accepted node tokens, one per line; `#` comments allowed.
    #[arg(long, env = "BURROW_NODE_TOKEN_FILE")]
    node_token_file: Option<std::path::PathBuf>,
    /// OTLP collector to export traces to, e.g. `http://collector:4317`.
    /// Unset leaves tracing local to this process's logs.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,
    /// Where the orchestrator keeps its key material and, without
    /// --database-url, its SQLite store. Nodes stay authoritative, so the
    /// store only covers the case they cannot: the whole fleet restarting at
    /// once, losing the sandbox-to-node mapping.
    #[arg(long, default_value = "/var/lib/burrow")]
    data_dir: std::path::PathBuf,
    /// PostgreSQL to keep placements and secrets in, as a libpq
    /// URL. Unset keeps them in SQLite under --data-dir, which is fine for one
    /// host but ties the control plane to its disk. `sslmode` in the URL
    /// governs TLS; it is attempted by default.
    #[arg(long, env = "BURROW_DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,
    /// Key that seals stored secrets. Every replica must use the same one,
    /// so with several, mount it from one place. Defaults to `secrets.key`
    /// under --data-dir, created on first start.
    #[arg(long, env = "BURROW_SECRETS_KEY_FILE")]
    secrets_key_file: Option<std::path::PathBuf>,
    /// Ed25519 key, PKCS#8 PEM, that Access tokens are signed with. Every
    /// replica must use the same one, so with several, mount it from one
    /// place. Defaults to `access.key` under --data-dir, created on first
    /// start.
    #[arg(long, env = "BURROW_ACCESS_KEY_FILE")]
    access_key_file: Option<std::path::PathBuf>,
    /// A key nodes accept tokens from but this orchestrator never signs
    /// with, public PEM or private; repeatable. How the signing key is
    /// rotated without a token failing: trust the new key on every replica,
    /// switch --access-key-file to it with the old one trusted here instead,
    /// and drop the old one an hour later, once every token it signed has
    /// expired.
    #[arg(long = "access-trusted-key-file", value_name = "PATH")]
    access_trusted_key_files: Vec<std::path::PathBuf>,
    /// This replica's own address, which nodes deny to sandboxes alongside
    /// every other replica's. Defaults to what this host's name resolves to,
    /// which in a container or a pod is its own IP. In Kubernetes, set it
    /// from the pod IP with the downward API.
    #[arg(long, env = "BURROW_ORCHESTRATOR_ADVERTISE")]
    advertise: Option<String>,
    /// Seconds without a heartbeat after which a node is written off: its entry
    /// and every placement against it are dropped, releasing the names and
    /// capacity they held. 0 disables it. Far longer than the 15s health
    /// threshold, which only means "unreachable right now".
    #[arg(long, default_value_t = 86_400, env = "BURROW_NODE_EXPIRY_SECS")]
    node_expiry_secs: u64,
    /// Creates and lifecycle calls (start, stop, pause, resume, delete, fork,
    /// move, snapshot) this replica sends one node at once. More queue here
    /// instead of piling onto the node.
    #[arg(
        long,
        default_value_t = admission::DEFAULT_LIMIT,
        value_parser = clap::value_parser!(u32).range(1..),
        env = "BURROW_NODE_CONCURRENCY"
    )]
    node_concurrency: u32,
    /// A node label, KEY=VALUE, every create that activates Windows with the
    /// caller's own license is placed on, as `--node-label` would place it:
    /// for keeping bring-your-own-license guests on the hosts that license
    /// covers. Repeatable.
    #[arg(
        long = "byol-node-label",
        env = "BURROW_BYOL_NODE_LABEL",
        value_delimiter = ','
    )]
    byol_node_labels: Vec<String>,
    /// The fleet's sandbox address pool: one /30 per sandbox, sliced between
    /// nodes. Private: inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or
    /// 100.64.0.0/10, a /10 at most, and overlapping no node's own network.
    /// Nodes are given it at registration. Kept in the store, and changed only
    /// while no sandbox is placed anywhere: startup is refused otherwise.
    /// Every replica must be given the same one.
    #[arg(
        long,
        default_value = burrow_net::ipam::DEFAULT_POOL,
        env = "BURROW_SANDBOX_POOL"
    )]
    sandbox_pool: String,
    /// The IPv6 pool beside it: a ULA prefix with a /64 for every /30 of
    /// --sandbox-pool, so a /48 serves a /16 and a /44 a /10.
    #[arg(
        long,
        default_value = burrow_net::ipam::DEFAULT_POOL6,
        env = "BURROW_SANDBOX_POOL6"
    )]
    sandbox_pool6: String,
    /// /30 blocks in each node's slice of --sandbox-pool, a power of two: the
    /// most sandboxes one node holds (one fewer on the first node). The pool
    /// holds as many nodes as it has slices, less the top two blocks.
    #[arg(
        long,
        default_value_t = burrow_net::ipam::DEFAULT_BLOCKS_PER_NODE,
        env = "BURROW_SANDBOX_POOL_NODE_BLOCKS"
    )]
    sandbox_pool_node_blocks: u32,
}

pub struct OrchestratorState {
    pub nodes: registry::NodeRegistry,
    pub sandboxes: sandboxes::SandboxRegistry,
    /// Where every replica's state meets. `None` only when even the local
    /// SQLite file could not be opened, which leaves a single process
    /// running from memory.
    pub store: Option<Arc<burrow_store::Store>>,
    /// Whether this replica runs the fleet's background work.
    pub leader: Arc<leader::Leader>,
    /// Every live replica's address, as last read from the store, for nodes
    /// to deny to their sandboxes.
    pub control_plane_hosts: std::sync::Mutex<Vec<String>>,
    /// Every node's lifecycle events, pushed here as they happen.
    pub events: events::EventLog,
    /// Credentials Kits ask for by service name, encrypted at rest. `None`
    /// without a durable store, in which case no secret can be bound.
    pub secrets: Option<secrets::Secrets>,
    /// Signs Access tokens. `None` when the key could not be opened, and
    /// then IssueAccess is refused and exec and files go through here.
    pub access: Option<burrow_common::access::Signer>,
    /// Keys announced alongside the signing key, as `(kid, public key)`.
    pub access_trusted: Vec<(String, Vec<u8>)>,
    /// Which node holds which snapshot, so a create from one is placed where
    /// it is.
    pub snapshots: snapshots::SnapshotRegistry,
    /// Which node holds which volume. A volume is a disk image on one machine,
    /// so a sandbox mounting one has to be placed where it is.
    pub volumes: volumes::VolumeRegistry,
    /// Reused channels to nodes, so routing a call does not dial one.
    pub channels: api::NodeChannels,
    /// Presented when calling *out* to nodes. This is `--node-token`, which
    /// guards the node-facing hop in both directions, so the client api key
    /// never reaches a node. Falls back to `--api-key` only when no node token
    /// is set, which the startup warning calls out.
    pub node_token: Option<String>,
    /// How long a node may go unheard before it must stop resuming durable
    /// sandboxes on its own say. 0 when nodes are never written off.
    pub sandbox_lease_secs: u32,
    /// Who may manage address pools, and the limits on everyone else.
    pub ips: api::ips::IpConfig,
    /// Bounds the creates and lifecycle calls in flight to each node.
    pub admission: admission::Admission,
    /// Labels a create activating Windows with the caller's license needs.
    pub byol_node_labels: std::collections::HashMap<String, String>,
    /// The builds tags resolve to, as last read from the store.
    pub tagged: builds::Tagged,
}

/// Makes `pool` the fleet's sandbox address pool, refusing when the store
/// records another and a sandbox is placed on it: every one of them has an
/// address from the pool it records.
async fn adopt_address_pool(
    store: &burrow_store::Store,
    pool: burrow_net::ipam::AddressPool,
) -> anyhow::Result<()> {
    let (v4, v6, blocks) = store
        .address_pool()
        .await
        .context("reading the sandbox address pool")?;
    let recorded = burrow_net::ipam::AddressPool::new(&v4, &v6, blocks)
        .map_err(|err| anyhow::anyhow!("the recorded sandbox address pool: {err}"))?;
    if recorded == pool {
        return Ok(());
    }
    let changed = store
        .change_address_pool(&pool.cidr(), &pool.cidr6(), pool.blocks_per_node())
        .await
        .context("changing the sandbox address pool")?;
    if !changed {
        anyhow::bail!(
            "the fleet's sandbox address pool is {v4} {v6} with {blocks} blocks per node, and \
             sandboxes are placed on it; {} {} with {} blocks per node can take its place only \
             once every sandbox is deleted. Start with the recorded pool, or delete every \
             sandbox first",
            pool.cidr(),
            pool.cidr6(),
            pool.blocks_per_node()
        );
    }
    tracing::warn!(
        from = %recorded,
        to = %pool,
        "changed the fleet's sandbox address pool; every node registers again and is given it"
    );
    Ok(())
}

#[derive(Clone)]
struct NodeRegistryService(Arc<OrchestratorState>);

#[tonic::async_trait]
impl NodeRegistry for NodeRegistryService {
    async fn register(
        &self,
        req: Request<nodepb::RegisterRequest>,
    ) -> Result<Response<nodepb::RegisterResponse>, Status> {
        let req = req.into_inner();
        let info = req
            .info
            .ok_or_else(|| Status::invalid_argument("missing node info"))?;
        if info.address.is_empty() {
            return Err(Status::invalid_argument("node address is required"));
        }
        // Labels are rendered into operator output and into placement errors,
        // so they are bounded at the door like any other caller-supplied map.
        burrow_common::tags::validate_labels(&info.labels)?;
        // A node that cannot be given a guest-address slice of its own is
        // refused: admitting it on someone else's slice would give two nodes
        // the same guest addresses, which is what the slicing exists to
        // prevent.
        // The store's pool, not this replica's flags: during a rolling change
        // another replica may already have moved it.
        let pool = match &self.0.store {
            Some(store) => cluster::reload_pool(&self.0, store)
                .await
                .map_err(|err| Status::unavailable(format!("reading the address pool: {err}")))?,
            None => self.0.nodes.pool(),
        };
        let (node_id, node_index) = match &self.0.store {
            // The slice is chosen by the store, so two replicas registering
            // two nodes at once cannot hand out the same one.
            Some(store) => {
                let max_nodes = pool.max_nodes();
                if let Some(claimed) = req.claimed_node_index
                    && claimed >= max_nodes
                {
                    return Err(Status::invalid_argument(
                        crate::registry::RegisterError::ClaimOutOfRange {
                            index: claimed,
                            max: max_nodes,
                        }
                        .to_string(),
                    ));
                }
                let mut info = info;
                if info.id.is_empty() {
                    info.id = burrow_common::NodeId::generate().to_string();
                }
                let row = cluster::node_row(
                    &info,
                    &burrow_proto::common::v1::NodeStatus::default(),
                    &req.wireguard_public_key,
                    &req.wireguard_endpoint,
                );
                let index = store
                    .register_node(&row, req.claimed_node_index, max_nodes)
                    .await
                    .map_err(|err| Status::unavailable(format!("recording the node: {err}")))?
                    .ok_or_else(|| {
                        Status::resource_exhausted(
                            crate::registry::RegisterError::NoAddressSlice(max_nodes).to_string(),
                        )
                    })?;
                if let Some(claimed) = req.claimed_node_index
                    && claimed != index
                {
                    tracing::error!(
                        node_id = info.id,
                        claimed,
                        assigned = index,
                        "node claimed an address slice another node holds; its existing \
                         sandboxes may have colliding addresses"
                    );
                }
                let node_id = info.id.clone();
                self.0.nodes.register_at(
                    info,
                    req.wireguard_public_key,
                    req.wireguard_endpoint,
                    index,
                );
                (node_id, index)
            }
            None => self
                .0
                .nodes
                .register(
                    info,
                    req.wireguard_public_key,
                    req.wireguard_endpoint,
                    req.claimed_node_index,
                )
                .map_err(|err| match err {
                    crate::registry::RegisterError::NoAddressSlice(_) => {
                        Status::resource_exhausted(err.to_string())
                    }
                    crate::registry::RegisterError::ClaimOutOfRange { .. } => {
                        Status::invalid_argument(err.to_string())
                    }
                })?,
        };
        tracing::info!(node_id, node_index, "node registered");
        let report_seq = self
            .0
            .sandboxes
            .store()
            .node_report_seq(&node_id)
            .await
            .map_err(|err| Status::unavailable(format!("reading the node: {err}")))?;

        // Off the registration path: the node is mid-call to us and is not
        // yet serving this request's caller.
        let state = Arc::clone(&self.0);
        let id = node_id.clone();
        tokio::spawn(async move { refresh_inventory(&state, &id).await });
        Ok(Response::new(nodepb::RegisterResponse {
            node_id,
            heartbeat_interval_secs: HEARTBEAT_INTERVAL.as_secs() as u32,
            node_index,
            report_seq: report_seq as u64,
            access_keys: access_keys(&self.0),
            address_pool: Some(nodepb::AddressPool {
                v4: pool.cidr(),
                v6: pool.cidr6(),
                blocks_per_node: pool.blocks_per_node(),
            }),
        }))
    }

    async fn heartbeat(
        &self,
        req: Request<nodepb::HeartbeatRequest>,
    ) -> Result<Response<nodepb::HeartbeatResponse>, Status> {
        let req = req.into_inner();
        // A node describes itself on every beat, and what it says about itself
        // is checked exactly as it is at registration: an unbounded label map
        // would otherwise reach the registry and every `nodes ls` after it.
        if let Some(info) = &req.info {
            burrow_common::tags::validate_labels(&info.labels)?;
        }
        let mut status = req.status.unwrap_or_default();
        let volumes = std::mem::take(&mut status.volumes);
        self.0.nodes.touch(&req.node_id);
        let mut info = req.info.clone().unwrap_or_default();
        info.id = req.node_id.clone();
        let row = cluster::node_row(&info, &status, "", "");
        let row = burrow_store::NodeRow {
            is_reported: true,
            info: match &req.info {
                Some(_) => row.info.clone(),
                None => Vec::new(),
            },
            ..row
        };
        // A Kit's volumes are made and removed with their sandbox on its node,
        // so the store names none of them.
        let named_volumes = volumes
            .iter()
            .filter(|volume| {
                !volume
                    .labels
                    .contains_key(burrow_common::kit::VOLUME_OWNER_LABEL)
            })
            .map(|volume| volume.name.clone())
            .collect();
        let started = std::time::Instant::now();
        let reconciled = self
            .0
            .sandboxes
            .reconcile(
                row,
                &info,
                req.report_seq,
                &req.sandboxes,
                sandboxes::Holdings {
                    snapshots: req.snapshots.clone(),
                    swept_snapshots: req.swept_snapshots.clone(),
                    volumes: named_volumes,
                },
            )
            .await?;
        tracing::debug!(
            node_id = req.node_id,
            sandboxes = req.sandboxes.len(),
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            "reconciled a heartbeat"
        );
        // The store decides whether the fleet knows this node: it may have
        // registered through another replica, whose cache this one only
        // catches up with once a second.
        if !reconciled.is_known {
            self.0.nodes.remove_node(&req.node_id);
        } else if !self.0.nodes.knows(&req.node_id)
            && let Some(store) = &self.0.store
        {
            let _ = cluster::reload_nodes(&self.0, store).await;
        }
        let known = match reconciled.is_applied {
            true => {
                builds::note_builds(&self.0, &req.node_id, &status).await;
                self.0.nodes.heartbeat(&req.node_id, status, req.info)
            }
            false => self.0.nodes.knows(&req.node_id),
        };
        if !known {
            tracing::warn!(
                node_id = req.node_id,
                "heartbeat from unknown node; asking to re-register"
            );
        } else if !reconciled.is_applied {
            tracing::info!(
                node_id = req.node_id,
                seq = req.report_seq,
                "ignored a heartbeat no newer than one already applied"
            );
        } else {
            if let Some(store) = &self.0.store
                && self.0.nodes.usage_due(&req.node_id)
            {
                let totals: Vec<_> = req
                    .sandboxes
                    .iter()
                    .map(|s| {
                        (
                            s.sandbox_id.clone(),
                            s.cpu_usage_usec,
                            s.rx_bytes,
                            s.tx_bytes,
                        )
                    })
                    .collect();
                if let Err(err) = store
                    .observe_usage(&req.node_id, burrow_common::unix_now_ms(), &totals)
                    .await
                {
                    tracing::warn!(node_id = req.node_id, %err, "could not record usage from a heartbeat");
                }
            }
            let unnamed_snapshots: std::collections::HashSet<&str> = reconciled
                .destroy_snapshots
                .iter()
                .map(String::as_str)
                .collect();
            let held: Vec<String> = req
                .snapshots
                .iter()
                .filter(|id| !unnamed_snapshots.contains(id.as_str()))
                .cloned()
                .collect();
            let forgotten =
                self.0
                    .snapshots
                    .apply_report(&req.node_id, &held, &req.durable_snapshots);
            if !forgotten.is_empty() {
                tracing::info!(
                    node_id = req.node_id,
                    dropped = forgotten.len(),
                    "forgot snapshots the node no longer holds"
                );
            }
            let volumes = volumes
                .into_iter()
                .filter(|volume| !reconciled.destroy_volumes.contains(&volume.name))
                .collect();
            self.0.volumes.reconcile_node(&req.node_id, volumes);
            if !reconciled.destroy_snapshots.is_empty() || !reconciled.destroy_volumes.is_empty() {
                tracing::warn!(
                    node_id = req.node_id,
                    snapshots = reconciled.destroy_snapshots.len(),
                    volumes = reconciled.destroy_volumes.len(),
                    "node holds snapshots or volumes no row names; telling it to destroy them"
                );
            }
            if reconciled.restated > 0 || !reconciled.lost.is_empty() {
                tracing::info!(
                    node_id = req.node_id,
                    restated = reconciled.restated,
                    lost = reconciled.lost.len(),
                    first_lost = reconciled.lost.first(),
                    "took node-initiated sandbox changes"
                );
            }
            if !reconciled.replaced.is_empty() {
                tracing::info!(
                    node_id = req.node_id,
                    count = reconciled.replaced.len(),
                    first = reconciled.replaced.first(),
                    "node still holds sandboxes nothing placed since it was written off; \
                     placing them back there"
                );
            }
            if !reconciled.destroy.is_empty() {
                tracing::warn!(
                    node_id = req.node_id,
                    count = reconciled.destroy.len(),
                    first = reconciled.destroy.first().map(|d| d.sandbox_id.as_str()),
                    "node holds sandboxes the store does not list for it; telling it to destroy them"
                );
            }
            if !reconciled.unanswered.is_empty() {
                tokio::spawn(settle_unanswered(
                    Arc::clone(&self.0),
                    req.node_id.clone(),
                    reconciled.unanswered,
                ));
            }
        }
        // The peer list and cross-node membership ride on the heartbeat, so a
        // node converges on the current fleet without a separate subscription.
        Ok(Response::new(nodepb::HeartbeatResponse {
            warm_builds: builds::tagged(&self.0).await,
            is_reregistration_required: !known,
            peers: self.0.nodes.mesh_peers(&req.node_id),
            network_members: self.0.sandboxes.network_members(&req.node_id),
            // Including the beating node's own: every edge in the fleet is
            // denied to every sandbox, and a node cannot know from its own
            // flags which of its peers serves one.
            edge_hosts: self.0.nodes.edge_hosts(),
            node_hosts: self.0.nodes.node_hosts(),
            control_plane_hosts: self.0.control_plane_hosts.lock().unwrap().clone(),
            sandbox_lease_secs: self.0.sandbox_lease_secs,
            is_report_applied: reconciled.is_applied,
            destroyed_sandboxes: reconciled.destroy,
            destroyed_snapshots: reconciled.destroy_snapshots,
            destroyed_volumes: reconciled.destroy_volumes,
            access_keys: access_keys(&self.0),
        }))
    }

    async fn push_events(
        &self,
        req: Request<nodepb::PushEventsRequest>,
    ) -> Result<Response<nodepb::PushEventsResponse>, Status> {
        let req = req.into_inner();
        if req.node_id.is_empty() {
            return Err(Status::invalid_argument("node_id is required"));
        }
        let committed_seq = self
            .0
            .events
            .push(&req.node_id, req.events)
            .await
            .map_err(|err| Status::unavailable(format!("recording events: {err}")))?;
        Ok(Response::new(nodepb::PushEventsResponse { committed_seq }))
    }
}

fn access_keys(state: &OrchestratorState) -> Vec<nodepb::AccessKey> {
    let signing = state
        .access
        .iter()
        .map(|signer| (signer.kid().to_string(), signer.public_key().to_vec()));
    let mut keys: Vec<nodepb::AccessKey> = signing
        .chain(state.access_trusted.iter().cloned())
        .map(|(kid, public_key)| nodepb::AccessKey { kid, public_key })
        .collect();
    keys.sort_by(|a, b| a.kid.cmp(&b.kid));
    keys.dedup_by(|a, b| a.kid == b.kid);
    keys
}

/// Records what a node built for creates and adopts whose answer never
/// reached the store: the replica that asked died, or lost the node's reply.
/// The node reports the sandbox at the generation the row has, so the record
/// it holds is the one the row should.
async fn settle_unanswered(state: Arc<OrchestratorState>, node_id: String, ids: Vec<String>) {
    let Some(endpoint) = state.nodes.endpoint(&node_id) else {
        return;
    };
    let mut client = match crate::api::connect_node(endpoint, state.node_token.as_deref()).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(node_id, %err, "cannot reach node to record what it built");
            return;
        }
    };
    for id in ids {
        let Ok(Some(row)) = state.sandboxes.store().get_placement(&id).await else {
            continue;
        };
        if row.node_id != node_id {
            continue;
        }
        let record = match client
            .get_sandbox(nodepb::NodeSandboxRef {
                sandbox_id: id.clone(),
            })
            .await
        {
            Ok(record) => record.into_inner(),
            Err(err) => {
                tracing::warn!(node_id, sandbox = id, %err, "could not read what the node built");
                continue;
            }
        };
        let record = burrow_proto::common::v1::Sandbox {
            node_id: node_id.clone(),
            ..record
        };
        match state.sandboxes.settle(record, row.generation).await {
            Ok(true) => tracing::info!(
                node_id,
                sandbox = id,
                "recorded a sandbox whose create or adopt went unanswered"
            ),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(node_id, sandbox = id, %err, "could not record what the node built")
            }
        }
    }
}

/// Re-reads a node's snapshots and volumes, for a replica that does not get
/// that node's heartbeats.
pub async fn refresh_inventory(state: &OrchestratorState, node_id: &str) {
    let Some(endpoint) = state.nodes.endpoint(node_id) else {
        return;
    };
    match crate::api::connect_node(endpoint, state.node_token.as_deref()).await {
        Ok(mut client) => inventory(state, node_id, &mut client).await,
        Err(err) => tracing::debug!(node_id, %err, "cannot reach node to refresh its inventory"),
    }
}

/// The snapshots among `listed` the store has rows for.
pub async fn named_snapshots(
    state: &OrchestratorState,
    mut listed: Vec<burrow_proto::common::v1::Snapshot>,
) -> burrow_store::Result<Vec<burrow_proto::common::v1::Snapshot>> {
    let named = state.sandboxes.store().snapshot_ids().await?;
    listed.retain(|snapshot| named.contains(&snapshot.id));
    Ok(listed)
}

/// The volumes among `listed` the store has rows for, and every Kit volume,
/// which belongs to its sandbox.
pub async fn named_volumes(
    state: &OrchestratorState,
    mut listed: Vec<burrow_proto::common::v1::Volume>,
) -> burrow_store::Result<Vec<burrow_proto::common::v1::Volume>> {
    let named = state.sandboxes.store().volume_names().await?;
    listed.retain(|volume| {
        named.contains(&volume.name)
            || volume
                .labels
                .contains_key(burrow_common::kit::VOLUME_OWNER_LABEL)
    });
    Ok(listed)
}

async fn inventory(state: &OrchestratorState, node_id: &str, client: &mut crate::api::NodeClient) {
    let node_id = node_id.to_string();
    // Where each snapshot lives is learned from the nodes, which of them
    // exist from the store.
    match client
        .list_snapshots(nodepb::NodeListSnapshotsRequest {
            sandbox_id: String::new(),
        })
        .await
    {
        Ok(resp) => match named_snapshots(state, resp.into_inner().snapshots).await {
            Ok(listed) => {
                let held = state.snapshots.reconcile_node(&node_id, listed);
                builds::note_inventory(state, &node_id);
                tracing::debug!(node_id, held, "refreshed node snapshots");
            }
            Err(err) => tracing::warn!(node_id, %err, "could not read snapshot rows"),
        },
        Err(err) => tracing::warn!(node_id, %err, "node snapshot inventory unavailable"),
    }
    // What the object store holds, as this node sees it. Any node with the
    // store configured answers the same, and one without refuses.
    match client
        .list_durable_snapshots(nodepb::NodeListSnapshotsRequest {
            sandbox_id: String::new(),
        })
        .await
    {
        Ok(resp) => match named_snapshots(state, resp.into_inner().snapshots).await {
            Ok(listed) => {
                let (adopted, forgotten) = state.snapshots.reconcile_remote(listed);
                if adopted > 0 || !forgotten.is_empty() {
                    tracing::info!(
                        node_id,
                        adopted,
                        forgotten = forgotten.len(),
                        "reconciled snapshots with the object store"
                    );
                }
            }
            Err(err) => tracing::warn!(node_id, %err, "could not read snapshot rows"),
        },
        Err(err) if err.code() == tonic::Code::FailedPrecondition => {}
        Err(err) => tracing::warn!(node_id, %err, "object store snapshot inventory unavailable"),
    }

    match client
        .list_volumes(burrow_proto::api::v1::ListVolumesRequest {
            node_id: String::new(),
        })
        .await
    {
        Ok(resp) => match named_volumes(state, resp.into_inner().volumes).await {
            Ok(listed) => {
                let held = state.volumes.reconcile_node(&node_id, listed);
                tracing::debug!(node_id, held, "refreshed node volumes");
            }
            Err(err) => tracing::warn!(node_id, %err, "could not read volume rows"),
        },
        Err(err) => tracing::warn!(node_id, %err, "node volume inventory unavailable"),
    }
    match client
        .list_durable_volumes(burrow_proto::api::v1::ListVolumesRequest {
            node_id: String::new(),
        })
        .await
    {
        Ok(resp) => match named_volumes(state, resp.into_inner().volumes).await {
            Ok(listed) => {
                let (adopted, forgotten) = state
                    .volumes
                    .reconcile_remote(listed, |node| state.nodes.knows(node));
                if adopted > 0 || forgotten > 0 {
                    tracing::info!(
                        node_id,
                        adopted,
                        forgotten,
                        "reconciled volumes with the object store"
                    );
                }
            }
            Err(err) => tracing::warn!(node_id, %err, "could not read volume rows"),
        },
        Err(err) if err.code() == tonic::Code::FailedPrecondition => {}
        Err(err) => tracing::warn!(node_id, %err, "object store volume inventory unavailable"),
    }
}

/// Publishes this replica's address and reads every live replica's back, so
/// heartbeat responses carry the whole control plane for nodes to deny.
async fn advertise_replica(state: Arc<OrchestratorState>, address: Option<String>) {
    let id = burrow_common::NodeId::generate().to_string();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        ticker.tick().await;
        let now = burrow_common::unix_now_ms();
        let mut hosts = match &state.store {
            Some(store) => {
                if let Some(address) = &address
                    && let Err(err) = store.touch_replica(&id, address, now).await
                {
                    tracing::warn!(%err, "could not advertise this replica");
                }
                store
                    .replica_addresses(now - REPLICA_SEEN_MS)
                    .await
                    .unwrap_or_default()
            }
            None => Vec::new(),
        };
        if let Some(address) = &address
            && !hosts.contains(address)
        {
            hosts.push(address.clone());
        }
        *state.control_plane_hosts.lock().unwrap() = hosts;
    }
}

/// How recently a replica must have advertised itself to be denied. A dead
/// replica's address is still denied for this long, which costs nothing.
const REPLICA_SEEN_MS: i64 = 60_000;

/// What this host's name resolves to, skipping loopback.
async fn own_address() -> Option<String> {
    let name = std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|name| name.trim().to_string())
        })?;
    tokio::net::lookup_host((name.as_str(), 0))
        .await
        .ok()?
        .map(|address| address.ip())
        .find(|ip| !ip.is_loopback())
        .map(|ip| ip.to_string())
}

/// How often the reaper looks, capped so a short expiry is still enforced
/// promptly and a long one does not mean a busy loop.
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a claim may sit without a sandbox before it is read as an
/// abandoned create. Far longer than any create takes.
const CLAIM_ORPHAN_SECS: i64 = 600;

/// Writes off nodes that have been silent far longer than unhealthy.
///
/// A node silent for `expiry` is presumed gone: its placements are dropped so
/// the names and capacity they held come back, and its entry with them. If it
/// ever comes back, it destroys whatever it still holds, since the store lists
/// nothing for it. A suspended sandbox whose state is in the object store is
/// kept, unplaced, for the next start to put on another node. Its open usage
/// intervals are closed at its last heartbeat, so none of the silence is
/// attributed to its sandboxes.
async fn reap_dead_nodes(state: Arc<OrchestratorState>, expiry: Option<std::time::Duration>) {
    let period = expiry.map_or(REAP_INTERVAL, |expiry| REAP_INTERVAL.min(expiry));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // Once for the fleet, not once per replica.
        if !state.leader.is_leader() {
            continue;
        }
        if let Some(expiry) = expiry {
            for node_id in state.nodes.expired(expiry) {
                write_off_node(&state, &node_id, expiry).await;
            }
        }
        // A replica that died half way through a create leaves its claims on
        // an id and a name with no sandbox behind them.
        if let Some(store) = &state.store {
            match store
                .sweep_claims(burrow_common::unix_now() - CLAIM_ORPHAN_SECS)
                .await
            {
                Ok(0) => {}
                Ok(swept) => {
                    tracing::info!(swept, "released claims of creates that never finished")
                }
                Err(err) => tracing::warn!(%err, "could not sweep abandoned claims"),
            }
            let before = burrow_common::unix_now_ms() - PLACEMENT_DELETES_KEPT_MS;
            if let Err(err) = store.prune_placement_deletes(before).await {
                tracing::warn!(%err, "could not prune the placement delete log");
            }
        }
    }
}

/// How long deleted placement ids are kept for replicas catching up, far
/// past the furthest back one reads.
const PLACEMENT_DELETES_KEPT_MS: i64 = 600_000;

/// Writes off one node, if this replica still leads and the node is still
/// silent in the store, which another replica's heartbeat may have updated
/// since this one read it. Returns whether it did.
async fn write_off_node(
    state: &OrchestratorState,
    node_id: &str,
    expiry: std::time::Duration,
) -> bool {
    let Some(epoch) = state.leader.epoch() else {
        return false;
    };
    let info = state.nodes.info(node_id).unwrap_or_default();
    let before = burrow_common::unix_now_ms() - expiry.as_millis() as i64;
    let written_off = match state
        .sandboxes
        .write_off(node_id, &info, before, epoch)
        .await
    {
        Ok(Some(written_off)) => written_off,
        Ok(None) => return false,
        Err(err) => {
            tracing::warn!(node_id, %err, "could not write off a node in the store");
            return false;
        }
    };
    ledger::write_off_node(state, node_id).await;
    let sandboxes::WrittenOff { dropped, unplaced } = written_off;
    // Its snapshots go with it: they only ever existed on that node.
    // Its durable volumes stay, to be taken from it.
    state.snapshots.forget_node(node_id);
    let volumes = state.volumes.forget_node(node_id);
    state.nodes.remove_node(node_id);
    for sandbox in unplaced.iter().filter(|s| !s.public_ips.is_empty()) {
        tracing::warn!(
            node_id,
            sandbox = sandbox.id,
            "sandbox holds public addresses that reach only this node; it stays \
             unplaced until the node returns or its addresses are detached"
        );
    }
    tracing::warn!(
        node_id,
        placements = dropped.len(),
        names = dropped.iter().filter(|s| !s.name.is_empty()).count(),
        unplaced = unplaced.len(),
        volumes,
        "node has been silent past its expiry; forgetting it and every \
         placement recorded against it, except those the object store can bring back"
    );
    true
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    burrow_common::banner::print(env!("CARGO_PKG_VERSION"));
    let telemetry =
        burrow_common::telemetry::init("burrow-orchestrator", args.otlp_endpoint.as_deref());
    let result = run(args).await;
    telemetry.shutdown();
    result
}

async fn run(args: Args) -> anyhow::Result<()> {
    let operator_tokens = burrow_common::auth::load_tokens(None, args.operator_key_file.as_deref());
    let mut tokens =
        burrow_common::auth::load_tokens(args.api_key.as_deref(), args.api_key_file.as_deref());
    tokens.extend(operator_tokens.iter().cloned());
    let auth = burrow_common::auth::TokenAuth::new(tokens.clone());
    if !auth.is_enabled() {
        tracing::warn!(
            "no --api-key configured: the API is UNAUTHENTICATED and anyone \
             who can reach it can create and exec into sandboxes"
        );
    }

    // The node-facing hop is a separate privilege from using the API, and it is
    // symmetric: `--node-token` both guards inbound registration *and* is what
    // this orchestrator presents when it dials a node. Sharing one secret with
    // clients lets any API client register a node over a real one and have
    // other tenants' exec and log streams routed to it, and hands every client
    // a key that drives nodes directly.
    let node_tokens = burrow_common::auth::load_tokens(
        args.node_token.as_deref(),
        args.node_token_file.as_deref(),
    );
    let (node_auth, outbound_node_token) = if node_tokens.is_empty() {
        if auth.is_enabled() {
            tracing::warn!(
                "no --node-token configured: node registration accepts the client \
                 api key and that key is what this orchestrator presents to nodes, \
                 so any API client can register a node over a real one, have other \
                 tenants' sandboxes routed to it, and call nodes directly. Set \
                 --node-token (or BURROW_NODE_TOKEN) and give nodes the same value."
            );
        }
        (auth.clone(), tokens.first().cloned())
    } else {
        (
            burrow_common::auth::TokenAuth::new(node_tokens.clone()),
            node_tokens.first().cloned(),
        )
    };

    let mut secrets = None;
    let store: Option<Arc<burrow_store::Store>> = match &args.database_url {
        // A database that was asked for and cannot be reached is a
        // misconfiguration, not something to paper over with an empty
        // in-memory registry that would then diverge from it.
        Some(url) => Some(Arc::new(
            burrow_store::Store::connect_postgres(url)
                .await
                .context("connecting to --database-url")?,
        )),
        None => Some(Arc::new(
            burrow_store::Store::open(&args.data_dir.join("orchestrator.db"))
                .await
                .with_context(|| {
                    format!(
                        "opening {}",
                        args.data_dir.join("orchestrator.db").display()
                    )
                })?,
        )),
    };
    let pool = burrow_net::ipam::AddressPool::new(
        &args.sandbox_pool,
        &args.sandbox_pool6,
        args.sandbox_pool_node_blocks,
    )
    .map_err(|err| anyhow::anyhow!("--sandbox-pool: {err}"))?;
    if let Some(store) = &store {
        adopt_address_pool(store, pool).await?;
    }
    let sandboxes = match &store {
        Some(store) => {
            let key = args
                .secrets_key_file
                .clone()
                .unwrap_or_else(|| args.data_dir.join("secrets.key"));
            match secrets::Secrets::open(Arc::clone(store), &key) {
                Ok(opened) => secrets = Some(opened),
                Err(err) => tracing::error!(%err, "secrets are unavailable: no usable key"),
            }
            sandboxes::SandboxRegistry::open(Arc::clone(store))
                .await
                .context("reading placements")?
        }
        None => anyhow::bail!("the orchestrator has no store"),
    };

    let access_key = args
        .access_key_file
        .clone()
        .unwrap_or_else(|| args.data_dir.join("access.key"));
    let access_trusted = args
        .access_trusted_key_files
        .iter()
        .map(|path| burrow_common::access::trusted_key(path))
        .collect::<Result<Vec<_>, _>>()
        .context("--access-trusted-key-file")?;
    let access = match burrow_common::access::Signer::open(&access_key) {
        Ok(signer) => Some(signer),
        Err(err) => {
            tracing::error!(%err, "access tokens are unavailable: no usable key");
            None
        }
    };

    let sandbox_lease_secs = match args.node_expiry_secs {
        0 => 0,
        // Short of the expiry by a few beats, so a node has stopped resuming
        // its durable sandboxes before any other node can be handed them.
        secs => secs
            .saturating_sub(3 * HEARTBEAT_INTERVAL.as_secs())
            .max(1)
            .min(u32::MAX as u64) as u32,
    };
    let state = Arc::new(OrchestratorState {
        nodes: registry::NodeRegistry::new(pool),
        sandboxes,
        leader: leader::Leader::spawn(store.clone()),
        events: events::EventLog::new(store.clone()),
        store: store.clone(),
        control_plane_hosts: std::sync::Mutex::new(Vec::new()),
        secrets,
        access,
        access_trusted,
        snapshots: snapshots::SnapshotRegistry::default(),
        volumes: volumes::VolumeRegistry::default(),
        channels: api::NodeChannels::default(),
        node_token: outbound_node_token,
        sandbox_lease_secs,
        ips: api::ips::IpConfig {
            operator_tokens,
            quota: args.ip_quota,
            quarantine_secs: args.ip_quarantine_secs.max(0),
        },
        admission: admission::Admission::new(args.node_concurrency),
        tagged: Default::default(),
        byol_node_labels: args
            .byol_node_labels
            .iter()
            .map(|pair| {
                pair.split_once('=')
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .ok_or_else(|| anyhow::anyhow!("--byol-node-label {pair:?} is not KEY=VALUE"))
            })
            .collect::<anyhow::Result<_>>()?,
    });

    tracing::info!(
        listen = %args.listen,
        authenticated = auth.is_enabled(),
        separate_node_token = args.node_token.is_some() || args.node_token_file.is_some(),
        node_expiry_secs = args.node_expiry_secs,
        "burrow-orchestrator starting"
    );

    let expiry = match args.node_expiry_secs {
        0 => {
            tracing::warn!(
                "--node-expiry-secs is 0: a node that never comes back keeps its \
                 placements, and the names and capacity they hold, indefinitely"
            );
            None
        }
        secs => Some(std::time::Duration::from_secs(secs)),
    };
    tokio::spawn(reap_dead_nodes(Arc::clone(&state), expiry));
    tokio::spawn(builds::retain_forever(Arc::clone(&state)));
    tokio::spawn(collect::run(Arc::clone(&state)));
    let advertise = match args.advertise.clone() {
        Some(address) => Some(address),
        None => own_address().await,
    };
    match &advertise {
        Some(address) => tracing::info!(
            address,
            "advertising this replica to nodes as a host to deny"
        ),
        None => tracing::warn!(
            "cannot tell this replica's own address; set --advertise, or sandboxes \
             may be able to reach it directly"
        ),
    }
    tokio::spawn(advertise_replica(Arc::clone(&state), advertise));
    tokio::spawn(ledger::run(Arc::clone(&state)));
    // Several replicas share a Postgres; each catches up with the others'
    // writes. One replica on SQLite has nobody to catch up with.
    if let Some(store) = &store
        && store.is_postgres()
    {
        if let Err(err) = cluster::reload_nodes(&state, store).await {
            tracing::warn!(%err, "could not read the fleet from the store");
        }
        cluster::spawn(Arc::clone(&state), Arc::clone(store));
    }

    Server::builder()
        .add_service(tonic::service::interceptor::InterceptedService::new(
            BurrowServer::new(api::ApiService(state.clone()))
                .max_decoding_message_size(burrow_proto::MAX_MESSAGE_BYTES)
                .max_encoding_message_size(burrow_proto::MAX_MESSAGE_BYTES),
            auth.clone(),
        ))
        .add_service(tonic::service::interceptor::InterceptedService::new(
            NodeRegistryServer::new(NodeRegistryService(state))
                .max_decoding_message_size(burrow_proto::MAX_MESSAGE_BYTES),
            node_auth,
        ))
        .serve(args.listen)
        .await?;
    Ok(())
}
