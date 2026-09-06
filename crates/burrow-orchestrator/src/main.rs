mod api;
mod registry;
mod sandboxes;
mod snapshots;
mod volumes;

use std::sync::Arc;

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
    #[arg(long, env = "BURROW_API_KEY")]
    api_key: Option<String>,
    /// File of accepted tokens, one per line; `#` comments allowed. Multiple
    /// tokens let a key be rotated without downtime.
    #[arg(long, env = "BURROW_API_KEY_FILE")]
    api_key_file: Option<std::path::PathBuf>,
    /// Bearer token nodes must present to register and heartbeat. Distinct
    /// from --api-key: registration decides where exec and logs are routed.
    /// Unset falls back to the api key, which the startup warning calls out.
    #[arg(long, env = "BURROW_NODE_TOKEN")]
    node_token: Option<String>,
    /// File of accepted node tokens, one per line; `#` comments allowed.
    #[arg(long, env = "BURROW_NODE_TOKEN_FILE")]
    node_token_file: Option<std::path::PathBuf>,
    /// OTLP collector to export traces to, e.g. `http://collector:4317`.
    /// Unset leaves tracing local to this process's logs.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,
    /// Where the orchestrator keeps its durable state. Nodes stay
    /// authoritative, so this only covers the case they cannot: the whole
    /// fleet restarting at once, losing the sandbox-to-node mapping.
    #[arg(long, default_value = "/var/lib/burrow")]
    data_dir: std::path::PathBuf,
    /// Seconds without a heartbeat after which a node is written off: its entry
    /// and every placement against it are dropped, releasing the names and
    /// capacity they held. 0 disables it. Far longer than the 15s health
    /// threshold, which only means "unreachable right now".
    #[arg(long, default_value_t = 86_400, env = "BURROW_NODE_EXPIRY_SECS")]
    node_expiry_secs: u64,
}

pub struct OrchestratorState {
    pub nodes: registry::NodeRegistry,
    pub sandboxes: sandboxes::SandboxRegistry,
    /// Which node holds which snapshot. Snapshots do not travel, so a create
    /// from one has to be placed where it is.
    pub snapshots: snapshots::SnapshotRegistry,
    /// Which node holds which volume. A volume is a disk image on one machine,
    /// so a sandbox mounting one has to be placed where it is.
    pub volumes: volumes::VolumeRegistry,
    /// Reused channels to nodes, so routing a call does not dial one.
    pub channels: api::NodeChannels,
    /// Presented when calling *out* to nodes, which are guarded by their own
    /// `--api-key`. Not the token nodes present when registering: that is
    /// `--node-token`, checked by the registry interceptor.
    pub node_token: Option<String>,
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
        burrow_core::tags::validate_labels(&info.labels)?;
        let (node_id, node_index) = self.0.nodes.register(
            info,
            req.wireguard_public_key,
            req.wireguard_endpoint,
            req.claimed_node_index,
        );
        tracing::info!(node_id, node_index, "node registered");

        // Adopt whatever the node currently has. Done off the registration
        // path because the node is mid-call to us and is not yet serving this
        // request's caller; blocking here would deadlock the handshake.
        let state = Arc::clone(&self.0);
        let id = node_id.clone();
        tokio::spawn(async move { reconcile_node(state, id).await });
        Ok(Response::new(nodepb::RegisterResponse {
            node_id,
            heartbeat_interval_secs: HEARTBEAT_INTERVAL.as_secs() as u32,
            node_index,
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
            burrow_core::tags::validate_labels(&info.labels)?;
        }
        let known = self
            .0
            .nodes
            .heartbeat(&req.node_id, req.status.unwrap_or_default(), req.info);
        if !known {
            tracing::warn!(
                node_id = req.node_id,
                "heartbeat from unknown node; asking to re-register"
            );
        } else {
            let dropped = self.0.snapshots.apply_report(&req.node_id, &req.snapshots);
            if dropped > 0 {
                tracing::info!(
                    node_id = req.node_id,
                    dropped,
                    "forgot snapshots the node no longer holds"
                );
            }
            let (restated, forgotten) = self.0.sandboxes.apply_states(&req.node_id, &req.sandboxes);
            if restated > 0 || forgotten > 0 {
                tracing::info!(
                    node_id = req.node_id,
                    restated,
                    forgotten,
                    "adopted node-initiated sandbox changes"
                );
            }
        }
        // The peer list and cross-node membership ride on the heartbeat, so a
        // node converges on the current fleet without a separate subscription.
        Ok(Response::new(nodepb::HeartbeatResponse {
            reregister: !known,
            peers: self.0.nodes.mesh_peers(&req.node_id),
            network_members: self.0.sandboxes.network_members(&req.node_id),
            // Including the beating node's own: every edge in the fleet is
            // denied to every sandbox, and a node cannot know from its own
            // flags which of its peers serves one.
            edge_hosts: self.0.nodes.edge_hosts(),
        }))
    }
}

/// Rebuilds the orchestrator's view of one node from that node's own listing.
async fn reconcile_node(state: Arc<OrchestratorState>, node_id: String) {
    let Some(endpoint) = state.nodes.endpoint(&node_id) else {
        return;
    };
    let mut client = match crate::api::connect_node(endpoint, state.node_token.as_deref()).await {
        Ok(client) => client,
        Err(err) => {
            tracing::warn!(node_id, %err, "cannot reach node to reconcile; its sandboxes stay as recorded");
            return;
        }
    };
    match client.list_sandboxes(nodepb::NodeListRequest {}).await {
        Ok(resp) => {
            let outcome = state
                .sandboxes
                .reconcile_node(&node_id, resp.into_inner().sandboxes);
            tracing::info!(
                node_id,
                adopted = outcome.adopted,
                forgotten = outcome.forgotten,
                tombstoned = outcome.tombstoned.len(),
                "reconciled node inventory"
            );
            // The node was down when these were deleted, so it never carried
            // the deletes out. Doing it now is what makes a delete against a
            // dead node mean the same thing as one against a live node.
            for sandbox_id in outcome.tombstoned {
                match client
                    .delete_sandbox(nodepb::NodeSandboxRef {
                        sandbox_id: sandbox_id.clone(),
                    })
                    .await
                {
                    Ok(_) => {
                        tracing::info!(
                            node_id,
                            sandbox = sandbox_id,
                            "destroyed a sandbox deleted while this node was down"
                        );
                        state.sandboxes.clear_tombstone(&sandbox_id);
                    }
                    // The tombstone is kept: the sandbox is still there, and
                    // the next registration gets another go at it.
                    Err(err) => tracing::warn!(
                        node_id,
                        sandbox = sandbox_id,
                        %err,
                        "could not destroy a sandbox deleted while this node was down"
                    ),
                }
            }
        }
        Err(err) => tracing::warn!(node_id, %err, "node inventory unavailable"),
    }

    // Snapshots are only recorded here, so a restarted orchestrator has no
    // idea where any of them live until each node says. The node is the
    // authority, exactly as it is for its sandboxes.
    match client
        .list_snapshots(nodepb::NodeListSnapshotsRequest {
            sandbox_id: String::new(),
        })
        .await
    {
        Ok(resp) => {
            let adopted = state
                .snapshots
                .reconcile_node(&node_id, resp.into_inner().snapshots);
            if adopted > 0 {
                tracing::info!(node_id, adopted, "adopted node snapshots");
            }
        }
        Err(err) => tracing::warn!(node_id, %err, "node snapshot inventory unavailable"),
    }

    match client
        .list_volumes(burrow_proto::api::v1::ListVolumesRequest {
            node_id: String::new(),
        })
        .await
    {
        Ok(resp) => {
            let adopted = state
                .volumes
                .reconcile_node(&node_id, resp.into_inner().volumes);
            if adopted > 0 {
                tracing::info!(node_id, adopted, "adopted node volumes");
            }
        }
        Err(err) => tracing::warn!(node_id, %err, "node volume inventory unavailable"),
    }
}

/// How often the reaper looks, capped so a short expiry is still enforced
/// promptly and a long one does not mean a busy loop.
const REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Writes off nodes that have been silent far longer than unhealthy.
///
/// A node silent for `expiry` is presumed gone: its placements are dropped so
/// the names and capacity they held come back, and its entry with them. No
/// tombstones are recorded, unlike a caller's delete against a dead node,
/// because nobody asked for these sandboxes to be destroyed; if the node comes
/// back, reconcile re-adopts its own inventory.
///
/// Ageing out tombstones rides on the same tick, and happens even when reaping
/// is switched off: they are bounded by their own TTL either way.
async fn reap_dead_nodes(state: Arc<OrchestratorState>, expiry: Option<std::time::Duration>) {
    let period = expiry.map_or(REAP_INTERVAL, |expiry| REAP_INTERVAL.min(expiry));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        for node_id in expiry.map(|e| state.nodes.expired(e)).unwrap_or_default() {
            let dropped = state.sandboxes.forget_node(&node_id);
            // Its snapshots go with it: they only ever existed on that node.
            state.snapshots.forget_node(&node_id);
            state.volumes.forget_node(&node_id);
            state.nodes.remove_node(&node_id);
            tracing::warn!(
                node_id,
                placements = dropped.len(),
                names = dropped.iter().filter(|s| !s.name.is_empty()).count(),
                "node has been silent past its expiry; forgetting it and every \
                 placement recorded against it"
            );
        }
        let pruned = state
            .sandboxes
            .prune_tombstones(sandboxes::TOMBSTONE_TTL_SECS);
        if pruned > 0 {
            tracing::info!(pruned, "aged out tombstones for nodes that never returned");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let telemetry =
        burrow_core::telemetry::init("burrow-orchestrator", args.otlp_endpoint.as_deref());
    let result = run(args).await;
    telemetry.shutdown();
    result
}

async fn run(args: Args) -> anyhow::Result<()> {
    let tokens =
        burrow_core::auth::load_tokens(args.api_key.as_deref(), args.api_key_file.as_deref());
    let auth = burrow_core::auth::TokenAuth::new(tokens.clone());
    if !auth.is_enabled() {
        tracing::warn!(
            "no --api-key configured: the API is UNAUTHENTICATED and anyone \
             who can reach it can create and exec into sandboxes"
        );
    }

    // Registering a node says where sandbox traffic goes, so it is a separate
    // privilege from using the API. Sharing one secret lets any API client
    // register a node over a real one and have other tenants' exec and log
    // streams routed to it.
    let node_tokens =
        burrow_core::auth::load_tokens(args.node_token.as_deref(), args.node_token_file.as_deref());
    let node_auth = if node_tokens.is_empty() {
        if auth.is_enabled() {
            tracing::warn!(
                "no --node-token configured: node registration accepts the client \
                 api key, so any API client can register a node and have other \
                 tenants' sandboxes routed to it. Set --node-token (or \
                 BURROW_NODE_TOKEN) and give nodes the same value."
            );
        }
        auth.clone()
    } else {
        burrow_core::auth::TokenAuth::new(node_tokens)
    };

    let sandboxes = match burrow_store::Store::open(&args.data_dir.join("orchestrator.db")) {
        Ok(store) => sandboxes::SandboxRegistry::with_store(Arc::new(store)),
        Err(err) => {
            // Not fatal: the registry works in memory, and nodes rebuild it on
            // registration. Only a simultaneous fleet restart would notice.
            tracing::error!(
                path = %args.data_dir.join("orchestrator.db").display(), %err,
                "no durable placement store; placements will not survive a full restart"
            );
            sandboxes::SandboxRegistry::default()
        }
    };

    let state = Arc::new(OrchestratorState {
        nodes: registry::NodeRegistry::default(),
        sandboxes,
        snapshots: snapshots::SnapshotRegistry::default(),
        volumes: volumes::VolumeRegistry::default(),
        channels: api::NodeChannels::default(),
        node_token: tokens.first().cloned(),
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

    Server::builder()
        .add_service(BurrowServer::with_interceptor(
            api::ApiService(state.clone()),
            auth.clone(),
        ))
        .add_service(NodeRegistryServer::with_interceptor(
            NodeRegistryService(state),
            node_auth,
        ))
        .serve(args.listen)
        .await?;
    Ok(())
}
