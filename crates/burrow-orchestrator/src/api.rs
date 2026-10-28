//! The public API: placement plus routing to the node that owns a sandbox.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use burrow_proto::api::v1 as api;
use burrow_proto::api::v1::burrow_server::Burrow;
use burrow_proto::common::v1 as common;
use burrow_proto::node::v1 as nodepb;
use burrow_proto::node::v1::node_service_client::NodeServiceClient;

use crate::OrchestratorState;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;
pub type NodeClient = NodeServiceClient<
    tonic::service::interceptor::InterceptedService<tonic::transport::Channel, NodeAuth>,
>;

/// Attaches the cluster token to orchestrator-to-node calls.
#[derive(Clone)]
pub struct NodeAuth(Option<String>);

impl tonic::service::Interceptor for NodeAuth {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = &self.0 {
            let value = format!("Bearer {token}")
                .parse()
                .map_err(|_| Status::internal("malformed node token"))?;
            req.metadata_mut().insert("authorization", value);
        }
        // Every call to a node goes through here, which makes it the one place
        // that can link a node's spans to the request that caused them.
        burrow_common::telemetry::propagation::inject(req.metadata_mut());
        Ok(req)
    }
}

/// Channels to nodes, keyed by the address they were opened to.
///
/// Every per-sandbox call is routed through a node, so dialling one per
/// request put a TCP connect and an HTTP/2 handshake in front of every exec.
/// Keying by address means a node that re-registers somewhere else simply
/// misses the cache rather than being served a channel to its old home.
#[derive(Default)]
pub struct NodeChannels {
    channels: tokio::sync::Mutex<std::collections::HashMap<String, NodeClient>>,
}

impl NodeChannels {
    pub async fn get(
        &self,
        endpoint: &str,
        token: Option<&str>,
    ) -> Result<NodeClient, tonic::transport::Error> {
        if let Some(client) = self.channels.lock().await.get(endpoint) {
            return Ok(client.clone());
        }
        let client = connect_node(endpoint.to_string(), token).await?;
        self.channels
            .lock()
            .await
            .insert(endpoint.to_string(), client.clone());
        Ok(client)
    }

    /// Drops a channel that has stopped working, so the next call redials.
    pub async fn forget(&self, endpoint: &str) {
        self.channels.lock().await.remove(endpoint);
    }
}

/// How long a node gets to answer a dial.
///
/// A node that is down but whose address still resolves answers nothing, and
/// the OS gives up on that only after minutes. Every call routed through such
/// a node would hold its caller for that long, and the fan-outs below would
/// hold it once per dead node.
const NODE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Deadline for a node call that is not a stream.
///
/// Only for the unary fan-outs: this is set on the endpoint, so it applies to
/// every request made over the channel, and an exec or a watch cut off after
/// thirty seconds would be a bug rather than a safeguard.
const NODE_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn node_endpoint(endpoint: String) -> Result<tonic::transport::Endpoint, tonic::transport::Error> {
    Ok(tonic::transport::Endpoint::try_from(endpoint)?.connect_timeout(NODE_CONNECT_TIMEOUT))
}

/// Dials a node's API with the cluster token attached.
///
/// No per-request deadline: the same channel carries exec, watch and file
/// streams, which are long-lived by design.
pub async fn connect_node(
    endpoint: String,
    token: Option<&str>,
) -> Result<NodeClient, tonic::transport::Error> {
    let channel = node_endpoint(endpoint)?.connect().await?;
    Ok(NodeServiceClient::with_interceptor(
        channel,
        NodeAuth(token.map(str::to_string)),
    ))
}

/// Dials a node for a one-shot call, with a deadline on it.
///
/// Used by the fan-outs, where one wedged node must not hold up an answer the
/// rest of the fleet has already given.
async fn connect_node_unary(
    endpoint: String,
    token: Option<&str>,
) -> Result<NodeClient, tonic::transport::Error> {
    let channel = node_endpoint(endpoint)?
        .timeout(NODE_REQUEST_TIMEOUT)
        .connect()
        .await?;
    Ok(NodeServiceClient::with_interceptor(
        channel,
        NodeAuth(token.map(str::to_string)),
    ))
}

/// The nodes a fan-out should ask: those that are registered and addressable.
fn reachable_nodes(state: &OrchestratorState) -> Vec<(String, String)> {
    state
        .nodes
        .snapshot()
        .into_iter()
        .filter_map(|node| {
            let id = node.info.as_ref().map(|i| i.id.clone())?;
            let endpoint = state.nodes.endpoint(&id)?;
            Some((id, endpoint))
        })
        .collect()
}

#[derive(Clone)]
pub struct ApiService(pub Arc<OrchestratorState>);

/// Holds a placement's optimistic capacity charge until the create commits.
struct PlacementGuard<'a> {
    nodes: &'a crate::registry::NodeRegistry,
    store: Option<Arc<burrow_store::Store>>,
    node_id: String,
    vcpus: u32,
    mem_mib: u64,
    is_kept: bool,
}

impl PlacementGuard<'_> {
    fn keep(mut self) {
        self.is_kept = true;
    }
}

impl Drop for PlacementGuard<'_> {
    fn drop(&mut self) {
        if !self.is_kept {
            self.nodes.release(&self.node_id, self.vcpus, self.mem_mib);
            release_in_store(self.store.clone(), &self.node_id, self.vcpus, self.mem_mib);
        }
    }
}

impl ApiService {
    /// Turns a caller's reference into the id it names.
    ///
    /// The public API takes a sandbox by id or by name; nodes are only ever
    /// told ids. A reference that matches nothing is passed through unchanged,
    /// so the caller gets the usual "no sandbox X".
    async fn resolve(&self, reference: &str) -> String {
        if self.0.sandboxes.get(reference).is_some() {
            return reference.to_string();
        }
        if let Some(id) = self.0.sandboxes.id_by_name(reference) {
            return id;
        }
        // Not in this replica's cache: possibly created through another one
        // in the last second.
        match self.0.sandboxes.load(reference).await {
            Some(sandbox) => sandbox.id,
            None => reference.to_string(),
        }
    }

    fn node_of(&self, sandbox_id: &str) -> Result<String, Status> {
        self.0
            .sandboxes
            .node_of(sandbox_id)
            .ok_or_else(|| Status::not_found(format!("no sandbox {sandbox_id}")))
    }

    /// Returns a placement's reservation unless the create succeeds.
    /// Chooses a node and takes the capacity on it in the store.
    ///
    /// The choice is made from this replica's view of the fleet, which other
    /// replicas may have placed on since; the store's reservation is the one
    /// that is checked and taken in a single statement. A node it refuses is
    /// passed over and the next best is tried.
    async fn place(
        &self,
        want: &crate::registry::Placement,
    ) -> Result<String, crate::registry::PlacementError> {
        self.place_avoiding(want, std::collections::HashSet::new())
            .await
    }

    /// [`place`](Self::place), never choosing a node in `excluded`.
    async fn place_avoiding(
        &self,
        want: &crate::registry::Placement,
        mut excluded: std::collections::HashSet<String>,
    ) -> Result<String, crate::registry::PlacementError> {
        loop {
            let node_id = self.0.nodes.place_excluding(want, &excluded)?;
            let Some(store) = &self.0.store else {
                return Ok(node_id);
            };
            match store
                .reserve_capacity(&node_id, want.vcpus, want.mem_mib)
                .await
            {
                Ok(true) => return Ok(node_id),
                Ok(false) => {
                    self.0.nodes.release(&node_id, want.vcpus, want.mem_mib);
                    excluded.insert(node_id);
                }
                Err(err) => {
                    self.0.nodes.release(&node_id, want.vcpus, want.mem_mib);
                    return Err(crate::registry::PlacementError::Store(err.to_string()));
                }
            }
        }
    }

    fn place_guard(&self, node_id: &str, want: &crate::registry::Placement) -> PlacementGuard<'_> {
        PlacementGuard {
            nodes: &self.0.nodes,
            store: self.0.store.clone(),
            node_id: node_id.to_string(),
            vcpus: want.vcpus,
            mem_mib: want.mem_mib,
            is_kept: false,
        }
    }

    /// Copies a template onto a node that has room, and returns that node.
    ///
    /// The transfer is node-to-node: the orchestrator names a source and a
    /// target and stays off the data path, so a rootfs never crosses the
    /// control plane.
    async fn replicate_then_place(
        &self,
        template: &str,
        want: &crate::registry::Placement,
    ) -> Result<String, Status> {
        // Only to tell whether placement chose the node that already holds it;
        // `replicate_to` looks the source up again when there is work to do.
        let Some((source_id, _)) = self.0.nodes.source_for_template(template) else {
            return Err(Status::not_found(format!(
                "no node has template {template:?}; import it with `burrow pull`"
            )));
        };

        let target = self
            .place(&crate::registry::Placement {
                is_template_transfer_allowed: true,
                ..want.clone()
            })
            .await
            .map_err(|err| match err {
                // A constraint the fleet cannot satisfy is not a capacity
                // problem, and telling a caller to try again later would be
                // telling them to wait for something that will not happen.
                crate::registry::PlacementError::NoNodeWithLabels(_) => {
                    Status::failed_precondition(err.to_string())
                }
                err => Status::resource_exhausted(err.to_string()),
            })?;
        if target == source_id {
            // The source had room after all; nothing to copy.
            return Ok(target);
        }
        self.replicate_to(template, &target).await?;
        Ok(target)
    }

    /// Copies a template onto one named node, which is already decided.
    ///
    /// A volume pins placement the way a snapshot does, and a pinned node that
    /// happens not to hold the template would otherwise fail the create with a
    /// missing-file error rather than fetching what it needs.
    async fn replicate_to(&self, template: &str, target: &str) -> Result<(), Status> {
        if self.0.nodes.has_template(target, template) {
            return Ok(());
        }
        let Some((source_id, source_address)) = self.0.nodes.source_for_template(template) else {
            return Err(Status::not_found(format!(
                "no node has template {template:?}; import it with `burrow pull`"
            )));
        };
        if source_id == target {
            return Ok(());
        }

        let manifest = {
            let endpoint =
                self.0.nodes.endpoint(&source_id).ok_or_else(|| {
                    Status::unavailable(format!("node {source_id} is unreachable"))
                })?;
            let mut source = connect_node(endpoint, self.0.node_token.as_deref())
                .await
                .map_err(|err| Status::unavailable(format!("node {source_id}: {err}")))?;
            source
                .get_template_manifest(nodepb::TemplateManifestRequest {
                    name: template.to_string(),
                    is_config_only: false,
                })
                .await?
                .into_inner()
        };

        let endpoint = self
            .0
            .nodes
            .endpoint(target)
            .ok_or_else(|| Status::unavailable(format!("node {target} is unreachable")))?;
        let mut client = connect_node(endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("node {target}: {err}")))?;
        let result = client
            .pull_template(nodepb::PullTemplateRequest {
                source_address,
                manifest: Some(manifest),
            })
            .await?
            .into_inner();

        tracing::info!(
            template,
            from = source_id,
            to = target,
            bytes = result.bytes_transferred,
            reused = result.blobs_reused,
            "template replicated to place a sandbox"
        );
        Ok(())
    }

    /// Address a client outside the sandbox uses to reach a published port:
    /// the node's advertised host with the published port substituted.
    fn node_host(&self, node_id: &str, host_port: u32) -> String {
        let host = self
            .0
            .nodes
            .snapshot()
            .into_iter()
            .find(|n| n.info.as_ref().is_some_and(|i| i.id == node_id))
            .and_then(|n| n.info)
            .map(|i| i.address)
            .unwrap_or_default();
        let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host);
        format!("{host}:{host_port}")
    }

    /// The stable URL a published port answers on, when its node serves an edge.
    ///
    /// Only the node holding the sandbox can answer this hostname. A node
    /// running no edge has none, and the empty string tells a caller so rather
    /// than handing back a name that resolves nowhere.
    fn edge_url(&self, node_id: &str, sandbox_id: &str, guest_port: u32) -> String {
        self.0
            .nodes
            .node_edge(node_id)
            .and_then(|(domain, port)| {
                burrow_common::edge::sandbox_url(&domain, port, sandbox_id, guest_port)
            })
            .unwrap_or_default()
    }

    /// Refuses a placement constraint the node in question does not satisfy.
    ///
    /// For the paths where the node is already decided (a fork, a create from a
    /// snapshot). Dropping the constraint silently would put the workload
    /// exactly where the caller said not to.
    fn require_labels(
        &self,
        node_id: &str,
        want: &std::collections::HashMap<String, String>,
    ) -> Result<(), Status> {
        let carried = self.0.nodes.labels(node_id);
        let mut missing: Vec<String> = want
            .iter()
            .filter(|(key, value)| carried.get(*key) != Some(*value))
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        missing.sort();
        Err(Status::failed_precondition(format!(
            "node {node_id} does not carry {}, and this sandbox is built there rather than placed",
            missing.join(", ")
        )))
    }

    fn secrets(&self) -> Result<&crate::secrets::Secrets, Status> {
        self.0
            .secrets
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no durable store; secrets cannot be kept"))
    }

    /// Replaces every `${secret:<name>}` in a policy's brokered values with
    /// the stored secret, so a header can name a credential without the
    /// value ever being on a command line or in a request. The node only ever
    /// sees the resolved policy, which it seals at rest like any other.
    async fn resolve_secret_refs(&self, network: &mut common::NetworkPolicy) -> Result<(), Status> {
        let mut values: Vec<&mut String> = Vec::new();
        for rule in &mut network.rules {
            match rule.action.as_mut() {
                Some(common::request_rule::Action::SetHeaders(set)) => {
                    values.extend(set.headers.iter_mut().map(|h| &mut h.value));
                }
                Some(common::request_rule::Action::Forward(forward)) => {
                    values.push(&mut forward.secret)
                }
                None => {}
            }
        }
        // Names first, then the store, then the substitution: the store is
        // async and the substitution is not.
        let mut names = Vec::new();
        for value in values.iter().filter(|v| v.contains(SECRET_REF)) {
            substitute_secret_refs(value, |name| {
                names.push(name.to_string());
                Ok(String::new())
            })?;
        }
        let mut resolved = HashMap::new();
        for name in names {
            if resolved.contains_key(&name) {
                continue;
            }
            let value = self.secrets()?.get(&name).await.map_err(internal)?;
            resolved.insert(name, value);
        }
        for value in values {
            if value.contains(SECRET_REF) {
                *value = substitute_secret_refs(value, |name| {
                    resolved.get(name).cloned().flatten().ok_or_else(|| {
                        Status::failed_precondition(format!(
                            "no secret {name:?}; store one with `burrow secret set`"
                        ))
                    })
                })?;
            }
        }
        Ok(())
    }

    /// The bound secrets for the credential services a Kit template's
    /// descriptors request, read through `client` on `node_id`; empty for any
    /// other template. An unbound service is left out: whether that refuses
    /// or skips is the descriptor's `optional` to say, and the node judges it.
    async fn kit_credentials(
        &self,
        client: &mut NodeClient,
        node_id: &str,
        template: &str,
    ) -> Result<HashMap<String, String>, Status> {
        let mut out = HashMap::new();
        if !self.0.nodes.is_kit_template(node_id, template) {
            return Ok(out);
        }
        let manifest = client
            .get_template_manifest(nodepb::TemplateManifestRequest {
                name: template.to_string(),
                is_config_only: true,
            })
            .await?
            .into_inner();
        let Some(secrets) = &self.0.secrets else {
            return Ok(out);
        };
        for service in burrow_kit::credential_services(&manifest.image_config) {
            if let Some(value) = secrets.get(&service).await.map_err(internal)? {
                out.insert(service, value);
            }
        }
        Ok(out)
    }

    /// Opens a connection to the node hosting `sandbox_id`.
    ///
    /// The address is looked up per request, because a node's address can
    /// change across re-registration. The channel for a given address is
    /// reused; see [`NodeChannels`].
    async fn node_for(&self, sandbox_id: &str) -> Result<NodeClient, Status> {
        let node_id = self.placed_on(sandbox_id).await?;
        let endpoint = self.0.nodes.endpoint(&node_id).ok_or_else(|| {
            Status::unavailable(format!(
                "node {node_id} hosting {sandbox_id} is unreachable"
            ))
        })?;
        match self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
        {
            Ok(client) => Ok(client),
            Err(err) => {
                // A dial that fails leaves nothing cached, but a channel that
                // broke after being cached would; drop it either way so the
                // next call starts clean.
                self.0.channels.forget(&endpoint).await;
                Err(Status::unavailable(format!(
                    "cannot reach node {node_id}: {err}"
                )))
            }
        }
    }

    /// The node holding `sandbox_id` now.
    async fn placed_on(&self, sandbox_id: &str) -> Result<String, Status> {
        let mut node_id = self.node_of(sandbox_id)?;
        // Beside other replicas the cache can be a second behind a move made
        // through one of them, naming a node that has already let go.
        let is_replicated = self.0.control_plane_hosts.lock().unwrap().len() > 1;
        if (node_id.is_empty() || is_replicated)
            && let Some(sandbox) = self.0.sandboxes.refresh(sandbox_id).await
        {
            node_id = sandbox.node_id;
        }
        if node_id.is_empty() {
            return Err(Status::failed_precondition(format!(
                "sandbox {sandbox_id} is suspended with its state in the object store, \
                 and no node holds it; start it to place it"
            )));
        }
        Ok(node_id)
    }

    /// Whether the orchestrator has given up on ever reaching a node.
    ///
    /// True when the node has missed its heartbeats, and true for a node the
    /// registry has no entry for at all: without an entry there is no address
    /// to dial, so nothing can ever be delivered to it. Both are distinct from
    /// a healthy node that happened to refuse one connection, which is a
    /// transient failure and stays an error.
    fn is_node_dead(&self, node_id: &str) -> bool {
        !self.0.nodes.health(node_id).unwrap_or(false)
    }

    /// Asks a healthy node what the object store holds and records it,
    /// returning whether `id` turned out to be there.
    async fn refresh_durable(&self, id: &str) -> bool {
        for node_id in self.0.nodes.healthy_ids() {
            let Some(endpoint) = self.0.nodes.endpoint(&node_id) else {
                continue;
            };
            let Ok(mut client) = self
                .0
                .channels
                .get(&endpoint, self.0.node_token.as_deref())
                .await
            else {
                continue;
            };
            let Ok(resp) = client
                .list_durable_snapshots(nodepb::NodeListSnapshotsRequest {
                    sandbox_id: String::new(),
                })
                .await
            else {
                continue;
            };
            let listed = resp.into_inner().snapshots;
            let is_there = listed.iter().any(|snapshot| snapshot.id == id);
            self.0.snapshots.adopt_remote(listed);
            if is_there {
                self.0.snapshots.mark_durable(id);
            }
            return is_there;
        }
        false
    }

    /// A snapshot this replica has not heard of, asked of every node.
    ///
    /// Snapshots are learned from nodes, and with several replicas only the
    /// one that took a snapshot, or the one its node heartbeats to, knows of
    /// it at once; the others catch up within half a minute. A caller who
    /// took a snapshot and used it straight away should not be told it does
    /// not exist in that window.
    async fn find_snapshot(&self, id: &str) -> Option<common::Snapshot> {
        let found = futures::future::join_all(reachable_nodes(&self.0).into_iter().map(
            |(node_id, endpoint)| async move {
                let mut client = self
                    .0
                    .channels
                    .get(&endpoint, self.0.node_token.as_deref())
                    .await
                    .ok()?;
                let snapshot = client
                    .get_snapshot(api::SnapshotRef { id: id.to_string() })
                    .await
                    .ok()?
                    .into_inner();
                Some((node_id, snapshot))
            },
        ))
        .await;
        let (node_id, snapshot) = found.into_iter().flatten().next()?;
        self.0.snapshots.insert(&node_id, snapshot);
        self.0.snapshots.get(id)
    }

    /// A volume this replica has not heard of, asked of every node, for the
    /// same reason as [`Self::find_snapshot`].
    async fn find_volume(&self, name: &str) -> Option<common::Volume> {
        let found = futures::future::join_all(reachable_nodes(&self.0).into_iter().map(
            |(node_id, endpoint)| async move {
                let mut client = self
                    .0
                    .channels
                    .get(&endpoint, self.0.node_token.as_deref())
                    .await
                    .ok()?;
                let volume = client
                    .get_volume(api::VolumeRef {
                        name: name.to_string(),
                    })
                    .await
                    .ok()?
                    .into_inner();
                Some((node_id, volume))
            },
        ))
        .await;
        let (node_id, volume) = found.into_iter().flatten().next()?;
        self.0.volumes.insert(&node_id, volume);
        self.0.volumes.get(name)
    }

    /// A snapshot by id, from this replica's view or, failing that, the fleet's.
    async fn snapshot(&self, id: &str) -> Option<common::Snapshot> {
        match self.0.snapshots.get(id) {
            Some(snapshot) => Some(snapshot),
            None => self.find_snapshot(id).await,
        }
    }

    /// A volume by name, from this replica's view or, failing that, the fleet's.
    async fn volume(&self, name: &str) -> Option<common::Volume> {
        match self.0.volumes.get(name) {
            Some(volume) => Some(volume),
            None => self.find_volume(name).await,
        }
    }

    /// The snapshot, the node a create from it should go to, and a client
    /// for that node.
    ///
    /// The node holding it, when reachable: restoring a local copy costs
    /// nothing. Otherwise a durable snapshot is placed like a sandbox, among
    /// nodes that can restore it, and that node fetches it from the object
    /// store. A snapshot that is neither is unusable right now, and placing it
    /// elsewhere would boot a different image and call it a restore.
    async fn node_for_snapshot(
        &self,
        id: &str,
        want: &crate::registry::Placement,
    ) -> Result<(common::Snapshot, String, NodeClient), Status> {
        let mut snapshot = self
            .snapshot(id)
            .await
            .ok_or_else(|| Status::not_found(format!("no snapshot {id}")))?;
        let holder = (!snapshot.node_id.is_empty()
            && self.0.nodes.endpoint(&snapshot.node_id).is_some())
        .then(|| snapshot.node_id.clone());
        // A node that uploaded a snapshot and died before its next heartbeat
        // never said so. The store knows, and any node with it configured can
        // ask, so one is asked before the snapshot is declared stranded.
        if holder.is_none() && !snapshot.is_durable && self.refresh_durable(id).await {
            snapshot.is_durable = true;
        }
        let node_id = match holder {
            Some(node_id) => {
                self.require_labels(&node_id, &want.node_labels)?;
                node_id
            }
            None if snapshot.is_durable => {
                let want = crate::registry::Placement {
                    // The snapshot carries its own kernel and rootfs, so the
                    // template need not be on the node.
                    template: String::new(),
                    arch: snapshot.arch.clone(),
                    firecracker_version: snapshot.firecracker_version.clone(),
                    ..want.clone()
                };
                self.place(&want).await.map_err(|err| match err {
                    crate::registry::PlacementError::NoHealthyNode
                    | crate::registry::PlacementError::NoCapacity { .. } => {
                        Status::resource_exhausted(err.to_string())
                    }
                    other => Status::failed_precondition(other.to_string()),
                })?
            }
            None => {
                return Err(Status::failed_precondition(format!(
                    "snapshot {id} lives on node {}, which is unreachable, and is not in the \
                     object store; configure --object-store on the nodes for snapshots that \
                     outlive their node",
                    snapshot.node_id
                )));
            }
        };
        let endpoint = self
            .0
            .nodes
            .endpoint(&node_id)
            .ok_or_else(|| Status::unavailable(format!("node {node_id} went away")))?;
        let client = self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node {node_id}: {err}")))?;
        Ok((snapshot, node_id, client))
    }

    /// The node every requested volume lives on, if any were requested.
    ///
    /// A volume is a disk image on one machine, so mounting one fixes
    /// placement the way a snapshot does. Mounting two that live on different
    /// nodes is refused rather than half satisfied: nothing can attach both.
    async fn node_for_volumes(
        &self,
        mounts: &[common::VolumeMount],
    ) -> Result<Option<String>, Status> {
        let mut pinned: Option<String> = None;
        for mount in mounts.iter().filter(|mount| !mount.is_tmpfs) {
            let volume = self
                .volume(&mount.volume)
                .await
                .ok_or_else(|| Status::not_found(format!("no volume {}", mount.volume)))?;
            match &pinned {
                Some(node) if *node != volume.node_id => {
                    return Err(Status::failed_precondition(format!(
                        "volumes are node-local: {} is on node {} but another requested volume                          is on node {node}",
                        mount.volume, volume.node_id
                    )));
                }
                Some(_) => {}
                None => pinned = Some(volume.node_id.clone()),
            }
        }
        Ok(pinned)
    }

    /// A client for the node holding one volume.
    async fn node_holding_volume(&self, name: &str) -> Result<(String, NodeClient), Status> {
        let volume = self
            .volume(name)
            .await
            .ok_or_else(|| Status::not_found(format!("no volume {name}")))?;
        let endpoint = self.0.nodes.endpoint(&volume.node_id).ok_or_else(|| {
            Status::failed_precondition(format!(
                "volume {name} lives on node {}, which is unreachable; volumes are \
                 node-local and cannot be reached anywhere else",
                volume.node_id
            ))
        })?;
        let client = self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| {
                Status::unavailable(format!("cannot reach node {}: {err}", volume.node_id))
            })?;
        Ok((volume.node_id, client))
    }

    /// Hands a sandbox no node holds to one, which takes it up from the
    /// object store and resumes it.
    ///
    /// `node_id` names the destination outright; otherwise it is placed like
    /// a create, on hardware carrying `node_labels` and able to restore what
    /// the sandbox's state was written on.
    async fn adopt(
        &self,
        sandbox: common::Sandbox,
        node_id: &str,
        node_labels: HashMap<String, String>,
    ) -> Result<common::Sandbox, Status> {
        let _adoption = self
            .0
            .sandboxes
            .claim_adoption(&sandbox.id)
            .await
            .map_err(Status::aborted)?;
        let want = self.adoption_placement(&sandbox, node_labels);
        let (target, placed) = if node_id.is_empty() {
            let target = self.place(&want).await.map_err(placement_status)?;
            let placed = self.place_guard(&target, &want);
            (target, Some(placed))
        } else {
            let info = self
                .0
                .nodes
                .info(node_id)
                .ok_or_else(|| Status::not_found(format!("no node {node_id}")))?;
            if (!want.arch.is_empty() && info.arch != want.arch)
                || (!want.firecracker_version.is_empty()
                    && info.firecracker_version != want.firecracker_version)
            {
                return Err(Status::failed_precondition(format!(
                    "node {node_id} cannot restore sandbox {}: its state needs {} and \
                     Firecracker {}",
                    sandbox.id, want.arch, want.firecracker_version
                )));
            }
            self.require_labels(node_id, &want.node_labels)?;
            (node_id.to_string(), None)
        };
        let endpoint = self
            .0
            .nodes
            .endpoint(&target)
            .ok_or_else(|| Status::unavailable(format!("node {target} is unreachable")))?;
        let mut client = self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node {target}: {err}")))?;
        let adopted = client
            .adopt_sandbox(nodepb::NodeAdoptRequest {
                record: Some(sandbox),
                node_id: target.clone(),
            })
            .await?
            .into_inner();
        if let Some(placed) = placed {
            placed.keep();
        }
        self.0.sandboxes.insert(adopted.clone());
        // Written through before the caller hears of it, so their next call
        // finds the sandbox here whichever replica it reaches.
        if let Some(writer) = self.0.sandboxes.writer() {
            writer.flush().await;
        }
        tracing::info!(
            sandbox = adopted.id,
            node = target,
            "sandbox adopted from the object store"
        );
        Ok(adopted)
    }

    /// What a node needs to take up `sandbox` from the object store.
    fn adoption_placement(
        &self,
        sandbox: &common::Sandbox,
        node_labels: HashMap<String, String>,
    ) -> crate::registry::Placement {
        let resources = sandbox
            .policy
            .as_ref()
            .and_then(|p| p.resources)
            .unwrap_or_default();
        let networks: Vec<String> = sandbox
            .policy
            .iter()
            .flat_map(|p| p.networks.iter())
            .map(|m| m.network.clone())
            .filter(|name| !name.is_empty())
            .collect();
        crate::registry::Placement {
            template: sandbox.template.clone(),
            prefer_node: self.0.sandboxes.node_hosting_networks(&networks),
            is_mesh_available: self.0.nodes.is_mesh_available(""),
            vcpus: resources.vcpus.max(1),
            mem_mib: match resources.mem_mib {
                0 => 512,
                mem => mem as u64,
            },
            // The kernel and rootfs travel with the state.
            is_template_transfer_allowed: true,
            node_labels,
            arch: sandbox.arch.clone(),
            firecracker_version: sandbox.firecracker_version.clone(),
        }
    }

    /// The unplaced sandbox `id` names, if that is what it is.
    ///
    /// A cached record saying so is checked against the store first: it may
    /// be from before another replica moved the sandbox onto a node.
    async fn unplaced(&self, id: &str) -> Option<common::Sandbox> {
        self.0.sandboxes.get(id).filter(|s| s.node_id.is_empty())?;
        self.0
            .sandboxes
            .refresh(id)
            .await
            .filter(|sandbox| sandbox.node_id.is_empty())
    }

    /// Deletes the stored state of a sandbox no node holds, through any node
    /// that can reach the object store.
    async fn purge(&self, id: &str) -> Result<(), Status> {
        let mut last = Status::unavailable(format!(
            "no healthy node to delete sandbox {id}'s stored state through"
        ));
        for (node_id, endpoint) in reachable_nodes(&self.0) {
            let mut client = match self
                .0
                .channels
                .get(&endpoint, self.0.node_token.as_deref())
                .await
            {
                Ok(client) => client,
                Err(err) => {
                    last = Status::unavailable(format!("cannot reach node {node_id}: {err}"));
                    continue;
                }
            };
            match client
                .purge_sandbox(nodepb::NodeSandboxRef {
                    sandbox_id: id.to_string(),
                })
                .await
            {
                Ok(_) => return Ok(()),
                // A node without the store, or one older than the call.
                Err(status)
                    if matches!(
                        status.code(),
                        tonic::Code::FailedPrecondition | tonic::Code::Unimplemented
                    ) =>
                {
                    last = status;
                }
                Err(status) => return Err(status),
            }
        }
        Err(last)
    }

    /// Returns the capacity a placement is still optimistically charged.
    fn release_charge(&self, sandbox: &common::Sandbox) {
        let resources = sandbox
            .policy
            .as_ref()
            .and_then(|policy| policy.resources)
            .unwrap_or_default();
        let vcpus = resources.vcpus.max(1);
        let mem_mib = match resources.mem_mib {
            0 => 512,
            mem => mem as u64,
        };
        self.0.nodes.release(&sandbox.node_id, vcpus, mem_mib);
        release_in_store(self.0.store.clone(), &sandbox.node_id, vcpus, mem_mib);
    }
}

#[tonic::async_trait]
impl Burrow for ApiService {
    async fn health(
        &self,
        _req: Request<api::HealthRequest>,
    ) -> Result<Response<api::HealthResponse>, Status> {
        Ok(Response::new(api::HealthResponse {
            version: burrow_common::VERSION.into(),
        }))
    }

    async fn list_nodes(
        &self,
        _req: Request<api::ListNodesRequest>,
    ) -> Result<Response<api::ListNodesResponse>, Status> {
        Ok(Response::new(api::ListNodesResponse {
            nodes: self.0.nodes.snapshot(),
        }))
    }

    async fn drain_node(
        &self,
        req: Request<api::DrainNodeRequest>,
    ) -> Result<Response<api::DrainNodeResponse>, Status> {
        let req = req.into_inner();
        let endpoint = self
            .0
            .nodes
            .endpoint(&req.node_id)
            .ok_or_else(|| Status::not_found(format!("no healthy node {}", req.node_id)))?;
        let mut client = connect_node(endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node: {err}")))?;

        let resp = client.set_drain(req.clone()).await?.into_inner();
        // Reflected locally too: placement consults the cached status, and
        // waiting for the next heartbeat would leave a window where a drained
        // node still receives sandboxes.
        self.0.nodes.set_draining(&req.node_id, req.is_draining);
        Ok(Response::new(resp))
    }

    #[tracing::instrument(skip_all, fields(template, node_id))]
    async fn create_sandbox(
        &self,
        req: Request<api::CreateSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let mut req = req.into_inner();
        // Refused here as well as on the node: placement charges a node and
        // may replicate a template before the create is ever sent, and none of
        // that should be spent on a request the node will reject anyway.
        burrow_common::tags::validate(&req.metadata)?;
        burrow_common::tags::validate_labels(&req.node_labels)?;
        if let Some(network) = req.policy.as_mut().and_then(|p| p.network.as_mut()) {
            self.resolve_secret_refs(network).await?;
        }
        // A name has to be settled before placement: refusing a duplicate
        // afterwards would mean charging a node for a sandbox that was never
        // going to be built.
        if !req.name.is_empty() {
            validate_name(&req.name)?;
        }
        // The orchestrator owns the id namespace outright: a caller names a
        // sandbox, and the server says what it is called.
        let sandbox_id = burrow_common::SandboxId::generate().to_string();
        // Held until the record is in the registry: an id and a name are both
        // claims on a namespace, and a create that is still building has to
        // hold them or a second create makes a duplicate.
        let reserved = self
            .0
            .sandboxes
            .reserve_claimed(&sandbox_id, &req.name)
            .await
            .map_err(Status::already_exists)?;

        // A create from a snapshot goes where the snapshot is, or, for one
        // the object store holds, to a node that can restore it; the template
        // and machine shape come from what the snapshot holds rather than
        // from the request.
        if !req.snapshot.is_empty() {
            let placement = crate::registry::Placement {
                vcpus: 1,
                mem_mib: 512,
                node_labels: req.node_labels.clone(),
                ..Default::default()
            };
            let (snapshot, node_id, mut client) =
                self.node_for_snapshot(&req.snapshot, &placement).await?;
            let mounts = req
                .policy
                .as_ref()
                .map(|p| p.volumes.clone())
                .unwrap_or_default();
            if let Some(node) = self.node_for_volumes(&mounts).await?
                && node != node_id
            {
                return Err(Status::failed_precondition(format!(
                    "snapshot {} is on node {node_id}, but the requested volumes are on node {node}; \
                     volumes do not travel",
                    snapshot.id
                )));
            }
            if !req.template.is_empty() && req.template != snapshot.template {
                return Err(Status::invalid_argument(format!(
                    "snapshot {} was taken of template {:?}; a sandbox created from it \
                     cannot use template {:?}",
                    snapshot.id, snapshot.template, req.template
                )));
            }
            let sandbox = client
                .create_sandbox(nodepb::NodeCreateRequest {
                    sandbox_id,
                    template: snapshot.template.clone(),
                    policy: req.policy,
                    metadata: req.metadata,
                    name: req.name,
                    snapshot: snapshot.id.clone(),
                    kit: None,
                    credentials: HashMap::new(),
                })
                .await?
                .into_inner();
            self.0.sandboxes.insert(sandbox.clone());
            drop(reserved);
            tracing::info!(
                sandbox = sandbox.id,
                snapshot = snapshot.id,
                node = node_id,
                is_fetched = node_id != snapshot.node_id,
                "sandbox created from a snapshot"
            );
            return Ok(Response::new(sandbox));
        }

        // No implicit template: burrow has no image of its own to fall back
        // on, and picking one for the caller would boot something they did not
        // ask for. Templates come from `burrow pull`.
        if req.template.is_empty() {
            return Err(Status::invalid_argument(
                "a template is required: import one with `burrow pull <image>`, \
                 or create from a snapshot with --snapshot",
            ));
        }
        let template = req.template;

        // Placement is constrained by where the template lives and where any
        // private-network peers already are; both are node-local facts that a
        // free-memory heuristic alone would happily get wrong.
        let networks: Vec<String> = req
            .policy
            .iter()
            .flat_map(|p| p.networks.iter())
            .map(|m| m.network.clone())
            .filter(|name| !name.is_empty())
            .collect();

        // Defaults mirror the node's own, so placement charges a node the same
        // resources the sandbox will actually be built with.
        let resources = req.policy.as_ref().and_then(|p| p.resources);
        let want = crate::registry::Placement {
            template: template.clone(),
            prefer_node: self.0.sandboxes.node_hosting_networks(&networks),
            is_mesh_available: self.0.nodes.is_mesh_available(""),
            vcpus: resources.as_ref().map(|r| r.vcpus).unwrap_or(0).max(1),
            mem_mib: match resources.as_ref().map(|r| r.mem_mib).unwrap_or(0) {
                0 => 512,
                mem => mem as u64,
            },
            // First pass insists the template is already there; only if that
            // finds nothing do we consider copying it.
            is_template_transfer_allowed: false,
            // Carried into the transfer pass too, so copying a template never
            // widens placement past the hardware the caller asked for.
            node_labels: req.node_labels,
            arch: String::new(),
            firecracker_version: String::new(),
        };
        // A mounted volume fixes the node, so placement is not a choice: it is
        // a check that the node holding the volumes can take the sandbox.
        let pinned = self
            .node_for_volumes(
                &req.policy
                    .as_ref()
                    .map(|p| p.volumes.clone())
                    .unwrap_or_default(),
            )
            .await?;
        // Whether `place_for` charged the node for this sandbox. A
        // volume-pinned create never goes through placement, so nothing was
        // reserved for it, and a guard over it would refund a charge it never
        // took, out of capacity belonging to whatever create runs alongside it.
        let mut charged = true;
        let node_id = match pinned {
            Some(node_id) => {
                charged = false;
                self.require_labels(&node_id, &want.node_labels)?;
                if self.0.nodes.endpoint(&node_id).is_none() {
                    return Err(Status::failed_precondition(format!(
                        "the requested volumes are on node {node_id}, which is unreachable; \
                         volumes are node-local and cannot be attached anywhere else"
                    )));
                }
                // The node is not a choice here, so the template has to come to
                // it rather than the sandbox going where the template is.
                self.replicate_to(&template, &node_id).await?;
                node_id
            }
            None => match self.place(&want).await {
                Ok(node_id) => node_id,
                // Every node that could take the sandbox lacks the template.
                // Refusing would make placement hostage to wherever a build
                // happened to land, so copy the template to a node with room.
                Err(crate::registry::PlacementError::TemplateNotOnAnyNode(name)) => {
                    self.replicate_then_place(&name, &want).await?
                }
                Err(err) => {
                    return Err(match err {
                        crate::registry::PlacementError::NoHealthyNode
                        | crate::registry::PlacementError::NoCapacity { .. } => {
                            Status::resource_exhausted(err.to_string())
                        }
                        crate::registry::PlacementError::PeersUnreachable(_)
                        | crate::registry::PlacementError::NoNodeWithLabels(_) => {
                            Status::failed_precondition(err.to_string())
                        }
                        other => Status::not_found(other.to_string()),
                    });
                }
            },
        };
        tracing::Span::current().record("template", template.as_str());
        tracing::Span::current().record("node_id", node_id.as_str());

        // Placement charged the node for this sandbox; every failure from here
        // has to give that back, or a run of failed creates makes a healthy
        // node look full. Nothing to give back on the pinned path.
        let placed = charged.then(|| self.place_guard(&node_id, &want));
        let endpoint = self
            .0
            .nodes
            .endpoint(&node_id)
            .ok_or_else(|| Status::unavailable(format!("node {node_id} went away")))?;

        let mut client = connect_node(endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node {node_id}: {err}")))?;
        let credentials = self
            .kit_credentials(&mut client, &node_id, &template)
            .await?;

        let sandbox = client
            .create_sandbox(nodepb::NodeCreateRequest {
                sandbox_id,
                template,
                policy: req.policy,
                metadata: req.metadata,
                name: req.name,
                snapshot: String::new(),
                kit: req.kit,
                credentials,
            })
            .await?
            .into_inner();
        // The sandbox exists and the node will report it; the optimistic
        // charge is now the registry's job, not the guard's.
        if let Some(placed) = placed {
            placed.keep();
        }

        self.0.sandboxes.insert(sandbox.clone());
        // The registry now holds the sandbox, so the id no longer needs
        // holding open on its behalf.
        drop(reserved);
        // The node's record is the truth rather than the request: it carries
        // the state and addresses the node actually assigned.
        tracing::info!(sandbox = sandbox.id, node = node_id, "sandbox placed");
        Ok(Response::new(sandbox))
    }

    async fn get_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let mut sandbox = self
            .0
            .sandboxes
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        // The registry holds the last state the node reported, which is a stale
        // guess once that node stops heartbeating.
        sandbox.is_unreachable = !sandbox.node_id.is_empty() && self.is_node_dead(&sandbox.node_id);
        Ok(Response::new(sandbox))
    }

    /// Lists from the registry, and filters there.
    ///
    /// The registry already holds every sandbox in the fleet (nodes reconcile
    /// it on registration and restate it on every heartbeat), so a tag filter
    /// is answered here rather than fanned out to each node and merged.
    async fn list_sandboxes(
        &self,
        req: Request<api::ListSandboxesRequest>,
    ) -> Result<Response<api::ListSandboxesResponse>, Status> {
        let filter = req.into_inner().tag;
        let filter = burrow_common::tags::parse_filter(&filter)?;
        let healthy = self.0.nodes.healthy_ids();
        let mut sandboxes = self.0.sandboxes.list_tagged(filter);
        for sandbox in &mut sandboxes {
            sandbox.is_unreachable =
                !sandbox.node_id.is_empty() && !healthy.contains(&sandbox.node_id);
        }
        Ok(Response::new(api::ListSandboxesResponse { sandboxes }))
    }

    async fn delete_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::DeleteSandboxResponse>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let node_id = self.node_of(&id)?;
        // Nothing on any node to destroy, so no tombstone either: the stored
        // state is all there is.
        if node_id.is_empty() {
            self.purge(&id).await?;
            self.0.sandboxes.remove(&id);
            return Ok(Response::new(api::DeleteSandboxResponse {}));
        }
        let mut client = match self.node_for(&id).await {
            Ok(client) => client,
            // The node is not merely refusing this connection, it has stopped
            // heartbeating. Waiting for it would leave an undeletable sandbox
            // holding its name and its capacity for as long as the node stays
            // down, which for a node that never returns is forever. So the
            // placement is dropped on the orchestrator's word, and a tombstone
            // remembers the delete in case the node comes back still holding it.
            Err(_) if self.is_node_dead(&node_id) => {
                let forgotten = self.0.sandboxes.forget_deleted(&id);
                if let Some(sandbox) = &forgotten {
                    self.release_charge(sandbox);
                }
                tracing::warn!(
                    sandbox = id,
                    node = node_id,
                    name = forgotten
                        .as_ref()
                        .map(|s| s.name.clone())
                        .unwrap_or_default(),
                    "node is unreachable; forgetting the sandbox and recording a \
                     tombstone. It will be destroyed if the node returns"
                );
                return Ok(Response::new(api::DeleteSandboxResponse {}));
            }
            Err(err) => return Err(err),
        };
        client
            .delete_sandbox(nodepb::NodeSandboxRef {
                sandbox_id: id.clone(),
            })
            .await?;
        // Return any capacity still charged optimistically for this sandbox.
        if let Some(sandbox) = self.0.sandboxes.remove(&id) {
            self.release_charge(&sandbox);
        }
        Ok(Response::new(api::DeleteSandboxResponse {}))
    }

    async fn pause_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .pause_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        // The registry mirrors node state, so the new state is written back.
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    async fn resume_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        if let Some(sandbox) = self.unplaced(&id).await {
            return Ok(Response::new(
                self.adopt(sandbox, "", HashMap::new()).await?,
            ));
        }
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .resume_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    async fn stop_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .stop_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    async fn start_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        if let Some(sandbox) = self.unplaced(&id).await {
            return Ok(Response::new(
                self.adopt(sandbox, "", HashMap::new()).await?,
            ));
        }
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .start_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    async fn recreate_sandbox(
        &self,
        req: Request<api::RecreateSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self.resolve(&req.sandbox_id).await;
        let current = self
            .0
            .sandboxes
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        let node_id = current.node_id.clone();
        let mut client = self.node_for(&id).await?;
        // A replacement template has to be where the sandbox is: its disks
        // and volumes do not move, so the template comes to them.
        if !req.template.is_empty() {
            self.replicate_to(&req.template, &node_id).await?;
        }
        let judged = if req.template.is_empty() {
            &current.template
        } else {
            &req.template
        };
        let credentials = self.kit_credentials(&mut client, &node_id, judged).await?;
        let sandbox = client
            .recreate_sandbox(nodepb::NodeRecreateRequest {
                sandbox_id: id,
                template: req.template,
                kit: req.kit,
                credentials,
            })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    async fn set_secret(
        &self,
        req: Request<api::SetSecretRequest>,
    ) -> Result<Response<api::SetSecretResponse>, Status> {
        let req = req.into_inner();
        validate_secret_name(&req.name)?;
        if req.value.is_empty() {
            return Err(Status::invalid_argument("a secret needs a value"));
        }
        self.secrets()?
            .set(&req.name, &req.value)
            .await
            .map_err(internal)?;
        Ok(Response::new(api::SetSecretResponse {}))
    }

    async fn list_secrets(
        &self,
        _req: Request<api::ListSecretsRequest>,
    ) -> Result<Response<api::ListSecretsResponse>, Status> {
        let names = self.secrets()?.list().await.map_err(internal)?;
        Ok(Response::new(api::ListSecretsResponse { names }))
    }

    async fn delete_secret(
        &self,
        req: Request<api::DeleteSecretRequest>,
    ) -> Result<Response<api::DeleteSecretResponse>, Status> {
        let name = req.into_inner().name;
        let removed = self.secrets()?.delete(&name).await.map_err(internal)?;
        if !removed {
            return Err(Status::not_found(format!("no secret {name}")));
        }
        Ok(Response::new(api::DeleteSecretResponse {}))
    }

    /// Read from the node that ran the VMs, like any other per-sandbox fact.
    ///
    /// Not mirrored in the registry: a session list is bounded per sandbox but
    /// unbounded across a fleet's lifetime, and nothing about placement or
    /// capacity is decided from it.
    async fn list_sessions(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::ListSessionsResponse>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let mut client = self.node_for(&id).await?;
        let sessions = client
            .list_sessions(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        Ok(Response::new(sessions))
    }

    /// Moves a sandbox's lifetime clocks on the owning node.
    ///
    /// The node holds the durable record and the reaper that reads it, so the
    /// registry mirror is updated from what the node returns rather than from
    /// the request.
    async fn update_resources(
        &self,
        req: Request<api::UpdateResourcesRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self
            .resolve(
                &req.r#ref
                    .map(|r| r.id)
                    .ok_or_else(|| Status::invalid_argument("ref is required"))?,
            )
            .await;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_resources(nodepb::NodeUpdateResourcesRequest {
                sandbox_id: id,
                max_lifetime_secs: req.max_lifetime_secs,
                idle_suspend_secs: req.idle_suspend_secs,
                suspended_ttl_secs: req.suspended_ttl_secs,
                vcpus: req.vcpus,
                mem_mib: req.mem_mib,
                scratch_disk_mib: req.scratch_disk_mib,
            })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    /// Forks onto the source's own node.
    ///
    /// A sandbox's snapshot, disks and address lease are node-local files, so
    /// there is nothing to place: the child is built where the state already
    /// is. The node is charged for it afterwards, from the record it returns,
    /// because placement never got a say.
    async fn fork_sandbox(
        &self,
        req: Request<api::ForkSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let mut req = req.into_inner();
        if let Some(network) = req.policy.as_mut().and_then(|p| p.network.as_mut()) {
            self.resolve_secret_refs(network).await?;
        }
        let source_id = self
            .resolve(
                &req.r#ref
                    .map(|r| r.id)
                    .ok_or_else(|| Status::invalid_argument("ref is required"))?,
            )
            .await;
        let node_id = self.node_of(&source_id)?;
        // A fork has no placement decision to constrain: the child is built
        // where its source's state is, so labels are checked against that node
        // before anything is built.
        burrow_common::tags::validate_labels(&req.node_labels)?;
        self.require_labels(&node_id, &req.node_labels)?;
        let child_id = if req.sandbox_id.is_empty() {
            burrow_common::SandboxId::generate().to_string()
        } else {
            validate_sandbox_id(&req.sandbox_id)?;
            req.sandbox_id
        };
        // Held until the child is in the registry, so two forks naming the
        // same child cannot both be built.
        let _reserved = self
            .0
            .sandboxes
            .reserve_claimed(&child_id, &req.name)
            .await
            .map_err(Status::already_exists)?;

        let mut client = self.node_for(&source_id).await?;
        let sandbox = client
            .fork_sandbox(nodepb::NodeForkRequest {
                sandbox_id: source_id.clone(),
                child_id: child_id.clone(),
                policy: req.policy,
                name: req.name,
            })
            .await?
            .into_inner();

        self.0.sandboxes.insert(sandbox.clone());
        tracing::info!(
            source = source_id,
            sandbox = child_id,
            node = node_id,
            "sandbox forked"
        );
        Ok(Response::new(sandbox))
    }

    /// Takes a snapshot of a sandbox, on the node that runs it.
    ///
    /// The sandbox keeps running. Nothing is placed: a snapshot is written
    /// beside the sandbox whose state it holds, and it stays on that node.
    async fn move_sandbox(
        &self,
        req: Request<api::MoveSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        burrow_common::tags::validate_labels(&req.node_labels)?;
        let id = self
            .resolve(&req.r#ref.map(|r| r.id).unwrap_or_default())
            .await;
        // Read from the store rather than the cache: the sandbox may have
        // moved through another replica in the last second.
        let mut current = self
            .0
            .sandboxes
            .refresh(&id)
            .await
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        if current.node_id.is_empty() {
            let moved = self.adopt(current, &req.node_id, req.node_labels).await?;
            return Ok(Response::new(moved));
        }
        let source = current.node_id.clone();
        if req.node_id == source {
            return Err(Status::invalid_argument(format!(
                "sandbox {id} is already on node {source}"
            )));
        }
        // Refused before anything is suspended: a volume is a disk on the
        // source node and cannot follow the sandbox.
        let mounts = current
            .policy
            .as_ref()
            .map(|p| p.volumes.as_slice())
            .unwrap_or_default();
        if mounts.iter().any(|mount| !mount.is_tmpfs) {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} mounts volumes, which are node-local and do not move"
            )));
        }
        if current.arch.is_empty() {
            let info = self.0.nodes.info(&source).unwrap_or_default();
            current.arch = info.arch;
            current.firecracker_version = info.firecracker_version;
        }
        // The destination is chosen before anything is suspended, so a move
        // that has nowhere to go leaves the sandbox running where it is.
        let placed = if req.node_id.is_empty() {
            let want = self.adoption_placement(&current, req.node_labels.clone());
            let target = self
                .place_avoiding(&want, std::collections::HashSet::from([source.clone()]))
                .await
                .map_err(placement_status)?;
            let guard = self.place_guard(&target, &want);
            Some((target, guard))
        } else if self.0.nodes.endpoint(&req.node_id).is_none() {
            return Err(Status::unavailable(format!(
                "node {} is unreachable",
                req.node_id
            )));
        } else {
            None
        };
        let target = placed
            .as_ref()
            .map_or_else(|| req.node_id.clone(), |(target, _)| target.clone());
        let mut client = self.node_for(&id).await?;
        let released = client
            .release_sandbox(nodepb::NodeSandboxRef {
                sandbox_id: id.clone(),
            })
            .await?
            .into_inner();
        // Between the two nodes the sandbox is nowhere, and recorded so: if
        // the adopt fails, a later start places it rather than routing to a
        // node that has let go of it.
        let mut released = self.0.sandboxes.unplace(released);
        self.release_charge(&common::Sandbox {
            node_id: source.clone(),
            ..released.clone()
        });
        if released.arch.is_empty() {
            released.arch = current.arch;
            released.firecracker_version = current.firecracker_version;
        }
        tracing::info!(sandbox = id, node = source, "sandbox released for a move");
        let moved = self.adopt(released, &target, req.node_labels).await?;
        if let Some((_, guard)) = placed {
            guard.keep();
        }
        Ok(Response::new(moved))
    }

    async fn create_snapshot(
        &self,
        req: Request<api::CreateSnapshotRequest>,
    ) -> Result<Response<common::Snapshot>, Status> {
        let req = req.into_inner();
        let sandbox_id = self
            .resolve(
                &req.r#ref
                    .map(|r| r.id)
                    .ok_or_else(|| Status::invalid_argument("ref is required"))?,
            )
            .await;
        let node_id = self.node_of(&sandbox_id)?;
        // The orchestrator owns the id namespace, here as everywhere else.
        let snapshot_id = burrow_common::SnapshotId::generate().to_string();

        let mut client = self.node_for(&sandbox_id).await?;
        let snapshot = client
            .create_snapshot(nodepb::NodeCreateSnapshotRequest {
                sandbox_id: sandbox_id.clone(),
                snapshot_id,
                expiration_secs: req.expiration_secs,
            })
            .await?
            .into_inner();

        self.0.snapshots.insert(&node_id, snapshot.clone());
        // Read back so the caller is told the node it is pinned to, which is
        // stamped on insert rather than by the node itself.
        let snapshot = self.0.snapshots.get(&snapshot.id).unwrap_or(snapshot);
        tracing::info!(
            snapshot = snapshot.id,
            sandbox = sandbox_id,
            node = node_id,
            size_bytes = snapshot.size_bytes,
            "snapshot created"
        );
        Ok(Response::new(snapshot))
    }

    /// Lists from the registry, which every node reconciles on registration
    /// and corrects on every heartbeat. Fanning out would ask each node for
    /// what one map already holds.
    async fn list_snapshots(
        &self,
        req: Request<api::ListSnapshotsRequest>,
    ) -> Result<Response<api::ListSnapshotsResponse>, Status> {
        let sandbox = req.into_inner().sandbox;
        let sandbox = if sandbox.is_empty() {
            None
        } else {
            Some(self.resolve(&sandbox).await)
        };
        Ok(Response::new(api::ListSnapshotsResponse {
            snapshots: self.0.snapshots.list(sandbox.as_deref()),
        }))
    }

    async fn get_snapshot(
        &self,
        req: Request<api::SnapshotRef>,
    ) -> Result<Response<common::Snapshot>, Status> {
        let id = req.into_inner().id;
        self.snapshot(&id)
            .await
            .map(Response::new)
            .ok_or_else(|| Status::not_found(format!("no snapshot {id}")))
    }

    async fn delete_snapshot(
        &self,
        req: Request<api::SnapshotRef>,
    ) -> Result<Response<api::DeleteSnapshotResponse>, Status> {
        let id = req.into_inner().id;
        let (_, _, mut client) = self
            .node_for_snapshot(&id, &crate::registry::Placement::default())
            .await?;
        client
            .delete_snapshot(api::SnapshotRef { id: id.clone() })
            .await?;
        // Only after the node has actually removed it: a record dropped on a
        // failed delete would leave disk nothing ever reclaims.
        self.0.snapshots.remove(&id);
        Ok(Response::new(api::DeleteSnapshotResponse {}))
    }

    /// Creates a volume on one node, which is then where it lives.
    ///
    /// Placed like a sandbox, because that is what the choice decides: every
    /// sandbox that ever mounts this volume is pinned to the node it lands on.
    async fn create_volume(
        &self,
        req: Request<api::CreateVolumeRequest>,
    ) -> Result<Response<common::Volume>, Status> {
        let req = req.into_inner();
        burrow_common::tags::validate_labels(&req.node_labels)?;
        if self.0.volumes.get(&req.name).is_some() {
            return Err(Status::already_exists(format!(
                "volume {} exists",
                req.name
            )));
        }

        // Sized as the sandbox charge is: a volume takes disk rather than
        // memory, so it is placed on labels and health alone.
        let want = crate::registry::Placement {
            template: String::new(),
            prefer_node: None,
            is_mesh_available: self.0.nodes.is_mesh_available(""),
            vcpus: 1,
            mem_mib: 0,
            is_template_transfer_allowed: true,
            node_labels: req.node_labels.clone(),
            arch: String::new(),
            firecracker_version: String::new(),
        };
        let node_id = self.place(&want).await.map_err(|err| match err {
            crate::registry::PlacementError::NoHealthyNode
            | crate::registry::PlacementError::NoCapacity { .. } => {
                Status::resource_exhausted(err.to_string())
            }
            other => Status::failed_precondition(other.to_string()),
        })?;
        let endpoint = self
            .0
            .nodes
            .endpoint(&node_id)
            .ok_or_else(|| Status::unavailable(format!("node {node_id} went away")))?;
        let mut client = self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node {node_id}: {err}")))?;

        let volume = client.create_volume(req).await?.into_inner();
        self.0.volumes.insert(&node_id, volume.clone());
        // Read back for the node stamp, which the node cannot know for itself.
        let volume = self.0.volumes.get(&volume.name).unwrap_or(volume);
        tracing::info!(
            volume = volume.name,
            node = node_id,
            size_mib = volume.size_mib,
            "volume created"
        );
        Ok(Response::new(volume))
    }

    async fn list_volumes(
        &self,
        req: Request<api::ListVolumesRequest>,
    ) -> Result<Response<api::ListVolumesResponse>, Status> {
        let node_id = req.into_inner().node_id;
        let filter = (!node_id.is_empty()).then_some(node_id.as_str());
        Ok(Response::new(api::ListVolumesResponse {
            volumes: self.0.volumes.list(filter),
        }))
    }

    /// Reads a volume from the node holding it, so the writable claim is live
    /// rather than whatever the registry last cached.
    async fn get_volume(
        &self,
        req: Request<api::VolumeRef>,
    ) -> Result<Response<common::Volume>, Status> {
        let name = req.into_inner().name;
        let (node_id, mut client) = self.node_holding_volume(&name).await?;
        let mut volume = client
            .get_volume(api::VolumeRef { name })
            .await?
            .into_inner();
        volume.node_id = node_id;
        Ok(Response::new(volume))
    }

    async fn delete_volume(
        &self,
        req: Request<api::VolumeRef>,
    ) -> Result<Response<api::DeleteVolumeResponse>, Status> {
        let name = req.into_inner().name;
        let (_, mut client) = self.node_holding_volume(&name).await?;
        client
            .delete_volume(api::VolumeRef { name: name.clone() })
            .await?;
        // Only after the node removed it: a record dropped on a failed delete
        // would leave disk nothing ever reclaims.
        self.0.volumes.remove(&name);
        Ok(Response::new(api::DeleteVolumeResponse {}))
    }

    /// Replaces a sandbox's tags on the owning node.
    ///
    /// The node holds the durable record, so the registry mirror is updated
    /// from what the node returns rather than from the request.
    async fn update_tags(
        &self,
        req: Request<api::UpdateTagsRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self
            .resolve(
                &req.r#ref
                    .map(|r| r.id)
                    .ok_or_else(|| Status::invalid_argument("ref is required"))?,
            )
            .await;
        burrow_common::tags::validate(&req.tags)?;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_tags(nodepb::NodeUpdateTagsRequest {
                sandbox_id: id,
                tags: req.tags,
            })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    /// Re-points a sandbox's exec and file policies at the owning node.
    ///
    /// The node is the enforcement point and validates the sections itself, so
    /// they are forwarded as they arrived, including their presence: that is
    /// what carries "leave this section alone" to the record.
    async fn update_access_policy(
        &self,
        req: Request<api::UpdateAccessPolicyRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self
            .resolve(
                &req.r#ref
                    .map(|r| r.id)
                    .ok_or_else(|| Status::invalid_argument("ref is required"))?,
            )
            .await;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_access_policy(nodepb::NodeUpdateAccessRequest {
                sandbox_id: id,
                exec: req.exec,
                fs: req.fs,
            })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    /// Re-points a running sandbox's egress policy at the owning node.
    ///
    /// The node is the enforcement point and validates the policy itself. The
    /// registry mirror is updated from the record the node returns rather than
    /// from the request, including its redaction of brokered credentials.
    async fn update_network_policy(
        &self,
        req: Request<api::UpdateNetworkPolicyRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self
            .resolve(
                &req.r#ref
                    .map(|r| r.id)
                    .ok_or_else(|| Status::invalid_argument("ref is required"))?,
            )
            .await;
        let mut network = req
            .network
            .ok_or_else(|| Status::invalid_argument("network is required"))?;
        self.resolve_secret_refs(&mut network).await?;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_network_policy(nodepb::NodeUpdateNetworkRequest {
                sandbox_id: id,
                network: Some(network),
            })
            .await?
            .into_inner();
        self.0.sandboxes.insert(sandbox.clone());
        Ok(Response::new(sandbox))
    }

    type BuildTemplateStream = BoxStream<api::BuildLog>;

    /// Builds on one node.
    ///
    /// Templates are node-local files, so a build only produces an image on the
    /// node that ran it; placement pins to nodes that hold it, and copies it
    /// on demand. See `place_for`.
    async fn build_template(
        &self,
        req: Request<api::BuildTemplateRequest>,
    ) -> Result<Response<Self::BuildTemplateStream>, Status> {
        let node_id = self
            .0
            .nodes
            .place()
            .ok_or_else(|| Status::resource_exhausted("no healthy node available"))?;
        let endpoint = self
            .0
            .nodes
            .endpoint(&node_id)
            .ok_or_else(|| Status::unavailable(format!("node {node_id} went away")))?;
        let mut client = connect_node(endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node {node_id}: {err}")))?;

        let stream = client.build_template(req.into_inner()).await?.into_inner();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_templates(
        &self,
        _req: Request<api::ListTemplatesRequest>,
    ) -> Result<Response<api::ListTemplatesResponse>, Status> {
        // Reported per node and merged, since an image built on one node does
        // not exist on the others.
        let mut seen: std::collections::BTreeMap<String, api::TemplateInfo> =
            std::collections::BTreeMap::new();
        // Dialled together rather than one after another: sequentially, this
        // costs the sum of the fleet's round trips.
        let polled = futures::future::join_all(reachable_nodes(&self.0).into_iter().map(
            |(_, endpoint)| async move {
                let mut client = connect_node_unary(endpoint, self.0.node_token.as_deref())
                    .await
                    .ok()?;
                client
                    .list_templates(api::ListTemplatesRequest {})
                    .await
                    .ok()
            },
        ))
        .await;
        for resp in polled.into_iter().flatten() {
            for template in resp.into_inner().templates {
                match seen.get_mut(&template.name) {
                    // Merged rather than overwritten. A warm snapshot is
                    // node-local, so one node holding the template cold says
                    // nothing about another holding it warm, and letting the
                    // last node polled win reported a template as cold while a
                    // create from it restored in milliseconds. Warm anywhere is
                    // the answer that matches what placement does with it,
                    // since placement prefers a node that has one.
                    Some(existing) => {
                        existing.is_warm |= template.is_warm;
                        existing.size_bytes = existing.size_bytes.max(template.size_bytes);
                    }
                    None => {
                        seen.insert(template.name.clone(), template);
                    }
                }
            }
        }
        Ok(Response::new(api::ListTemplatesResponse {
            templates: seen.into_values().collect(),
        }))
    }

    async fn delete_template(
        &self,
        req: Request<api::DeleteTemplateRequest>,
    ) -> Result<Response<api::DeleteTemplateResponse>, Status> {
        let req = req.into_inner();
        let mut removed = false;
        let mut last_error = None;
        // A template can be on any number of nodes, so every node is asked,
        // and asked at once.
        let outcomes = futures::future::join_all(reachable_nodes(&self.0).into_iter().map({
            let req = &req;
            move |(_, endpoint)| async move {
                let mut client = connect_node_unary(endpoint, self.0.node_token.as_deref())
                    .await
                    .ok()?;
                Some(client.delete_template(req.clone()).await)
            }
        }))
        .await;
        for outcome in outcomes.into_iter().flatten() {
            match outcome {
                Ok(_) => removed = true,
                Err(err) if err.code() == tonic::Code::NotFound => {}
                Err(err) => last_error = Some(err),
            }
        }
        match (removed, last_error) {
            (true, _) => Ok(Response::new(api::DeleteTemplateResponse {})),
            (false, Some(err)) => Err(err),
            (false, None) => Err(Status::not_found(format!("no template {}", req.name))),
        }
    }

    async fn expose_port(
        &self,
        req: Request<api::ExposePortRequest>,
    ) -> Result<Response<api::PortMapping>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let node_id = self.node_of(&req.sandbox_id)?;
        let mut client = self.node_for(&req.sandbox_id).await?;
        let sandbox_id = req.sandbox_id.clone();
        let mut mapping = client.expose_port(req).await?.into_inner();
        // Only the orchestrator knows how callers address the node, or what
        // domain its edge serves.
        mapping.host_address = self.node_host(&node_id, mapping.host_port);
        if !mapping.is_udp {
            mapping.edge_url = self.edge_url(&node_id, &sandbox_id, mapping.guest_port);
        }
        Ok(Response::new(mapping))
    }

    async fn list_ports(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::ListPortsResponse>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let node_id = self.node_of(&id)?;
        let mut client = self.node_for(&id).await?;
        let mut resp = client
            .list_ports(nodepb::NodeSandboxRef {
                sandbox_id: id.clone(),
            })
            .await?
            .into_inner();
        for mapping in &mut resp.ports {
            mapping.host_address = self.node_host(&node_id, mapping.host_port);
            // The node names the sandbox by whatever it recorded; the edge
            // hostname has to carry the id the router will resolve. A UDP
            // mapping gets none, because the edge only ever carries HTTP.
            if !mapping.is_udp {
                mapping.edge_url = self.edge_url(&node_id, &id, mapping.guest_port);
            }
        }
        Ok(Response::new(resp))
    }

    async fn close_port(
        &self,
        req: Request<api::ClosePortRequest>,
    ) -> Result<Response<api::ClosePortResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.close_port(req).await?.into_inner()))
    }

    async fn share_sandbox(
        &self,
        req: Request<api::ShareRequest>,
    ) -> Result<Response<api::Share>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.share_sandbox(req).await?.into_inner()))
    }

    async fn get_share(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::Share>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let mut client = self.node_for(&id).await?;
        Ok(Response::new(
            client
                .get_share(nodepb::NodeSandboxRef { sandbox_id: id })
                .await?
                .into_inner(),
        ))
    }

    async fn unshare_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::UnshareResponse>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        let mut client = self.node_for(&id).await?;
        Ok(Response::new(
            client
                .unshare_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
                .await?
                .into_inner(),
        ))
    }

    type QueryAuditStream = BoxStream<api::AuditEvent>;

    /// Merges audit records from every node into one newest-first stream.
    ///
    /// Records live on the node that produced them, so answering means asking
    /// each node and interleaving the results. `limit` is applied per node and
    /// again after merging, so a fleet cannot return more than was asked for.
    async fn query_audit(
        &self,
        req: Request<api::AuditQuery>,
    ) -> Result<Response<Self::QueryAuditStream>, Status> {
        let mut query = req.into_inner();
        query.sandbox_id = self.resolve(&query.sandbox_id).await;
        let limit = if query.limit == 0 { 100 } else { query.limit } as usize;

        // Every node holds part of the answer, and the pages are merged
        // anyway, so all of them are asked at once.
        let pages = futures::future::join_all(reachable_nodes(&self.0).into_iter().map({
            let query = &query;
            move |(_, endpoint)| async move {
                let mut client = connect_node_unary(endpoint, self.0.node_token.as_deref())
                    .await
                    .ok()?;
                client.query_audit(query.clone()).await.ok()
            }
        }))
        .await;
        let mut events = Vec::new();
        for page in pages.into_iter().flatten() {
            events.extend(page.into_inner().events);
        }

        // Timestamps are RFC 3339, which sorts lexically.
        events.sort_by(|a, b| b.at.cmp(&a.at));
        events.truncate(limit);

        Ok(Response::new(Box::pin(tokio_stream::iter(
            events.into_iter().map(Ok),
        ))))
    }

    type TailEventsStream = BoxStream<common::Event>;

    /// Replays the fleet log after a position, then follows it. Subscribed
    /// before the replay so nothing between the two is missed, and live
    /// events at or below the last replayed position are dropped so nothing
    /// is doubled.
    async fn tail_events(
        &self,
        req: Request<api::TailEventsRequest>,
    ) -> Result<Response<Self::TailEventsStream>, Status> {
        let req = req.into_inner();
        let sandbox = if req.sandbox.is_empty() {
            None
        } else {
            Some(self.resolve(&req.sandbox).await)
        };
        let limit = if req.limit == 0 {
            1000
        } else {
            req.limit as usize
        };
        let mut live = self.0.events.subscribe();
        let state = Arc::clone(&self.0);
        let stream = async_stream::try_stream! {
            let mut last = req.after_seq;
            let mut sent = 0usize;
            while sent < limit {
                let batch = state
                    .events
                    .replay(last, sandbox.as_deref(), (limit - sent).min(1000))
                    .await
                    .map_err(|err| Status::internal(format!("reading events: {err}")))?;
                if batch.is_empty() {
                    break;
                }
                for event in batch {
                    last = event.seq;
                    sent += 1;
                    yield event;
                }
            }
            if !req.is_follow {
                return;
            }
            // Only the leader copies node logs, so with several replicas the
            // live broadcast is only fed on one of them; every replica can read
            // the shared log, so followers poll it instead.
            if state.events.is_shared() {
                loop {
                    let batch = state
                        .events
                        .replay(last, sandbox.as_deref(), 1000)
                        .await
                        .map_err(|err| Status::internal(format!("reading events: {err}")))?;
                    if batch.is_empty() {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        continue;
                    }
                    for event in batch {
                        last = event.seq;
                        yield event;
                    }
                }
            }
            loop {
                match live.recv().await {
                    Ok(event) => {
                        if event.seq > last
                            && sandbox.as_deref().is_none_or(|id| event.sandbox_id == id)
                        {
                            last = event.seq;
                            yield event;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let batch = state
                            .events
                            .replay(last, sandbox.as_deref(), 1000)
                            .await
                            .map_err(|err| Status::internal(format!("reading events: {err}")))?;
                        for event in batch {
                            last = event.seq;
                            yield event;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    type ExecStream = BoxStream<api::ExecOutput>;

    async fn exec(
        &self,
        req: Request<tonic::Streaming<api::ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let mut inbound = req.into_inner();

        // Routing needs the sandbox id, which only the first message carries,
        // so it is read here and replayed unchanged to the node.
        let first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("Exec stream closed before Start"))?;
        let mut first = first;
        let Some(api::exec_input::Input::Start(ref mut start)) = first.input else {
            return Err(Status::invalid_argument("first Exec message must be Start"));
        };
        // Rewritten rather than merely resolved: the node is handed this same
        // message, and it only speaks ids.
        start.sandbox_id = self.resolve(&start.sandbox_id).await;

        let mut client = self.node_for(&start.sandbox_id).await?;
        let outbound = async_stream::stream! {
            yield first;
            while let Some(Ok(msg)) = inbound.next().await {
                yield msg;
            }
        };

        let responses = client.exec(outbound).await?.into_inner();
        Ok(Response::new(Box::pin(responses)))
    }

    async fn upload_file(
        &self,
        req: Request<tonic::Streaming<api::FileChunk>>,
    ) -> Result<Response<api::UploadResult>, Status> {
        let mut inbound = req.into_inner();
        let first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("upload stream was empty"))?;

        // Only the first chunk names the sandbox, so this is the one place the
        // reference can be turned into the id the node expects.
        let mut first = first;
        first.sandbox_id = self.resolve(&first.sandbox_id).await;
        let mut client = self.node_for(&first.sandbox_id).await?;

        // tonic's client streaming takes messages, not results, so a failed
        // read from the caller cannot be forwarded down the stream, and ending
        // it quietly is what the node reads as a complete upload. The error is
        // parked here instead and becomes this RPC's own failure.
        let failed: Arc<std::sync::Mutex<Option<Status>>> = Arc::default();
        let sink = Arc::clone(&failed);
        let outbound = async_stream::stream! {
            yield first;
            while let Some(chunk) = inbound.next().await {
                match chunk {
                    Ok(chunk) => yield chunk,
                    Err(err) => {
                        *sink.lock().unwrap() = Some(err);
                        break;
                    }
                }
            }
        };
        let result = client.upload_file(outbound).await;
        if let Some(err) = failed.lock().unwrap().take() {
            return Err(Status::new(
                err.code(),
                format!(
                    "the upload was cut short, leaving a partial file: {}",
                    err.message()
                ),
            ));
        }
        Ok(Response::new(result?.into_inner()))
    }

    type DownloadFileStream = BoxStream<api::FileChunk>;

    async fn download_file(
        &self,
        req: Request<api::DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        let stream = client.download_file(req).await?.into_inner();
        Ok(Response::new(Box::pin(stream)))
    }

    type WatchStream = BoxStream<api::WatchEvent>;

    async fn watch(
        &self,
        req: Request<api::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        // Watches are long-lived by nature, so no deadline is imposed here;
        // the client ends it by dropping the stream.
        let stream = client.watch(req).await?.into_inner();
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_dir(
        &self,
        req: Request<api::ListDirRequest>,
    ) -> Result<Response<api::ListDirResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.list_dir(req).await?.into_inner()))
    }

    type AttachStream = BoxStream<api::ExecOutput>;

    async fn attach(
        &self,
        req: Request<tonic::Streaming<api::AttachInput>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        let mut inbound = req.into_inner();
        // Routed by the first message, as an exec is, and replayed unchanged.
        let mut first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("Attach stream closed before Start"))?;
        let Some(api::attach_input::Input::Start(ref mut start)) = first.input else {
            return Err(Status::invalid_argument(
                "first Attach message must be Start",
            ));
        };
        start.sandbox_id = self.resolve(&start.sandbox_id).await;
        let mut client = self.node_for(&start.sandbox_id).await?;
        let outbound = async_stream::stream! {
            yield first;
            while let Some(Ok(msg)) = inbound.next().await {
                yield msg;
            }
        };
        let responses = client.attach(outbound).await?.into_inner();
        Ok(Response::new(Box::pin(responses)))
    }

    async fn issue_access(
        &self,
        req: Request<api::IssueAccessRequest>,
    ) -> Result<Response<api::AccessGrant>, Status> {
        use burrow_common::access;

        let req = req.into_inner();
        let signer = self.0.access.as_ref().ok_or_else(|| {
            Status::failed_precondition("this orchestrator has no key to sign access tokens with")
        })?;
        let id = self
            .resolve(&req.r#ref.map(|r| r.id).unwrap_or_default())
            .await;
        let node_id = self.placed_on(&id).await?;
        let endpoint = self
            .0
            .nodes
            .info(&node_id)
            .map(|info| info.access_endpoint)
            .unwrap_or_default();
        if endpoint.is_empty() {
            return Err(Status::failed_precondition(format!(
                "node {node_id} serves no Access endpoint; exec and files for {id} go \
                 through the orchestrator"
            )));
        }
        let mut ops = if req.ops.is_empty() {
            access::ALL_OPS.map(String::from).to_vec()
        } else {
            req.ops
        };
        ops.sort();
        ops.dedup();
        if let Some(unknown) = ops
            .iter()
            .find(|op| !access::ALL_OPS.contains(&op.as_str()))
        {
            return Err(Status::invalid_argument(format!(
                "unknown access op {unknown:?}; expected one of {}",
                access::ALL_OPS.join(", ")
            )));
        }
        let ttl_secs = match req.ttl_secs {
            0 => access::DEFAULT_TTL_SECS,
            secs if secs > access::MAX_TTL_SECS => {
                return Err(Status::invalid_argument(format!(
                    "ttl_secs is at most {}",
                    access::MAX_TTL_SECS
                )));
            }
            secs => secs,
        };
        let claims = access::Claims::new(&node_id, &id, ops, req.user, ttl_secs);
        let token = signer
            .sign(&claims)
            .map_err(|err| Status::internal(err.to_string()))?;
        tracing::info!(
            sandbox = id,
            node = node_id,
            ops = ?claims.ops,
            ttl_secs,
            jti = claims.jti,
            "issued an access token"
        );
        Ok(Response::new(api::AccessGrant {
            endpoint,
            token,
            expires_at: claims.exp as i64,
            node_id,
            sandbox_id: claims.sub,
        }))
    }

    async fn revoke_access(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::RevokeAccessResponse>, Status> {
        let id = self.resolve(&req.into_inner().id).await;
        // A sandbox no node holds has no sessions to end, and its tokens are
        // refused by whichever node adopts it, which is handed this record.
        if let Some(mut sandbox) = self.unplaced(&id).await {
            sandbox.access_revoked_at = burrow_common::unix_now();
            let revoked_at = sandbox.access_revoked_at;
            self.0.sandboxes.insert(sandbox);
            if let Some(writer) = self.0.sandboxes.writer() {
                writer.flush().await;
            }
            tracing::info!(sandbox = id, "access tokens revoked");
            return Ok(Response::new(api::RevokeAccessResponse {
                revoked_at,
                ended_sessions: 0,
            }));
        }
        let mut client = self.node_for(&id).await?;
        let revoked = client
            .revoke_access(nodepb::NodeSandboxRef {
                sandbox_id: id.clone(),
            })
            .await?
            .into_inner();
        tracing::info!(
            sandbox = id,
            ended_sessions = revoked.ended_sessions,
            "access tokens revoked"
        );
        Ok(Response::new(revoked))
    }

    async fn list_commands(
        &self,
        req: Request<api::ListCommandsRequest>,
    ) -> Result<Response<api::ListCommandsResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.list_commands(req).await?.into_inner()))
    }

    async fn get_command(
        &self,
        req: Request<api::GetCommandRequest>,
    ) -> Result<Response<api::CommandInfo>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.get_command(req).await?.into_inner()))
    }

    async fn signal_command(
        &self,
        req: Request<api::SignalCommandRequest>,
    ) -> Result<Response<api::SignalCommandResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(
            client.signal_command(req).await?.into_inner(),
        ))
    }

    async fn prune_commands(
        &self,
        req: Request<api::PruneCommandsRequest>,
    ) -> Result<Response<api::PruneCommandsResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(
            client.prune_commands(req).await?.into_inner(),
        ))
    }

    async fn create_user(
        &self,
        req: Request<api::CreateUserRequest>,
    ) -> Result<Response<api::CreateUserResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.create_user(req).await?.into_inner()))
    }

    async fn create_group(
        &self,
        req: Request<api::CreateGroupRequest>,
    ) -> Result<Response<api::CreateGroupResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.create_group(req).await?.into_inner()))
    }

    async fn add_user_to_group(
        &self,
        req: Request<api::GroupMembershipRequest>,
    ) -> Result<Response<api::GroupMembershipResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(
            client.add_user_to_group(req).await?.into_inner(),
        ))
    }

    async fn remove_user_from_group(
        &self,
        req: Request<api::GroupMembershipRequest>,
    ) -> Result<Response<api::GroupMembershipResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(
            client.remove_user_from_group(req).await?.into_inner(),
        ))
    }
}

/// Checks an id the caller chose for a new sandbox.
///
/// Sandbox ids end up in filenames on a node and in edge hostnames as
/// `<port>-<id>.<domain>`, so the charset is the one template names use and the
/// length is capped short of a DNS label. Generated ids (`sbx_<uuid>`) satisfy
/// the same rules, which keeps chosen and generated ids interchangeable
/// everywhere downstream.
/// The status a caller is given for a placement that found nowhere to go.
fn placement_status(err: crate::registry::PlacementError) -> Status {
    match err {
        crate::registry::PlacementError::NoHealthyNode
        | crate::registry::PlacementError::NoCapacity { .. } => {
            Status::resource_exhausted(err.to_string())
        }
        crate::registry::PlacementError::PeersUnreachable(_)
        | crate::registry::PlacementError::NoNodeWithLabels(_)
        | crate::registry::PlacementError::NoCompatibleNode { .. } => {
            Status::failed_precondition(err.to_string())
        }
        other => Status::not_found(other.to_string()),
    }
}

fn validate_sandbox_id(id: &str) -> Result<(), Status> {
    if id.len() > 63 {
        return Err(Status::invalid_argument(
            "sandbox_id may be at most 63 bytes",
        ));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !id.starts_with('.');
    if !ok {
        return Err(Status::invalid_argument(
            "sandbox_id may contain only letters, digits, '-', '_', '.' and may not start with '.'",
        ));
    }
    Ok(())
}

const SECRET_REF: &str = "${secret:";

fn internal(err: anyhow::Error) -> Status {
    Status::internal(format!("{err:#}"))
}

/// Gives back capacity in the store from code that cannot wait for it.
fn release_in_store(
    store: Option<Arc<burrow_store::Store>>,
    node_id: &str,
    vcpus: u32,
    mem_mib: u64,
) {
    let Some(store) = store else { return };
    let node_id = node_id.to_string();
    tokio::spawn(async move {
        if let Err(err) = store.release_capacity(&node_id, vcpus, mem_mib).await {
            tracing::warn!(node_id, %err, "could not release capacity in the store");
        }
    });
}

fn substitute_secret_refs(
    value: &str,
    mut lookup: impl FnMut(&str) -> Result<String, Status>,
) -> Result<String, Status> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find(SECRET_REF) {
        out.push_str(&rest[..start]);
        let after = &rest[start + SECRET_REF.len()..];
        let end = after
            .find('}')
            .ok_or_else(|| Status::invalid_argument("unterminated ${secret:...} reference"))?;
        let name = &after[..end];
        validate_secret_name(name)?;
        out.push_str(&lookup(name)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Lowercase letters, digits and dashes, at most `max` bytes, with no
/// leading or trailing dash.
fn is_kebab(name: &str, max: usize) -> bool {
    (1..=max).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

fn validate_secret_name(name: &str) -> Result<(), Status> {
    if !is_kebab(name, 64) {
        return Err(Status::invalid_argument(format!(
            "secret name {name:?} must be lowercase kebab-case, 1 to 64 characters"
        )));
    }
    Ok(())
}

/// Checks a caller-chosen sandbox name.
///
/// A name goes into hostnames and command lines, and it has to be told apart
/// from an id at a glance, so it is a DNS label: lowercase letters, digits and
/// dashes, no leading or trailing dash. Generated ids carry a `sbx_` prefix and
/// underscores, neither of which a name may contain, so the two namespaces
/// cannot overlap.
fn validate_name(name: &str) -> Result<(), Status> {
    if !is_kebab(name, 63) {
        return Err(Status::invalid_argument(
            "name must be 1-63 characters of lowercase letters, digits and '-', \
             and may not start or end with '-'",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_references_substitute_in_place() {
        let lookup = |name: &str| match name {
            "github" => Ok("ghp_x".to_string()),
            other => Err(Status::failed_precondition(format!("no secret {other}"))),
        };
        assert_eq!(
            substitute_secret_refs("Bearer ${secret:github}", lookup).unwrap(),
            "Bearer ghp_x"
        );
        assert_eq!(substitute_secret_refs("plain", lookup).unwrap(), "plain");
        assert_eq!(
            substitute_secret_refs("${secret:github}:${secret:github}", lookup).unwrap(),
            "ghp_x:ghp_x"
        );
        assert!(substitute_secret_refs("${secret:missing}", lookup).is_err());
        assert!(substitute_secret_refs("${secret:github", lookup).is_err());
        assert!(substitute_secret_refs("${secret:Bad Name}", lookup).is_err());
    }

    #[test]
    fn a_name_is_a_dns_label() {
        for good in ["api", "build-482", "a", "x9", &"a".repeat(63)] {
            assert!(validate_name(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn a_name_that_could_be_mistaken_for_an_id_or_a_hostname_is_refused() {
        for bad in [
            "",
            "-api",
            "api-",
            "API",
            "my_api",
            "sbx_abc",
            "api.internal",
            &"a".repeat(64),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_chosen_id_follows_the_same_rules_as_a_generated_one() {
        for good in ["build-482", "my_sandbox", "a.b", "sbx_abc123", "x"] {
            assert!(validate_sandbox_id(good).is_ok(), "{good:?}");
        }
        assert!(validate_sandbox_id(&burrow_common::SandboxId::generate().to_string()).is_ok());
    }

    #[test]
    fn an_id_that_could_escape_a_path_or_a_hostname_is_refused() {
        for bad in [
            "../etc",
            ".hidden",
            "has space",
            "sbx/1",
            "sbx:1",
            &"a".repeat(64),
        ] {
            assert!(validate_sandbox_id(bad).is_err(), "{bad:?}");
        }
    }
}
