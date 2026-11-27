//! The public API: placement plus routing to the node that owns a sandbox.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use burrow_common::hypervisor::Hypervisor;
use burrow_proto::api::v1 as api;
use burrow_proto::api::v1::burrow_server::Burrow;
use burrow_proto::common::v1 as common;
use burrow_proto::node::v1 as nodepb;
use burrow_proto::node::v1::node_service_client::NodeServiceClient;

use crate::OrchestratorState;

#[path = "ips.rs"]
pub mod ips;

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

fn node_client(channel: tonic::transport::Channel, token: Option<&str>) -> NodeClient {
    NodeServiceClient::with_interceptor(channel, NodeAuth(token.map(str::to_string)))
        .max_decoding_message_size(burrow_proto::MAX_MESSAGE_BYTES)
        .max_encoding_message_size(burrow_proto::MAX_MESSAGE_BYTES)
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
    Ok(node_client(channel, token))
}

/// Dials a node for a one-shot call, with a deadline on it.
///
/// Used by the fan-outs, where one wedged node must not hold up an answer the
/// rest of the fleet has already given.
pub(crate) async fn connect_node_unary(
    endpoint: String,
    token: Option<&str>,
) -> Result<NodeClient, tonic::transport::Error> {
    let channel = node_endpoint(endpoint)?
        .timeout(NODE_REQUEST_TIMEOUT)
        .connect()
        .await?;
    Ok(node_client(channel, token))
}

/// How long a node gets to carry out a delete before the caller is answered
/// anyway. One it has not finished by then it finishes at its next heartbeat.
const DELETE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// Destroys `sandbox_id` on `node_id`, through the node's admission slots.
pub async fn delete_on_node(
    state: &OrchestratorState,
    node_id: &str,
    sandbox_id: &str,
) -> Result<(), Status> {
    let endpoint = state
        .nodes
        .endpoint_any(node_id)
        .ok_or_else(|| Status::unavailable(format!("no node {node_id}")))?;
    let _admitted = state.admission.admit(node_id).await;
    let mut client = match state
        .channels
        .get(&endpoint, state.node_token.as_deref())
        .await
    {
        Ok(client) => client,
        Err(err) => {
            state.channels.forget(&endpoint).await;
            return Err(Status::unavailable(format!(
                "cannot reach node {node_id}: {err}"
            )));
        }
    };
    let mut request = Request::new(nodepb::NodeSandboxRef {
        sandbox_id: sandbox_id.to_string(),
    });
    request.set_timeout(DELETE_DEADLINE);
    client.delete_sandbox(request).await.map(drop)
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
    cpu_millis: u64,
    mem_mib: u64,
    disk_bytes: u64,
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
            self.nodes.release(
                &self.node_id,
                self.cpu_millis,
                self.mem_mib,
                self.disk_bytes,
            );
            release_in_store(
                self.nodes,
                self.store.clone(),
                &self.node_id,
                self.cpu_millis,
                self.mem_mib,
            );
        }
    }
}

impl ApiService {
    /// Runs a create at most once per request id: a retry of one that made a
    /// sandbox gets that sandbox, and one of a create still running waits for
    /// it, up to [`REQUEST_WAIT`].
    ///
    /// A node that could not be heard from may still be building the
    /// sandbox, so then the claim is held until it is reported or
    /// [`REQUEST_WAIT`] passes, and a retry finds it rather than making
    /// another.
    async fn create_once(
        &self,
        metadata: tonic::metadata::MetadataMap,
        req: api::CreateSandboxRequest,
        reply: tokio::sync::oneshot::Sender<Result<common::Sandbox, Status>>,
    ) {
        let request_id = req.request_id.clone();
        let Some(claim) = self.claimed(metadata, req, reply).await else {
            return;
        };
        let deadline = std::time::Instant::now() + REQUEST_WAIT;
        while std::time::Instant::now() < deadline
            && self.0.sandboxes.by_request(&request_id).await.is_none()
        {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        drop(claim);
    }

    /// Runs the create and answers `reply`, returning the request claim when
    /// the node's outcome is unknown.
    async fn claimed(
        &self,
        metadata: tonic::metadata::MetadataMap,
        req: api::CreateSandboxRequest,
        reply: tokio::sync::oneshot::Sender<Result<common::Sandbox, Status>>,
    ) -> Option<crate::sandboxes::RequestClaim> {
        let sandbox_id = burrow_common::SandboxId::generate().to_string();
        if req.request_id.is_empty() {
            let _ = reply.send(self.create_new(metadata, req, sandbox_id).await);
            return None;
        }
        let claim = match self.claim_request(&req.request_id, &sandbox_id).await {
            Ok(Ok(claim)) => claim,
            Ok(Err(sandbox)) => {
                let _ = reply.send(Ok(sandbox));
                return None;
            }
            Err(err) => {
                let _ = reply.send(Err(err));
                return None;
            }
        };
        let created = self.create_new(metadata, req, sandbox_id).await;
        let is_unknown = created.as_ref().is_err_and(is_outcome_unknown);
        let _ = reply.send(created);
        is_unknown.then_some(claim)
    }

    /// Claims `request_id` for a create of `sandbox_id`, or answers with the
    /// sandbox a create of it made, waiting up to [`REQUEST_WAIT`] for one
    /// still running.
    async fn claim_request(
        &self,
        request_id: &str,
        sandbox_id: &str,
    ) -> Result<Result<crate::sandboxes::RequestClaim, common::Sandbox>, Status> {
        let deadline = std::time::Instant::now() + REQUEST_WAIT;
        let claim = loop {
            if let Some(sandbox) = self.0.sandboxes.by_request(request_id).await {
                return Ok(Err(sandbox));
            }
            match self.0.sandboxes.claim_request(request_id, sandbox_id).await {
                Ok(claim) => break claim,
                Err(err)
                    if err.code() == tonic::Code::Aborted
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(REQUEST_POLL).await
                }
                Err(err) if err.code() == tonic::Code::Aborted => {
                    return Err(Status::aborted(format!(
                        "a create with request id {request_id} is still running; retry it"
                    )));
                }
                Err(err) => return Err(err),
            }
        };
        // The create holding the claim may have finished between the lookup
        // and the claim.
        match self.0.sandboxes.by_request(request_id).await {
            Some(sandbox) => Ok(Err(sandbox)),
            None => Ok(Ok(claim)),
        }
    }

    async fn create_new(
        &self,
        metadata: tonic::metadata::MetadataMap,
        mut req: api::CreateSandboxRequest,
        sandbox_id: String,
    ) -> Result<common::Sandbox, Status> {
        let (public_ips, ip_node, ip_labels) =
            self.ips_for_create(&metadata, &req.public_ips).await?;
        if !public_ips.is_empty() && !req.snapshot.is_empty() {
            return Err(Status::invalid_argument(
                "attach public IPs to a sandbox created from a snapshot once it exists",
            ));
        }
        req.node_labels.extend(ip_labels);
        let activation = self
            .activation_for(
                req.activation.take(),
                crate::secrets::Subject {
                    id: &sandbox_id,
                    name: &req.name,
                    tags: &req.tags,
                },
            )
            .await?;
        if activation.is_some() {
            req.node_labels.extend(self.0.byol_node_labels.clone());
        }
        // Refused here as well as on the node: placement charges a node
        // before the create is ever sent, and that should not be spent on a
        // request the node will reject anyway.
        burrow_common::tags::validate(&req.tags)?;
        burrow_common::tags::validate_labels(&req.node_labels)?;
        // A name has to be settled before placement: refusing a duplicate
        // afterwards would mean charging a node for a sandbox that was never
        // going to be built.
        if !req.name.is_empty() {
            validate_name(&req.name)?;
        }
        // The orchestrator owns the id namespace outright: a caller names a
        // sandbox, and the server says what it is called.
        // After the id, which a secret's scope may name.
        if let Some(network) = req.policy.as_mut().and_then(|p| p.network.as_mut()) {
            let subject = crate::secrets::Subject {
                id: &sandbox_id,
                name: &req.name,
                tags: &req.tags,
            };
            self.resolve_secret_refs(network, subject).await?;
        }
        // Held until the sandbox exists, or may: a create that is still
        // building has to hold its name or a second create takes it.
        let mut reserved = self.0.sandboxes.reserve(&sandbox_id, &req.name).await?;

        // A create from a snapshot goes where the snapshot is, or, for one
        // the object store holds, to a node that can restore it; the template
        // and machine shape come from what the snapshot holds rather than
        // from the request.
        if !req.snapshot.is_empty() {
            let limits = req
                .policy
                .as_ref()
                .and_then(|p| p.resources.clone())
                .unwrap_or_default();
            let placement = crate::registry::Placement {
                vcpus: limits.vcpus,
                mem_mib: u64::from(limits.mem_mib),
                disk_bytes: u64::from(limits.disk_mib) * burrow_common::disk::MIB,
                cpuset_cpus: limits.cpuset_cpus,
                blkio_weight: limits.blkio_weight,
                node_labels: req.node_labels.clone(),
                policy_features: crate::registry::policy_features(
                    req.policy.as_ref().and_then(|p| p.network.as_ref()),
                ),
                ..Default::default()
            };
            let is_inspected = req
                .policy
                .as_ref()
                .and_then(|p| p.network.as_ref())
                .is_some_and(|n| n.is_tls_inspected);
            let (snapshot, node_id, mut client, placed) = self
                .node_for_snapshot(
                    &req.snapshot,
                    &placement,
                    is_inspected,
                    req.policy.is_none(),
                )
                .await?;
            // A durable snapshot was placed, which reserved the node; the
            // node holding a local one is held to having room for it here.
            let shape = snapshot.resources.clone().unwrap_or_default();
            let pick = |want: u32, have: u32| if want == 0 { have } else { want };
            let is_placed = placed.is_some();
            let held = match placed {
                Some(guard) => guard,
                None => self
                    .hold_growth(
                        &node_id,
                        self.0.nodes.mem_charge_mib(
                            &node_id,
                            &snapshot.hypervisor,
                            &snapshot.build_digest,
                            u64::from(pick(limits.mem_mib, shape.mem_mib)),
                        ),
                    )
                    .await
                    .map_err(Status::resource_exhausted)?,
            };

            let cpu_millis = crate::registry::cpu_charge_millis(
                pick(limits.vcpus, shape.vcpus),
                limits.cpus,
                limits.reserved_cpus,
            );
            let mounts = req
                .policy
                .as_ref()
                .map(|p| p.volumes.clone())
                .unwrap_or_default();
            if let Some(node) = self.node_for_volumes(&mounts).await?
                && node != node_id
            {
                return Err(Status::failed_precondition(format!(
                    "snapshot {} is on node {node_id}, but the requested volumes are on node {node}",
                    snapshot.id
                )));
            }
            self.bring_volumes(&node_id, &mounts).await?;
            if !req.template.is_empty()
                && crate::builds::resolve(crate::builds::store(&self.0)?, &req.template).await?
                    != snapshot.build_digest
            {
                return Err(Status::invalid_argument(format!(
                    "snapshot {} was taken of template {:?}; a sandbox created from it \
                     cannot use template {:?}",
                    snapshot.id, snapshot.template, req.template
                )));
            }
            self.0
                .sandboxes
                .write_ahead(
                    &mut reserved,
                    common::Sandbox {
                        build_digest: snapshot.build_digest.clone(),
                        ..stub(
                            &sandbox_id,
                            &node_id,
                            &req.name,
                            &req.tags,
                            &snapshot.template,
                            &req.request_id,
                            req.policy.as_ref(),
                        )
                    },
                )
                .await?;
            let _admitted = self.0.admission.admit(&node_id).await;
            let created = client
                .create_sandbox(nodepb::NodeCreateRequest {
                    sandbox_id,
                    request_id: req.request_id,
                    template: snapshot.template.clone(),
                    build_digest: String::new(),
                    policy: req.policy,
                    tags: req.tags,
                    name: req.name,
                    snapshot: snapshot.id.clone(),
                    kit: None,
                    credentials: HashMap::new(),
                    is_remote_desktop_enabled: req.is_remote_desktop_enabled,
                    activation,
                    display_resolution: req.display_resolution,
                })
                .await;
            let (mut sandbox, reserved) = answered(created, reserved)?;
            held.keep();
            if !is_placed {
                self.0.nodes.charge_cpu(&node_id, cpu_millis);
            }
            // The caller's alone: the registry and every later read go without.
            let remote_desktop = sandbox.remote_desktop.take();
            self.settle_created(&sandbox, reserved).await?;
            tracing::info!(
                sandbox = sandbox.id,
                snapshot = snapshot.id,
                node = node_id,
                is_fetched = node_id != snapshot.node_id,
                "sandbox created from a snapshot"
            );
            sandbox.remote_desktop = remote_desktop;
            return Ok(sandbox);
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
        let build = crate::builds::resolve(crate::builds::store(&self.0)?, &template).await?;

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
        let resources = req.policy.as_ref().and_then(|p| p.resources.clone());
        if let Some(r) = &resources {
            burrow_common::cpu::validate(
                r.vcpus,
                r.cpus,
                r.reserved_cpus,
                r.cpu_shares,
                &r.cpuset_cpus,
                r.blkio_weight,
                None,
            )
            .map_err(Status::invalid_argument)?;
        }
        let want = crate::registry::Placement {
            template: build.clone(),
            prefer_node: self.0.sandboxes.node_hosting_networks(&networks),
            is_mesh_available: self.0.nodes.is_mesh_available(""),
            vcpus: resources.as_ref().map(|r| r.vcpus).unwrap_or(0).max(1),
            cpus: resources.as_ref().map(|r| r.cpus).unwrap_or(0.0),
            reserved_cpus: resources.as_ref().map(|r| r.reserved_cpus).unwrap_or(0.0),
            cpuset_cpus: resources
                .as_ref()
                .map(|r| r.cpuset_cpus.clone())
                .unwrap_or_default(),
            blkio_weight: resources.as_ref().map_or(0, |r| r.blkio_weight),
            is_nested_virt_enabled: resources.as_ref().is_some_and(|r| r.is_nested_virt_enabled),
            is_kvm_kernel_needed: resources.as_ref().is_some_and(|r| r.is_nested_virt_enabled),
            mem_mib: match resources.as_ref().map(|r| r.mem_mib).unwrap_or(0) {
                0 => 512,
                mem => mem as u64,
            },
            disk_bytes: crate::registry::disk_bytes(resources.as_ref()),
            node_labels: req.node_labels,
            arch: String::new(),
            hypervisor_version: String::new(),
            cpu: None,
            // The build decides.
            hypervisor: self.template_hypervisor(&build).await?,
            kernel: None,
            policy_features: crate::registry::policy_features(
                req.policy.as_ref().and_then(|p| p.network.as_ref()),
            ),
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
        let pinned = match (pinned, ip_node) {
            (Some(volumes), Some(ips)) if volumes != ips => {
                return Err(Status::failed_precondition(format!(
                    "the requested volumes are on node {volumes} and the requested static IPs \
                     reach only node {ips}"
                )));
            }
            (volumes, ips) => volumes.or(ips),
        };
        // Whether `place_for` charged the node for this sandbox. A
        // volume-pinned create never goes through placement, so nothing was
        // reserved for it, and a guard over it would refund a charge it never
        // took, out of capacity belonging to whatever create runs alongside it.
        let mut charged = true;
        let node_id = match pinned {
            Some(node_id) => {
                charged = false;
                self.require_labels(&node_id, &want.node_labels)?;
                self.require_policy_features(
                    &node_id,
                    req.policy.as_ref().and_then(|p| p.network.as_ref()),
                )?;
                if !want.hypervisor.is_empty()
                    && !self
                        .0
                        .nodes
                        .info(&node_id)
                        .is_some_and(|info| crate::registry::offers(&info, &want.hypervisor))
                {
                    return Err(Status::failed_precondition(format!(
                        "the requested volumes are on node {node_id}, which does not offer {}, \
                         the hypervisor template {template} runs under",
                        want.hypervisor
                    )));
                }
                if self.0.nodes.endpoint(&node_id).is_none() {
                    return Err(Status::failed_precondition(format!(
                        "the requested volumes are on node {node_id}, which is unreachable; \
                         one kept in the object store is attached elsewhere once the node is \
                         written off"
                    )));
                }
                node_id
            }
            None => match self.place(&want).await {
                Ok(node_id) => node_id,
                Err(err) => {
                    return Err(match err {
                        crate::registry::PlacementError::NoHealthyNode
                        | crate::registry::PlacementError::NoCapacity { .. } => {
                            Status::resource_exhausted(err.to_string())
                        }
                        crate::registry::PlacementError::PeersUnreachable(_)
                        | crate::registry::PlacementError::NoNodeWithLabels(_)
                        | crate::registry::PlacementError::NoNodeWithHypervisor(_)
                        | crate::registry::PlacementError::NoNodeWithPolicyFeatures(_)
                        | crate::registry::PlacementError::NoNodeForHostLimits(_) => {
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
        let mut client = self.node_client(&node_id).await?;
        self.bring_volumes(
            &node_id,
            req.policy
                .as_ref()
                .map(|p| p.volumes.as_slice())
                .unwrap_or_default(),
        )
        .await?;
        let subject = crate::secrets::Subject {
            id: &sandbox_id,
            name: &req.name,
            tags: &req.tags,
        };
        let credentials = self
            .kit_credentials(&mut client, &node_id, &build, subject)
            .await?;

        self.0
            .sandboxes
            .write_ahead(
                &mut reserved,
                common::Sandbox {
                    build_digest: build.clone(),
                    ..stub(
                        &sandbox_id,
                        &node_id,
                        &req.name,
                        &req.tags,
                        &template,
                        &req.request_id,
                        req.policy.as_ref(),
                    )
                },
            )
            .await?;
        let _admitted = self.0.admission.admit(&node_id).await;
        let created = client
            .create_sandbox(nodepb::NodeCreateRequest {
                sandbox_id,
                request_id: req.request_id,
                template,
                build_digest: build,
                policy: req.policy,
                tags: req.tags,
                name: req.name,
                snapshot: String::new(),
                kit: req.kit,
                credentials,
                is_remote_desktop_enabled: req.is_remote_desktop_enabled,
                activation,
                display_resolution: req.display_resolution,
            })
            .await;
        let (mut sandbox, reserved) = answered(created, reserved)?;
        let remote_desktop = sandbox.remote_desktop.take();
        // The sandbox exists and the node will report it; the optimistic
        // charge is now the registry's job, not the guard's.
        if let Some(placed) = placed {
            placed.keep();
        }
        self.settle_created(&sandbox, reserved).await?;
        let mut sandbox = match public_ips.is_empty() {
            true => sandbox,
            false => {
                self.attach_for_create(&sandbox.id, public_ips).await?;
                self.0.sandboxes.get(&sandbox.id).unwrap_or(sandbox)
            }
        };
        // The node's record is the truth rather than the request: it carries
        // the state and addresses the node actually assigned.
        tracing::info!(sandbox = sandbox.id, node = node_id, "sandbox placed");
        sandbox.remote_desktop = remote_desktop;
        Ok(sandbox)
    }
}

impl ApiService {
    /// Records the sandbox a node built for a create or a fork, over the row
    /// written ahead of it. A row that went meanwhile was deleted while the
    /// node built it, which the node destroys at its next heartbeat.
    async fn settle_created(
        &self,
        sandbox: &common::Sandbox,
        reserved: crate::sandboxes::Reservation,
    ) -> Result<(), Status> {
        let settled = self
            .0
            .sandboxes
            .settle(sandbox.clone(), crate::sandboxes::FIRST_GENERATION)
            .await?;
        reserved.keep();
        if !settled {
            return Err(Status::aborted(format!(
                "sandbox {} was deleted while its node built it",
                sandbox.id
            )));
        }
        Ok(())
    }

    /// Takes `mem_mib` on a node for a sandbox growing there, or says why the
    /// node has no room for it.
    async fn hold_growth(&self, node_id: &str, mem_mib: u64) -> Result<PlacementGuard<'_>, String> {
        let refusal = || format!("node {node_id} has no room for {mem_mib} MiB more host memory");
        if !self.0.nodes.reserve_growth(node_id, mem_mib) {
            return Err(refusal());
        }
        if let Some(store) = &self.0.store {
            let reserved = store.reserve_capacity(node_id, 0, mem_mib).await;
            if !matches!(reserved, Ok(true)) {
                self.0.nodes.release(node_id, 0, mem_mib, 0);
                return Err(match reserved {
                    Err(err) => format!("could not reserve memory on node {node_id}: {err}"),
                    _ => refusal(),
                });
            }
        }
        Ok(PlacementGuard {
            nodes: &self.0.nodes,
            store: self.0.store.clone(),
            node_id: node_id.to_string(),
            cpu_millis: 0,
            mem_mib,
            disk_bytes: 0,
            is_kept: false,
        })
    }

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
            let cpu_millis = want.cpu_charge_millis();
            let mem_mib = self.0.nodes.mem_charge_mib(
                &node_id,
                &want.hypervisor,
                &want.template,
                want.mem_mib,
            );
            match store.reserve_capacity(&node_id, cpu_millis, mem_mib).await {
                Ok(true) => return Ok(node_id),
                Ok(false) => {
                    self.0
                        .nodes
                        .release(&node_id, cpu_millis, mem_mib, want.disk_bytes);
                    excluded.insert(node_id);
                }
                Err(err) => {
                    self.0
                        .nodes
                        .release(&node_id, cpu_millis, mem_mib, want.disk_bytes);
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
            cpu_millis: want.cpu_charge_millis(),
            mem_mib: self.0.nodes.mem_charge_mib(
                node_id,
                &want.hypervisor,
                &want.template,
                want.mem_mib,
            ),
            disk_bytes: want.disk_bytes,
            is_kept: false,
        }
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

    /// Refuses to hand `network` to `node_id` when the node does not enforce
    /// a field it uses, which it would otherwise drop without a word.
    fn require_policy_features(
        &self,
        node_id: &str,
        network: Option<&common::NetworkPolicy>,
    ) -> Result<(), Status> {
        let wanted = crate::registry::policy_features(network);
        if wanted.is_empty() {
            return Ok(());
        }
        let info = self.0.nodes.info(node_id).unwrap_or_default();
        let missing = crate::registry::missing_features(&info, &wanted);
        if missing.is_empty() {
            return Ok(());
        }
        Err(Status::failed_precondition(format!(
            "node {node_id} does not enforce {}, which this policy uses",
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
    ///
    /// Resolved for `subject`, the sandbox the policy is for: a scoped secret
    /// it is not allowed refuses the whole call, and a rule that took a value
    /// from a scoped secret is bound to that sandbox, so a copy of the policy
    /// made by a fork or a snapshot cannot carry the credential anywhere the
    /// scope does not reach.
    async fn resolve_secret_refs(
        &self,
        network: &mut common::NetworkPolicy,
        subject: crate::secrets::Subject<'_>,
    ) -> Result<(), Status> {
        // Names first, then the store, then the substitution: the store is
        // async and the substitution is not.
        let mut names = Vec::new();
        for value in brokered_values(network) {
            if value.contains(SECRET_REF) {
                substitute_secret_refs(value, |name| {
                    names.push(name.to_string());
                    Ok(String::new())
                })?;
            }
        }
        let mut stored = HashMap::new();
        for name in names {
            if stored.contains_key(&name) {
                continue;
            }
            if let Some(secret) = self.secrets()?.get_scoped(&name).await.map_err(internal)? {
                stored.insert(name, secret);
            }
        }
        apply_secrets(network, subject, &stored)
    }

    /// What a node is told to activate a Windows guest with: the product key
    /// read out of the secret the request names, which must be scoped to the
    /// sandbox, and the KMS host as given.
    async fn activation_for(
        &self,
        requested: Option<api::ActivationRequest>,
        subject: crate::secrets::Subject<'_>,
    ) -> Result<Option<nodepb::NodeActivation>, Status> {
        let Some(requested) = requested else {
            return Ok(None);
        };
        let product_key = match requested.product_key_secret.as_str() {
            "" => String::new(),
            name => {
                let secret = self
                    .secrets()?
                    .get_scoped(name)
                    .await
                    .map_err(internal)?
                    .filter(|secret| secret.scope.is_product_key && secret.scope.admits(&subject))
                    .ok_or_else(|| {
                        Status::failed_precondition(format!(
                            "no product-key secret {name} this sandbox may use; store one with \
                             `burrow secret set {name} --product-key`"
                        ))
                    })?;
                secret.value
            }
        };
        Ok(Some(nodepb::NodeActivation {
            product_key,
            kms_host: requested.kms_host,
        }))
    }

    /// The hypervisor the build `template` runs under, from its manifest.
    ///
    /// Empty, meaning any, when every healthy node offers the same ones: a
    /// node only holds a build it can boot.
    async fn template_hypervisor(&self, template: &str) -> Result<String, Status> {
        if self.0.nodes.is_uniform_in_hypervisors() {
            return Ok(String::new());
        }
        let manifest = crate::builds::manifest(crate::builds::store(&self.0)?, template).await?;
        Ok(crate::builds::hypervisor_of(&manifest))
    }

    /// The bound secrets for the credential services a Kit template's
    /// descriptors request, read through `client` on `node_id`; empty for any
    /// other template. An unbound service is left out: whether that refuses
    /// or skips is the descriptor's `optional` to say, and the node judges it.
    ///
    /// A secret scoped away from `subject` is treated as unbound, as though it
    /// had not been stored: the descriptor's `optional` then decides.
    async fn kit_credentials(
        &self,
        _client: &mut NodeClient,
        node_id: &str,
        template: &str,
        subject: crate::secrets::Subject<'_>,
    ) -> Result<HashMap<String, String>, Status> {
        let mut out = HashMap::new();
        // A node about to fetch the build has not reported it, so its
        // manifest says instead.
        let manifest = match self.0.nodes.holds_build(node_id, template) {
            _ if template.is_empty() => return Ok(out),
            true if !self.0.nodes.is_kit_template(node_id, template) => return Ok(out),
            _ => crate::builds::manifest(crate::builds::store(&self.0)?, template).await?,
        };
        if manifest
            .config
            .get("kit")
            .is_none_or(serde_json::Value::is_null)
        {
            return Ok(out);
        }
        let Some(secrets) = &self.0.secrets else {
            return Ok(out);
        };
        for service in burrow_common::kit::credential_services(&manifest.config.to_string()) {
            if let Some(secret) = secrets.get_scoped(&service).await.map_err(internal)?
                && secret.scope.admits(&subject)
            {
                out.insert(service, secret.value);
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
        self.client_on(&node_id, sandbox_id).await
    }

    /// [`Self::node_for`] for a create or lifecycle call, holding one of the
    /// node's admission slots until the permit drops.
    async fn admitted_node_for(
        &self,
        sandbox_id: &str,
    ) -> Result<(NodeClient, tokio::sync::OwnedSemaphorePermit), Status> {
        let node_id = self.placed_on(sandbox_id).await?;
        let admitted = self.0.admission.admit(&node_id).await;
        Ok((self.client_on(&node_id, sandbox_id).await?, admitted))
    }

    async fn client_on(&self, node_id: &str, sandbox_id: &str) -> Result<NodeClient, Status> {
        let endpoint = self.0.nodes.endpoint(node_id).ok_or_else(|| {
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

    /// Whether other orchestrator replicas share this one's store, so its
    /// cache can be up to a reload behind their writes.
    fn is_replicated(&self) -> bool {
        self.0.control_plane_hosts.lock().unwrap().len() > 1
    }

    /// The node holding `sandbox_id` now, or empty for a sandbox no node
    /// holds.
    async fn holder(&self, sandbox_id: &str) -> Result<String, Status> {
        let mut node_id = self.node_of(sandbox_id)?;
        // Beside other replicas the cache can be a second behind a move made
        // through one of them, naming a node that has already let go.
        if (node_id.is_empty() || self.is_replicated())
            && let Some(sandbox) = self.0.sandboxes.refresh(sandbox_id).await
        {
            node_id = sandbox.node_id;
        }
        Ok(node_id)
    }

    /// The node holding `sandbox_id` now.
    async fn placed_on(&self, sandbox_id: &str) -> Result<String, Status> {
        let node_id = self.holder(sandbox_id).await?;
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
        let Some((_, listed)) = self.store_node().await else {
            return false;
        };
        let is_there = listed.iter().any(|snapshot| snapshot.id == id);
        self.0.snapshots.reconcile_remote(listed);
        if is_there {
            self.0.snapshots.mark_durable(id);
        }
        is_there
    }

    /// A healthy node with the object store configured, and what the store
    /// lists. A node without one refuses the listing, so it is skipped.
    async fn store_node(&self) -> Option<(NodeClient, Vec<common::Snapshot>)> {
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
            let listed = crate::named_snapshots(&self.0, resp.into_inner().snapshots)
                .await
                .ok()?;
            return Some((client, listed));
        }
        None
    }

    /// A snapshot this replica has not heard of, asked of every node.
    ///
    /// Snapshots are learned from nodes, and with several replicas only the
    /// one that took a snapshot, or the one its node heartbeats to, knows of
    /// it at once; the others catch up within half a minute. A caller who
    /// took a snapshot and used it straight away should not be told it does
    /// not exist in that window.
    async fn find_snapshot(&self, id: &str) -> Option<common::Snapshot> {
        if !self
            .0
            .sandboxes
            .store()
            .snapshot_ids()
            .await
            .ok()?
            .contains(id)
        {
            return None;
        }
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
        let found = found.into_iter().flatten().next();
        let found = match found {
            Some((node_id, volume)) => crate::named_volumes(&self.0, vec![volume])
                .await
                .ok()?
                .pop()
                .map(|volume| (node_id, volume)),
            None => None,
        };
        match found {
            Some((node_id, volume)) => self.0.volumes.insert(&node_id, volume),
            None => {
                let (_, listed) = self.store_volumes().await?;
                self.0
                    .volumes
                    .reconcile_remote(listed, |node| self.0.nodes.knows(node));
            }
        }
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
        is_inspected: bool,
        inherits_policy: bool,
    ) -> Result<
        (
            common::Snapshot,
            String,
            NodeClient,
            Option<PlacementGuard<'_>>,
        ),
        Status,
    > {
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
        let (node_id, placed) = match holder {
            Some(node_id) => {
                self.require_labels(&node_id, &want.node_labels)?;
                let missing = self
                    .0
                    .nodes
                    .info(&node_id)
                    .map(|info| crate::registry::missing_features(&info, &want.policy_features))
                    .unwrap_or_default();
                if !missing.is_empty() {
                    return Err(Status::failed_precondition(format!(
                        "node {node_id} holds snapshot {id} and does not enforce {}",
                        missing.join(", ")
                    )));
                }
                (node_id, None)
            }
            None if snapshot.is_durable => {
                let shape = snapshot.resources.clone().unwrap_or_default();
                let pick = |want: u64, have: u32| match want {
                    0 => u64::from(have),
                    want => want,
                };
                // A macOS guest's snapshot is its disk alone and boots cold,
                // under whatever version of the framework the Mac has.
                let is_disk_only = snapshot.hypervisor == Hypervisor::Vz.as_str();
                let want = crate::registry::Placement {
                    // The snapshot carries its own kernel and rootfs, so the
                    // template need not be on the node.
                    template: String::new(),
                    arch: snapshot.arch.clone(),
                    hypervisor_version: match is_disk_only {
                        true => String::new(),
                        false => snapshot.hypervisor_version.clone(),
                    },
                    cpu: snapshot.cpu.clone().filter(|_| !is_disk_only),
                    hypervisor: snapshot.hypervisor.clone(),
                    vcpus: pick(u64::from(want.vcpus), shape.vcpus).max(1) as u32,
                    mem_mib: pick(want.mem_mib, shape.mem_mib),
                    disk_bytes: match want.disk_bytes {
                        0 => crate::registry::disk_bytes(Some(&shape)),
                        bytes => bytes,
                    },
                    is_nested_virt_enabled: snapshot
                        .resources
                        .as_ref()
                        .is_some_and(|r| r.is_nested_virt_enabled),
                    // A sandbox taking the snapshot's own policy carries
                    // fields the orchestrator never sees, so the node
                    // restoring it elsewhere has to enforce ingress, unless
                    // the snapshot is a macOS guest's, whose policy cannot
                    // hold any.
                    policy_features: match inherits_policy {
                        true if is_disk_only => Vec::new(),
                        true => vec![burrow_common::features::INGRESS],
                        false => want.policy_features.clone(),
                    },
                    ..want.clone()
                };
                let root = match is_inspected {
                    true => snapshot.inspection_root_fingerprint.as_str(),
                    false => "",
                };
                let excluded = self.other_roots(&format!("snapshot {id}"), root, None)?;
                let node_id =
                    self.place_avoiding(&want, excluded)
                        .await
                        .map_err(|err| match err {
                            crate::registry::PlacementError::NoHealthyNode
                            | crate::registry::PlacementError::NoCapacity { .. } => {
                                Status::resource_exhausted(err.to_string())
                            }
                            other => Status::failed_precondition(other.to_string()),
                        })?;
                let guard = self.place_guard(&node_id, &want);
                (node_id, Some(guard))
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
        Ok((snapshot, node_id, client, placed))
    }

    /// The node every requested volume lives on, if any were requested.
    ///
    /// A volume is a disk image on one machine, so mounting one fixes
    /// placement the way a snapshot does. Mounting two that live on different
    /// nodes is refused rather than half satisfied: nothing can attach both.
    /// A durable volume no node holds pins nothing: it goes where the sandbox
    /// does ([`Self::bring_volumes`]). Nor does a read-only mount of a durable
    /// volume: a node other than its holder reads a copy of its last upload.
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
            if volume.node_id.is_empty() || (mount.is_read_only && volume.is_durable) {
                continue;
            }
            match &pinned {
                Some(node) if *node != volume.node_id => {
                    return Err(Status::failed_precondition(format!(
                        "{} is on node {} but another requested volume is on node {node}; \
                         nothing can attach both",
                        mount.volume, volume.node_id
                    )));
                }
                Some(_) => {}
                None => pinned = Some(volume.node_id.clone()),
            }
        }
        Ok(pinned)
    }

    /// Has `target` take every requested volume no node holds from the
    /// object store, before a sandbox mounting them is created or adopted
    /// there.
    async fn bring_volumes(
        &self,
        target: &str,
        mounts: &[common::VolumeMount],
    ) -> Result<(), Status> {
        for mount in mounts
            .iter()
            .filter(|mount| !mount.is_tmpfs && !mount.is_read_only)
        {
            let Some(volume) = self.volume(&mount.volume).await else {
                return Err(Status::not_found(format!("no volume {}", mount.volume)));
            };
            if !volume.node_id.is_empty() {
                continue;
            }
            let endpoint = self
                .0
                .nodes
                .endpoint(target)
                .ok_or_else(|| Status::unavailable(format!("node {target} is unreachable")))?;
            let mut client = self
                .0
                .channels
                .get(&endpoint, self.0.node_token.as_deref())
                .await
                .map_err(|err| Status::unavailable(format!("cannot reach node {target}: {err}")))?;
            let from = self.0.volumes.taken_from(&volume.name);
            let adopted = client
                .adopt_volume(nodepb::NodeAdoptVolumeRequest {
                    name: volume.name.clone(),
                    node_id: target.to_string(),
                    from_node_id: from.clone(),
                })
                .await?
                .into_inner();
            self.0.volumes.insert(target, adopted);
            tracing::info!(
                volume = volume.name,
                node = target,
                from,
                "volume adopted from the object store"
            );
        }
        Ok(())
    }

    /// A healthy node with the object store configured, and the volumes the
    /// store lists.
    async fn store_volumes(&self) -> Option<(NodeClient, Vec<common::Volume>)> {
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
                .list_durable_volumes(api::ListVolumesRequest {
                    node_id: String::new(),
                })
                .await
            else {
                continue;
            };
            let listed = crate::named_volumes(&self.0, resp.into_inner().volumes)
                .await
                .ok()?;
            return Some((client, listed));
        }
        None
    }

    /// A client for the node holding one volume.
    async fn node_holding_volume(&self, name: &str) -> Result<(String, NodeClient), Status> {
        let volume = self
            .volume(name)
            .await
            .ok_or_else(|| Status::not_found(format!("no volume {name}")))?;
        let endpoint = self.0.nodes.endpoint(&volume.node_id).ok_or_else(|| {
            Status::failed_precondition(format!(
                "volume {name} lives on node {}, which is unreachable; a volume kept in the \
                 object store is attached elsewhere once the node is written off",
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
    /// Refuses a node that cannot restore what `want` was written by.
    fn require_restorer(
        &self,
        node_id: &str,
        sandbox_id: &str,
        want: &crate::registry::Placement,
    ) -> Result<(), Status> {
        let info = self
            .0
            .nodes
            .info(node_id)
            .ok_or_else(|| Status::not_found(format!("no node {node_id}")))?;
        if let Some(gap) = crate::registry::host_limits_gap(&info, want) {
            return Err(Status::failed_precondition(format!(
                "node {node_id} cannot hold sandbox {sandbox_id}'s host limits: it {gap}; move \
                 it with is_cpuset_dropped (`burrow move --drop-cpuset`) to unpin it, or clear \
                 the setting with UpdateResources"
            )));
        }
        if crate::registry::can_restore(
            &info,
            &want.arch,
            &want.hypervisor,
            &want.hypervisor_version,
        ) {
            return match want.cpu.as_ref().and_then(|cpu| {
                crate::registry::cpu_mismatch(cpu, info.cpu.as_ref(), &want.hypervisor)
            }) {
                Some(why) => Err(Status::failed_precondition(format!(
                    "node {node_id} cannot restore sandbox {sandbox_id}'s memory on its CPU: it \
                     {why}"
                ))),
                None => Ok(()),
            };
        }
        Err(Status::failed_precondition(format!(
            "node {node_id} cannot restore sandbox {sandbox_id}: its state needs {} and {} {}, \
             and the node has {} with {} {}",
            want.arch,
            want.hypervisor,
            want.hypervisor_version,
            info.arch,
            want.hypervisor,
            crate::registry::version_of(&info, &want.hypervisor),
        )))
    }

    /// Refuses `node_id` when its TLS inspection root is not `root`, the one
    /// `subject`'s guest was told to trust. An empty root asks for nothing.
    ///
    /// A guest's processes load their trust store once, so restoring one
    /// under leaves from another root fails every inspected connection it
    /// holds, and every one it opens.
    fn require_inspection_root(
        &self,
        node_id: &str,
        subject: &str,
        root: &str,
    ) -> Result<(), Status> {
        let theirs = self
            .0
            .nodes
            .info(node_id)
            .map(|info| info.inspection_root_fingerprint)
            .unwrap_or_default();
        if root.is_empty() || theirs == root {
            return Ok(());
        }
        Err(Status::failed_precondition(format!(
            "{subject}'s guest trusts the TLS inspection root {root}, and node {node_id}'s \
             inspection root is {}; inspected sandboxes move only between nodes under one fleet \
             root (`burrowd ca`)",
            if theirs.is_empty() {
                "unknown"
            } else {
                &theirs
            }
        )))
    }

    /// Healthy nodes whose TLS inspection root is not `root`, for placement
    /// to pass over, refusing when no other node (`except` aside) has it.
    fn other_roots(
        &self,
        subject: &str,
        root: &str,
        except: Option<&str>,
    ) -> Result<std::collections::HashSet<String>, Status> {
        let mut excluded = std::collections::HashSet::new();
        if root.is_empty() {
            return Ok(excluded);
        }
        let mut others = Vec::new();
        let mut is_trusted = false;
        for id in self.0.nodes.healthy_ids() {
            let theirs = self
                .0
                .nodes
                .info(&id)
                .map(|info| info.inspection_root_fingerprint)
                .unwrap_or_default();
            if theirs == root {
                is_trusted |= except != Some(id.as_str());
                continue;
            }
            others.push(format!("{id}: {theirs}"));
            excluded.insert(id);
        }
        if is_trusted {
            return Ok(excluded);
        }
        others.sort();
        Err(Status::failed_precondition(format!(
            "{subject}'s guest trusts the TLS inspection root {root}, and no other healthy node \
             has it ({}); inspected sandboxes move only between nodes under one fleet root \
             (`burrowd ca`)",
            others.join(", ")
        )))
    }

    /// Places a sandbox no node holds, as read from the store.
    async fn adopt(
        &self,
        sandbox: common::Sandbox,
        node_id: &str,
        node_labels: HashMap<String, String>,
    ) -> Result<common::Sandbox, Status> {
        let (current, generation) = self.0.sandboxes.placed(&sandbox.id).await?;
        if !current.node_id.is_empty() {
            return Err(Status::aborted(format!(
                "sandbox {} was placed on node {} by another call",
                sandbox.id, current.node_id
            )));
        }
        self.adopt_from(sandbox, "", generation, node_id, node_labels)
            .await
    }

    /// Hands `sandbox`, which the store has on `from` (`""` for no node) at
    /// `generation`, to `node_id`, or wherever placement finds room for it,
    /// to take up from the object store.
    ///
    /// The row is moved to the target at the next generation before the
    /// target is asked, so of two calls placing one sandbox only one gets
    /// that far, and any copy left behind is older than the one the target
    /// takes up. A target whose answer says it let go leaves the sandbox
    /// unplaced; one that may still be taking it up leaves it there, for its
    /// heartbeats to settle.
    async fn adopt_from(
        &self,
        sandbox: common::Sandbox,
        from: &str,
        generation: i64,
        node_id: &str,
        node_labels: HashMap<String, String>,
    ) -> Result<common::Sandbox, Status> {
        let node_id = &self.pinned_target(&sandbox.id, node_id).await?;
        let want = self.adoption_placement(&sandbox, node_labels);
        let subject = format!("sandbox {}", sandbox.id);
        let root = sandbox.inspection_root_fingerprint.clone();
        let mounts = sandbox
            .policy
            .as_ref()
            .map(|p| p.volumes.clone())
            .unwrap_or_default();
        let node_id = match (self.node_for_volumes(&mounts).await?, node_id.as_str()) {
            (Some(held), "") => held,
            (Some(held), wanted) if held != wanted => {
                return Err(Status::failed_precondition(format!(
                    "sandbox {}'s volumes are on node {held}, not node {wanted}",
                    sandbox.id
                )));
            }
            (_, wanted) => wanted.to_string(),
        };
        let node_id = node_id.as_str();
        let (target, placed) = if node_id.is_empty() {
            let excluded = self.other_roots(&subject, &root, None)?;
            let target = self
                .place_avoiding(&want, excluded)
                .await
                .map_err(placement_status)?;
            let placed = self.place_guard(&target, &want);
            (target, Some(placed))
        } else {
            self.require_restorer(node_id, &sandbox.id, &want)?;
            self.require_labels(node_id, &want.node_labels)?;
            self.require_inspection_root(node_id, &subject, &root)?;
            self.require_policy_features(
                node_id,
                sandbox.policy.as_ref().and_then(|p| p.network.as_ref()),
            )?;
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
        self.bring_volumes(&target, &mounts).await?;
        let next = self
            .0
            .sandboxes
            .move_to(&sandbox, from, generation, &target)
            .await?;
        let _admitted = self.0.admission.admit(&target).await;
        let adopted = match client
            .adopt_sandbox(nodepb::NodeAdoptRequest {
                record: Some(sandbox.clone()),
                node_id: target.clone(),
                generation: next as u64,
            })
            .await
        {
            Ok(adopted) => adopted.into_inner(),
            Err(err) => {
                if target_let_go(&err) {
                    self.0.sandboxes.unplace(sandbox, &target, next).await?;
                }
                return Err(err);
            }
        };
        if let Some(placed) = placed {
            placed.keep();
        }
        self.0.sandboxes.settle(adopted.clone(), next).await?;
        tracing::info!(
            sandbox = adopted.id,
            node = target,
            generation = next,
            "sandbox adopted from the object store"
        );
        Ok(adopted)
    }

    /// Gives a sandbox whose move failed at the target back to the node it
    /// left, returning the error the caller hears either way.
    ///
    /// The source had it running a moment ago and can restore what it just
    /// wrote, so without this a target that fails strands a running sandbox
    /// as a suspended one nobody holds. Only when the target's answer says it
    /// let go: see [`target_let_go`].
    async fn hand_back(
        &self,
        released: common::Sandbox,
        source: &str,
        target: &str,
        err: Status,
    ) -> Status {
        let id = released.id.clone();
        let failed = format!(
            "moving sandbox {id} to node {target} failed: {}",
            err.message()
        );
        let unplaced = match self.0.sandboxes.placed(&id).await {
            Ok((current, generation)) if current.node_id.is_empty() => Some(generation),
            _ => None,
        };
        let Some(generation) = unplaced.filter(|_| target_let_go(&err)) else {
            return Status::new(
                err.code(),
                format!(
                    "{failed}; node {target} may still be taking it up, so it is left in the \
                     object store, and its heartbeats settle where it is"
                ),
            );
        };
        match self
            .adopt_from(released, "", generation, source, HashMap::new())
            .await
        {
            Ok(_) => {
                tracing::warn!(
                    sandbox = id,
                    source,
                    target,
                    err = err.message(),
                    "move failed at the target; the sandbox is back on its source"
                );
                Status::new(err.code(), format!("{failed}; it is back on node {source}"))
            }
            Err(back) => Status::new(
                err.code(),
                format!(
                    "{failed}, and handing it back to node {source} failed too: {}; it is \
                     suspended in the object store, and `burrow start` places it",
                    back.message()
                ),
            ),
        }
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
            .and_then(|p| p.resources.clone())
            .unwrap_or_default();
        let networks: Vec<String> = sandbox
            .policy
            .iter()
            .flat_map(|p| p.networks.iter())
            .map(|m| m.network.clone())
            .filter(|name| !name.is_empty())
            .collect();
        let is_booted = sandbox.checkpoint_at_unix_ms > 0
            && sandbox.checkpoint_kind == common::CheckpointKind::Disk as i32;
        crate::registry::Placement {
            template: sandbox.build_digest.clone(),
            prefer_node: self.0.sandboxes.node_hosting_networks(&networks),
            is_mesh_available: self.0.nodes.is_mesh_available(""),
            vcpus: resources.vcpus.max(1),
            cpus: resources.cpus,
            reserved_cpus: resources.reserved_cpus,
            cpuset_cpus: resources.cpuset_cpus.clone(),
            blkio_weight: resources.blkio_weight,
            is_nested_virt_enabled: resources.is_nested_virt_enabled,
            // Its kernel is the one the state ran, which travels with it.
            is_kvm_kernel_needed: false,
            kernel: None,
            mem_mib: match resources.mem_mib {
                0 => 512,
                mem => mem as u64,
            },
            disk_bytes: crate::registry::disk_bytes(Some(&resources)),
            node_labels,
            arch: sandbox.arch.clone(),
            // A disk checkpoint is booted, not restored, so any version will
            // do, and a macOS guest only ever moves by its disk.
            hypervisor_version: match is_booted || sandbox.hypervisor == Hypervisor::Vz.as_str() {
                true => String::new(),
                false => sandbox.hypervisor_version.clone(),
            },
            // A stopped sandbox is booted from its disk too.
            cpu: sandbox.cpu.clone().filter(|_| {
                sandbox.state != common::SandboxState::Stopped as i32
                    && !is_booted
                    && sandbox.hypervisor != Hypervisor::Vz.as_str()
            }),
            hypervisor: sandbox.hypervisor.clone(),
            policy_features: crate::registry::policy_features(
                sandbox.policy.as_ref().and_then(|p| p.network.as_ref()),
            ),
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
                // A node without the store.
                Err(status) if status.code() == tonic::Code::FailedPrecondition => {
                    last = status;
                }
                Err(status) => return Err(status),
            }
        }
        Err(last)
    }

    /// Returns what a deleted sandbox was charged: its CPU, which the node
    /// counts until a delete whatever the state, and its memory ceiling if it
    /// still had a VMM.
    fn release_charge(&self, sandbox: &common::Sandbox) {
        let resources = sandbox
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.clone())
            .unwrap_or_default();
        let cpu_millis = crate::registry::cpu_charge_millis(
            resources.vcpus,
            resources.cpus,
            resources.reserved_cpus,
        );
        let has_vmm = matches!(
            common::SandboxState::try_from(sandbox.state),
            Ok(common::SandboxState::Creating | common::SandboxState::Running)
        );
        let mem_mib = match has_vmm {
            true => self.0.nodes.mem_charge_mib(
                &sandbox.node_id,
                &sandbox.hypervisor,
                &sandbox.build_digest,
                match resources.mem_mib {
                    0 => 512,
                    mem => mem as u64,
                },
            ),
            false => 0,
        };
        let disk_bytes = crate::registry::disk_bytes(Some(&resources));
        self.0
            .nodes
            .release(&sandbox.node_id, cpu_millis, mem_mib, disk_bytes);
        release_in_store(
            &self.0.nodes,
            self.0.store.clone(),
            &sandbox.node_id,
            cpu_millis,
            mem_mib,
        );
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
        let pinned = match (req.is_draining, self.0.store.is_some()) {
            (true, true) => self.pinned_on(&req.node_id).await?,
            _ => Vec::new(),
        };
        if !pinned.is_empty() && !req.is_pinned_kept {
            return Err(Status::failed_precondition(format!(
                "node {} holds sandboxes with public addresses, which cannot leave it: {}. \
                 Detach the addresses so they can move, or drain keeping them here \
                 (is_pinned_kept, `burrow nodes drain --keep-pinned`): with is_suspending they \
                 are suspended and resume on this node after maintenance",
                req.node_id,
                pinned
                    .iter()
                    .map(|(sandbox, addresses)| format!("{sandbox} ({})", addresses.join(", ")))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let mut client = self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
            .map_err(|err| Status::unavailable(format!("cannot reach node: {err}")))?;
        let mut resp = client.set_drain(req.clone()).await?.into_inner();
        // Reflected locally too: placement consults the cached status, and
        // waiting for the next heartbeat would leave a window where a drained
        // node still receives sandboxes.
        self.0.nodes.set_draining(&req.node_id, req.is_draining);
        resp.pinned_sandbox_ids = pinned.into_iter().map(|(sandbox, _)| sandbox).collect();
        Ok(Response::new(resp))
    }

    #[tracing::instrument(skip_all, fields(template, node_id))]
    async fn create_sandbox(
        &self,
        req: Request<api::CreateSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        use tracing::Instrument as _;
        let metadata = req.metadata().clone();
        let req = req.into_inner();
        validate_request_id(&req.request_id)?;
        // On a task of its own, so a caller that gives up does not leave a
        // sandbox built on its node and missing from the registry.
        let api = self.clone();
        let (reply, created) = tokio::sync::oneshot::channel();
        tokio::spawn(async move { api.create_once(metadata, req, reply).await }.in_current_span());
        created
            .await
            .map_err(|err| Status::internal(format!("the create did not finish: {err}")))?
            .map(Response::new)
    }

    async fn get_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().sandbox_id).await;
        // Read through beside other replicas: a caller reading back what it
        // just did through one of them must not see the state from before.
        let sandbox = match self.is_replicated() {
            true => self.0.sandboxes.refresh(&id).await,
            false => self.0.sandboxes.get(&id),
        };
        let mut sandbox = sandbox.ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
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
        let arrived = std::time::Instant::now();
        let filter = req.into_inner().tag;
        let filter = burrow_common::tags::parse_filter(&filter)?;
        // As for a single sandbox: the reload loop is up to a second behind
        // the other replicas, and a listing right after a create or a delete
        // through one of them would contradict it. A reload that started
        // after this call arrived is as good as one of its own.
        if self.is_replicated() {
            self.0
                .sandboxes
                .reload_since(arrived)
                .await
                .map_err(|err| Status::unavailable(format!("reading placements: {err}")))?;
        }
        let healthy = self.0.nodes.healthy_ids();
        let mut sandboxes = self.0.sandboxes.list_tagged(filter);
        for sandbox in &mut sandboxes {
            sandbox.is_unreachable =
                !sandbox.node_id.is_empty() && !healthy.contains(&sandbox.node_id);
        }
        Ok(Response::new(api::ListSandboxesResponse { sandboxes }))
    }

    /// Deletes a sandbox, which always succeeds once its row is gone,
    /// whether or not its node can be reached. A reachable node is told at
    /// once; one that is not destroys the sandbox at its next heartbeat,
    /// however long that takes, because the store no longer lists it.
    async fn delete_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::DeleteSandboxResponse>, Status> {
        let id = self.resolve(&req.into_inner().sandbox_id).await;
        let sandbox = self
            .0
            .sandboxes
            .remove(&id)
            .await?
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        self.forget_attachments(&id).await;
        if sandbox.node_id.is_empty() {
            // Its state in the object store is all there is. Left for the
            // collector when no node can delete it now.
            if let Err(err) = self.purge(&id).await {
                tracing::warn!(sandbox = id, %err, "could not delete a sandbox's stored state; the collector takes it");
            }
            return Ok(Response::new(api::DeleteSandboxResponse {}));
        }
        // Return any capacity still charged optimistically for this sandbox.
        self.release_charge(&sandbox);
        if self.is_node_dead(&sandbox.node_id) {
            tracing::info!(
                sandbox = id,
                node = sandbox.node_id,
                "deleted a sandbox whose node is not heard from; it destroys it when it is"
            );
        } else if let Err(err) = delete_on_node(&self.0, &sandbox.node_id, &id).await
            && err.code() != tonic::Code::NotFound
        {
            tracing::warn!(
                sandbox = id,
                node = sandbox.node_id,
                %err,
                "deleted a sandbox its node could not destroy now; it does at its next heartbeat"
            );
        }
        Ok(Response::new(api::DeleteSandboxResponse {}))
    }

    async fn pause_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().sandbox_id).await;
        let (mut client, _admitted) = self.admitted_node_for(&id).await?;
        let sandbox = client
            .pause_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        // The registry mirrors node state, so the new state is written back.
        self.0.sandboxes.update(sandbox.clone()).await;
        Ok(Response::new(sandbox))
    }

    async fn resume_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().sandbox_id).await;
        if let Some(sandbox) = self.unplaced(&id).await {
            return Ok(Response::new(
                self.adopt(sandbox, "", HashMap::new()).await?,
            ));
        }
        let (mut client, _admitted) = self.admitted_node_for(&id).await?;
        let sandbox = client
            .resume_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
        Ok(Response::new(sandbox))
    }

    async fn get_console(
        &self,
        req: Request<api::GetConsoleRequest>,
    ) -> Result<Response<api::ConsoleLog>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.get_console(req).await?.into_inner()))
    }

    async fn stop_sandbox(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let id = self.resolve(&req.into_inner().sandbox_id).await;
        let (mut client, _admitted) = self.admitted_node_for(&id).await?;
        let sandbox = client
            .stop_sandbox(nodepb::NodeSandboxRef { sandbox_id: id })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
        Ok(Response::new(sandbox))
    }

    async fn start_sandbox(
        &self,
        req: Request<api::StartSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self.resolve(&req.sandbox_id).await;
        if let Some(sandbox) = self.unplaced(&id).await {
            return Ok(Response::new(
                self.adopt(sandbox, "", HashMap::new()).await?,
            ));
        }
        let (mut client, _admitted) = self.admitted_node_for(&id).await?;
        let sandbox = client
            .start_sandbox(nodepb::NodeStartRequest {
                sandbox_id: id,
                is_kernel_kept: req.is_kernel_kept,
            })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
        Ok(Response::new(sandbox))
    }

    async fn recreate_sandbox(
        &self,
        req: Request<api::RecreateSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let keep = burrow_common::keep::validate(&req.keep).map_err(Status::invalid_argument)?;
        let id = self.resolve(&req.sandbox_id).await;
        let current = self
            .0
            .sandboxes
            .get(&id)
            .ok_or_else(|| Status::not_found(format!("no sandbox {id}")))?;
        let node_id = current.node_id.clone();
        let build = match req.template.is_empty() {
            true => current.build_digest.clone(),
            false => crate::builds::resolve(crate::builds::store(&self.0)?, &req.template).await?,
        };
        let judged = &build;
        let (mut client, _admitted) = self.admitted_node_for(&id).await?;
        let subject = crate::secrets::Subject {
            id: &id,
            name: &current.name,
            tags: &current.tags,
        };
        let credentials = self
            .kit_credentials(&mut client, &node_id, judged, subject)
            .await?;
        let sandbox = client
            .recreate_sandbox(nodepb::NodeRecreateRequest {
                sandbox_id: id,
                build_digest: match req.template.is_empty() {
                    true => String::new(),
                    false => build.clone(),
                },
                template: req.template,
                kit: req.kit,
                credentials,
                keep,
            })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
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
        let scope = crate::secrets::Scope {
            is_product_key: req.is_product_key,
            ..validate_secret_scope(req.allowed_sandboxes, req.allowed_tags)?
        };
        self.secrets()?
            .set_scoped(&req.name, &req.value, &scope)
            .await
            .map_err(internal)?;
        Ok(Response::new(api::SetSecretResponse {}))
    }

    async fn list_secrets(
        &self,
        _req: Request<api::ListSecretsRequest>,
    ) -> Result<Response<api::ListSecretsResponse>, Status> {
        let scoped = self.secrets()?.list_scoped().await.map_err(internal)?;
        Ok(Response::new(api::ListSecretsResponse {
            secrets: scoped
                .into_iter()
                .map(|(name, scope)| api::SecretInfo {
                    name,
                    allowed_sandboxes: scope.sandboxes,
                    allowed_tags: scope.tags,
                    is_product_key: scope.is_product_key,
                })
                .collect(),
        }))
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
        let id = self.resolve(&req.into_inner().sandbox_id).await;
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
    async fn update_lifetime(
        &self,
        req: Request<api::UpdateLifetimeRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_lifetime(nodepb::NodeUpdateLifetimeRequest {
                sandbox_id: id,
                max_lifetime_secs: req.max_lifetime_secs,
                idle_suspend_secs: req.idle_suspend_secs,
                suspended_ttl_secs: req.suspended_ttl_secs,
                snapshot_expiration_secs: req.snapshot_expiration_secs,
                snapshot_keep_last: req.snapshot_keep_last,
                is_evicted_snapshot_kept: req.is_evicted_snapshot_kept,
                checkpoint_secs: req.checkpoint_secs,
                is_memory_checkpointed: req.is_memory_checkpointed,
            })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
        Ok(Response::new(sandbox))
    }

    /// Reshapes a sandbox on the owning node, which alone can see its VM and
    /// disk and admits what it grows by. The registry mirror takes the record
    /// it returns, and the node's next report carries its new commitments.
    async fn update_resources(
        &self,
        req: Request<api::UpdateResourcesRequest>,
    ) -> Result<Response<api::UpdateResourcesResponse>, Status> {
        let req = req.into_inner();
        let id = self.resolve(&req.sandbox_id).await;
        let node_id = self.node_of(&id)?;
        let record = self.0.sandboxes.get(&id).unwrap_or_default();
        let current = record
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.as_ref())
            .map_or(0, |resources| resources.mem_mib);
        // More memory is placed like a create: the node is charged what its
        // cgroup ceiling grows by, until its next heartbeat reports it in use.
        let charge = |mem_mib: u32| {
            self.0.nodes.mem_charge_mib(
                &node_id,
                &record.hypervisor,
                &record.build_digest,
                u64::from(mem_mib),
            )
        };
        let is_running = record.state == common::SandboxState::Running as i32;
        // A boot of a sandbox that is not running is charged its whole ceiling,
        // since nothing of its memory is in use on the node yet.
        let growth = match (is_running, req.boot) {
            (true, _) => req
                .mem_mib
                .filter(|want| *want > current)
                .map_or(0, |want| charge(want) - charge(current)),
            (false, true) => charge(req.mem_mib.unwrap_or(current)),
            (false, false) => 0,
        };
        let (held, refusal) = match growth {
            0 => (None, None),
            mib => match self.hold_growth(&node_id, mib).await {
                Ok(guard) => (Some(guard), None),
                Err(reason) => (None, Some(reason)),
            },
        };
        let is_limited = req.cpus.is_some()
            || req.reserved_cpus.is_some()
            || req.cpu_shares.is_some()
            || req.cpuset_cpus.is_some()
            || req.blkio_weight.is_some();
        if let Some(reason) = refusal.as_ref().filter(|_| req.boot && !is_running) {
            return Err(Status::resource_exhausted(reason.clone()));
        }
        let mut updated = match (&refusal, req.vcpus, req.disk_mib, is_limited) {
            (Some(_), None, None, false) => api::UpdateResourcesResponse {
                sandbox: self.0.sandboxes.get(&id),
                ..Default::default()
            },
            _ => self
                .node_for(&id)
                .await?
                .update_resources(nodepb::NodeUpdateResourcesRequest {
                    sandbox_id: id,
                    vcpus: req.vcpus,
                    mem_mib: req.mem_mib.filter(|_| refusal.is_none()),
                    disk_mib: req.disk_mib,
                    cpus: req.cpus,
                    reserved_cpus: req.reserved_cpus,
                    cpu_shares: req.cpu_shares,
                    cpuset_cpus: req.cpuset_cpus,
                    blkio_weight: req.blkio_weight,
                    boot: req.boot,
                })
                .await?
                .into_inner(),
        };
        if let Some(reason) = refusal {
            updated.mem_mib = Some(api::ResourceOutcome {
                change: api::ResourceChange::Refused as i32,
                previous: current,
                value: current,
                reason,
            });
        }
        let is_plugged = updated.mem_mib.as_ref().is_some_and(|outcome| {
            matches!(
                api::ResourceChange::try_from(outcome.change),
                Ok(api::ResourceChange::Live | api::ResourceChange::Partial)
            )
        });
        let is_booted = !is_running
            && updated
                .sandbox
                .as_ref()
                .is_some_and(|sandbox| sandbox.state == common::SandboxState::Running as i32);
        if let Some(guard) = held
            && (is_plugged || is_booted)
        {
            guard.keep();
        }
        // The node admitted what the sandbox is charged now; its next
        // heartbeat counts it, and until then placement does here.
        let charged = |sandbox: &common::Sandbox| {
            let resources = sandbox
                .policy
                .as_ref()
                .and_then(|policy| policy.resources.clone())
                .unwrap_or_default();
            crate::registry::cpu_charge_millis(
                resources.vcpus,
                resources.cpus,
                resources.reserved_cpus,
            )
        };
        // What it gave back is free from now, not from the next heartbeat.
        let shrunk = updated
            .mem_mib
            .as_ref()
            .filter(|outcome| is_running && is_plugged && outcome.value < outcome.previous)
            .map_or(0, |outcome| {
                charge(outcome.previous) - charge(outcome.value)
            });
        let mut eased = 0;
        if let Some(sandbox) = &updated.sandbox {
            let grown = charged(sandbox).saturating_sub(charged(&record));
            if grown > 0 {
                self.0.nodes.charge_cpu(&node_id, grown);
            }
            eased = charged(&record).saturating_sub(charged(sandbox));
        }
        if shrunk > 0 || eased > 0 {
            self.0.nodes.release(&node_id, eased, shrunk, 0);
            release_in_store(&self.0.nodes, self.0.store.clone(), &node_id, eased, shrunk);
        }
        if let Some(sandbox) = &updated.sandbox {
            self.0.sandboxes.update(sandbox.clone()).await;
        }
        Ok(Response::new(updated))
    }

    /// Forks onto the source's own node.
    ///
    /// A sandbox's snapshot, disks and address lease are node-local files, so
    /// there is nothing to place: the child is built where the state already
    /// is. That node is held to having room for the child's memory first, as
    /// a create's node is, and charged its CPU once it exists.
    async fn fork_sandbox(
        &self,
        req: Request<api::ForkSandboxRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let mut req = req.into_inner();
        let source_id = self.resolve(&req.sandbox_id).await;
        let node_id = self.node_of(&source_id)?;
        // A fork has no placement decision to constrain: the child is built
        // where its source's state is, so labels are checked against that node
        // before anything is built.
        burrow_common::tags::validate_labels(&req.node_labels)?;
        self.require_labels(&node_id, &req.node_labels)?;
        let child_id = burrow_common::SandboxId::generate().to_string();
        // Resolved for the child, which carries its source's tags: a scope
        // naming the source does not reach a fork of it.
        if let Some(network) = req.policy.as_mut().and_then(|p| p.network.as_mut()) {
            let tags = self
                .0
                .sandboxes
                .get(&source_id)
                .map(|source| source.tags)
                .unwrap_or_default();
            let subject = crate::secrets::Subject {
                id: &child_id,
                name: &req.name,
                tags: &tags,
            };
            self.resolve_secret_refs(network, subject).await?;
        }
        // Held until the child exists, so two forks naming the same child
        // cannot both be built.
        let mut reserved = self.0.sandboxes.reserve(&child_id, &req.name).await?;

        self.require_policy_features(
            &node_id,
            req.policy.as_ref().and_then(|p| p.network.as_ref()),
        )?;
        // Charged at the shape the child ends at, which may be bigger than its
        // source's: it restores at the source's and is resized before the
        // node answers.
        let source = match self.0.sandboxes.get(&source_id) {
            Some(source) => source,
            None => self
                .0
                .sandboxes
                .load(&source_id)
                .await
                .ok_or_else(|| Status::not_found(format!("no sandbox {source_id}")))?,
        };
        let inherited = source
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.clone())
            .unwrap_or_default();
        let wanted = req
            .policy
            .as_ref()
            .and_then(|policy| policy.resources.clone())
            .unwrap_or_default();
        let pick = |want: u32, have: u32| if want == 0 { have } else { want };
        let mem_mib = pick(wanted.mem_mib, inherited.mem_mib);
        let cpu_millis = crate::registry::cpu_charge_millis(
            pick(wanted.vcpus, inherited.vcpus),
            inherited.cpus,
            inherited.reserved_cpus,
        );
        let held = self
            .hold_growth(
                &node_id,
                self.0.nodes.mem_charge_mib(
                    &node_id,
                    &source.hypervisor,
                    &source.build_digest,
                    u64::from(mem_mib),
                ),
            )
            .await
            .map_err(Status::resource_exhausted)?;
        self.0
            .sandboxes
            .write_ahead(
                &mut reserved,
                stub(
                    &child_id,
                    &node_id,
                    &req.name,
                    &source.tags,
                    &source.template,
                    "",
                    source.policy.as_ref(),
                ),
            )
            .await?;
        let (mut client, _admitted) = self.admitted_node_for(&source_id).await?;
        let forked = client
            .fork_sandbox(nodepb::NodeForkRequest {
                sandbox_id: source_id.clone(),
                child_id: child_id.clone(),
                policy: req.policy,
                name: req.name,
            })
            .await;
        let (sandbox, reserved) = answered(forked, reserved)?;
        held.keep();
        self.0.nodes.charge_cpu(&node_id, cpu_millis);
        self.settle_created(&sandbox, reserved).await?;
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
        let id = self.resolve(&req.sandbox_id).await;
        // Read from the store rather than the cache: the sandbox may have
        // moved through another replica in the last second.
        let (mut current, generation) = self.0.sandboxes.placed(&id).await?;
        let before = current.clone();
        if req.is_cpuset_dropped {
            drop_cpuset(&mut current);
        }
        if current.node_id.is_empty() {
            let moved = self
                .adopt_from(current, "", generation, &req.node_id, req.node_labels)
                .await?;
            return Ok(Response::new(moved));
        }
        let source = current.node_id.clone();
        if req.node_id == source {
            return Err(Status::invalid_argument(format!(
                "sandbox {id} is already on node {source}"
            )));
        }
        if current.hypervisor == Hypervisor::Vz.as_str()
            && current.state == common::SandboxState::Suspended as i32
        {
            return Err(Status::failed_precondition(format!(
                "sandbox {id} is suspended, and a macOS guest's saved memory restores only on \
                 the Mac that wrote it; resume it, or shut it down, and move its disk"
            )));
        }
        // Refused before anything is suspended: a volume follows the
        // sandbox only through the object store.
        let mounts: Vec<String> = current
            .policy
            .iter()
            .flat_map(|p| p.volumes.iter())
            .filter(|mount| !mount.is_tmpfs)
            .map(|mount| mount.volume.clone())
            .collect();
        let written: Vec<String> = current
            .policy
            .iter()
            .flat_map(|p| p.volumes.iter())
            .filter(|mount| !mount.is_tmpfs && !mount.is_read_only)
            .map(|mount| mount.volume.clone())
            .collect();
        for name in &mounts {
            if !self.volume(name).await.is_some_and(|v| v.is_durable) {
                return Err(Status::failed_precondition(format!(
                    "sandbox {id} mounts volume {name}, which is not in the object store and \
                     cannot follow it"
                )));
            }
        }
        self.require_unpinned(&id).await?;
        let info = self.0.nodes.info(&source).unwrap_or_default();
        if current.arch.is_empty() {
            current.hypervisor_version =
                crate::registry::version_of(&info, &current.hypervisor).to_string();
            current.arch = info.arch.clone();
        }
        // The move suspends it here, so its memory is written on this CPU.
        current.cpu = info.cpu;
        // The destination is chosen before anything is suspended, so a move
        // that has nowhere to go leaves the sandbox running where it is.
        let subject = format!("sandbox {id}");
        let root = current.inspection_root_fingerprint.clone();
        let placed = if req.node_id.is_empty() {
            let want = self.adoption_placement(&current, req.node_labels.clone());
            let mut excluded = self.other_roots(&subject, &root, Some(&source))?;
            excluded.insert(source.clone());
            let target = self
                .place_avoiding(&want, excluded)
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
            // Checked here, before the source lets go: the adoption below
            // would refuse the same node only once nothing held the sandbox.
            let want = self.adoption_placement(&current, req.node_labels.clone());
            self.require_restorer(&req.node_id, &id, &want)?;
            self.require_labels(&req.node_id, &want.node_labels)?;
            self.require_inspection_root(&req.node_id, &subject, &root)?;
            None
        };
        let target = placed
            .as_ref()
            .map_or_else(|| req.node_id.clone(), |(target, _)| target.clone());
        let (mut client, admitted) = self.admitted_node_for(&id).await?;
        self.0.sandboxes.mark_releasing(&before, generation).await?;
        let released = match client
            .release_sandbox(nodepb::NodeSandboxRef {
                sandbox_id: id.clone(),
            })
            .await
        {
            Ok(released) => released.into_inner(),
            Err(err) => {
                // The source kept it, or may have: put the record back, and
                // let its listings settle which.
                if !is_outcome_unknown(&err) {
                    self.0.sandboxes.settle(before, generation).await?;
                }
                return Err(err);
            }
        };
        // A hand back is admitted to the source again.
        drop(admitted);
        for name in &written {
            if self
                .0
                .volumes
                .get(name)
                .is_some_and(|volume| volume.node_id == source)
            {
                self.0.volumes.release(name);
            }
        }
        let mut released = common::Sandbox {
            node_id: String::new(),
            ..released
        };
        if req.is_cpuset_dropped {
            drop_cpuset(&mut released);
        }
        self.release_charge(&common::Sandbox {
            node_id: source.clone(),
            ..released.clone()
        });
        if released.arch.is_empty() {
            released.arch = current.arch;
            released.hypervisor_version = current.hypervisor_version;
            released.cpu = current.cpu;
        }
        tracing::info!(sandbox = id, node = source, "sandbox released for a move");
        let moved = match self
            .adopt_from(
                released.clone(),
                &source,
                generation,
                &target,
                req.node_labels,
            )
            .await
        {
            Ok(moved) => moved,
            Err(err) => return Err(self.hand_back(released, &source, &target, err).await),
        };
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
        let sandbox_id = self.resolve(&req.sandbox_id).await;
        let node_id = self.node_of(&sandbox_id)?;
        // The orchestrator owns the id namespace, here as everywhere else.
        let snapshot_id = burrow_common::SnapshotId::generate().to_string();

        let (mut client, _admitted) = self.admitted_node_for(&sandbox_id).await?;
        let store = self.0.sandboxes.store();
        store
            .insert_snapshot(&snapshot_id, burrow_common::unix_now_ms())
            .await
            .map_err(|err| Status::unavailable(format!("recording the snapshot: {err}")))?;
        let taken = client
            .create_snapshot(nodepb::NodeCreateSnapshotRequest {
                sandbox_id: sandbox_id.clone(),
                snapshot_id: snapshot_id.clone(),
                expiration_secs: req.expiration_secs,
            })
            .await;
        let snapshot = match taken {
            Ok(snapshot) => snapshot.into_inner(),
            Err(err) => {
                // One the node may have taken anyway keeps its row, so the
                // node's heartbeat does not destroy it.
                if !is_outcome_unknown(&err) {
                    let _ = store.remove_snapshot(&snapshot_id).await;
                }
                return Err(err);
            }
        };

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
        let sandbox = req.into_inner().sandbox_id;
        let sandbox = if sandbox.is_empty() {
            None
        } else {
            Some(self.resolve(&sandbox).await)
        };
        let listed = self.0.snapshots.list(sandbox.as_deref());
        let snapshots = crate::named_snapshots(&self.0, listed)
            .await
            .map_err(|err| Status::unavailable(format!("reading snapshots: {err}")))?;
        Ok(Response::new(api::ListSnapshotsResponse { snapshots }))
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

    /// Deletes a snapshot, which always succeeds once its row is gone. The
    /// node holding it is told at once if it answers, and otherwise destroys
    /// its copy at its next heartbeat; a copy in the object store is deleted
    /// through any node that can reach it, or collected once no row names it.
    async fn delete_snapshot(
        &self,
        req: Request<api::SnapshotRef>,
    ) -> Result<Response<api::DeleteSnapshotResponse>, Status> {
        let id = req.into_inner().id;
        let removed = self
            .0
            .sandboxes
            .store()
            .remove_snapshot(&id)
            .await
            .map_err(|err| Status::unavailable(format!("deleting the snapshot: {err}")))?;
        let held = self.0.snapshots.remove(&id);
        if !removed {
            return Err(Status::not_found(format!("no snapshot {id}")));
        }
        let holder = held
            .as_ref()
            .filter(|snapshot| !snapshot.node_id.is_empty())
            .and_then(|snapshot| self.0.nodes.endpoint(&snapshot.node_id));
        let client = match holder {
            Some(endpoint) => self
                .0
                .channels
                .get(&endpoint, self.0.node_token.as_deref())
                .await
                .ok(),
            None => match held.is_some_and(|snapshot| snapshot.is_durable) {
                true => self.store_node().await.map(|(client, _)| client),
                false => None,
            },
        };
        if let Some(mut client) = client
            && let Err(err) = client
                .delete_snapshot(api::SnapshotRef { id: id.clone() })
                .await
            && err.code() != tonic::Code::NotFound
        {
            tracing::warn!(snapshot = id, %err, "deleted a snapshot no node could remove now; its node or the collector does");
        }
        Ok(Response::new(api::DeleteSnapshotResponse {}))
    }

    /// Creates a volume on one node, which is then where it lives.
    ///
    /// Placed like a sandbox, because that is what the choice decides: a
    /// sandbox mounting this volume runs on the node holding it, which only a
    /// durable volume ever leaves.
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
            cpus: 0.0,
            reserved_cpus: 0.0,
            cpuset_cpus: String::new(),
            blkio_weight: 0,
            is_nested_virt_enabled: false,
            is_kvm_kernel_needed: false,
            kernel: None,
            mem_mib: 0,
            // A volume's image is the volume's, which disk admission does
            // not count yet.
            disk_bytes: 0,
            node_labels: req.node_labels.clone(),
            arch: String::new(),
            hypervisor_version: String::new(),
            cpu: None,
            hypervisor: String::new(),
            policy_features: Vec::new(),
        };
        let node_id = self.place(&want).await.map_err(|err| match err {
            crate::registry::PlacementError::NoHealthyNode
            | crate::registry::PlacementError::NoCapacity { .. } => {
                Status::resource_exhausted(err.to_string())
            }
            other => Status::failed_precondition(other.to_string()),
        })?;
        let store = self.0.sandboxes.store();
        if !store
            .insert_volume(&req.name, burrow_common::unix_now_ms())
            .await
            .map_err(|err| Status::unavailable(format!("recording the volume: {err}")))?
        {
            return Err(Status::already_exists(format!(
                "volume {} exists",
                req.name
            )));
        }
        let name = req.name.clone();
        let endpoint = self
            .0
            .nodes
            .endpoint(&node_id)
            .ok_or_else(|| Status::unavailable(format!("node {node_id} went away")))?;
        let made = match self
            .0
            .channels
            .get(&endpoint, self.0.node_token.as_deref())
            .await
        {
            Ok(mut client) => client.create_volume(req).await,
            Err(err) => Err(Status::unavailable(format!(
                "cannot reach node {node_id}: {err}"
            ))),
        };
        let volume = match made {
            Ok(volume) => volume.into_inner(),
            Err(err) => {
                if !is_outcome_unknown(&err) {
                    let _ = store.remove_volume(&name).await;
                }
                return Err(err);
            }
        };
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
        let volumes = crate::named_volumes(&self.0, self.0.volumes.list(filter))
            .await
            .map_err(|err| Status::unavailable(format!("reading volumes: {err}")))?;
        Ok(Response::new(api::ListVolumesResponse { volumes }))
    }

    /// Reads a volume from the node holding it, so the writable claim is live
    /// rather than whatever the registry last cached.
    async fn get_volume(
        &self,
        req: Request<api::VolumeRef>,
    ) -> Result<Response<common::Volume>, Status> {
        let name = req.into_inner().name;
        if let Some(volume) = self.volume(&name).await
            && volume.node_id.is_empty()
        {
            return Ok(Response::new(volume));
        }
        let (node_id, mut client) = self.node_holding_volume(&name).await?;
        let mut volume = client
            .get_volume(api::VolumeRef { name })
            .await?
            .into_inner();
        volume.node_id = node_id;
        Ok(Response::new(volume))
    }

    /// Deletes a volume, which always succeeds once its row is gone, unless
    /// a sandbox has it attached. The node holding it is told at once if it
    /// answers, and otherwise destroys it at its next heartbeat; a copy in
    /// the object store is deleted through any node that can reach it, or
    /// collected once no row names it.
    async fn delete_volume(
        &self,
        req: Request<api::VolumeRef>,
    ) -> Result<Response<api::DeleteVolumeResponse>, Status> {
        let name = req.into_inner().name;
        let held = self.volume(&name).await;
        if let Some(sandbox) = held
            .as_ref()
            .map(|volume| &volume.attached_to)
            .filter(|sandbox| !sandbox.is_empty())
        {
            return Err(Status::failed_precondition(format!(
                "volume {name} is attached to sandbox {sandbox}"
            )));
        }
        let mounts = |record: &[u8]| {
            crate::sandboxes::decode(record).is_some_and(|sandbox| {
                sandbox
                    .policy
                    .iter()
                    .flat_map(|policy| policy.volumes.iter())
                    .any(|mount| mount.volume == name)
            })
        };
        let removed = match self
            .0
            .sandboxes
            .store()
            .remove_volume_unless_mounted(&name, mounts)
            .await
            .map_err(|err| Status::unavailable(format!("deleting the volume: {err}")))?
        {
            burrow_store::VolumeRemoval::Removed => true,
            burrow_store::VolumeRemoval::Missing => false,
            burrow_store::VolumeRemoval::Mounted(sandbox) => {
                return Err(Status::failed_precondition(format!(
                    "volume {name} is mounted by sandbox {sandbox}"
                )));
            }
        };
        self.0.volumes.remove(&name);
        if !removed {
            return Err(Status::not_found(format!("no volume {name}")));
        }
        let deleted = match held {
            Some(volume) if volume.node_id.is_empty() => match self.store_volumes().await {
                Some((mut client, _)) => client
                    .purge_volume(api::VolumeRef { name: name.clone() })
                    .await
                    .map(drop),
                None => Ok(()),
            },
            Some(volume) => match self.0.nodes.endpoint(&volume.node_id) {
                Some(endpoint) => match self
                    .0
                    .channels
                    .get(&endpoint, self.0.node_token.as_deref())
                    .await
                {
                    Ok(mut client) => client
                        .delete_volume(api::VolumeRef { name: name.clone() })
                        .await
                        .map(drop),
                    Err(err) => Err(Status::unavailable(err.to_string())),
                },
                None => Ok(()),
            },
            None => Ok(()),
        };
        if let Err(err) = deleted
            && err.code() != tonic::Code::NotFound
        {
            tracing::warn!(volume = name, %err, "deleted a volume no node could remove now; its node or the collector does");
        }
        Ok(Response::new(api::DeleteVolumeResponse {}))
    }

    async fn allocate_ip(
        &self,
        req: Request<api::AllocateIpRequest>,
    ) -> Result<Response<common::PublicIp>, Status> {
        let metadata = req.metadata().clone();
        Ok(Response::new(
            self.allocate_ip_inner(&metadata, req.into_inner()).await?,
        ))
    }

    async fn release_ip(
        &self,
        req: Request<api::IpRef>,
    ) -> Result<Response<api::ReleaseIpResponse>, Status> {
        let metadata = req.metadata().clone();
        self.release_ip_inner(&metadata, &req.into_inner().address)
            .await?;
        Ok(Response::new(api::ReleaseIpResponse {}))
    }

    async fn attach_ip(
        &self,
        req: Request<api::AttachIpRequest>,
    ) -> Result<Response<common::PublicIp>, Status> {
        let metadata = req.metadata().clone();
        let req = req.into_inner();
        Ok(Response::new(
            self.attach_ip_inner(&metadata, &req.address, &req.sandbox_id)
                .await?,
        ))
    }

    async fn detach_ip(
        &self,
        req: Request<api::IpRef>,
    ) -> Result<Response<common::PublicIp>, Status> {
        let metadata = req.metadata().clone();
        Ok(Response::new(
            self.detach_ip_inner(&metadata, &req.into_inner().address)
                .await?,
        ))
    }

    async fn list_ips(
        &self,
        req: Request<api::ListIpsRequest>,
    ) -> Result<Response<api::ListIpsResponse>, Status> {
        let metadata = req.metadata().clone();
        let ips = self.list_ips_inner(&metadata, req.into_inner()).await?;
        Ok(Response::new(api::ListIpsResponse { ips }))
    }

    async fn create_ip_pool(
        &self,
        req: Request<common::IpPool>,
    ) -> Result<Response<common::IpPool>, Status> {
        let metadata = req.metadata().clone();
        Ok(Response::new(
            self.create_ip_pool_inner(&metadata, req.into_inner(), false)
                .await?,
        ))
    }

    async fn update_ip_pool(
        &self,
        req: Request<common::IpPool>,
    ) -> Result<Response<common::IpPool>, Status> {
        let metadata = req.metadata().clone();
        Ok(Response::new(
            self.create_ip_pool_inner(&metadata, req.into_inner(), true)
                .await?,
        ))
    }

    async fn delete_ip_pool(
        &self,
        req: Request<api::IpPoolRef>,
    ) -> Result<Response<api::DeleteIpPoolResponse>, Status> {
        let metadata = req.metadata().clone();
        self.delete_ip_pool_inner(&metadata, &req.into_inner().name)
            .await?;
        Ok(Response::new(api::DeleteIpPoolResponse {}))
    }

    async fn list_ip_pools(
        &self,
        _req: Request<api::ListIpPoolsRequest>,
    ) -> Result<Response<api::ListIpPoolsResponse>, Status> {
        Ok(Response::new(api::ListIpPoolsResponse {
            pools: self.list_ip_pools_inner().await?,
        }))
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
        let id = self.resolve(&req.sandbox_id).await;
        burrow_common::tags::validate(&req.tags)?;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_tags(nodepb::NodeUpdateTagsRequest {
                sandbox_id: id,
                tags: req.tags,
            })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
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
        let id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_access_policy(nodepb::NodeUpdateAccessRequest {
                sandbox_id: id,
                exec: req.exec,
                fs: req.fs,
            })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
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
        let id = self.resolve(&req.sandbox_id).await;
        let mut network = req
            .network
            .ok_or_else(|| Status::invalid_argument("network is required"))?;
        let current = self.0.sandboxes.get(&id).unwrap_or_default();
        let subject = crate::secrets::Subject {
            id: &id,
            name: &current.name,
            tags: &current.tags,
        };
        self.resolve_secret_refs(&mut network, subject).await?;
        self.require_policy_features(&current.node_id, Some(&network))?;
        let mut client = self.node_for(&id).await?;
        let sandbox = client
            .update_network_policy(nodepb::NodeUpdateNetworkRequest {
                sandbox_id: id,
                network: Some(network),
            })
            .await?
            .into_inner();
        self.0.sandboxes.update(sandbox.clone()).await;
        Ok(Response::new(sandbox))
    }

    type BuildTemplateStream = BoxStream<api::BuildLog>;

    /// Builds on one node and records the build.
    ///
    /// The base is resolved to one build first, and the build runs on a node
    /// holding it. The new build gets a row while it runs, each step it keeps
    /// one of its own, and the tag moves to it only once it is ready. A
    /// caller that goes away does not stop the recording.
    async fn build_template(
        &self,
        req: Request<api::BuildTemplateRequest>,
    ) -> Result<Response<Self::BuildTemplateStream>, Status> {
        let mut req = req.into_inner();
        let store = Arc::clone(crate::builds::store(&self.0)?);
        let (name, tag) = match req.name.is_empty() && !req.kits.is_empty() {
            true => (String::new(), burrow_common::build::DEFAULT_TAG.to_string()),
            false => crate::builds::target(&req.name)?,
        };
        req.name = name.clone();
        let is_on_base = req.from_image.is_empty()
            && req.kits.is_empty()
            && req.from_ipsw.is_empty()
            && req.from_disk.is_empty();
        if is_on_base {
            let from = match req.from.is_empty() {
                true => "default",
                false => req.from.as_str(),
            };
            req.from = crate::builds::resolve(&store, from).await?;
        }
        let node_id = match (req.from_disk.is_empty(), req.node_id.is_empty()) {
            // The disk is on one node, which imports it.
            (false, false) if burrow_common::build::validate_name(&req.from_disk).is_ok() => {
                req.node_id.clone()
            }
            (false, false) => {
                return Err(Status::invalid_argument(format!(
                    "from_disk {:?} names a file in the node's imports directory, not a path",
                    req.from_disk
                )));
            }
            (false, true) => {
                return Err(Status::invalid_argument(
                    "a disk import names the node holding the disk in node_id",
                ));
            }
            (true, false) => {
                return Err(Status::invalid_argument(
                    "node_id is taken only with from_disk; other builds are placed",
                ));
            }
            (true, true) if req.display.is_some() => {
                return Err(Status::invalid_argument(
                    "display is taken only with from_disk",
                ));
            }
            (true, true) => self
                .0
                .nodes
                .place_for(&build_placement(&req))
                .map_err(placement_status)?,
        };
        let mut client = self.node_client(&node_id).await?;
        let mut recorder = crate::builds::Recorder::begin(
            store,
            name,
            tag,
            node_id,
            match is_on_base {
                true => req.from.clone(),
                false => String::new(),
            },
        )
        .await?;
        let mut stream = match client.build_template(req).await {
            Ok(stream) => stream.into_inner(),
            Err(err) => {
                recorder.fail(err.message()).await;
                return Err(err);
            }
        };
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let item = match stream.message().await {
                    Ok(Some(mut log)) => match recorder.observe(&log).await {
                        Ok(()) => {
                            if let Some(api::build_log::Event::Done(done)) = &mut log.event {
                                done.template = recorder.reference();
                            }
                            Ok(log)
                        }
                        Err(err) => {
                            recorder.fail(err.message()).await;
                            Err(err)
                        }
                    },
                    Ok(None) => {
                        recorder.fail("the build ended without a result").await;
                        break;
                    }
                    Err(err) => {
                        recorder.fail(err.message()).await;
                        Err(err)
                    }
                };
                let is_err = item.is_err();
                let _ = tx.send(item).await;
                if is_err {
                    break;
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn list_templates(
        &self,
        _req: Request<api::ListTemplatesRequest>,
    ) -> Result<Response<api::ListTemplatesResponse>, Status> {
        Ok(Response::new(api::ListTemplatesResponse {
            templates: crate::builds::list(&self.0).await?,
        }))
    }

    async fn get_template(
        &self,
        req: Request<api::GetTemplateRequest>,
    ) -> Result<Response<api::TemplateDetail>, Status> {
        Ok(Response::new(
            crate::builds::detail(&self.0, &req.into_inner().name).await?,
        ))
    }

    async fn delete_template(
        &self,
        req: Request<api::DeleteTemplateRequest>,
    ) -> Result<Response<api::DeleteTemplateResponse>, Status> {
        crate::builds::delete(&self.0, &req.into_inner().name).await?;
        Ok(Response::new(api::DeleteTemplateResponse {}))
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
        let id = self.resolve(&req.into_inner().sandbox_id).await;
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
        let id = self.resolve(&req.into_inner().sandbox_id).await;
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
        let id = self.resolve(&req.into_inner().sandbox_id).await;
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

        events.sort_by_key(|event| std::cmp::Reverse(event.at_unix_ms));
        events.truncate(limit);

        Ok(Response::new(Box::pin(tokio_stream::iter(
            events.into_iter().map(Ok),
        ))))
    }

    type TailEventsStream = BoxStream<common::Event>;

    async fn query_usage(
        &self,
        req: Request<api::QueryUsageRequest>,
    ) -> Result<Response<api::QueryUsageResponse>, Status> {
        let req = req.into_inner();
        let store = self
            .0
            .store
            .as_ref()
            .ok_or_else(|| Status::unavailable("the usage ledger needs a store"))?;
        let sandbox = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(self.resolve(&req.sandbox_id).await)
        };
        let resp = crate::ledger::query(store, &req, sandbox)
            .await
            .map_err(|err| Status::internal(format!("reading usage: {err}")))?;
        Ok(Response::new(resp))
    }

    /// Replays the fleet log after a position, then follows it. Subscribed
    /// before the replay so nothing between the two is missed, and live
    /// events at or below the last replayed position are dropped so nothing
    /// is doubled.
    async fn tail_events(
        &self,
        req: Request<api::TailEventsRequest>,
    ) -> Result<Response<Self::TailEventsStream>, Status> {
        let req = req.into_inner();
        let sandbox = if req.sandbox_id.is_empty() {
            None
        } else {
            Some(self.resolve(&req.sandbox_id).await)
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
            // Nodes push to whichever replica they reach, so with several the
            // live broadcast here carries only some of the log; every replica
            // can read the shared log, so they poll it instead.
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

    async fn fs(&self, req: Request<api::FsRequest>) -> Result<Response<api::FsResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.fs(req).await?.into_inner()))
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
        let id = self.resolve(&req.sandbox_id).await;
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
            node_id,
            sandbox_id: claims.sub,
            expires_at_unix_ms: claims.exp as i64 * 1000,
        }))
    }

    async fn revoke_access(
        &self,
        req: Request<api::SandboxRef>,
    ) -> Result<Response<api::RevokeAccessResponse>, Status> {
        let id = self.resolve(&req.into_inner().sandbox_id).await;
        // By the clock tokens are issued by, so a token issued a moment after
        // this, in the same second, is told apart from one issued before.
        let revoked_at_ms = burrow_common::unix_now_ms();
        // A sandbox no node holds has no sessions to end, and its tokens are
        // refused by whichever node adopts it, which is handed this record.
        if let Some(mut sandbox) = self.unplaced(&id).await {
            let revoked_at_ms = revoked_at_ms.max(sandbox.access_revoked_at_ms);
            sandbox.access_revoked_at_ms = revoked_at_ms;
            self.0.sandboxes.update(sandbox).await;
            tracing::info!(sandbox = id, revoked_at_ms, "access tokens revoked");
            return Ok(Response::new(api::RevokeAccessResponse {
                ended_sessions: 0,
                revoked_at_ms,
                killed_commands: 0,
            }));
        }
        let mut client = self.node_for(&id).await?;
        let revoked = client
            .revoke_access(nodepb::NodeRevokeAccessRequest {
                sandbox_id: id.clone(),
                revoked_at_ms,
            })
            .await?
            .into_inner();
        tracing::info!(
            sandbox = id,
            revoked_at_ms = revoked.revoked_at_ms,
            ended_sessions = revoked.ended_sessions,
            killed_commands = revoked.killed_commands,
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

    async fn set_password(
        &self,
        req: Request<api::SetPasswordRequest>,
    ) -> Result<Response<api::SetPasswordResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.set_password(req).await?.into_inner()))
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

    async fn delete_user(
        &self,
        req: Request<api::DeleteUserRequest>,
    ) -> Result<Response<api::DeleteUserResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.delete_user(req).await?.into_inner()))
    }

    async fn delete_group(
        &self,
        req: Request<api::DeleteGroupRequest>,
    ) -> Result<Response<api::DeleteGroupResponse>, Status> {
        let mut req = req.into_inner();
        req.sandbox_id = self.resolve(&req.sandbox_id).await;
        let mut client = self.node_for(&req.sandbox_id).await?;
        Ok(Response::new(client.delete_group(req).await?.into_inner()))
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
/// Where a build can run: on a node holding the template it starts from,
/// offering the hypervisor it asks for. A restore image is installed only
/// on a Mac, which is a node offering vz.
fn build_placement(req: &api::BuildTemplateRequest) -> crate::registry::Placement {
    let hypervisor = match (req.hypervisor.as_str(), req.from_ipsw.is_empty()) {
        ("", false) => Hypervisor::Vz.as_str(),
        (hypervisor, _) => hypervisor,
    };
    let is_on_base = req.from_image.is_empty() && req.kits.is_empty() && req.from_ipsw.is_empty();
    crate::registry::Placement {
        template: match is_on_base {
            true => req.from.clone(),
            false => String::new(),
        },
        hypervisor: hypervisor.to_string(),
        // A build on a base keeps the base's kernel unless it names one.
        kernel: (req.from_ipsw.is_empty() && (!is_on_base || !req.kernel.is_empty()))
            .then(|| req.kernel.clone()),
        ..Default::default()
    }
}

pub(crate) fn placement_status(err: crate::registry::PlacementError) -> Status {
    match err {
        crate::registry::PlacementError::NoHealthyNode
        | crate::registry::PlacementError::NoCapacity { .. } => {
            Status::resource_exhausted(err.to_string())
        }
        crate::registry::PlacementError::PeersUnreachable(_)
        | crate::registry::PlacementError::NoNodeWithLabels(_)
        | crate::registry::PlacementError::NoNodeWithHypervisor(_)
        | crate::registry::PlacementError::NoNodeWithPolicyFeatures(_)
        | crate::registry::PlacementError::NoNodeForHostLimits(_)
        | crate::registry::PlacementError::NoNodeWithKernel(_)
        | crate::registry::PlacementError::NoCompatibleNode { .. }
        | crate::registry::PlacementError::NoCompatibleCpu(_) => {
            Status::failed_precondition(err.to_string())
        }
        other => Status::not_found(other.to_string()),
    }
}

/// Unpins a moving sandbox from the host CPUs it ran on, which rarely mean
/// the same on another machine.
fn drop_cpuset(sandbox: &mut common::Sandbox) {
    if let Some(resources) = sandbox
        .policy
        .as_mut()
        .and_then(|policy| policy.resources.as_mut())
    {
        resources.cpuset_cpus.clear();
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

/// Every brokered value in a policy: header values and forward secrets.
fn brokered_values(network: &mut common::NetworkPolicy) -> Vec<&mut String> {
    network.rules.iter_mut().flat_map(rule_values).collect()
}

/// One rule's brokered values.
fn rule_values(rule: &mut common::RequestRule) -> Vec<&mut String> {
    match rule.action.as_mut() {
        Some(common::request_rule::Action::SetHeaders(set)) => {
            set.headers.iter_mut().map(|h| &mut h.value).collect()
        }
        Some(common::request_rule::Action::Forward(forward)) => vec![&mut forward.secret],
        None => Vec::new(),
    }
}

/// Substitutes the `stored` secrets into `network` for `subject`.
///
/// A reference to a secret that is not stored, or one scoped away from
/// `subject`, refuses the whole policy rather than sending the literal text
/// or a partial grant. A rule that took any value from a scoped secret is
/// bound to `subject`.
fn apply_secrets(
    network: &mut common::NetworkPolicy,
    subject: crate::secrets::Subject<'_>,
    stored: &HashMap<String, crate::secrets::Secret>,
) -> Result<(), Status> {
    for rule in &mut network.rules {
        let mut is_scoped = false;
        for value in rule_values(rule) {
            if !value.contains(SECRET_REF) {
                continue;
            }
            *value = substitute_secret_refs(value, |name| {
                let secret = stored.get(name).ok_or_else(|| {
                    Status::failed_precondition(format!(
                        "no secret {name:?}; store one with `burrow secret set`"
                    ))
                })?;
                if !secret.scope.admits(&subject) {
                    return Err(Status::permission_denied(format!(
                        "secret {name:?} is not scoped to sandbox {}",
                        subject.id
                    )));
                }
                is_scoped |= !secret.scope.is_unscoped();
                Ok(secret.value.clone())
            })?;
        }
        if is_scoped {
            rule.bound_sandbox_id = subject.id.to_string();
        }
    }
    Ok(())
}

/// Whether a node call's failure leaves open that the node did what it was
/// asked: its answer, not its work, may be what was lost.
fn is_outcome_unknown(err: &Status) -> bool {
    matches!(
        err.code(),
        tonic::Code::Unavailable
            | tonic::Code::Unknown
            | tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
    )
}

/// The row written ahead of a create, before the node has built anything:
/// enough to name and route it, and the volumes it mounts, which a volume
/// delete checks against; nothing else of its policy.
fn stub(
    id: &str,
    node_id: &str,
    name: &str,
    tags: &HashMap<String, String>,
    template: &str,
    request_id: &str,
    policy: Option<&common::Policy>,
) -> common::Sandbox {
    let volumes = policy.map(|p| p.volumes.clone()).unwrap_or_default();
    common::Sandbox {
        policy: (!volumes.is_empty()).then(|| common::Policy {
            volumes,
            ..Default::default()
        }),
        id: id.to_string(),
        node_id: node_id.to_string(),
        name: name.to_string(),
        tags: tags.clone(),
        template: template.to_string(),
        create_request_id: request_id.to_string(),
        state: common::SandboxState::Creating as i32,
        ..Default::default()
    }
}

/// A create's node answer, with its reservation. A failure gives the
/// reservation back unless the node may have built the sandbox anyway, in
/// which case its row stays for the node's next heartbeat to settle.
fn answered(
    result: Result<Response<common::Sandbox>, Status>,
    reserved: crate::sandboxes::Reservation,
) -> Result<(common::Sandbox, crate::sandboxes::Reservation), Status> {
    match result {
        Ok(response) => Ok((response.into_inner(), reserved)),
        Err(err) => {
            if is_outcome_unknown(&err) {
                reserved.keep();
            }
            Err(err)
        }
    }
}

fn internal(err: anyhow::Error) -> Status {
    Status::internal(format!("{err:#}"))
}

/// Gives back capacity in the store from code that cannot wait for it.
fn release_in_store(
    nodes: &crate::registry::NodeRegistry,
    store: Option<Arc<burrow_store::Store>>,
    node_id: &str,
    cpu_millis: u64,
    mem_mib: u64,
) {
    let Some(store) = store else { return };
    nodes.release_stored(node_id, cpu_millis, mem_mib);
    let node_id = node_id.to_string();
    tokio::spawn(async move {
        if let Err(err) = store.release_capacity(&node_id, cpu_millis, mem_mib).await {
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

/// Checks a secret's scope and puts it in canonical order.
///
/// Sandbox entries are ids or names, so they are held to what either may be;
/// tags are `key=value` with a key, since a bare key would read as a grant to
/// every value of it.
fn validate_secret_scope(
    sandboxes: Vec<String>,
    tags: Vec<String>,
) -> Result<crate::secrets::Scope, Status> {
    let max = crate::secrets::MAX_SCOPE_ENTRIES;
    if sandboxes.len() > max || tags.len() > max {
        return Err(Status::invalid_argument(format!(
            "a secret's scope names at most {max} sandboxes and {max} tags"
        )));
    }
    for entry in &sandboxes {
        if entry.is_empty() {
            return Err(Status::invalid_argument(
                "an allowed_sandboxes entry may not be empty",
            ));
        }
        validate_sandbox_id(entry).map_err(|_| {
            Status::invalid_argument(format!(
                "allowed_sandboxes entry {entry:?} is not a sandbox id or name"
            ))
        })?;
    }
    for entry in &tags {
        let usable = entry.split_once('=').is_some_and(|(key, value)| {
            !key.is_empty()
                && entry.len() <= 512
                && !entry.bytes().any(|b| b.is_ascii_control())
                && !value.is_empty()
        });
        if !usable {
            return Err(Status::invalid_argument(format!(
                "allowed_tags entry {entry:?} is not key=value"
            )));
        }
    }
    Ok(crate::secrets::Scope::new(sandboxes, tags))
}

fn validate_secret_name(name: &str) -> Result<(), Status> {
    if !is_kebab(name, 64) {
        return Err(Status::invalid_argument(format!(
            "secret name {name:?} must be lowercase kebab-case, 1 to 64 characters"
        )));
    }
    Ok(())
}

/// How long a create waits for another create of the same request id.
const REQUEST_WAIT: std::time::Duration = std::time::Duration::from_secs(120);
const REQUEST_POLL: std::time::Duration = std::time::Duration::from_millis(200);

#[allow(clippy::result_large_err)]
fn validate_request_id(request_id: &str) -> Result<(), Status> {
    let is_valid = request_id.len() <= 128
        && request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    match is_valid {
        true => Ok(()),
        false => Err(Status::invalid_argument(
            "request_id is up to 128 characters of [A-Za-z0-9._:-]",
        )),
    }
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

/// Whether a failed adopt left the target holding nothing.
///
/// A node that answered has either never claimed the stored state or handed
/// the claim back before answering. A call that timed out, was cut off, or
/// broke in transport may still be running on the target, and restoring the
/// sandbox elsewhere as well would run it twice; tonic reports a connection
/// dropped after the request went out as unavailable, so that code is no
/// proof either. Already exists means the target holds the sandbox, or is
/// taking it up for an earlier attempt. An abort is another start placing it.
fn target_let_go(err: &Status) -> bool {
    !matches!(
        err.code(),
        tonic::Code::Aborted
            | tonic::Code::AlreadyExists
            | tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
            | tonic::Code::Unavailable
            | tonic::Code::Unknown
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn replica(sandboxes: crate::sandboxes::SandboxRegistry) -> ApiService {
        ApiService(Arc::new(OrchestratorState {
            nodes: crate::registry::NodeRegistry::default(),
            sandboxes,
            store: None,
            leader: crate::leader::Leader::spawn(None),
            control_plane_hosts: std::sync::Mutex::new(vec!["a".into(), "b".into()]),
            events: crate::events::EventLog::new(None),
            secrets: None,
            access: None,
            access_trusted: Vec::new(),
            snapshots: crate::snapshots::SnapshotRegistry::default(),
            volumes: crate::volumes::VolumeRegistry::default(),
            channels: NodeChannels::default(),
            node_token: None,
            sandbox_lease_secs: 0,
            ips: Default::default(),
            admission: Default::default(),
            byol_node_labels: Default::default(),
            tagged: Default::default(),
        }))
    }

    async fn offering(nodes: &[(&str, &[&str])]) -> ApiService {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        for (id, hypervisors) in nodes {
            let info = burrow_proto::common::v1::NodeInfo {
                id: id.to_string(),
                address: format!("{id}:7071"),
                hypervisors: hypervisors.iter().map(|h| h.to_string()).collect(),
                ..Default::default()
            };
            api.0
                .nodes
                .register(info, String::new(), String::new(), None)
                .unwrap();
        }
        api
    }

    /// A restore image is installed only on a node offering vz, and a fleet
    /// without one says so rather than sending it to a node that cannot.
    #[tokio::test]
    async fn a_build_is_placed_where_it_can_run() {
        let ipsw = api::BuildTemplateRequest {
            name: "macos-27".into(),
            from_ipsw: "latest".into(),
            ..Default::default()
        };
        let on_mac = api::BuildTemplateRequest {
            name: "macos-dev".into(),
            from: "macos-27".into(),
            hypervisor: "vz".into(),
            ..Default::default()
        };
        let linux = api::BuildTemplateRequest {
            name: "tools".into(),
            from: "alpine".into(),
            hypervisor: "firecracker".into(),
            ..Default::default()
        };
        let fleet = offering(&[("linux", &["firecracker"]), ("mac", &["vz"])]).await;
        for (request, node) in [(&ipsw, "mac"), (&on_mac, "mac"), (&linux, "linux")] {
            assert_eq!(
                fleet.0.nodes.place_for(&build_placement(request)).unwrap(),
                node
            );
        }
        assert_eq!(build_placement(&on_mac).template, "macos-27");
        assert_eq!(build_placement(&ipsw).template, "");

        let linux_only = offering(&[("linux", &["firecracker", "cloud-hypervisor"])]).await;
        let refused = placement_status(
            linux_only
                .0
                .nodes
                .place_for(&build_placement(&ipsw))
                .unwrap_err(),
        );
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert!(refused.message().contains("vz"), "{}", refused.message());
    }

    /// A fleet of nodes, each under the inspection root named beside it.
    async fn under_roots(nodes: &[(&str, &str)]) -> ApiService {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        for (id, root) in nodes {
            let info = burrow_proto::common::v1::NodeInfo {
                id: id.to_string(),
                address: format!("{id}:7071"),
                inspection_root_fingerprint: root.to_string(),
                hypervisors: vec!["firecracker".into()],
                ..Default::default()
            };
            api.0
                .nodes
                .register(info, String::new(), String::new(), None)
                .unwrap();
        }
        api
    }

    fn inspected(id: &str, node: &str, root: &str) -> common::Sandbox {
        common::Sandbox {
            id: id.into(),
            node_id: node.into(),
            state: common::SandboxState::Running as i32,
            inspection_root_fingerprint: root.into(),
            hypervisor: "firecracker".into(),
            ..Default::default()
        }
    }

    /// A guest holds its inspection root in memory, so a move to a node under
    /// another root is refused before the source lets go, naming both.
    #[tokio::test]
    async fn an_inspected_sandbox_moves_only_to_a_node_under_its_root() {
        let api = under_roots(&[("node1", "aaaa"), ("node2", "bbbb"), ("node3", "aaaa")]).await;
        api.0
            .sandboxes
            .put(inspected("sbx_a", "node1", "aaaa"))
            .await;

        let err = api
            .move_sandbox(Request::new(api::MoveSandboxRequest {
                sandbox_id: "sbx_a".into(),
                node_id: "node2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(err.message().contains("aaaa"), "{err}");
        assert!(
            err.message().contains("node2's inspection root is bbbb"),
            "{err}"
        );

        // Under the same root the checks pass, and the move goes on to the
        // source, which a test has no way to reach.
        let err = api
            .move_sandbox(Request::new(api::MoveSandboxRequest {
                sandbox_id: "sbx_a".into(),
                node_id: "node3".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_ne!(err.code(), tonic::Code::FailedPrecondition, "{err}");
    }

    /// A node's own authority is a root no other node has: an automatic move
    /// finds nowhere to go and says so, rather than failing every connection
    /// the guest holds once it lands.
    #[tokio::test]
    async fn a_sandbox_under_a_per_node_root_has_nowhere_to_move() {
        let api = under_roots(&[("node1", "aaaa"), ("node2", "bbbb")]).await;
        api.0
            .sandboxes
            .put(inspected("sbx_a", "node1", "aaaa"))
            .await;
        let err = api
            .move_sandbox(Request::new(api::MoveSandboxRequest {
                sandbox_id: "sbx_a".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(
            err.message()
                .contains("trusts the TLS inspection root aaaa"),
            "{err}"
        );
        assert!(err.message().contains("node2: bbbb"), "{err}");
    }

    #[tokio::test]
    async fn placement_passes_over_nodes_under_another_root() {
        let api = under_roots(&[("node1", "aaaa"), ("node2", "bbbb"), ("node3", "aaaa")]).await;
        let excluded = api
            .other_roots("sandbox sbx_a", "aaaa", Some("node1"))
            .unwrap();
        assert_eq!(
            excluded,
            std::collections::HashSet::from(["node2".to_string()])
        );
        // A sandbox that is not inspected trusts nothing of the node's.
        assert!(
            api.other_roots("sandbox sbx_b", "", None)
                .unwrap()
                .is_empty()
        );
        assert!(
            api.require_inspection_root("node2", "sandbox sbx_b", "")
                .is_ok()
        );
        assert!(api.other_roots("sandbox sbx_a", "cccc", None).is_err());
    }

    /// The request names the source, never the child: a fork of `sbx_a`, by
    /// id or by name, is not refused as a second `sbx_a` and goes on to the
    /// source's node, which a test has no way to reach.
    #[tokio::test]
    async fn a_fork_names_its_source_not_its_child() {
        let api = offering(&[("node1", &["firecracker"])]).await;
        api.0
            .sandboxes
            .put(common::Sandbox {
                id: "sbx_a".into(),
                name: "web".into(),
                node_id: "node1".into(),
                state: common::SandboxState::Running as i32,
                ..Default::default()
            })
            .await;
        for source in ["sbx_a", "web"] {
            let err = api
                .fork_sandbox(Request::new(api::ForkSandboxRequest {
                    sandbox_id: source.into(),
                    ..Default::default()
                }))
                .await
                .unwrap_err();
            assert_ne!(err.code(), tonic::Code::AlreadyExists, "{source}: {err}");
            assert_ne!(err.code(), tonic::Code::InvalidArgument, "{source}: {err}");
        }
    }

    /// A delete always succeeds once the row is gone. For a sandbox no node
    /// holds, the stored state is purged through any node that can reach the
    /// object store, and left for the collector when none can; for one on a
    /// node that does not answer, the node destroys it at its next heartbeat.
    /// A replica whose cache still names the node a move left does not stop
    /// it either.
    #[tokio::test]
    async fn a_delete_succeeds_whether_or_not_a_node_answers() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let mover = crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
            .await
            .unwrap();
        let stale = crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
            .await
            .unwrap();
        mover.put(sandbox_a("node1")).await;
        assert_eq!(stale.refresh("sbx_a").await.unwrap().node_id, "node1");
        mover.unplace(sandbox_a("node1"), "node1", 1).await.unwrap();
        let api = replica(stale);
        api.delete_sandbox(Request::new(api::SandboxRef {
            sandbox_id: "sbx_a".into(),
        }))
        .await
        .unwrap();
        assert!(store.get_placement("sbx_a").await.unwrap().is_none());

        let info = common::NodeInfo {
            id: "node1".into(),
            address: "127.0.0.1:1".into(),
            ..Default::default()
        };
        api.0
            .nodes
            .register(info, String::new(), String::new(), None)
            .unwrap();
        for aged in [None, Some(crate::registry::ABSENT_AFTER)] {
            api.0
                .sandboxes
                .put(common::Sandbox {
                    name: "web".into(),
                    ..sandbox_a("node1")
                })
                .await;
            store.claim("name:web", "sbx_a", 1).await.unwrap();
            if let Some(aged) = aged {
                api.0.nodes.age("node1", aged);
            }
            api.delete_sandbox(Request::new(api::SandboxRef {
                sandbox_id: "web".into(),
            }))
            .await
            .unwrap();
            assert!(api.0.sandboxes.get("sbx_a").is_none());
            assert_eq!(store.claim_holder("name:web").await.unwrap(), None);
        }
        let err = api
            .delete_sandbox(Request::new(api::SandboxRef {
                sandbox_id: "sbx_a".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound, "{err}");
    }

    /// A move whose memory the target's CPU cannot restore is refused before
    /// the source suspends it, naming the difference. Stopped, it boots from
    /// its disk and is not held to the CPU.
    #[tokio::test]
    async fn a_move_is_refused_before_suspending_to_an_incompatible_cpu() {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        let fingerprint = |features: &[&str]| common::CpuFingerprint {
            vendor: "GenuineIntel".into(),
            family: 6,
            model: 0x55,
            features: features.iter().map(|f| f.to_string()).collect(),
            physical_address_bits: 46,
        };
        for (id, features) in [("node1", &["avx", "avx2"][..]), ("node2", &["avx"][..])] {
            let info = common::NodeInfo {
                id: id.into(),
                address: format!("{id}:7071"),
                hypervisors: vec!["cloud-hypervisor".into()],
                cpu: Some(fingerprint(features)),
                ..Default::default()
            };
            api.0
                .nodes
                .register(info, String::new(), String::new(), None)
                .unwrap();
        }
        let running = common::Sandbox {
            hypervisor: "cloud-hypervisor".into(),
            ..sandbox_a("node1")
        };
        api.0.sandboxes.put(running.clone()).await;
        let move_to_node2 = || {
            api.move_sandbox(Request::new(api::MoveSandboxRequest {
                sandbox_id: "sbx_a".into(),
                node_id: "node2".into(),
                ..Default::default()
            }))
        };

        let err = move_to_node2().await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(err.message().contains("lacks avx2"), "{err}");
        let err = api
            .move_sandbox(Request::new(api::MoveSandboxRequest {
                sandbox_id: "sbx_a".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(err.message().contains("node node2 lacks avx2"), "{err}");

        api.0
            .sandboxes
            .update(common::Sandbox {
                state: common::SandboxState::Stopped as i32,
                ..running
            })
            .await;
        let err = move_to_node2().await.unwrap_err();
        assert_ne!(err.code(), tonic::Code::FailedPrecondition, "{err}");
    }

    /// A volume a suspended or unplaced sandbox mounts is attached to no VM,
    /// so its node does not count it held, but the sandbox needs it back. Its
    /// delete is refused on the store's word, whatever any replica caches.
    #[tokio::test]
    async fn a_volume_a_stopped_sandbox_mounts_is_not_deleted() {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        let store = Arc::clone(api.0.sandboxes.store());
        store.insert_volume("data", 1).await.unwrap();
        let mounting = common::Sandbox {
            policy: Some(common::Policy {
                volumes: vec![common::VolumeMount {
                    volume: "data".into(),
                    path: "/data".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..sandbox_a("")
        };
        api.0.sandboxes.put(mounting).await;
        let err = api
            .delete_volume(Request::new(api::VolumeRef {
                name: "data".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(err.message().contains("sbx_a"), "{err}");
        assert!(store.volume_names().await.unwrap().contains("data"));
    }

    /// A heartbeat sampled before a snapshot was taken, and applied after,
    /// lists the node's snapshots without it. That is no word on its row,
    /// which goes only when the node reports it swept the snapshot itself.
    #[tokio::test]
    async fn a_heartbeat_older_than_a_snapshot_keeps_its_row() {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        let store = Arc::clone(api.0.sandboxes.store());
        store
            .register_node(
                &burrow_store::NodeRow {
                    id: "n1".into(),
                    ..Default::default()
                },
                None,
                8,
            )
            .await
            .unwrap();
        api.0
            .nodes
            .register(
                common::NodeInfo {
                    id: "n1".into(),
                    address: "127.0.0.1:1".into(),
                    ..Default::default()
                },
                String::new(),
                String::new(),
                None,
            )
            .unwrap();
        for id in ["snap_old", "snap_new"] {
            store.insert_snapshot(id, 1).await.unwrap();
            api.0.snapshots.insert(
                "n1",
                common::Snapshot {
                    id: id.into(),
                    ..Default::default()
                },
            );
        }
        let service = crate::NodeRegistryService(Arc::clone(&api.0));
        let beat = |seq, swept: Vec<String>| {
            service.heartbeat(Request::new(nodepb::HeartbeatRequest {
                node_id: "n1".into(),
                report_seq: seq,
                snapshots: vec!["snap_old".into()],
                swept_snapshots: swept,
                ..Default::default()
            }))
        };
        use burrow_proto::node::v1::node_registry_server::NodeRegistry as _;
        beat(1, Vec::new()).await.unwrap();
        assert!(store.snapshot_ids().await.unwrap().contains("snap_new"));
        beat(2, vec!["snap_old".into()]).await.unwrap();
        assert!(!store.snapshot_ids().await.unwrap().contains("snap_old"));
    }

    /// A snapshot or volume delete succeeds once its row is gone, with its
    /// node unreachable, which destroys its copy when next heard from. A
    /// volume a sandbox has attached is still refused.
    #[tokio::test]
    async fn snapshot_and_volume_deletes_need_no_node() {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        let store = Arc::clone(api.0.sandboxes.store());
        let info = common::NodeInfo {
            id: "node1".into(),
            address: "127.0.0.1:1".into(),
            ..Default::default()
        };
        api.0
            .nodes
            .register(info, String::new(), String::new(), None)
            .unwrap();
        store.insert_snapshot("snap_a", 1).await.unwrap();
        api.0.snapshots.insert(
            "node1",
            common::Snapshot {
                id: "snap_a".into(),
                ..Default::default()
            },
        );
        let delete = || {
            api.delete_snapshot(Request::new(api::SnapshotRef {
                id: "snap_a".into(),
            }))
        };
        delete().await.unwrap();
        assert!(!store.snapshot_ids().await.unwrap().contains("snap_a"));
        assert_eq!(delete().await.unwrap_err().code(), tonic::Code::NotFound);

        store.insert_volume("data", 1).await.unwrap();
        let volume = |attached_to: &str| common::Volume {
            name: "data".into(),
            attached_to: attached_to.into(),
            ..Default::default()
        };
        let delete = || {
            api.delete_volume(Request::new(api::VolumeRef {
                name: "data".into(),
            }))
        };
        api.0.volumes.insert("node1", volume("sbx_a"));
        let err = delete().await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(store.volume_names().await.unwrap().contains("data"));
        api.0.volumes.insert("node1", volume(""));
        delete().await.unwrap();
        assert!(store.volume_names().await.unwrap().is_empty());
    }

    /// Two starts of one unplaced sandbox through two replicas: the second
    /// read it unplaced before the first placed it. The first raised its
    /// generation, so the second cannot place it again.
    #[tokio::test]
    async fn a_sandbox_another_replica_placed_is_not_placed_again() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let first = crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
            .await
            .unwrap();
        let second = crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
            .await
            .unwrap();
        first.put(sandbox_a("")).await;
        let (stale, generation) = second.placed("sbx_a").await.unwrap();
        assert!(stale.node_id.is_empty());

        first
            .move_to(&stale, "", generation, "node1")
            .await
            .unwrap();
        let err = second
            .move_to(&stale, "", generation, "node2")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted, "{err}");
        assert!(err.message().contains("node node1"), "{err}");
        let err = replica(second)
            .adopt(stale, "", HashMap::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted, "{err}");
        assert!(err.message().contains("node node1"), "{err}");
    }

    /// A leader that lost its term without noticing yet wrote nodes off on
    /// its own stale view, as did one whose cache had not caught up with a
    /// heartbeat another replica took.
    /// A replica started on the old pool follows the one another replica
    /// recorded, so a node registering through it is given the fleet's pool
    /// and a slice of it.
    #[tokio::test]
    async fn a_replica_follows_the_pool_another_replica_recorded() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let mut state =
            Arc::try_unwrap(replica(crate::sandboxes::SandboxRegistry::in_memory().await).0)
                .ok()
                .unwrap();
        state.store = Some(Arc::clone(&store));
        assert!(
            store
                .change_address_pool("100.64.0.0/16", "fd00:b070::/48", 1024)
                .await
                .unwrap()
        );
        let pool = crate::cluster::reload_pool(&state, &store).await.unwrap();
        assert_eq!(pool.cidr(), "100.64.0.0/16");
        assert_eq!(pool.max_nodes(), 15);
        assert_eq!(state.nodes.pool(), pool);
    }

    #[tokio::test]
    async fn only_the_current_leader_writes_off_a_node_still_silent() {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let row = |last_heartbeat_ms| burrow_store::NodeRow {
            id: "node1".into(),
            last_heartbeat_ms,
            ..Default::default()
        };
        store.register_node(&row(1_000), None, 8).await.unwrap();
        let deposed = store.next_leader_epoch().await.unwrap();
        let current = store.next_leader_epoch().await.unwrap();
        let leader = async |epoch| {
            let registry = crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
                .await
                .unwrap();
            let mut state = Arc::try_unwrap(replica(registry).0).ok().unwrap();
            state.store = Some(Arc::clone(&store));
            state.leader = crate::leader::Leader::holding(epoch);
            let api = ApiService(Arc::new(state));
            api.0.sandboxes.put(sandbox_a("node1")).await;
            api
        };
        let expiry = std::time::Duration::from_secs(60);

        for epoch in [None, Some(deposed)] {
            let api = leader(epoch).await;
            assert!(!crate::write_off_node(&api.0, "node1", expiry).await);
            assert_eq!(api.0.sandboxes.node_of("sbx_a").as_deref(), Some("node1"));
        }
        let beat = |seq, last_heartbeat_ms| burrow_store::NodeReport {
            node: row(last_heartbeat_ms),
            seq,
            sandboxes: vec![burrow_store::ReportedSandbox {
                id: "sbx_a".into(),
                generation: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        store
            .reconcile_node(
                &beat(1, burrow_common::unix_now_ms()),
                |_| None,
                |_, _| None,
            )
            .await
            .unwrap();
        assert!(!crate::write_off_node(&leader(Some(current)).await.0, "node1", expiry).await);
        store
            .reconcile_node(&beat(2, 1_000), |_| None, |_, _| None)
            .await
            .unwrap();
        let api = leader(Some(current)).await;
        assert!(crate::write_off_node(&api.0, "node1", expiry).await);
        assert_eq!(api.0.sandboxes.node_of("sbx_a").as_deref(), Some(""));
    }

    /// A replica over a store holding `sbx_a`'s address 203.0.113.17, which
    /// reaches node1.
    async fn pinned(sandbox: common::Sandbox, nodes: &[&str]) -> ApiService {
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let ip = common::PublicIp {
            address: "203.0.113.17".into(),
            family: 4,
            pool: "rack-a".into(),
            sandbox_id: "sbx_a".into(),
            node_id: "node1".into(),
            state: common::PublicIpState::Allocated as i32,
            ..Default::default()
        };
        store
            .put_ip(&burrow_store::IpRow {
                address: ip.address.clone(),
                pool: ip.pool.clone(),
                owner: "anonymous".into(),
                state: ip.state,
                available_at_ms: 0,
                record: prost::Message::encode_to_vec(&ip),
            })
            .await
            .unwrap();
        let registry = crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
            .await
            .unwrap();
        let mut state = Arc::try_unwrap(replica(registry).0).ok().unwrap();
        state.store = Some(store);
        state.control_plane_hosts = std::sync::Mutex::new(Vec::new());
        let api = ApiService(Arc::new(state));
        for id in nodes {
            let info = common::NodeInfo {
                id: id.to_string(),
                address: format!("{id}:7071"),
                ..Default::default()
            };
            api.0
                .nodes
                .register(info, String::new(), String::new(), None)
                .unwrap();
        }
        api.0
            .sandboxes
            .put(common::Sandbox {
                public_ips: vec![ip],
                ..sandbox
            })
            .await;
        api
    }

    fn sandbox_a(node: &str) -> common::Sandbox {
        common::Sandbox {
            id: "sbx_a".into(),
            node_id: node.into(),
            state: common::SandboxState::Suspended as i32,
            is_durable: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_sandbox_holding_a_public_ip_does_not_move() {
        let api = pinned(sandbox_a("node1"), &["node1", "node2"]).await;
        for node in ["node2", ""] {
            let err = api
                .move_sandbox(Request::new(api::MoveSandboxRequest {
                    sandbox_id: "sbx_a".into(),
                    node_id: node.into(),
                    ..Default::default()
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
            assert!(err.message().contains("203.0.113.17"), "{err}");
            assert!(err.message().contains("detach"), "{err}");
        }
    }

    /// A move to a node that lacks a CPU the sandbox is pinned to, or the
    /// io.weight its IO weight needs, is refused naming the setting before
    /// the source is asked to let go. Dropping the cpuset gets it past.
    #[tokio::test]
    async fn a_move_to_a_node_that_cannot_hold_its_limits_is_refused_first() {
        let api = replica(crate::sandboxes::SandboxRegistry::in_memory().await);
        for (id, vcpus) in [("node1", 8), ("node2", 2)] {
            api.0
                .nodes
                .register(
                    common::NodeInfo {
                        id: id.into(),
                        address: "127.0.0.1:1".into(),
                        total_vcpus: vcpus,
                        hypervisors: vec!["firecracker".into()],
                        ..Default::default()
                    },
                    String::new(),
                    String::new(),
                    None,
                )
                .unwrap();
        }
        let pinned = |cpuset: &str, blkio_weight| common::Sandbox {
            id: "sbx_a".into(),
            node_id: "node1".into(),
            state: common::SandboxState::Running as i32,
            policy: Some(common::Policy {
                resources: Some(common::ResourcePolicy {
                    vcpus: 2,
                    cpuset_cpus: cpuset.into(),
                    blkio_weight,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            hypervisor: "firecracker".into(),
            ..Default::default()
        };
        let move_to = |dropped| api::MoveSandboxRequest {
            sandbox_id: "sbx_a".into(),
            node_id: "node2".into(),
            is_cpuset_dropped: dropped,
            ..Default::default()
        };
        api.0.sandboxes.put(pinned("6-7", 0)).await;
        let err = api
            .move_sandbox(Request::new(move_to(false)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(
            err.message().contains("cpuset_cpus \"6-7\" names CPU 7"),
            "{err}"
        );
        assert!(err.message().contains("--drop-cpuset"), "{err}");

        // Past the check, the move goes on to ask the source to let go, which
        // this fleet's unreachable nodes cannot answer.
        let err = api
            .move_sandbox(Request::new(move_to(true)))
            .await
            .unwrap_err();
        assert_ne!(err.code(), tonic::Code::FailedPrecondition, "{err}");

        api.0.sandboxes.put(pinned("", 500)).await;
        let err = api
            .move_sandbox(Request::new(move_to(true)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(
            err.message().contains("io.weight for blkio_weight 500"),
            "{err}"
        );
    }

    /// Refused before the node is asked anything, naming the sandbox and its
    /// address; kept on request.
    #[tokio::test]
    async fn a_drain_is_refused_while_a_sandbox_holds_a_public_ip() {
        let api = pinned(sandbox_a("node1"), &["node1"]).await;
        let drain = |is_pinned_kept| api::DrainNodeRequest {
            node_id: "node1".into(),
            is_draining: true,
            is_suspending: true,
            is_pinned_kept,
        };
        let err = api
            .drain_node(Request::new(drain(false)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(err.message().contains("sbx_a (203.0.113.17)"), "{err}");
        assert!(err.message().contains("--keep-pinned"), "{err}");
        // Past the check, to the node, which a test cannot reach.
        let err = api.drain_node(Request::new(drain(true))).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable, "{err}");
    }

    /// A written-off node leaves a durable sandbox unplaced, and one whose
    /// address reaches only that node is not restored anywhere else.
    #[tokio::test]
    async fn a_pinned_sandbox_waits_for_its_node() {
        let api = pinned(sandbox_a(""), &["node2"]).await;
        let err = api
            .resume_sandbox(Request::new(api::SandboxRef {
                sandbox_id: "sbx_a".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(
            err.message().contains("node node1, and that node is down"),
            "{err}"
        );
        let err = api
            .move_sandbox(Request::new(api::MoveSandboxRequest {
                sandbox_id: "sbx_a".into(),
                node_id: "node2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(err.message().contains("on node node2"), "{err}");
    }

    /// A running sandbox with a checkpoint outlives its node like a suspended
    /// one, and like it, one holding a public address recovers only there.
    #[tokio::test]
    async fn a_pinned_checkpoint_waits_for_its_node() {
        let running = common::Sandbox {
            state: common::SandboxState::Running as i32,
            is_durable: false,
            checkpoint_at_unix_ms: 1_787_000_000_000,
            checkpoint_kind: common::CheckpointKind::Disk as i32,
            ..sandbox_a("node1")
        };
        let api = pinned(running, &["node2"]).await;
        let store = api.0.sandboxes.store();
        let node = burrow_store::NodeRow {
            id: "node1".into(),
            last_heartbeat_ms: 1_000,
            ..Default::default()
        };
        store.register_node(&node, None, 8).await.unwrap();
        let epoch = store.next_leader_epoch().await.unwrap();
        let written_off = api
            .0
            .sandboxes
            .write_off("node1", &common::NodeInfo::default(), 2_000, epoch)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(written_off.unplaced.len(), 1);
        let err = api
            .start_sandbox(Request::new(api::StartSandboxRequest {
                sandbox_id: "sbx_a".into(),
                is_kernel_kept: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{err}");
        assert!(
            err.message().contains("node node1, and that node is down"),
            "{err}"
        );
    }

    /// A move whose target failed used to leave the sandbox suspended in the
    /// object store with no node holding it, though its source had it running.
    /// It goes back to the source when the target's answer says the target let
    /// go, and is left alone when the target may still be taking it up.
    #[test]
    fn a_failed_move_is_handed_back_only_when_the_target_let_go() {
        for code in [
            tonic::Code::Internal,
            tonic::Code::FailedPrecondition,
            tonic::Code::NotFound,
            tonic::Code::ResourceExhausted,
        ] {
            assert!(target_let_go(&Status::new(code, "")), "{code:?}");
        }
        for code in [
            tonic::Code::Aborted,
            tonic::Code::AlreadyExists,
            tonic::Code::Unavailable,
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Unknown,
        ] {
            assert!(!target_let_go(&Status::new(code, "")), "{code:?}");
        }
    }

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

    fn brokering(domain: &str, value: &str) -> common::RequestRule {
        common::RequestRule {
            domain: domain.into(),
            action: Some(common::request_rule::Action::SetHeaders(
                common::SetHeaders {
                    headers: vec![common::HeaderValue {
                        name: "Authorization".into(),
                        value: value.into(),
                    }],
                },
            )),
            ..Default::default()
        }
    }

    fn header_value(rule: &common::RequestRule) -> &str {
        match rule.action.as_ref() {
            Some(common::request_rule::Action::SetHeaders(set)) => &set.headers[0].value,
            _ => panic!("set_headers expected"),
        }
    }

    /// A scoped secret resolves only for the sandboxes its scope names, and
    /// the rule it went into is bound to the one it was resolved for. An
    /// unscoped one behaves as secrets always have.
    #[test]
    fn a_scoped_secret_resolves_only_where_it_is_scoped_and_binds_its_rule() {
        use crate::secrets::{Scope, Secret, Subject};
        let stored: HashMap<String, Secret> = [
            (
                "api".to_string(),
                Secret {
                    value: "scoped-token".into(),
                    scope: Scope::new(vec!["sbx_a".into()], vec!["team=ml".into()]),
                },
            ),
            (
                "shared".to_string(),
                Secret {
                    value: "shared-token".into(),
                    scope: Scope::default(),
                },
            ),
        ]
        .into();
        let none = HashMap::new();
        let policy = || common::NetworkPolicy {
            rules: vec![
                brokering("api.example.com", "Bearer ${secret:api}"),
                brokering("other.example.com", "Bearer ${secret:shared}"),
            ],
            ..Default::default()
        };

        let mut granted = policy();
        let subject = Subject {
            id: "sbx_a",
            name: "",
            tags: &none,
        };
        apply_secrets(&mut granted, subject, &stored).unwrap();
        assert_eq!(header_value(&granted.rules[0]), "Bearer scoped-token");
        assert_eq!(granted.rules[0].bound_sandbox_id, "sbx_a");
        assert_eq!(header_value(&granted.rules[1]), "Bearer shared-token");
        assert!(granted.rules[1].bound_sandbox_id.is_empty());

        let ml = [("team".to_string(), "ml".to_string())].into();
        let mut tagged = policy();
        let by_tag = Subject {
            id: "sbx_b",
            name: "",
            tags: &ml,
        };
        apply_secrets(&mut tagged, by_tag, &stored).unwrap();
        assert_eq!(tagged.rules[0].bound_sandbox_id, "sbx_b");

        let mut refused = policy();
        let outsider = Subject {
            id: "sbx_c",
            name: "",
            tags: &none,
        };
        let err = apply_secrets(&mut refused, outsider, &stored).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        // Refused whole: nothing of the scoped value reached the policy.
        assert!(!format!("{refused:?}").contains("scoped-token"));

        let mut missing = common::NetworkPolicy {
            rules: vec![brokering("api.example.com", "${secret:gone}")],
            ..Default::default()
        };
        assert_eq!(
            apply_secrets(&mut missing, subject, &stored)
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn a_secret_scope_is_held_to_ids_names_and_key_value_tags() {
        let scope = validate_secret_scope(
            vec!["builder".into(), "sbx_a".into(), "builder".into()],
            vec!["team=ml".into()],
        )
        .unwrap();
        assert_eq!(scope.sandboxes, vec!["builder", "sbx_a"]);
        for bad in ["", "has space", ".hidden"] {
            assert!(
                validate_secret_scope(vec![bad.into()], vec![]).is_err(),
                "{bad:?}"
            );
        }
        for bad in ["team", "=ml", "team=", "a=b\n"] {
            assert!(
                validate_secret_scope(vec![], vec![bad.into()]).is_err(),
                "{bad:?}"
            );
        }
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

#[cfg(test)]
mod create_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use tonic::codegen::{BoxFuture, Service, http};

    use super::*;

    /// A node that answers CreateSandbox after `delay`, failing the first
    /// `failures` with INTERNAL, and counts the creates it was sent.
    #[derive(Clone)]
    struct Node {
        delay: std::time::Duration,
        failures: usize,
        code: tonic::Code,
        calls: Arc<AtomicUsize>,
    }

    impl tonic::server::NamedService for Node {
        const NAME: &'static str = "burrow.node.v1.NodeService";
    }

    impl Service<http::Request<tonic::body::Body>> for Node {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
            let node = self.clone();
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                Ok(grpc.unary(node, req).await)
            })
        }
    }

    impl tonic::server::UnaryService<nodepb::NodeCreateRequest> for Node {
        type Response = common::Sandbox;
        type Future = BoxFuture<Response<common::Sandbox>, Status>;

        fn call(&mut self, req: Request<nodepb::NodeCreateRequest>) -> Self::Future {
            let node = self.clone();
            Box::pin(async move {
                let call = node.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(node.delay).await;
                if call < node.failures {
                    return Err(Status::new(node.code, "boot failed"));
                }
                let req = req.into_inner();
                Ok(Response::new(common::Sandbox {
                    id: req.sandbox_id,
                    node_id: "n1".into(),
                    template: req.template,
                    state: common::SandboxState::Running as i32,
                    create_request_id: req.request_id,
                    ..Default::default()
                }))
            })
        }
    }

    async fn fleet(delay_ms: u64, failures: usize) -> (ApiService, Arc<AtomicUsize>) {
        fleet_failing(delay_ms, failures, tonic::Code::Internal).await
    }

    async fn fleet_failing(
        delay_ms: u64,
        failures: usize,
        code: tonic::Code,
    ) -> (ApiService, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let node = Node {
            delay: std::time::Duration::from_millis(delay_ms),
            failures,
            code,
            calls: Arc::clone(&calls),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(node)
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
        );
        let store = Arc::new(burrow_store::Store::open_in_memory().await.unwrap());
        let mut api = super::tests::replica(
            crate::sandboxes::SandboxRegistry::open(Arc::clone(&store))
                .await
                .unwrap(),
        );
        let build = format!("sha256:{}", "b".repeat(64));
        store
            .put_ready_build(&burrow_store::BuildRow {
                id: "b1".into(),
                digest: build.clone(),
                template: "t".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        store.assign_tag("t", "latest", &build, 1).await.unwrap();
        let info = common::NodeInfo {
            id: "n1".into(),
            address: addr.to_string(),
            ..Default::default()
        };
        let status = common::NodeStatus {
            builds: vec![build],
            free_mem_mib: 1 << 20,
            ..Default::default()
        };
        let row = crate::cluster::node_row(&info, &status, "", "");
        store.register_node(&row, None, 64).await.unwrap();
        Arc::get_mut(&mut api.0).unwrap().store = Some(store);
        api.0
            .nodes
            .register(info, String::new(), String::new(), None)
            .unwrap();
        api.0.nodes.heartbeat("n1", status, None);
        (api, calls)
    }

    fn create(request_id: &str) -> Request<api::CreateSandboxRequest> {
        Request::new(api::CreateSandboxRequest {
            template: "t".into(),
            request_id: request_id.into(),
            ..Default::default()
        })
    }

    async fn settled(api: &ApiService) -> Vec<common::Sandbox> {
        for _ in 0..200 {
            if !api.0.sandboxes.list_tagged(Default::default()).is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        api.0.sandboxes.list_tagged(Default::default())
    }

    /// A create whose caller gave up used to be cancelled with it, leaving
    /// the node to finish a sandbox the registry never heard of. It runs to
    /// its end, at whichever point the caller left.
    #[tokio::test]
    async fn a_create_whose_caller_gives_up_still_lands() {
        for gives_up_ms in [1, 50, 150] {
            let (api, calls) = fleet(200, 0).await;
            let given_up = tokio::time::timeout(
                std::time::Duration::from_millis(gives_up_ms),
                api.create_sandbox(create("")),
            )
            .await;
            assert!(given_up.is_err());
            let placed = settled(&api).await;
            assert_eq!(placed.len(), 1, "gave up after {gives_up_ms}ms");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    /// A client retrying one create ten times, giving up on most of them at
    /// different points, ends with one sandbox, built once.
    #[tokio::test]
    async fn retries_of_one_request_make_one_sandbox() {
        let (api, calls) = fleet(300, 0).await;
        let mut made = std::collections::HashSet::new();
        for attempt in 0..10u64 {
            let tried = tokio::time::timeout(
                std::time::Duration::from_millis(attempt * 40),
                api.create_sandbox(create("req-1")),
            )
            .await;
            if let Ok(Ok(sandbox)) = tried {
                made.insert(sandbox.into_inner().id);
            }
        }
        let sandbox = api
            .create_sandbox(create("req-1"))
            .await
            .unwrap()
            .into_inner();
        made.insert(sandbox.id.clone());
        assert_eq!(made.len(), 1, "{made:?}");
        assert_eq!(sandbox.create_request_id, "req-1");
        assert_eq!(api.0.sandboxes.list_tagged(Default::default()).len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let other = api
            .create_sandbox(create("req-2"))
            .await
            .unwrap()
            .into_inner();
        assert_ne!(other.id, sandbox.id);
    }

    /// A create that failed made nothing, so its request id is free for the
    /// retry to make the sandbox.
    #[tokio::test]
    async fn a_failed_create_frees_its_request_id() {
        let (api, calls) = fleet(10, 1).await;
        let err = api.create_sandbox(create("req-1")).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
        let sandbox = api
            .create_sandbox(create("req-1"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(sandbox.create_request_id, "req-1");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.0.sandboxes.list_tagged(Default::default()).len(), 1);
    }

    /// A node that could not be heard from may have built the sandbox all
    /// the same. A retry waits for it to be reported rather than building a
    /// second.
    #[tokio::test]
    async fn a_retry_after_an_unanswered_create_finds_what_the_node_built() {
        let (api, calls) = fleet_failing(10, 1, tonic::Code::Unavailable).await;
        let err = api.create_sandbox(create("req-1")).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        let reported = api.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            reported
                .0
                .sandboxes
                .put(common::Sandbox {
                    id: "sbx_reported".into(),
                    node_id: "n1".into(),
                    create_request_id: "req-1".into(),
                    ..Default::default()
                })
                .await;
        });
        let sandbox = api
            .create_sandbox(create("req-1"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(sandbox.id, "sbx_reported");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A boot of a resized sandbox is charged its whole memory ceiling, and
    /// one the node has no room for is refused before the node is asked to
    /// change anything.
    #[tokio::test]
    async fn a_resize_and_boot_the_node_has_no_room_for_is_refused_first() {
        let (api, _) = fleet(10, 0).await;
        api.0.nodes.heartbeat(
            "n1",
            common::NodeStatus {
                builds: vec!["t".into()],
                free_mem_mib: 256,
                ..Default::default()
            },
            Some(common::NodeInfo {
                address: api
                    .0
                    .nodes
                    .endpoint("n1")
                    .unwrap()
                    .trim_start_matches("http://")
                    .into(),
                ..Default::default()
            }),
        );
        api.0
            .sandboxes
            .put(common::Sandbox {
                id: "sbx_stopped".into(),
                node_id: "n1".into(),
                state: common::SandboxState::Stopped as i32,
                ..Default::default()
            })
            .await;
        let err = api
            .update_resources(Request::new(api::UpdateResourcesRequest {
                sandbox_id: "sbx_stopped".into(),
                mem_mib: Some(4096),
                boot: true,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("no room"), "{}", err.message());
    }

    #[test]
    fn a_request_id_is_checked() {
        assert!(validate_request_id("").is_ok());
        assert!(validate_request_id("0f9c-4b:retry_1.a").is_ok());
        assert!(validate_request_id("has space").is_err());
        assert!(validate_request_id(&"a".repeat(129)).is_err());
    }
}

#[cfg(test)]
mod relay_tests {
    use std::task::{Context, Poll};

    use tonic::codegen::{BoxFuture, Service, http};

    use super::*;

    /// A node that answers only Fs, as a guest would, with the limits a node
    /// serves under.
    #[derive(Clone)]
    struct Node;

    impl tonic::server::NamedService for Node {
        const NAME: &'static str = "burrow.node.v1.NodeService";
    }

    impl Service<http::Request<tonic::body::Body>> for Node {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
            Box::pin(async move {
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                    .apply_max_message_size_config(
                        Some(burrow_proto::MAX_MESSAGE_BYTES),
                        Some(burrow_proto::MAX_MESSAGE_BYTES),
                    );
                Ok(grpc.unary(Fs, req).await)
            })
        }
    }

    struct Fs;

    impl tonic::server::UnaryService<api::FsRequest> for Fs {
        type Response = api::FsResponse;
        type Future = BoxFuture<Response<api::FsResponse>, Status>;

        fn call(&mut self, req: Request<api::FsRequest>) -> Self::Future {
            use api::fs_request::Op;
            use api::fs_response::Result as Outcome;
            let result = match req.into_inner().op {
                Some(Op::Write(write)) => Outcome::Written(write.data.len() as u64),
                Some(Op::Read(read)) => Outcome::Data(vec![1; read.length as usize]),
                _ => Outcome::IsDone(true),
            };
            Box::pin(async move {
                Ok(Response::new(api::FsResponse {
                    result: Some(result),
                }))
            })
        }
    }

    /// The relay hands a full chunk to the node, and back, in one call.
    #[tokio::test]
    async fn a_full_chunk_is_relayed_to_the_node_and_back() {
        use api::fs_request::Op;
        use api::fs_response::Result as Outcome;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(Node)
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
        );
        let mut node = connect_node(format!("http://{addr}"), None).await.unwrap();
        let chunk = burrow_proto::MAX_FILE_CHUNK;
        let call = |op| api::FsRequest {
            sandbox_id: "sbx_a".into(),
            op: Some(op),
            ..Default::default()
        };
        let written = node
            .fs(call(Op::Write(api::FsWrite {
                data: vec![0; chunk],
                ..Default::default()
            })))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(written.result, Some(Outcome::Written(chunk as u64)));
        let read = node
            .fs(call(Op::Read(api::FsRead {
                length: chunk as u32,
                ..Default::default()
            })))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(read.result, Some(Outcome::Data(data)) if data.len() == chunk));
    }
}
