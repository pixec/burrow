//! The node gRPC service: sandbox lifecycle plus pass-through to guest agents.

#![allow(clippy::result_large_err)]

use std::pin::Pin;

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use burrow_proto::agent::v1 as agentpb;
use burrow_proto::api::v1 as api;
use burrow_proto::common::v1 as common;
use burrow_proto::node::v1 as nodepb;
use burrow_proto::node::v1::node_service_server::NodeService;
use burrow_proxy::policy as proxypolicy;

use crate::sandbox::{RunningSandbox, SandboxManager};

pub struct NodeApi {
    pub sandboxes: SandboxManager,
    pub node_id: std::sync::Arc<std::sync::Mutex<String>>,
    pub data_dir: std::path::PathBuf,
    pub store: std::sync::Arc<burrow_store::Store>,
    /// Presented when this node dials another to pull a template.
    pub cluster_token: Option<String>,
    /// Guest agent binary, installed into images imported from OCI. Those
    /// images have no init of their own, and a VM booted without one panics.
    pub agent_binary: std::path::PathBuf,
    /// Credentials for registries that need them. Empty means anonymous pulls
    /// only, which covers public images.
    pub registry_credentials: crate::oci::auth::Store,
    /// Registry hosts allowed to be plain HTTP.
    pub insecure_registries: Vec<String>,
}

impl NodeApi {
    fn node_id(&self) -> String {
        self.node_id.lock().unwrap().clone()
    }

    /// Checks a membership change and opens the agent that will make it.
    ///
    /// Both memberships RPCs are the same call with a different verb, so the
    /// validation and the policy check live in one place rather than twice.
    async fn membership(
        &self,
        req: api::GroupMembershipRequest,
    ) -> Result<
        (
            String,
            String,
            burrow_proto::agent::v1::agent_client::AgentClient<tonic::transport::Channel>,
        ),
        Status,
    > {
        check_user_name(&req.user)?;
        check_user_name(&req.group)?;
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let agent = sandbox.agent().await?;
        Ok((req.user, req.group, agent))
    }

    /// The environment an imported image declared, if this template came from
    /// one. Templates built the old way simply have none.
    async fn image_environment(&self, template: &str) -> crate::oci::ImageEnvironment {
        crate::oci::image_environment(&self.data_dir, template).await
    }
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl NodeService for NodeApi {
    async fn health(
        &self,
        _req: Request<nodepb::NodeHealthRequest>,
    ) -> Result<Response<nodepb::NodeHealthResponse>, Status> {
        Ok(Response::new(nodepb::NodeHealthResponse {
            version: burrow_core::VERSION.into(),
        }))
    }

    async fn set_drain(
        &self,
        req: Request<api::DrainNodeRequest>,
    ) -> Result<Response<api::DrainNodeResponse>, Status> {
        let req = req.into_inner();
        let suspended = self
            .sandboxes
            .set_drain(req.drain, req.suspend_sandboxes)
            .await;
        Ok(Response::new(api::DrainNodeResponse { suspended }))
    }

    #[tracing::instrument(skip_all, fields(sandbox_id, template))]
    async fn create_sandbox(
        &self,
        req: Request<nodepb::NodeCreateRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        // Joins the orchestrator's trace rather than starting a new one, so the
        // node's share of a create is visible against the request that caused it.
        burrow_core::telemetry::propagation::adopt(req.metadata());
        let req = req.into_inner();
        tracing::Span::current().record("sandbox_id", req.sandbox_id.as_str());
        tracing::Span::current().record("template", req.template.as_str());
        validate_sandbox_id("sandbox_id", &req.sandbox_id)?;
        // Placement should have avoided a draining node, but a race between
        // heartbeats could still land here; refusing keeps drain meaningful.
        if self.sandboxes.is_draining() {
            return Err(Status::failed_precondition("node is draining"));
        }
        let policy = req.policy.unwrap_or_default();
        validate_policy(&policy)?;
        burrow_core::tags::validate(&req.metadata)?;
        // A create from a snapshot restores rather than boots, and takes its
        // template and shape from what the snapshot holds; it shares nothing
        // with the cold path but the checks above.
        let sandbox = if req.snapshot.is_empty() {
            // The template names a directory under `images/`, and a create is
            // the one path that reaches it with a string the orchestrator
            // passed straight through from a tenant.
            crate::template::validate_name(&req.template)?;
            self.sandboxes
                .create(
                    req.sandbox_id,
                    req.template,
                    policy,
                    req.metadata,
                    self.node_id(),
                    req.name,
                )
                .await?
        } else {
            self.sandboxes
                .create_from_snapshot(
                    req.sandbox_id,
                    &req.snapshot,
                    policy,
                    req.metadata,
                    self.node_id(),
                    req.name,
                )
                .await?
        };
        Ok(Response::new(redact_secrets(sandbox)))
    }

    /// Takes a sandbox's state and keeps it as a snapshot object.
    async fn create_snapshot(
        &self,
        req: Request<nodepb::NodeCreateSnapshotRequest>,
    ) -> Result<Response<common::Snapshot>, Status> {
        burrow_core::telemetry::propagation::adopt(req.metadata());
        let req = req.into_inner();
        if req.snapshot_id.is_empty() {
            return Err(Status::invalid_argument("snapshot_id is required"));
        }
        let snapshot = self
            .sandboxes
            .create_snapshot(&req.sandbox_id, req.snapshot_id, req.expiration_secs)
            .await?;
        Ok(Response::new(snapshot))
    }

    async fn list_snapshots(
        &self,
        req: Request<nodepb::NodeListSnapshotsRequest>,
    ) -> Result<Response<api::ListSnapshotsResponse>, Status> {
        let sandbox_id = req.into_inner().sandbox_id;
        Ok(Response::new(api::ListSnapshotsResponse {
            snapshots: self
                .sandboxes
                .snapshots()
                .list((!sandbox_id.is_empty()).then_some(sandbox_id.as_str()))
                .await,
        }))
    }

    async fn get_snapshot(
        &self,
        req: Request<api::SnapshotRef>,
    ) -> Result<Response<common::Snapshot>, Status> {
        let snapshot = self.sandboxes.snapshots().get(&req.into_inner().id).await?;
        Ok(Response::new(snapshot))
    }

    async fn delete_snapshot(
        &self,
        req: Request<api::SnapshotRef>,
    ) -> Result<Response<api::DeleteSnapshotResponse>, Status> {
        self.sandboxes
            .snapshots()
            .delete(&req.into_inner().id)
            .await?;
        Ok(Response::new(api::DeleteSnapshotResponse {}))
    }

    async fn create_volume(
        &self,
        req: Request<api::CreateVolumeRequest>,
    ) -> Result<Response<common::Volume>, Status> {
        let req = req.into_inner();
        let volume = self
            .sandboxes
            .volumes()
            .create(&req.name, req.size_mib)
            .await?;
        Ok(Response::new(volume))
    }

    async fn list_volumes(
        &self,
        _req: Request<api::ListVolumesRequest>,
    ) -> Result<Response<api::ListVolumesResponse>, Status> {
        Ok(Response::new(api::ListVolumesResponse {
            volumes: self.sandboxes.volumes().list().await,
        }))
    }

    async fn get_volume(
        &self,
        req: Request<api::VolumeRef>,
    ) -> Result<Response<common::Volume>, Status> {
        let volume = self.sandboxes.volumes().get(&req.into_inner().name).await?;
        Ok(Response::new(volume))
    }

    async fn delete_volume(
        &self,
        req: Request<api::VolumeRef>,
    ) -> Result<Response<api::DeleteVolumeResponse>, Status> {
        self.sandboxes
            .volumes()
            .delete(&req.into_inner().name)
            .await?;
        Ok(Response::new(api::DeleteVolumeResponse {}))
    }

    async fn get_sandbox(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let sandbox = self.sandboxes.get(&req.into_inner().sandbox_id).await?;
        Ok(Response::new(redact_secrets(sandbox.record())))
    }

    async fn list_sandboxes(
        &self,
        _req: Request<nodepb::NodeListRequest>,
    ) -> Result<Response<nodepb::NodeListResponse>, Status> {
        Ok(Response::new(nodepb::NodeListResponse {
            sandboxes: self
                .sandboxes
                .list()
                .await
                .into_iter()
                .map(redact_secrets)
                .collect(),
        }))
    }

    async fn delete_sandbox(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<nodepb::NodeDeleteResponse>, Status> {
        self.sandboxes.delete(&req.into_inner().sandbox_id).await?;
        Ok(Response::new(nodepb::NodeDeleteResponse {}))
    }

    async fn pause_sandbox(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let sandbox = self.sandboxes.pause(&req.into_inner().sandbox_id).await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    async fn resume_sandbox(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let sandbox = self.sandboxes.resume(&req.into_inner().sandbox_id).await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    async fn list_sessions(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<api::ListSessionsResponse>, Status> {
        let sessions = self
            .sandboxes
            .list_sessions(&req.into_inner().sandbox_id)
            .await?;
        Ok(Response::new(api::ListSessionsResponse { sessions }))
    }

    /// Moves a sandbox's lifetime clocks.
    ///
    /// The machine shape is refused rather than ignored: a running VM's
    /// configuration is fixed and a restore takes it from the snapshot, so a
    /// caller who asked for four vCPUs has to hear that they did not get them.
    /// The result is held to the same ceilings a create is, since it is the
    /// same record and the same reaper reads it.
    async fn update_resources(
        &self,
        req: Request<nodepb::NodeUpdateResourcesRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        check_shape_unchanged(req.vcpus, req.mem_mib, req.scratch_disk_mib)?;
        let sandbox = self
            .sandboxes
            .update_resources(
                &req.sandbox_id,
                req.max_lifetime_secs,
                req.idle_suspend_secs,
                req.suspended_ttl_secs,
            )
            .await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    /// Builds a sandbox from another's state.
    ///
    /// A policy override is held to exactly the checks a create is: the child
    /// is a sandbox on this node like any other, and one created by a different
    /// call must not be able to carry a policy a create would have refused.
    async fn fork_sandbox(
        &self,
        req: Request<nodepb::NodeForkRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        burrow_core::telemetry::propagation::adopt(req.metadata());
        let req = req.into_inner();
        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        validate_sandbox_id("child_id", &req.child_id)?;
        if self.sandboxes.is_draining() {
            return Err(Status::failed_precondition("node is draining"));
        }
        if let Some(policy) = &req.policy {
            validate_policy(policy)?;
        }
        let sandbox = self
            .sandboxes
            .fork(
                &req.sandbox_id,
                req.child_id,
                req.policy,
                self.node_id(),
                req.name,
            )
            .await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    /// Replaces a sandbox's tags.
    ///
    /// Validated exactly as a create's are: the same map reaches the same
    /// record and the same store either way.
    async fn update_tags(
        &self,
        req: Request<nodepb::NodeUpdateTagsRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        burrow_core::tags::validate(&req.tags)?;
        let sandbox = self
            .sandboxes
            .update_tags(&req.sandbox_id, req.tags)
            .await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    /// Replaces a sandbox's exec and file policies.
    ///
    /// A present section replaces that section wholesale; an absent one is
    /// left alone, so tightening one policy cannot re-open the other. The fs
    /// section is validated exactly as a create's is: the same scopes are
    /// matched by the same matcher either way.
    async fn update_access_policy(
        &self,
        req: Request<nodepb::NodeUpdateAccessRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        if req.exec.is_none() && req.fs.is_none() {
            // Naming neither section changes nothing, which is far more likely
            // to be a caller who spelled a field wrong than an intent.
            return Err(Status::invalid_argument(
                "name exec, fs or both: a request with neither would change nothing",
            ));
        }
        if let Some(fs) = &req.fs {
            validate_fs_policy(fs)?;
        }
        let sandbox = self
            .sandboxes
            .update_access_policy(&req.sandbox_id, req.exec, req.fs)
            .await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    /// Replaces a running sandbox's egress policy.
    ///
    /// Validated exactly as a create is: the same values reach the same
    /// nftables render and the same proxy table, so a policy that would be
    /// refused at creation must be refused here too.
    async fn update_network_policy(
        &self,
        req: Request<nodepb::NodeUpdateNetworkRequest>,
    ) -> Result<Response<common::Sandbox>, Status> {
        let req = req.into_inner();
        let network = req
            .network
            .ok_or_else(|| Status::invalid_argument("network is required"))?;
        validate_network_policy(&network)?;
        let sandbox = self
            .sandboxes
            .update_network_policy(&req.sandbox_id, network)
            .await?;
        Ok(Response::new(redact_secrets(sandbox)))
    }

    type BuildTemplateStream = BoxStream<api::BuildLog>;

    async fn build_template(
        &self,
        req: Request<api::BuildTemplateRequest>,
    ) -> Result<Response<Self::BuildTemplateStream>, Status> {
        // Bounded: a chatty build must not let log production outrun the
        // client reading it.
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let manager = self.sandboxes.clone();
        let data_dir = self.data_dir.clone();
        let node_id = self.node_id();
        let agent_binary = self.agent_binary.clone();
        let credentials = self.registry_credentials.clone();
        let insecure = self.insecure_registries.clone();
        tokio::spawn(async move {
            let announce = manager.clone();
            crate::template::build(
                manager,
                data_dir,
                node_id,
                req.into_inner(),
                agent_binary,
                credentials,
                insecure,
                tx,
            )
            .await;
            // A template nobody knows about cannot be placed on, and someone
            // who just built one is about to try using it.
            announce.announce_now();
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
            templates: crate::template::list(&self.data_dir).await,
        }))
    }

    async fn delete_template(
        &self,
        req: Request<api::DeleteTemplateRequest>,
    ) -> Result<Response<api::DeleteTemplateResponse>, Status> {
        crate::template::delete(&self.data_dir, &req.into_inner().name).await?;
        Ok(Response::new(api::DeleteTemplateResponse {}))
    }

    async fn get_template_manifest(
        &self,
        req: Request<nodepb::TemplateManifestRequest>,
    ) -> Result<Response<nodepb::TemplateManifest>, Status> {
        let manifest =
            crate::template::distribute::manifest(&self.data_dir, &req.into_inner().name).await?;
        Ok(Response::new(manifest))
    }

    type FetchBlobStream = BoxStream<nodepb::BlobChunk>;

    /// Streams a stored artifact to a peer.
    ///
    /// Chunked rather than sent whole: a rootfs is hundreds of megabytes and
    /// neither side should have to hold it in memory.
    async fn fetch_blob(
        &self,
        req: Request<nodepb::BlobRequest>,
    ) -> Result<Response<Self::FetchBlobStream>, Status> {
        use tokio::io::AsyncReadExt;

        let mut file =
            crate::template::distribute::open_blob(&self.data_dir, &req.into_inner().digest)
                .await?;

        let stream = async_stream::try_stream! {
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .await
                    .map_err(|err| Status::internal(format!("reading blob: {err}")))?;
                if read == 0 {
                    break;
                }
                yield nodepb::BlobChunk { data: buffer[..read].to_vec() };
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn pull_template(
        &self,
        req: Request<nodepb::PullTemplateRequest>,
    ) -> Result<Response<nodepb::PullTemplateResponse>, Status> {
        let req = req.into_inner();
        let manifest = req
            .manifest
            .ok_or_else(|| Status::invalid_argument("manifest is required"))?;
        let (bytes_transferred, blobs_reused) = crate::template::distribute::pull(
            &self.data_dir,
            &req.source_address,
            &manifest,
            self.cluster_token.as_deref(),
        )
        .await?;
        // The point of pulling was to be placed on; say so at once.
        self.sandboxes.announce_now();
        // The snapshot is the one artifact that does not travel, so a node
        // that received a template warms it itself. Never blocks the pull.
        // Anything already here was captured on the rootfs this pull replaced.
        self.sandboxes.invalidate_warm(&manifest.name).await;
        self.sandboxes
            .warm_in_background(manifest.name.clone(), common::ResourcePolicy::default());
        Ok(Response::new(nodepb::PullTemplateResponse {
            bytes_transferred,
            blobs_reused,
        }))
    }

    async fn expose_port(
        &self,
        req: Request<api::ExposePortRequest>,
    ) -> Result<Response<api::PortMapping>, Status> {
        let req = req.into_inner();
        let (host_port, guest_port) = self
            .sandboxes
            .expose_port(
                &req.sandbox_id,
                port_u16(req.guest_port)?,
                port_u16(req.host_port)?,
            )
            .await?;
        Ok(Response::new(api::PortMapping {
            sandbox_id: req.sandbox_id,
            guest_port: guest_port as u32,
            host_port: host_port as u32,
            // The node does not know which address callers reach it on, nor
            // whether an edge is serving; the orchestrator fills both in from
            // its own view of the fleet.
            host_address: String::new(),
            edge_url: String::new(),
        }))
    }

    async fn list_ports(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<api::ListPortsResponse>, Status> {
        let sandbox_id = req.into_inner().sandbox_id;
        let ports = self.sandboxes.list_ports(&sandbox_id).await;
        Ok(Response::new(api::ListPortsResponse {
            ports: ports
                .into_iter()
                .map(|(host_port, guest_port)| api::PortMapping {
                    sandbox_id: sandbox_id.clone(),
                    guest_port: guest_port as u32,
                    host_port: host_port as u32,
                    host_address: String::new(),
                    edge_url: String::new(),
                })
                .collect(),
        }))
    }

    async fn close_port(
        &self,
        req: Request<api::ClosePortRequest>,
    ) -> Result<Response<api::ClosePortResponse>, Status> {
        let req = req.into_inner();
        self.sandboxes
            .close_port(&req.sandbox_id, port_u16(req.host_port)?)
            .await?;
        Ok(Response::new(api::ClosePortResponse {}))
    }

    async fn share_sandbox(
        &self,
        req: Request<api::ShareRequest>,
    ) -> Result<Response<api::Share>, Status> {
        let req = req.into_inner();
        let ports = share_ports(&req.ports)?;
        let udp_ports = share_ports(&req.udp_ports)?;
        let info = self
            .sandboxes
            .share(
                &req.sandbox_id,
                crate::share::ShareShape {
                    ports,
                    allowed_clients: req.allowed_clients,
                    udp_ports,
                    all_udp: req.all_udp,
                    transparent_ip: !req.no_transparent_ip,
                },
                req.rotate,
            )
            .await?;
        Ok(Response::new(share_proto(req.sandbox_id, info)))
    }

    async fn get_share(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<api::Share>, Status> {
        let sandbox_id = req.into_inner().sandbox_id;
        let info = self.sandboxes.get_share(&sandbox_id).await?;
        Ok(Response::new(share_proto(sandbox_id, info)))
    }

    async fn unshare_sandbox(
        &self,
        req: Request<nodepb::NodeSandboxRef>,
    ) -> Result<Response<api::UnshareResponse>, Status> {
        self.sandboxes.unshare(&req.into_inner().sandbox_id).await?;
        Ok(Response::new(api::UnshareResponse {}))
    }

    type ExecStream = BoxStream<api::ExecOutput>;

    async fn exec(
        &self,
        req: Request<tonic::Streaming<api::ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let mut inbound = req.into_inner();

        // The first message names the sandbox, so it must be read here to
        // route; it is then replayed to the agent without its sandbox_id.
        let first = inbound
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Status::invalid_argument("Exec stream closed before Start"))?;
        let Some(api::exec_input::Input::Start(start)) = first.input else {
            return Err(Status::invalid_argument("first Exec message must be Start"));
        };

        let sandbox = self.sandboxes.get(&start.sandbox_id).await?;
        // Checked here rather than in the guest: the agent is inside the
        // boundary this policy draws, so it cannot be the thing that holds it.
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        // A sandbox from an OCI image should behave like that image: its `PATH`
        // is usually the only reason an interpreter installed at an unusual
        // prefix is findable at all. The caller's own values win, because they
        // are the more specific instruction.
        let image = self.image_environment(sandbox.template()).await;
        let mut env = image.as_map();
        env.extend(start.env);
        let cwd = if !start.cwd.is_empty() {
            start.cwd
        } else if !start.user.is_empty() {
            // A command running as a user starts in that user's home, which
            // only the guest knows. The image's WORKDIR is the default for
            // root, not a reason to drop somebody into a directory that is
            // not theirs.
            String::new()
        } else {
            image.working_dir.clone()
        };

        // Checked here as well as in the guest: the name reaches an argv and a
        // `/etc/passwd` lookup, and the daemon does not take the guest's word
        // for what is safe to send it.
        if !start.user.is_empty() {
            check_user_name(&start.user)?;
        }

        let agent_start = agentpb::ExecInput {
            input: Some(agentpb::exec_input::Input::Start(agentpb::ExecStart {
                cmd: start.cmd,
                env,
                cwd,
                pty: start.pty,
                rows: start.rows,
                cols: start.cols,
                user: start.user,
            })),
        };

        let outbound = async_stream::stream! {
            yield agent_start;
            while let Some(Ok(msg)) = inbound.next().await {
                if let Some(translated) = translate_exec_input(msg) {
                    yield translated;
                }
            }
        };

        let responses = agent.exec(outbound).await?.into_inner();
        let mapped = responses.map(|res| res.map(translate_exec_output));
        Ok(Response::new(Box::pin(mapped)))
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

        let sandbox = self.sandboxes.get(&first.sandbox_id).await?;
        // The destination arrives in this first chunk, so this is the only
        // point where it can be refused before the agent has been handed a
        // byte of it.
        let max_bytes = check_upload(&sandbox.policy(), &first.path)?;
        let mut agent = sandbox.agent().await?;

        let path = first.path.clone();
        let agent_first = agentpb::FileChunk {
            path: first.path,
            mode: first.mode,
            data: first.data,
        };
        // A cap can only be checked as the bytes go past, so the stream stops
        // at the chunk that crosses it and says so here. Two flags rather than
        // one: an upload refused before its first chunk never opened the file,
        // and must not have an existing file at that path cleaned up under it.
        let exceeded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wrote = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The caller's stream breaking is the third way this ends, and it is
        // reported the same way the cap is. Ending the outbound stream on an
        // inbound error would otherwise look to the agent exactly like a
        // complete upload, and the truncated file would be reported written.
        let broken: std::sync::Arc<std::sync::Mutex<Option<Status>>> = Default::default();
        let (tripped, started, failed) = (exceeded.clone(), wrote.clone(), broken.clone());
        let outbound = async_stream::stream! {
            use std::sync::atomic::Ordering::Relaxed;

            let mut sent = agent_first.data.len() as u64;
            if over_cap(max_bytes, sent) {
                tripped.store(true, Relaxed);
                return;
            }
            started.store(true, Relaxed);
            yield agent_first;
            loop {
                let chunk = match inbound.next().await {
                    Some(Ok(chunk)) => chunk,
                    Some(Err(err)) => {
                        *failed.lock().unwrap() = Some(err);
                        return;
                    }
                    None => break,
                };
                sent += chunk.data.len() as u64;
                if over_cap(max_bytes, sent) {
                    tripped.store(true, Relaxed);
                    return;
                }
                yield agentpb::FileChunk {
                    path: String::new(),
                    mode: 0,
                    data: chunk.data,
                };
            }
        };

        let result = agent.upload_file(outbound).await;
        // Read before the agent's own result: an upload cut short may well
        // have failed on its side too, and the cap is the truer reason.
        if exceeded.load(std::sync::atomic::Ordering::Relaxed) {
            if wrote.load(std::sync::atomic::Ordering::Relaxed) {
                remove_partial_upload(&sandbox, &path).await;
            }
            return Err(Status::resource_exhausted(format!(
                "upload exceeds this sandbox's max_upload_bytes ({max_bytes})"
            )));
        }
        // Same order and the same reason: what the caller's stream did is a
        // truer account of the failure than whatever the agent made of it.
        let broken = broken.lock().unwrap().take();
        if let Some(err) = broken {
            if wrote.load(std::sync::atomic::Ordering::Relaxed) {
                remove_partial_upload(&sandbox, &path).await;
            }
            return Err(Status::new(
                err.code(),
                format!("upload stream ended early: {}", err.message()),
            ));
        }
        let result = result?.into_inner();
        Ok(Response::new(api::UploadResult {
            bytes_written: result.bytes_written,
        }))
    }

    type DownloadFileStream = BoxStream<api::FileChunk>;

    async fn download_file(
        &self,
        req: Request<api::DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let req = req.into_inner();
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_download(&sandbox.policy(), &req.path)?;
        let mut agent = sandbox.agent().await?;

        let stream = agent
            .download_file(agentpb::DownloadRequest { path: req.path })
            .await?
            .into_inner()
            .map(|res| {
                res.map(|chunk| api::FileChunk {
                    sandbox_id: String::new(),
                    path: String::new(),
                    mode: 0,
                    data: chunk.data,
                })
            });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn query_audit(
        &self,
        req: Request<api::AuditQuery>,
    ) -> Result<Response<api::AuditPage>, Status> {
        let req = req.into_inner();
        let node_id = self.node_id();
        let rows = self
            .store
            .query_egress(&burrow_store::EgressFilter {
                sandbox_id: (!req.sandbox_id.is_empty()).then(|| req.sandbox_id.clone()),
                denied_only: req.denied_only,
                since: (!req.since.is_empty()).then(|| req.since.clone()),
                limit: req.limit,
            })
            .map_err(|err| Status::internal(format!("reading audit: {err}")))?;

        Ok(Response::new(api::AuditPage {
            events: rows
                .into_iter()
                .map(|r| api::AuditEvent {
                    at: r.at,
                    sandbox_id: r.sandbox_id,
                    source_ip: r.source_ip,
                    destination: r.destination,
                    host: r.host,
                    port: r.port,
                    allowed: r.allowed,
                    reason: r.reason,
                    bytes_sent: r.bytes_sent as u64,
                    bytes_received: r.bytes_received as u64,
                    node_id: node_id.clone(),
                })
                .collect(),
        }))
    }

    type WatchStream = BoxStream<api::WatchEvent>;

    async fn watch(
        &self,
        req: Request<api::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = req.into_inner();
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        // A watch reports every path under the one it is given, so it is held
        // to the same scopes a listing is.
        check_read_path(&sandbox.policy(), &req.path)?;
        let mut agent = sandbox.agent().await?;

        let stream = agent
            .watch(agentpb::WatchRequest {
                path: req.path,
                recursive: req.recursive,
                interval_ms: req.interval_ms,
            })
            .await?
            .into_inner()
            .map(|res| {
                res.map(|e| api::WatchEvent {
                    r#type: e.r#type,
                    path: e.path,
                    is_dir: e.is_dir,
                })
            });
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_dir(
        &self,
        req: Request<api::ListDirRequest>,
    ) -> Result<Response<api::ListDirResponse>, Status> {
        let req = req.into_inner();
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_read_path(&sandbox.policy(), &req.path)?;
        let mut agent = sandbox.agent().await?;

        let resp = agent
            .list_dir(agentpb::ListDirRequest { path: req.path })
            .await?
            .into_inner();
        Ok(Response::new(api::ListDirResponse {
            entries: resp
                .entries
                .into_iter()
                .map(|e| api::DirEntry {
                    name: e.name,
                    is_dir: e.is_dir,
                    size: e.size,
                    mode: e.mode,
                })
                .collect(),
        }))
    }

    /// Commands the sandbox has run.
    ///
    /// Held to the exec policy like exec itself: a sandbox nobody may run
    /// commands in is not one whose command history is readable either.
    async fn list_commands(
        &self,
        req: Request<api::ListCommandsRequest>,
    ) -> Result<Response<api::ListCommandsResponse>, Status> {
        let sandbox = self.sandboxes.get(&req.into_inner().sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        let resp = agent
            .list_commands(agentpb::ListCommandsRequest {})
            .await?
            .into_inner();
        Ok(Response::new(api::ListCommandsResponse {
            commands: resp
                .commands
                .into_iter()
                .take(MAX_REPORTED_COMMANDS)
                .map(command_info)
                .collect(),
        }))
    }

    async fn get_command(
        &self,
        req: Request<api::GetCommandRequest>,
    ) -> Result<Response<api::CommandInfo>, Status> {
        let req = req.into_inner();
        let command_id = check_command_id(&req.command_id)?;
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        let info = agent
            .get_command(agentpb::GetCommandRequest { command_id })
            .await?
            .into_inner();
        Ok(Response::new(command_info(info)))
    }

    type AttachCommandStream = BoxStream<api::ExecOutput>;

    /// Follows a command that is already running.
    ///
    /// The same permission as starting one: what comes back is the output of a
    /// command, and a sandbox that forbids exec must not hand it over.
    async fn attach_command(
        &self,
        req: Request<api::AttachCommandRequest>,
    ) -> Result<Response<Self::AttachCommandStream>, Status> {
        let req = req.into_inner();
        let command_id = check_command_id(&req.command_id)?;
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        let stream = agent
            .attach_command(agentpb::AttachCommandRequest { command_id })
            .await?
            .into_inner()
            .map(|res| res.map(translate_exec_output));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn signal_command(
        &self,
        req: Request<api::SignalCommandRequest>,
    ) -> Result<Response<api::SignalCommandResponse>, Status> {
        let req = req.into_inner();
        let command_id = check_command_id(&req.command_id)?;
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        agent
            .signal_command(agentpb::SignalCommandRequest {
                command_id,
                signal: req.signal,
            })
            .await?;
        Ok(Response::new(api::SignalCommandResponse {}))
    }

    /// Creates a guest user.
    ///
    /// Held to the exec policy: creating a user runs the guest's own `useradd`
    /// or `adduser`, so a sandbox that may not run commands may not create one
    /// through this door either.
    async fn create_user(
        &self,
        req: Request<api::CreateUserRequest>,
    ) -> Result<Response<api::CreateUserResponse>, Status> {
        let req = req.into_inner();
        check_user_name(&req.name)?;
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        let resp = agent
            .create_user(agentpb::CreateUserRequest { name: req.name })
            .await?
            .into_inner();
        Ok(Response::new(api::CreateUserResponse {
            username: bounded(resp.username, MAX_NAME),
            uid: resp.uid,
            gid: resp.gid,
            home: bounded(resp.home, MAX_PATH),
        }))
    }

    async fn create_group(
        &self,
        req: Request<api::CreateGroupRequest>,
    ) -> Result<Response<api::CreateGroupResponse>, Status> {
        let req = req.into_inner();
        check_user_name(&req.name)?;
        let sandbox = self.sandboxes.get(&req.sandbox_id).await?;
        check_exec(&sandbox.policy())?;
        let mut agent = sandbox.agent().await?;

        let resp = agent
            .create_group(agentpb::CreateGroupRequest { name: req.name })
            .await?
            .into_inner();
        Ok(Response::new(api::CreateGroupResponse {
            groupname: bounded(resp.groupname, MAX_NAME),
            gid: resp.gid,
            shared_dir: bounded(resp.shared_dir, MAX_PATH),
        }))
    }

    async fn add_user_to_group(
        &self,
        req: Request<api::GroupMembershipRequest>,
    ) -> Result<Response<api::GroupMembershipResponse>, Status> {
        let (user, group, mut agent) = self.membership(req.into_inner()).await?;
        agent
            .add_user_to_group(agentpb::GroupMembership { user, group })
            .await?;
        Ok(Response::new(api::GroupMembershipResponse {}))
    }

    async fn remove_user_from_group(
        &self,
        req: Request<api::GroupMembershipRequest>,
    ) -> Result<Response<api::GroupMembershipResponse>, Status> {
        let (user, group, mut agent) = self.membership(req.into_inner()).await?;
        agent
            .remove_user_from_group(agentpb::GroupMembership { user, group })
            .await?;
        Ok(Response::new(api::GroupMembershipResponse {}))
    }
}

/// Ceilings on what the guest is allowed to say about its own commands.
///
/// Everything a guest reports is untrusted: the sandbox is the thing the
/// boundary exists to contain, and an agent that has been replaced could answer
/// a listing with megabytes of argv or a command id carrying anything at all.
/// These are applied to what comes back, not just to what goes in.
const MAX_REPORTED_COMMANDS: usize = 256;
const MAX_COMMAND_ID: usize = 64;
const MAX_ARGV: usize = 64;
const MAX_ARG: usize = 4096;
const MAX_NAME: usize = 32;
const MAX_PATH: usize = 4096;

/// Checks a command id before it is sent to a guest.
///
/// The agent mints these, so the shape is known; a caller's string is not, and
/// it is about to be looked up in the guest's registry.
fn check_command_id(id: &str) -> Result<String, Status> {
    let ok = (1..=MAX_COMMAND_ID).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(Status::invalid_argument(format!(
            "command id {id:?} may be at most {MAX_COMMAND_ID} characters of letters, \
             digits, '_' and '-'"
        )));
    }
    Ok(id.to_string())
}

/// Checks a user or group name, exactly as the guest agent does.
///
/// POSIX portable: `[a-z_][a-z0-9_-]*`, at most 32. The name reaches an argv in
/// the guest, so it is refused at the door rather than escaped later.
fn check_user_name(name: &str) -> Result<(), Status> {
    let mut chars = name.chars();
    let ok = (1..=MAX_NAME).contains(&name.len())
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !ok {
        return Err(Status::invalid_argument(format!(
            "name {name:?} must be 1-{MAX_NAME} characters matching [a-z_][a-z0-9_-]*"
        )));
    }
    Ok(())
}

/// Trims a string a guest reported to something a client can be handed.
fn bounded(mut value: String, max: usize) -> String {
    value.retain(|c| !c.is_control());
    // On a char boundary, so a multi-byte character is never cut in half.
    if value.len() > max {
        let cut = (0..=max).rev().find(|i| value.is_char_boundary(*i));
        value.truncate(cut.unwrap_or(0));
    }
    value
}

/// Maps a guest's report of one command onto the public shape, bounding every
/// field the guest chose the size of.
fn command_info(info: agentpb::CommandInfo) -> api::CommandInfo {
    api::CommandInfo {
        command_id: bounded(info.command_id, MAX_COMMAND_ID),
        cmd: info
            .cmd
            .into_iter()
            .take(MAX_ARGV)
            .map(|arg| bounded(arg, MAX_ARG))
            .collect(),
        user: bounded(info.user, MAX_NAME),
        // A state this daemon has no name for is reported as such rather than
        // passed through: a client branches on this string.
        state: match info.state.as_str() {
            "running" => "running".into(),
            "exited" => "exited".into(),
            _ => "unknown".into(),
        },
        exit_code: info.exit_code,
        started_at_unix_ms: info.started_at_unix_ms,
        ended_at_unix_ms: info.ended_at_unix_ms,
        buffered_bytes: info.buffered_bytes,
    }
}

/// The most path scopes one policy may carry.
///
/// Every scope is walked on every file call, and a caller with an unbounded
/// list would be writing the node's own per-request cost.
const MAX_PATH_SCOPES: usize = 16;

/// Whether an upload of `sent` bytes has passed `max`. 0 is unlimited.
fn over_cap(max: u64, sent: u64) -> bool {
    max != 0 && sent > max
}

/// Splits a guest path into the components a scope is matched on.
///
/// Component-wise rather than on the raw string, or the scope `/data` would
/// admit `/database`. `..` is refused outright rather than resolved: what it
/// means depends on symlinks only the guest can see, and a scope that can be
/// climbed out of is not a scope.
fn path_components(path: &str) -> Result<Vec<&str>, Status> {
    if !path.starts_with('/') {
        return Err(Status::permission_denied(format!(
            "path {path:?} must be absolute: this sandbox confines file access to path scopes"
        )));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                return Err(Status::permission_denied(format!(
                    "path {path:?} contains a '..' component"
                )));
            }
            part => parts.push(part),
        }
    }
    Ok(parts)
}

/// Confines a path to one of the policy's scopes. No scopes means the whole fs.
fn within_scopes(scopes: &[String], path: &str) -> Result<(), Status> {
    if scopes.is_empty() {
        return Ok(());
    }
    let wanted = path_components(path)?;
    for scope in scopes {
        // A scope is validated at create, so this only fails for a record
        // written before that check existed, where refusing is the safe read.
        let scope = path_components(scope)?;
        if wanted.len() >= scope.len() && wanted[..scope.len()] == scope[..] {
            return Ok(());
        }
    }
    Err(Status::permission_denied(format!(
        "path {path:?} is outside this sandbox's path scopes"
    )))
}

/// An absent section allows everything, which is what every sandbox created
/// before these policies were enforced carries.
fn check_exec(policy: &common::Policy) -> Result<(), Status> {
    match &policy.exec {
        Some(exec) if !exec.allow_exec => Err(Status::permission_denied(
            "this sandbox's policy does not allow exec",
        )),
        _ => Ok(()),
    }
}

/// Checks an upload's destination and returns the cap on its size, 0 for none.
fn check_upload(policy: &common::Policy, path: &str) -> Result<u64, Status> {
    let Some(fs) = &policy.fs else {
        return Ok(0);
    };
    if !fs.allow_upload {
        return Err(Status::permission_denied(
            "this sandbox's policy does not allow uploads",
        ));
    }
    within_scopes(&fs.path_scopes, path)?;
    Ok(fs.max_upload_bytes)
}

fn check_download(policy: &common::Policy, path: &str) -> Result<(), Status> {
    let Some(fs) = &policy.fs else {
        return Ok(());
    };
    if !fs.allow_download {
        return Err(Status::permission_denied(
            "this sandbox's policy does not allow downloads",
        ));
    }
    within_scopes(&fs.path_scopes, path)
}

/// Calls that read a path without carrying its contents out: list_dir, watch.
///
/// The scopes apply, but `allow_download` does not: a listing is not the file.
fn check_read_path(policy: &common::Policy, path: &str) -> Result<(), Status> {
    match &policy.fs {
        Some(fs) => within_scopes(&fs.path_scopes, path),
        None => Ok(()),
    }
}

/// How long the node waits on its own cleanup inside a guest.
///
/// The exec below is a stream, and a stream is not covered by the per-call
/// deadline the agent channel carries, so a guest that accepts the command and
/// then never finishes it would hold this task open forever.
const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Best-effort removal of what a refused upload had already written.
///
/// A cap that trips mid-stream leaves a truncated file behind. Nothing rests on
/// this working: the guest may not have `rm` at all, and the refusal stands
/// either way. Issued straight at the agent so a sandbox that forbids exec is
/// still cleaned up, this being the node's own housekeeping rather than a
/// caller's command.
async fn remove_partial_upload(sandbox: &RunningSandbox, path: &str) {
    if tokio::time::timeout(CLEANUP_TIMEOUT, remove_partial_upload_inner(sandbox, path))
        .await
        .is_err()
    {
        tracing::warn!(
            sandbox = sandbox.id(),
            path,
            "gave up cleaning up a refused upload; the guest did not finish the removal"
        );
    }
}

async fn remove_partial_upload_inner(sandbox: &RunningSandbox, path: &str) {
    let Ok(mut agent) = sandbox.agent().await else {
        return;
    };
    let start = agentpb::ExecInput {
        input: Some(agentpb::exec_input::Input::Start(agentpb::ExecStart {
            // argv, not a shell line: the path is a caller's string.
            cmd: vec!["/bin/rm".into(), "-f".into(), "--".into(), path.to_string()],
            env: Default::default(),
            cwd: String::new(),
            pty: false,
            rows: 0,
            cols: 0,
            // The node's own housekeeping, which is root's.
            user: String::new(),
        })),
    };
    if let Ok(response) = agent.exec(tokio_stream::iter(vec![start])).await {
        // Drained rather than dropped: dropping the response stream would
        // cancel the command that is doing the cleaning.
        let mut stream = response.into_inner();
        while let Some(Ok(_)) = stream.next().await {}
    }
}

fn share_ports(ports: &[u32]) -> Result<Vec<u16>, Status> {
    let ports = ports
        .iter()
        .map(|p| port_u16(*p))
        .collect::<Result<Vec<_>, _>>()?;
    if ports.contains(&0) {
        return Err(Status::invalid_argument("port 0 cannot be shared"));
    }
    Ok(ports)
}

fn share_proto(sandbox_id: String, info: crate::share::ShareInfo) -> api::Share {
    api::Share {
        sandbox_id,
        address: info.address,
        ports: info.spec.ports.iter().map(|p| u32::from(*p)).collect(),
        allowed_clients: info.spec.allowed_clients,
        created_at: burrow_core::rfc3339_from_unix_secs(info.spec.created_at),
        udp_ports: info.spec.udp_ports.iter().map(|p| u32::from(*p)).collect(),
        all_udp: info.spec.all_udp,
        transparent_ip: info.transparent_ip,
    }
}

fn port_u16(value: u32) -> Result<u16, Status> {
    u16::try_from(value).map_err(|_| Status::invalid_argument(format!("port {value} out of range")))
}

/// Ceilings on what a caller may ask a warm build for.
///
/// Firecracker is handed these verbatim, and each distinct memory size becomes
/// its own disk-resident snapshot, so an unbounded `mem_mib` is both a
/// four-terabyte allocation request and a way to fill the node's disk.
const MAX_VCPUS: u32 = 64;
const MAX_MEM_MIB: u32 = 262_144;
const MIN_MEM_MIB: u32 = 128;
const MAX_SCRATCH_MIB: u32 = 262_144;

fn vcpus(requested: u32) -> Result<u32, Status> {
    match requested {
        0 => Ok(1),
        n if n <= MAX_VCPUS => Ok(n),
        n => Err(Status::invalid_argument(format!(
            "vcpus {n} out of range (1..={MAX_VCPUS})"
        ))),
    }
}

fn mem_mib(requested: u32) -> Result<u32, Status> {
    match requested {
        0 => Ok(512),
        n if (MIN_MEM_MIB..=MAX_MEM_MIB).contains(&n) => Ok(n),
        n => Err(Status::invalid_argument(format!(
            "mem_mib {n} out of range ({MIN_MEM_MIB}..={MAX_MEM_MIB})"
        ))),
    }
}

fn scratch_mib(requested: u32) -> Result<u32, Status> {
    match requested {
        0 => Ok(1024),
        n if n <= MAX_SCRATCH_MIB => Ok(n),
        n => Err(Status::invalid_argument(format!(
            "scratch_disk_mib {n} out of range (1..={MAX_SCRATCH_MIB})"
        ))),
    }
}

/// The shape and scratch size a warm build for `resources` uses.
///
/// One place every automatic build goes through, so a template warmed as it
/// lands and one warmed for a shape a create asked for agree on what an unset
/// value means.
pub(crate) fn warm_request(
    resources: &common::ResourcePolicy,
) -> Result<(crate::warm::Shape, u32), Status> {
    Ok((
        crate::warm::Shape {
            vcpus: vcpus(resources.vcpus)?,
            mem_mib: mem_mib(resources.mem_mib)?,
        },
        scratch_mib(resources.scratch_disk_mib)?,
    ))
}

/// Refuses an update that tries to reshape the machine.
///
/// Firecracker fixes a VM's configuration when it starts and takes a restored
/// one's from the snapshot, so burrow could never honour this, and a request
/// silently dropped would leave the caller believing their sandbox grew.
/// Recreating it, or creating one from a snapshot at the shape they want, is
/// what actually works.
fn check_shape_unchanged(vcpus: u32, mem_mib: u32, scratch_disk_mib: u32) -> Result<(), Status> {
    let named = [
        ("vcpus", vcpus),
        ("mem_mib", mem_mib),
        ("scratch_disk_mib", scratch_disk_mib),
    ]
    .into_iter()
    .filter(|(_, value)| *value != 0)
    .map(|(name, _)| name)
    .collect::<Vec<_>>();
    if named.is_empty() {
        return Ok(());
    }
    Err(Status::invalid_argument(format!(
        "a running sandbox's machine shape is fixed and cannot be updated ({} given); \
         create a new sandbox, or a snapshot and a sandbox from it, at the shape you want",
        named.join(", ")
    )))
}

/// Checks an id that is about to become a sandbox's workdir name, cgroup name
/// and jail chroot directory, before anything is created under it.
///
/// The orchestrator already validates a sandbox id before it reaches a node,
/// but this API accepts whatever id it is handed rather than deriving one
/// itself. An id like `../../etc` becomes a path this sandbox's own workdir
/// setup will `remove_dir_all` and recreate, so it gets the same charset and
/// length the orchestrator already holds a caller-chosen sandbox id to.
fn validate_sandbox_id(field: &str, id: &str) -> Result<(), Status> {
    if id.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    if id.len() > 63 {
        return Err(Status::invalid_argument(format!(
            "{field} may be at most 63 bytes"
        )));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !id.starts_with('.');
    if !ok {
        return Err(Status::invalid_argument(format!(
            "{field} may contain only letters, digits, '-', '_', '.' and may not start with '.'"
        )));
    }
    Ok(())
}

/// Checks a whole caller-supplied policy before anything is allocated for it.
///
/// Shared by create and fork so one call cannot give a sandbox a policy the
/// other would have refused. Values flow through unchanged, 0 still meaning
/// "the manager's default"; only out-of-range requests are refused.
fn validate_policy(policy: &common::Policy) -> Result<(), Status> {
    // These are rendered into the node's shared nftables ruleset, where one bad
    // entry breaks every sandbox on the host.
    if let Some(network) = &policy.network {
        validate_network_policy(network)?;
    }
    // Same ceilings as warm builds: firecracker is handed these verbatim.
    if let Some(resources) = &policy.resources {
        vcpus(resources.vcpus)?;
        mem_mib(resources.mem_mib)?;
        scratch_mib(resources.scratch_disk_mib)?;
        // Every retained snapshot is a memory image plus a scratch disk on this
        // node, so how deep a caller may ask to keep is bounded here rather
        // than discovered when the disk fills.
        if resources.keep_last_snapshots > crate::snapshot::MAX_KEEP_LAST {
            return Err(Status::invalid_argument(format!(
                "keep_last_snapshots {} out of range (1..={}; 0 is unlimited)",
                resources.keep_last_snapshots,
                crate::snapshot::MAX_KEEP_LAST
            )));
        }
        // Keeping what retention evicted only bounds anything if the evicted
        // snapshot expires on its own. Refused rather than accepted as a policy
        // that says "bound this" and then keeps every snapshot forever.
        if resources.keep_evicted_snapshots {
            if resources.keep_last_snapshots == 0 {
                return Err(Status::invalid_argument(
                    "keep_evicted_snapshots needs keep_last_snapshots: nothing is evicted without it",
                ));
            }
            if resources.snapshot_expiration_secs == 0 {
                return Err(Status::invalid_argument(
                    "keep_evicted_snapshots needs snapshot_expiration_secs: an evicted snapshot with no expiry is never reclaimed",
                ));
            }
        }
    }
    if let Some(fs) = &policy.fs {
        validate_fs_policy(fs)?;
    }
    Ok(())
}

/// Checks the scopes a caller wants file access confined to.
///
/// A scope is what every later path is measured against, so one that can never
/// match, being relative or carrying a `..` the matcher refuses on sight, is a
/// confinement the caller believes is in force and is not.
fn validate_fs_policy(fs: &common::FsPolicy) -> Result<(), Status> {
    if fs.path_scopes.len() > MAX_PATH_SCOPES {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_PATH_SCOPES} path_scopes ({} given)",
            fs.path_scopes.len()
        )));
    }
    for scope in &fs.path_scopes {
        if !scope.starts_with('/')
            || scope.split('/').any(|part| part == "..")
            || scope.chars().any(|c| c.is_control())
        {
            return Err(Status::invalid_argument(format!(
                "path_scopes entry {scope:?} must be an absolute path without '..'"
            )));
        }
    }
    Ok(())
}

/// Checks a caller-supplied network policy before anything renders it.
///
/// Most of these fields end up in this node's nftables ruleset. A port outside
/// u16, or a CIDR carrying anything but digits, dots and a prefix, would fail
/// the whole re-render and take every other sandbox's rules with it, or worse
/// smuggle nft syntax into the script. Injected headers are the same problem
/// one layer up: a name or value carrying CRLF would forge header lines in
/// every request the proxy rewrites.
fn validate_network_policy(policy: &common::NetworkPolicy) -> Result<(), Status> {
    for port in &policy.allow_ports {
        if !(1..=65535).contains(port) {
            return Err(Status::invalid_argument(format!(
                "allow_ports entry {port} out of range (1..=65535)"
            )));
        }
    }
    for cidr in &policy.allow_cidrs {
        if !is_ipv4_cidr(cidr) {
            return Err(Status::invalid_argument(format!(
                "allow_cidrs entry {cidr:?} is not an IPv4 CIDR"
            )));
        }
    }
    for cidr in &policy.deny_cidrs {
        if !is_ipv4_cidr(cidr) {
            return Err(Status::invalid_argument(format!(
                "deny_cidrs entry {cidr:?} is not an IPv4 CIDR"
            )));
        }
    }

    // Inspection happens in the egress proxy, and only allowlist mode
    // redirects traffic there. Anywhere else it is a promise the boundary
    // cannot keep, which is worse than refusing it.
    if policy.inspect_tls && policy.mode != common::NetworkMode::Allowlist as i32 {
        return Err(Status::invalid_argument(
            "inspect_tls requires the allowlist network mode",
        ));
    }
    if !policy.rules.is_empty() && !policy.inspect_tls {
        return Err(Status::invalid_argument(
            "rules require inspect_tls: the proxy must terminate TLS to read a request at all",
        ));
    }
    if policy.rules.len() > proxypolicy::MAX_RULES {
        return Err(Status::invalid_argument(format!(
            "at most {} rules ({} given)",
            proxypolicy::MAX_RULES,
            policy.rules.len()
        )));
    }
    for rule in &policy.rules {
        compile_rule(rule).map_err(Status::invalid_argument)?;
    }
    Ok(())
}

/// Turns one wire rule into the compiled rule the proxy evaluates.
///
/// The same function validates and loads, so a rule the API door accepted is a
/// rule the proxy can certainly run, and one it could not compile is refused
/// where the operator can still read the error rather than at the request that
/// would have used it.
pub(crate) fn compile_rule(rule: &common::RequestRule) -> Result<proxypolicy::Rule, String> {
    if !is_domain_glob(&rule.domain) {
        return Err(format!(
            "rule domain {:?} is not a domain glob",
            rule.domain
        ));
    }
    let matcher = rule.r#match.as_ref().map(compile_match).transpose()?;
    let action = match rule.action.as_ref() {
        None => return Err(format!("the rule for {:?} names no action", rule.domain)),
        Some(common::request_rule::Action::SetHeaders(set)) => {
            if set.headers.len() > proxypolicy::MAX_MATCH_ENTRIES {
                return Err(format!(
                    "a rule sets at most {} headers",
                    proxypolicy::MAX_MATCH_ENTRIES
                ));
            }
            let mut headers = Vec::with_capacity(set.headers.len());
            for header in &set.headers {
                if header.name.is_empty() || !header.name.bytes().all(is_tchar) {
                    return Err(format!("{:?} is not a header token", header.name));
                }
                // A name or value carrying CRLF would forge header lines in
                // every request the proxy rewrites: a request smuggled by the
                // policy rather than by the guest.
                if header
                    .value
                    .bytes()
                    .any(|b| b == b'\r' || b == b'\n' || b == 0)
                {
                    return Err(format!(
                        "the value for {:?} contains a line break",
                        header.name
                    ));
                }
                headers.push((header.name.clone(), header.value.clone()));
            }
            proxypolicy::Action::SetHeaders(headers)
        }
        Some(common::request_rule::Action::Forward(forward)) => {
            let target = proxypolicy::ForwardTarget::parse(&forward.url)?;
            if forward
                .secret
                .bytes()
                .any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                return Err("a forward secret contains a line break".into());
            }
            proxypolicy::Action::Forward(proxypolicy::Forward {
                target,
                url: forward.url.clone(),
                secret: forward.secret.clone(),
            })
        }
    };
    Ok(proxypolicy::Rule {
        domain: rule.domain.clone(),
        matcher,
        action,
    })
}

fn compile_match(matcher: &common::RequestMatch) -> Result<proxypolicy::RequestMatch, String> {
    let entries = |what: &str, len: usize| {
        if len > proxypolicy::MAX_MATCH_ENTRIES {
            Err(format!(
                "a matcher names at most {} {what} entries ({len} given)",
                proxypolicy::MAX_MATCH_ENTRIES
            ))
        } else {
            Ok(())
        }
    };
    entries("method", matcher.methods.len())?;
    entries("query", matcher.query.len())?;
    entries("header", matcher.headers.len())?;

    for method in &matcher.methods {
        if method.is_empty() || !method.bytes().all(is_tchar) {
            return Err(format!("{method:?} is not a method token"));
        }
    }
    Ok(proxypolicy::RequestMatch {
        path: matcher
            .path
            .as_ref()
            .map(compile_string_match)
            .transpose()?,
        methods: matcher.methods.clone(),
        query: compile_fields(&matcher.query)?,
        headers: compile_fields(&matcher.headers)?,
    })
}

fn compile_fields(
    fields: &[common::FieldMatch],
) -> Result<Vec<(String, proxypolicy::Match)>, String> {
    fields
        .iter()
        .map(|field| {
            if field.key.is_empty() {
                return Err("a matcher entry names no key".to_string());
            }
            let value = field
                .value
                .as_ref()
                .ok_or_else(|| format!("the matcher entry for {:?} names no value", field.key))?;
            Ok((field.key.clone(), compile_string_match(value)?))
        })
        .collect()
}

fn compile_string_match(value: &common::StringMatch) -> Result<proxypolicy::Match, String> {
    let op = match common::StringMatchOp::try_from(value.op) {
        Ok(common::StringMatchOp::Exact) => proxypolicy::MatchOp::Exact,
        Ok(common::StringMatchOp::StartsWith) => proxypolicy::MatchOp::StartsWith,
        Ok(common::StringMatchOp::Regex) => proxypolicy::MatchOp::Regex,
        _ => return Err("a match names no comparison".into()),
    };
    proxypolicy::Match::compile(op, &value.value)
}

/// Strictly `a.b.c.d/prefix`, IPv4 only, nothing else in the string.
fn is_ipv4_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    if address.parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }
    // Digits only, checked before parsing: `u8::from_str` accepts a leading
    // `+`, and nothing but digits may reach the nft script.
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    matches!(prefix.parse::<u8>(), Ok(bits) if bits <= 32)
}

/// A hostname or a `*.`-prefixed glob, and nothing else.
///
/// The same shape `allow_domains` entries have, because the two are matched by
/// the same code: a pattern that cannot match anything is a rule the caller
/// believes is in force and is not.
fn is_domain_glob(value: &str) -> bool {
    let labels = value.strip_prefix("*.").unwrap_or(value);
    if labels.is_empty() || labels.len() > 253 {
        return false;
    }
    labels.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// RFC 9110 `tchar`: what a header name may contain.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Replaces every brokered credential in a record with a placeholder.
///
/// The value is held on the node so the proxy can set it, and nothing outside
/// needs to read it back: echoing it would hand the credential to exactly the
/// callers brokering exists to keep it from. Applied to every response that
/// carries a policy outward.
fn redact_secrets(mut sandbox: common::Sandbox) -> common::Sandbox {
    if let Some(network) = sandbox
        .policy
        .as_mut()
        .and_then(|policy| policy.network.as_mut())
    {
        for rule in &mut network.rules {
            match rule.action.as_mut() {
                Some(common::request_rule::Action::SetHeaders(set)) => {
                    for header in &mut set.headers {
                        header.value = REDACTED.to_string();
                    }
                }
                // The secret authenticates the node to the endpoint, so it is
                // exactly as much a secret as an injected value is. A rule
                // without one stays visibly without one.
                Some(common::request_rule::Action::Forward(forward))
                    if !forward.secret.is_empty() =>
                {
                    forward.secret = REDACTED.to_string();
                }
                _ => {}
            }
        }
    }
    sandbox
}

const REDACTED: &str = "<redacted>";

/// Maps a public Exec message onto the agent protocol. A second `Start` is
/// dropped: the stream already has one, and the agent rejects duplicates.
fn translate_exec_input(msg: api::ExecInput) -> Option<agentpb::ExecInput> {
    use agentpb::exec_input::Input as AgentInput;
    use api::exec_input::Input as ApiInput;

    let input = match msg.input? {
        ApiInput::Stdin(bytes) => AgentInput::Stdin(bytes),
        ApiInput::Signal(sig) => AgentInput::Signal(sig),
        ApiInput::Resize(size) => AgentInput::Resize(agentpb::ExecResize {
            rows: size.rows,
            cols: size.cols,
        }),
        ApiInput::StdinEof(eof) => AgentInput::StdinEof(eof),
        ApiInput::Start(_) => return None,
    };
    Some(agentpb::ExecInput { input: Some(input) })
}

fn translate_exec_output(msg: agentpb::ExecOutput) -> api::ExecOutput {
    use agentpb::exec_output::Output as AgentOutput;
    use api::exec_output::Output as ApiOutput;

    api::ExecOutput {
        output: msg.output.map(|out| match out {
            AgentOutput::Stdout(b) => ApiOutput::Stdout(b),
            AgentOutput::Stderr(b) => ApiOutput::Stderr(b),
            AgentOutput::ExitCode(c) => ApiOutput::ExitCode(c),
            AgentOutput::CommandId(id) => ApiOutput::CommandId(bounded(id, MAX_COMMAND_ID)),
        }),
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    /// A traversal-shaped id becomes a path this sandbox's own setup will
    /// `remove_dir_all` and recreate, so it must be refused before it gets
    /// that far, exactly like the orchestrator already refuses one of its
    /// own callers.
    #[test]
    fn a_path_traversal_shaped_id_is_refused() {
        for id in ["../../etc", "..", ".", "a/b", ".hidden", ""] {
            assert!(
                validate_sandbox_id("sandbox_id", id).is_err(),
                "{id:?} should be refused"
            );
        }
    }

    #[test]
    fn an_ordinary_generated_or_chosen_id_is_accepted() {
        for id in ["sbx_4f9a1c2e", "my-sandbox", "a.b-c_9"] {
            assert!(
                validate_sandbox_id("sandbox_id", id).is_ok(),
                "{id:?} should be accepted"
            );
        }
    }

    #[test]
    fn an_id_longer_than_a_dns_label_is_refused() {
        assert!(validate_sandbox_id("sandbox_id", &"a".repeat(64)).is_err());
        assert!(validate_sandbox_id("sandbox_id", &"a".repeat(63)).is_ok());
    }

    fn policy(cidrs: &[&str], ports: &[u32]) -> common::NetworkPolicy {
        common::NetworkPolicy {
            allow_cidrs: cidrs.iter().map(|c| (*c).to_string()).collect(),
            allow_ports: ports.to_vec(),
            ..Default::default()
        }
    }

    /// Keeping evicted snapshots only bounds the disk if they expire, so the
    /// combinations that would keep them forever are refused at the edge rather
    /// than found when a node fills up.
    #[test]
    fn keeping_evicted_snapshots_needs_a_cap_and_an_expiry() {
        let resources = |keep_last, expiry| common::Policy {
            resources: Some(common::ResourcePolicy {
                keep_evicted_snapshots: true,
                keep_last_snapshots: keep_last,
                snapshot_expiration_secs: expiry,
                ..Default::default()
            }),
            ..Default::default()
        };
        // Nothing is ever evicted, so the flag cannot mean anything.
        assert!(validate_policy(&resources(0, 3_600)).is_err());
        // Evicted, kept, and never reclaimed.
        assert!(validate_policy(&resources(3, 0)).is_err());
        assert!(validate_policy(&resources(3, 3_600)).is_ok());

        // And the flag is not required: the default deletes, as it always did.
        assert!(
            validate_policy(&common::Policy {
                resources: Some(common::ResourcePolicy {
                    keep_last_snapshots: 3,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn a_plain_policy_is_accepted() {
        let ok = policy(&["10.0.0.0/8", "192.168.1.4/32"], &[1, 443, 65535]);
        assert!(validate_network_policy(&ok).is_ok());
    }

    #[test]
    fn a_port_outside_u16_is_refused() {
        // The bug: this reached nftables rendering, where it broke the whole
        // node's ruleset rather than just this sandbox.
        for bad in [0, 65536, 70000, u32::MAX] {
            assert!(
                validate_network_policy(&policy(&[], &[bad])).is_err(),
                "port {bad} should be refused"
            );
        }
    }

    #[test]
    fn only_a_strict_ipv4_cidr_is_accepted() {
        for bad in [
            "10.0.0.0",
            "10.0.0.0/33",
            "10.0.0.0/8 ",
            " 10.0.0.0/8",
            "10.0.0.0/8\nadd rule inet burrow forward accept",
            "10.0.0.0/+8",
            "::/0",
            "2001:db8::/32",
            "example.com/8",
            "",
        ] {
            assert!(!is_ipv4_cidr(bad), "{bad:?} should not be a usable cidr");
            assert!(validate_network_policy(&policy(&[bad], &[])).is_err());
        }
    }

    fn inspected(rules: Vec<common::RequestRule>) -> common::NetworkPolicy {
        common::NetworkPolicy {
            mode: common::NetworkMode::Allowlist as i32,
            inspect_tls: true,
            rules,
            ..Default::default()
        }
    }

    /// The rule an `--inject-header` becomes: one domain, no matcher, one
    /// header set.
    fn header(domain: &str, name: &str, value: &str) -> common::RequestRule {
        common::RequestRule {
            domain: domain.into(),
            r#match: None,
            action: Some(common::request_rule::Action::SetHeaders(
                common::SetHeaders {
                    headers: vec![common::HeaderValue {
                        name: name.into(),
                        value: value.into(),
                    }],
                },
            )),
        }
    }

    fn pattern(op: common::StringMatchOp, value: &str) -> common::StringMatch {
        common::StringMatch {
            op: op as i32,
            value: value.into(),
        }
    }

    fn forwarding(domain: &str, url: &str) -> common::RequestRule {
        common::RequestRule {
            domain: domain.into(),
            r#match: None,
            action: Some(common::request_rule::Action::Forward(
                common::ForwardRequest {
                    url: url.into(),
                    secret: "shared".into(),
                },
            )),
        }
    }

    #[test]
    fn denied_ranges_are_held_to_the_same_strictness_as_allowed_ones() {
        let mut ok = policy(&[], &[]);
        ok.deny_cidrs = vec!["10.0.0.0/8".into(), "169.254.169.254/32".into()];
        assert!(validate_network_policy(&ok).is_ok());

        for bad in [
            "10.0.0.0",
            "10.0.0.0/33",
            "10.0.0.0/8\nadd rule inet burrow sandbox accept",
            "::/0",
            "",
        ] {
            let mut policy = policy(&[], &[]);
            policy.deny_cidrs = vec![bad.to_string()];
            assert!(
                validate_network_policy(&policy).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn a_brokered_header_is_accepted_only_on_an_inspected_allowlist() {
        assert!(
            validate_network_policy(&inspected(vec![header(
                "api.example.com",
                "Authorization",
                "Bearer t"
            )]))
            .is_ok()
        );

        // Without inspection the proxy never sees a request to rewrite.
        let mut uninspected = inspected(vec![header("api.example.com", "X-Key", "k")]);
        uninspected.inspect_tls = false;
        assert!(validate_network_policy(&uninspected).is_err());

        // And inspection itself only means something in allowlist mode.
        let mut open = inspected(vec![]);
        open.mode = common::NetworkMode::Open as i32;
        assert!(validate_network_policy(&open).is_err());
    }

    /// A name or value carrying CRLF would forge header lines in every request
    /// the proxy rewrites: a request smuggled by the policy itself.
    #[test]
    fn a_header_that_could_forge_lines_is_refused() {
        for rule in [
            header("api.example.com", "X-Key", "v\r\nX-Evil: 1"),
            header("api.example.com", "X-Key", "v\nX-Evil: 1"),
            header("api.example.com", "X-Key", "v\0"),
            header("api.example.com", "X Key", "v"),
            header("api.example.com", "X:Key", "v"),
            header("api.example.com", "", "v"),
            header("", "X-Key", "v"),
            header("  ", "X-Key", "v"),
            header("api example.com", "X-Key", "v"),
            header("*.example.com\nadd rule", "X-Key", "v"),
        ] {
            assert!(
                validate_network_policy(&inspected(vec![rule.clone()])).is_err(),
                "{rule:?} should be refused"
            );
        }
        assert!(is_domain_glob("*.pythonhosted.org"));
        assert!(is_domain_glob("pypi.org"));
        assert!(!is_domain_glob("*"));
        assert!(!is_domain_glob("a..b"));
    }

    /// The value exists so the proxy can use it, not so callers can read it
    /// back: brokering that hands the secret to whoever asks brokers nothing.
    #[test]
    fn read_paths_never_carry_a_brokered_secret() {
        let sandbox = common::Sandbox {
            id: "sbx".into(),
            policy: Some(common::Policy {
                network: Some(inspected(vec![
                    header("api.example.com", "Authorization", "Bearer super-secret"),
                    forwarding("gate.example.com", "http://gate.internal/"),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        };
        let redacted = redact_secrets(sandbox);
        let network = redacted.policy.unwrap().network.unwrap();
        let Some(common::request_rule::Action::SetHeaders(set)) = &network.rules[0].action else {
            panic!("expected a set-headers rule");
        };
        assert_eq!(set.headers[0].value, REDACTED);
        // Everything else about the rule stays visible, so an operator can
        // still see which header goes where.
        assert_eq!(set.headers[0].name, "Authorization");
        assert_eq!(network.rules[0].domain, "api.example.com");

        // The forward secret is exactly as much a secret as an injected value.
        let Some(common::request_rule::Action::Forward(forward)) = &network.rules[1].action else {
            panic!("expected a forward rule");
        };
        assert_eq!(forward.secret, REDACTED);
        assert_eq!(forward.url, "http://gate.internal/");
    }

    #[test]
    fn a_matcher_is_compiled_at_the_door_and_a_bad_pattern_is_refused() {
        let matched = |matcher: common::RequestMatch| {
            let mut rule = header("api.example.com", "X-Key", "k");
            rule.r#match = Some(matcher);
            validate_network_policy(&inspected(vec![rule]))
        };
        assert!(
            matched(common::RequestMatch {
                path: Some(pattern(common::StringMatchOp::Regex, r"^/v\d+/")),
                methods: vec!["GET".into(), "POST".into()],
                query: vec![common::FieldMatch {
                    key: "tenant".into(),
                    value: Some(pattern(common::StringMatchOp::Exact, "acme")),
                }],
                headers: vec![common::FieldMatch {
                    key: "X-Client".into(),
                    value: Some(pattern(common::StringMatchOp::StartsWith, "cli/")),
                }],
            })
            .is_ok()
        );

        // A pattern that cannot compile is refused where the operator can read
        // the error, not at the request that would have used it.
        assert!(
            matched(common::RequestMatch {
                path: Some(pattern(common::StringMatchOp::Regex, "(unclosed")),
                ..Default::default()
            })
            .is_err()
        );
        // A comparison nobody named is not a comparison.
        assert!(
            matched(common::RequestMatch {
                path: Some(pattern(common::StringMatchOp::Unspecified, "/v1")),
                ..Default::default()
            })
            .is_err()
        );
        // Bounds: patterns, entry counts and methods.
        assert!(
            matched(common::RequestMatch {
                path: Some(pattern(
                    common::StringMatchOp::Exact,
                    &"x".repeat(proxypolicy::MAX_PATTERN + 1)
                )),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            matched(common::RequestMatch {
                methods: vec!["GET".into(); proxypolicy::MAX_MATCH_ENTRIES + 1],
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            matched(common::RequestMatch {
                methods: vec!["GET POST".into()],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn a_forward_is_an_http_endpoint_and_needs_inspection_like_everything_else() {
        // Both schemes are endpoints burrow will dial. `https` is verified
        // against public roots, so the shared secret is protected in transit;
        // `http` protects it only by where the endpoint sits.
        for good in [
            "http://gate.internal:8080/inspect",
            "https://gate.example.com/inspect",
        ] {
            assert!(
                validate_network_policy(&inspected(vec![forwarding("api.example.com", good)]))
                    .is_ok(),
                "{good:?} should be accepted"
            );
        }

        for bad in [
            "https://gate.internal/?a=1",
            "http://gate.internal/?a=1",
            "ftp://gate.internal/",
            "gate.internal",
            "",
        ] {
            assert!(
                validate_network_policy(&inspected(vec![forwarding("api.example.com", bad)]))
                    .is_err(),
                "{bad:?} should be refused"
            );
        }

        let mut uninspected = inspected(vec![forwarding("api.example.com", "http://gate/")]);
        uninspected.inspect_tls = false;
        assert!(validate_network_policy(&uninspected).is_err());

        // A rule naming no action at all says nothing about what to do.
        let empty = common::RequestRule {
            domain: "api.example.com".into(),
            r#match: None,
            action: None,
        };
        assert!(validate_network_policy(&inspected(vec![empty])).is_err());

        let too_many = vec![header("api.example.com", "X-K", "v"); proxypolicy::MAX_RULES + 1];
        assert!(validate_network_policy(&inspected(too_many)).is_err());
    }

    /// Create and fork reach the same allocation, the same nftables render and
    /// the same store, so a policy one refuses the other must refuse too.
    #[test]
    fn a_fork_override_is_held_to_the_create_checks() {
        let ok = common::Policy {
            network: Some(inspected(vec![header("api.example.com", "X-Key", "k")])),
            resources: Some(common::ResourcePolicy {
                vcpus: 2,
                mem_mib: 1024,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_policy(&ok).is_ok());

        let mut forged = ok.clone();
        forged.network = Some(inspected(vec![header(
            "api.example.com",
            "X-Key",
            "v\r\nX-Evil: 1",
        )]));
        assert!(validate_policy(&forged).is_err());

        let mut oversized = ok.clone();
        oversized.resources = Some(common::ResourcePolicy {
            vcpus: MAX_VCPUS + 1,
            ..Default::default()
        });
        assert!(validate_policy(&oversized).is_err());

        // An unstated policy is the common case and must stay accepted.
        assert!(validate_policy(&common::Policy::default()).is_ok());
    }

    /// Tags are echoed to every caller and written to both tiers' stores, so
    /// the node checks them itself rather than trusting the orchestrator's
    /// identical check.
    #[test]
    fn tags_are_bounded_at_the_node_too() {
        use std::collections::HashMap;

        let ok: HashMap<String, String> = [("env".to_string(), "staging".to_string())]
            .into_iter()
            .collect();
        assert!(burrow_core::tags::validate(&ok).is_ok());

        let forged: HashMap<String, String> = [("env".to_string(), "a\nb".to_string())]
            .into_iter()
            .collect();
        assert!(burrow_core::tags::validate(&forged).is_err());

        let too_many: HashMap<String, String> = (0..=burrow_core::tags::MAX_TAGS)
            .map(|i| (format!("k{i}"), String::new()))
            .collect();
        assert!(burrow_core::tags::validate(&too_many).is_err());
    }

    fn scopes(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|p| (*p).to_string()).collect()
    }

    /// The bug a raw string prefix would have: `/data` is not a prefix of
    /// `/database` in any sense the caller meant.
    #[test]
    fn a_scope_matches_whole_components_only() {
        let only_data = scopes(&["/data"]);
        assert!(within_scopes(&only_data, "/data").is_ok());
        assert!(within_scopes(&only_data, "/data/in.csv").is_ok());
        assert!(within_scopes(&only_data, "/data/nested/deep/in.csv").is_ok());

        assert!(within_scopes(&only_data, "/database/dump.sql").is_err());
        assert!(within_scopes(&only_data, "/data-old/in.csv").is_err());
        assert!(within_scopes(&only_data, "/etc/shadow").is_err());
        assert!(within_scopes(&only_data, "/").is_err());

        // Trailing and doubled separators describe the same path.
        assert!(within_scopes(&scopes(&["/data/"]), "/data//in.csv").is_ok());

        // Several scopes, and a nested one inside another.
        let several = scopes(&["/work", "/data/public"]);
        assert!(within_scopes(&several, "/work/main.py").is_ok());
        assert!(within_scopes(&several, "/data/public/report.csv").is_ok());
        assert!(within_scopes(&several, "/data/private/report.csv").is_err());

        // A root scope is a scope over everything.
        assert!(within_scopes(&scopes(&["/"]), "/etc/shadow").is_ok());
    }

    /// Normalising after the prefix check would let `/work/../etc/shadow`
    /// through, so `..` never reaches the matcher at all.
    #[test]
    fn traversal_and_relative_paths_are_refused() {
        let work = scopes(&["/work"]);
        for bad in [
            "/work/../etc/shadow",
            "/work/sub/../../etc/shadow",
            "/..",
            "work/main.py",
            "../work/main.py",
            "",
        ] {
            assert!(
                within_scopes(&work, bad).is_err(),
                "{bad:?} should be refused"
            );
        }
        // A file merely named `..something` is not traversal.
        assert!(within_scopes(&work, "/work/..hidden").is_ok());
    }

    /// Absent means allowed: every sandbox created before these sections were
    /// enforced carries no exec or fs policy at all.
    #[test]
    fn an_absent_section_allows_everything() {
        let open = common::Policy::default();
        assert!(check_exec(&open).is_ok());
        assert_eq!(check_upload(&open, "/etc/passwd").unwrap(), 0);
        assert!(check_download(&open, "/etc/shadow").is_ok());
        assert!(check_read_path(&open, "relative/path").is_ok());
    }

    /// A present section is enforced exactly as written.
    #[test]
    fn a_present_section_is_enforced() {
        let locked = common::Policy {
            exec: Some(common::ExecPolicy { allow_exec: false }),
            fs: Some(common::FsPolicy {
                allow_upload: true,
                allow_download: false,
                path_scopes: scopes(&["/work"]),
                max_upload_bytes: 1024,
            }),
            ..Default::default()
        };
        assert!(check_exec(&locked).is_err());
        assert_eq!(check_upload(&locked, "/work/in.csv").unwrap(), 1024);
        assert!(check_upload(&locked, "/etc/passwd").is_err());
        // Downloads are refused wherever they point, scope or not.
        assert!(check_download(&locked, "/work/in.csv").is_err());
        // A listing is not the file, so only the scopes apply to it.
        assert!(check_read_path(&locked, "/work").is_ok());
        assert!(check_read_path(&locked, "/etc").is_err());

        // A section that permits everything it names still reads as permission.
        let open = common::Policy {
            exec: Some(common::ExecPolicy { allow_exec: true }),
            fs: Some(common::FsPolicy {
                allow_upload: true,
                allow_download: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(check_exec(&open).is_ok());
        assert_eq!(check_upload(&open, "/anywhere").unwrap(), 0);
        assert!(check_download(&open, "/anywhere").is_ok());
    }

    #[test]
    fn an_upload_cap_counts_the_whole_stream() {
        assert!(!over_cap(0, u64::MAX));
        assert!(!over_cap(1024, 1024));
        assert!(over_cap(1024, 1025));
    }

    /// A scope the matcher would refuse on sight is a confinement the caller
    /// believes is in force and is not, so it is refused at create instead.
    #[test]
    fn scopes_are_checked_when_the_policy_is_set() {
        let with = |paths: &[&str]| common::Policy {
            fs: Some(common::FsPolicy {
                path_scopes: scopes(paths),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_policy(&with(&["/work", "/data/public"])).is_ok());

        for bad in ["work", "/work/../etc", "..", "/work\n/etc", "/work\0"] {
            assert!(validate_policy(&with(&[bad])).is_err(), "{bad:?}");
        }

        let too_many: Vec<&str> = std::iter::repeat_n("/work", MAX_PATH_SCOPES + 1).collect();
        assert!(validate_policy(&with(&too_many)).is_err());
    }

    /// The lifetime clocks move; the machine does not. A shape silently
    /// dropped would leave a caller believing their sandbox grew.
    #[test]
    fn an_update_may_move_the_clocks_but_not_the_machine() {
        assert!(check_shape_unchanged(0, 0, 0).is_ok());

        for (vcpus, mem, scratch) in [(4, 0, 0), (0, 2048, 0), (0, 0, 4096), (4, 2048, 4096)] {
            let err = check_shape_unchanged(vcpus, mem, scratch).unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            // Says which field it refused, so a caller who sent one of three
            // is not left guessing.
            for (name, value) in [
                ("vcpus", vcpus),
                ("mem_mib", mem),
                ("scratch_disk_mib", scratch),
            ] {
                assert_eq!(
                    err.message().contains(name),
                    value != 0,
                    "{name} in {:?}",
                    err.message()
                );
            }
        }
    }

    /// The clocks a caller may move are exactly the ones a create sets and the
    /// reaper reads, and 0 keeps meaning "unlimited" rather than "unchanged":
    /// the request's optional fields carry that distinction instead.
    #[test]
    fn moved_clocks_leave_a_policy_a_create_would_accept() {
        let updated = common::Policy {
            resources: Some(common::ResourcePolicy {
                vcpus: 2,
                mem_mib: 1024,
                max_lifetime_secs: 0,
                idle_suspend_secs: 86_400,
                suspended_ttl_secs: u64::MAX,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_policy(&updated).is_ok());
    }

    #[test]
    fn warm_shapes_are_bounded_at_both_ends() {
        assert_eq!(vcpus(0).unwrap(), 1);
        assert_eq!(vcpus(64).unwrap(), 64);
        assert!(vcpus(65).is_err());

        assert_eq!(mem_mib(0).unwrap(), 512);
        assert!(mem_mib(64).is_err());
        assert!(mem_mib(u32::MAX).is_err());
        assert_eq!(mem_mib(2048).unwrap(), 2048);

        assert_eq!(scratch_mib(0).unwrap(), 1024);
        assert!(scratch_mib(u32::MAX).is_err());
    }
}
