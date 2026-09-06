//! The burrow guest agent.
//!
//! Runs as PID 1 inside the microVM and serves the node daemon over vsock.

mod asyncfd;
mod commands;
mod exec;
mod files;
mod init;
mod netconf;
mod pty;
mod reaper;
mod resume;
mod users;
mod vsock;

use tonic::{Request, Response, Status, transport::Server};

use burrow_proto::agent::v1 as agentpb;
use burrow_proto::agent::v1::agent_server::{Agent, AgentServer};

/// vsock port the node daemon dials.
const AGENT_PORT: u32 = 1024;

/// The only peer the agent will talk to.
///
/// The listener has to bind `VMADDR_CID_ANY`, because a guest cannot bind its
/// own cid before the hypervisor assigns one, so the check belongs after accept.
/// Firecracker's hybrid vsock terminates the host side itself and presents
/// every host-originated connection to the guest as coming from
/// `VMADDR_CID_HOST` (2); a process inside the guest dialling the local cid
/// (its own, or `VMADDR_CID_LOCAL`) arrives as something else, which is
/// exactly what this rejects.
const HOST_CID: u32 = tokio_vsock::VMADDR_CID_HOST;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
struct AgentService;

#[tonic::async_trait]
impl Agent for AgentService {
    async fn handshake(
        &self,
        req: Request<agentpb::HandshakeRequest>,
    ) -> Result<Response<agentpb::HandshakeResponse>, Status> {
        let arrival = req.extensions().get::<vsock::Arrival>().copied();
        let req = req.into_inner();
        tracing::debug!(restored = req.restored, "handshake from host");
        let started = std::time::Instant::now();

        // Best-effort: a guest that cannot reseed is still usable, but it is
        // a real weakness after a restore, so it is logged loudly.
        if let Err(err) = resume::reseed_rng(&req.entropy) {
            tracing::error!(%err, "failed to reseed rng");
        }
        let reseeded = started.elapsed();
        if let Err(err) = resume::set_clock(req.host_time_unix_nanos) {
            tracing::error!(%err, "failed to set guest clock");
        }
        let clocked = started.elapsed();

        // Installed before anything in the sandbox can make a request, so the
        // first HTTPS call already sees a trust store it can verify against.
        //
        // Fatal, unlike the two above: a sandbox told to trust a CA and unable
        // to would fail every HTTPS request against a proxy it cannot verify,
        // and the host has to hear that rather than be told the handshake
        // worked.
        let trust =
            match resume::install_inspection_ca(&req.inspection_ca_pem, &req.extra_trust_bundles) {
                Ok(timing) => timing,
                Err(err) => {
                    tracing::error!(%err, "failed to install the inspection ca");
                    return Err(Status::internal(format!(
                        "installing the inspection ca: {err}"
                    )));
                }
            };
        let trusted = started.elapsed();

        // Only a restored guest has the wrong address; a cold boot got its
        // own from the kernel command line.
        //
        // Fatal, like the CA install above and unlike the reseed/clock steps:
        // a guest that fails this keeps the source's address and MAC for
        // whatever it does next, and the host needs to know the handshake
        // did not really succeed.
        if req.restored
            && let Some(network) = &req.network
            && let Err(err) = resume::apply_network(network).await
        {
            tracing::error!(%err, "failed to reapply network after restore");
            return Err(Status::internal(format!(
                "reapplying network after restore: {err}"
            )));
        }
        // After the network, because a mount is local work and nothing above
        // depends on it, and before the response, because a caller that gets a
        // successful handshake is entitled to find its volumes mounted.
        if let Err(err) = init::mount_volumes(&req.volumes) {
            tracing::error!(%err, "failed to mount volumes");
            return Err(Status::internal(format!("mounting volumes: {err}")));
        }

        let total = started.elapsed();
        let timing = agentpb::GuestResumeTiming {
            parked_us: arrival.map_or(0, |a| a.parked.as_micros() as u64),
            accept_to_call_us: arrival.map_or(0, |a| {
                a.accepted_at.elapsed().saturating_sub(total).as_micros() as u64
            }),
            reseed_us: reseeded.as_micros() as u64,
            clock_us: (clocked - reseeded).as_micros() as u64,
            trust_us: (trusted - clocked).as_micros() as u64,
            trust_read_us: trust.read.as_micros() as u64,
            trust_scan_us: trust.scan.as_micros() as u64,
            trust_write_us: trust.write.as_micros() as u64,
            network_us: (total - trusted).as_micros() as u64,
            total_us: total.as_micros() as u64,
        };
        // Debug, not warn: the agent's stdout is the emulated serial console
        // and every line costs guest time on the create path this measures.
        // The host gets the same numbers in the response, which is where they
        // are actually read from.
        tracing::debug!(
            parked_us = timing.parked_us,
            accept_to_call_us = timing.accept_to_call_us,
            reseed_us = timing.reseed_us,
            clock_us = timing.clock_us,
            trust_us = timing.trust_us,
            network_us = timing.network_us,
            total_us = timing.total_us,
            "handshake timing"
        );

        Ok(Response::new(agentpb::HandshakeResponse {
            agent_version: VERSION.into(),
            timing: Some(timing),
        }))
    }

    async fn health(
        &self,
        _req: Request<agentpb::AgentHealthRequest>,
    ) -> Result<Response<agentpb::AgentHealthResponse>, Status> {
        Ok(Response::new(agentpb::AgentHealthResponse {}))
    }

    type ExecStream = tokio_stream::wrappers::ReceiverStream<Result<agentpb::ExecOutput, Status>>;

    async fn exec(
        &self,
        req: Request<tonic::Streaming<agentpb::ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let rx = exec::run(req.into_inner()).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn upload_file(
        &self,
        req: Request<tonic::Streaming<agentpb::FileChunk>>,
    ) -> Result<Response<agentpb::UploadResult>, Status> {
        Ok(Response::new(files::upload(req.into_inner()).await?))
    }

    type DownloadFileStream =
        tokio_stream::wrappers::ReceiverStream<Result<agentpb::FileChunk, Status>>;

    async fn download_file(
        &self,
        req: Request<agentpb::DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let rx = files::download(req.into_inner().path).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<agentpb::WatchEvent, Status>>;

    async fn watch(
        &self,
        req: Request<agentpb::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = req.into_inner();
        let interval = std::time::Duration::from_millis(if req.interval_ms == 0 {
            500
        } else {
            req.interval_ms.max(50) as u64
        });
        let rx = files::watch(req.path, req.recursive, interval).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn list_dir(
        &self,
        req: Request<agentpb::ListDirRequest>,
    ) -> Result<Response<agentpb::ListDirResponse>, Status> {
        Ok(Response::new(
            files::list_dir(&req.into_inner().path).await?,
        ))
    }

    async fn list_commands(
        &self,
        _req: Request<agentpb::ListCommandsRequest>,
    ) -> Result<Response<agentpb::ListCommandsResponse>, Status> {
        Ok(Response::new(commands::list()))
    }

    async fn get_command(
        &self,
        req: Request<agentpb::GetCommandRequest>,
    ) -> Result<Response<agentpb::CommandInfo>, Status> {
        Ok(Response::new(commands::get(&req.into_inner().command_id)?))
    }

    type AttachCommandStream =
        tokio_stream::wrappers::ReceiverStream<Result<agentpb::ExecOutput, Status>>;

    async fn attach_command(
        &self,
        req: Request<agentpb::AttachCommandRequest>,
    ) -> Result<Response<Self::AttachCommandStream>, Status> {
        let rx = commands::attach(&req.into_inner().command_id)?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn signal_command(
        &self,
        req: Request<agentpb::SignalCommandRequest>,
    ) -> Result<Response<agentpb::SignalCommandResponse>, Status> {
        let req = req.into_inner();
        commands::signal(&req.command_id, req.signal)?;
        Ok(Response::new(agentpb::SignalCommandResponse {}))
    }

    async fn create_user(
        &self,
        req: Request<agentpb::CreateUserRequest>,
    ) -> Result<Response<agentpb::CreateUserResponse>, Status> {
        Ok(Response::new(
            users::create_user(&req.into_inner().name).await?,
        ))
    }

    async fn create_group(
        &self,
        req: Request<agentpb::CreateGroupRequest>,
    ) -> Result<Response<agentpb::CreateGroupResponse>, Status> {
        Ok(Response::new(
            users::create_group(&req.into_inner().name).await?,
        ))
    }

    async fn add_user_to_group(
        &self,
        req: Request<agentpb::GroupMembership>,
    ) -> Result<Response<agentpb::GroupMembershipResponse>, Status> {
        let req = req.into_inner();
        users::add_to_group(&req.user, &req.group).await?;
        Ok(Response::new(agentpb::GroupMembershipResponse {}))
    }

    async fn remove_user_from_group(
        &self,
        req: Request<agentpb::GroupMembership>,
    ) -> Result<Response<agentpb::GroupMembershipResponse>, Status> {
        let req = req.into_inner();
        users::remove_from_group(&req.user, &req.group).await?;
        Ok(Response::new(agentpb::GroupMembershipResponse {}))
    }
}

async fn serve() -> anyhow::Result<()> {
    let listener = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
        tokio_vsock::VMADDR_CID_ANY,
        AGENT_PORT,
    ))?;
    tracing::debug!(
        port = AGENT_PORT,
        version = VERSION,
        "burrow-agent listening on vsock"
    );

    let incoming = async_stream::stream! {
        loop {
            // Taken before the await, so the first connection after a restore
            // reports how long the guest was parked here. The guest's
            // monotonic clock is frozen while the VM is paused, so what this
            // measures is guest wake, not the wall time the host waited.
            let parked_since = std::time::Instant::now();
            match listener.accept().await {
                Ok((stream, addr)) if addr.cid() == HOST_CID => {
                    yield Ok::<_, std::io::Error>(vsock::VsockConn {
                        stream,
                        arrival: vsock::Arrival {
                            accepted_at: std::time::Instant::now(),
                            parked: parked_since.elapsed(),
                        },
                    })
                }
                // Anything else is a process inside this guest dialling the
                // agent over vsock loopback. The agent's API is unauthenticated
                // because only the host is supposed to reach it: Handshake
                // installs a CA into the guest's trust stores as root, and Exec
                // runs commands. A guest-originated connection is dropped.
                Ok((_, addr)) => {
                    tracing::warn!(
                        cid = addr.cid(),
                        "refusing a vsock connection that did not come from the host"
                    );
                }
                Err(err) => {
                    tracing::warn!(%err, "vsock accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    };

    Server::builder()
        .add_service(AgentServer::new(AgentService))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let is_init = std::process::id() == 1;

    // The agent's stdout is the guest's serial console, which Firecracker
    // emulates a byte at a time: every log line costs milliseconds of guest
    // time and shows up directly in boot and resume latency. Default to
    // `warn`; `RUST_LOG=info` turns the detail back on when debugging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    if is_init {
        // Pivot into the writable overlay before mounting anything else, so
        // the pseudo-filesystems land inside the final root.
        init::setup_writable_root();
        if let Err(err) = init::mount_essentials() {
            tracing::error!(%err, "failed to mount essential filesystems");
        }
        init::write_resolv_conf();
    }
    // Exec depends on the reaper for exit statuses, so it runs even when the
    // agent is not PID 1 (development outside a microVM).
    reaper::spawn();

    // Established before any snapshot is taken, so a restored clone does not
    // pay for it on the critical path of a warm create.
    netconf::prepare().await;

    if let Err(err) = serve().await {
        tracing::error!(%err, "agent server exited");
    }

    // As PID 1, exiting would panic the kernel and take the sandbox with it.
    // Park instead so the VM stays alive and inspectable (and snapshottable).
    if is_init {
        tracing::error!("agent is pid 1 and cannot exit; parking");
        std::future::pending::<()>().await;
    }
}
