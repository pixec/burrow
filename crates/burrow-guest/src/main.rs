//! The burrow guest agent.
//!
//! Runs as PID 1 inside the microVM and serves the node daemon over vsock,
//! alone or with the template's systemd under it (see [`systemd`]).

mod asyncfd;
mod commands;
mod exec;
mod files;
mod init;
mod netconf;
mod pty;
mod reaper;
mod resume;
mod systemd;
mod users;
mod vsock;

use std::os::unix::fs::PermissionsExt as _;
use tonic::{Request, Response, Status, transport::Server};

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::guest_server::{Guest, GuestServer};

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

/// Set in the environment of an agent that replaced itself, so the new
/// process skips the one-time init a fresh PID 1 does: the root is already
/// pivoted and the pseudo-filesystems are mounted, and mounting a second tmpfs
/// over `/run` would hide the very binary it is running from.
const REEXEC_MARK: &str = "BURROW_GUEST_REEXEC";

/// Where an upgraded agent binary is written. tmpfs, so it costs memory
/// rather than the read-only root, and survives a snapshot with the rest of
/// the guest's memory.
const UPGRADE_PATH: &str = "/run/burrow-guest";
/// Where the finished-command table is handed across the re-exec.
const COMMANDS_STATE: &str = "/run/burrow-guest.commands";
/// How long a handshake waits for systemd to finish booting. Under the host's
/// default 30s bound on the call, so a slow systemd delays the handshake
/// rather than failing it.
const SYSTEMD_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// SHA-256 of the binary this process is running, as the host compares it.
fn self_digest() -> &'static str {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(|| {
        use sha2::Digest as _;
        std::fs::read("/proc/self/exe")
            .map(|bytes| hex_lower(&sha2::Sha256::digest(&bytes)))
            .unwrap_or_default()
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Default)]
struct AgentService;

#[tonic::async_trait]
impl Guest for AgentService {
    async fn handshake(
        &self,
        req: Request<guestpb::HandshakeRequest>,
    ) -> Result<Response<guestpb::HandshakeResponse>, Status> {
        let arrival = req.extensions().get::<vsock::Arrival>().copied();
        let req = req.into_inner();
        tracing::debug!(restored = req.is_restored, "handshake from host");
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
        if req.is_restored
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
        // Last, because it can take as long as systemd's boot. A warm snapshot
        // is taken when this returns, so its clones restore with systemd up.
        systemd::wait_ready(SYSTEMD_READY_TIMEOUT).await;

        let total = started.elapsed();
        let timing = guestpb::GuestResumeTiming {
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

        Ok(Response::new(guestpb::HandshakeResponse {
            agent_version: VERSION.into(),
            timing: Some(timing),
            agent_digest: self_digest().to_string(),
        }))
    }

    /// Replaces this agent with the binary streamed in.
    ///
    /// Written to tmpfs and verified against the digest before anything
    /// changes, then the process re-executes itself: PID 1 survives an
    /// `execve`, so the kernel sees the same init, and the host reconnects to
    /// the listener the new process binds. Refused while a command is running,
    /// because its pipes and pty live in this process.
    async fn upgrade(
        &self,
        req: Request<tonic::Streaming<guestpb::UpgradeChunk>>,
    ) -> Result<Response<guestpb::UpgradeResponse>, Status> {
        use sha2::Digest as _;
        use tokio::io::AsyncWriteExt as _;
        if commands::has_running() {
            return Err(Status::failed_precondition(
                "a command is running; the agent upgrades once it is idle",
            ));
        }
        let mut stream = req.into_inner();
        let temp = format!("{UPGRADE_PATH}.{}.new", std::process::id());
        let mut file = tokio::fs::File::create(&temp)
            .await
            .map_err(|err| Status::internal(format!("creating {temp}: {err}")))?;
        let mut hasher = sha2::Sha256::new();
        let mut expected = String::new();
        let mut written = 0usize;
        while let Some(chunk) = stream.message().await? {
            if !chunk.digest.is_empty() {
                expected = chunk.digest;
            }
            hasher.update(&chunk.data);
            file.write_all(&chunk.data)
                .await
                .map_err(|err| Status::internal(format!("writing {temp}: {err}")))?;
            written += chunk.data.len();
        }
        file.sync_all()
            .await
            .map_err(|err| Status::internal(format!("syncing {temp}: {err}")))?;
        drop(file);
        let actual = hex_lower(&hasher.finalize());
        if written == 0 || expected.is_empty() || actual != expected {
            let _ = tokio::fs::remove_file(&temp).await;
            return Err(Status::invalid_argument(format!(
                "upgrade binary hashed as {actual}, expected {expected}"
            )));
        }
        if actual == self_digest() {
            let _ = tokio::fs::remove_file(&temp).await;
            return Ok(Response::new(guestpb::UpgradeResponse {
                is_restarting: false,
            }));
        }
        tokio::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))
            .await
            .map_err(|err| Status::internal(format!("chmod {temp}: {err}")))?;
        tokio::fs::rename(&temp, UPGRADE_PATH)
            .await
            .map_err(|err| Status::internal(format!("installing {UPGRADE_PATH}: {err}")))?;
        if let Err(err) = commands::save(COMMANDS_STATE) {
            tracing::warn!(%err, "command history will not survive the upgrade");
        }
        tracing::warn!(digest = actual, "agent upgrading; re-executing");
        // After the response has gone out, from a plain thread: `execve`
        // replaces the whole process and must not run under the runtime that
        // is still writing the reply.
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let path = std::ffi::CString::new(UPGRADE_PATH).expect("static path");
            // SAFETY: setting an environment variable before exec, from a
            // thread that does nothing else.
            unsafe {
                std::env::set_var(REEXEC_MARK, "1");
                if let Some(pid) = systemd::pid() {
                    std::env::set_var(systemd::PID_MARK, pid.to_string());
                }
            };
            let Err(err) = nix::unistd::execv(&path, &[path.as_c_str()]);
            tracing::error!(%err, "re-exec failed; the old agent keeps serving");
        });
        Ok(Response::new(guestpb::UpgradeResponse {
            is_restarting: true,
        }))
    }

    async fn health(
        &self,
        _req: Request<guestpb::GuestHealthRequest>,
    ) -> Result<Response<guestpb::GuestHealthResponse>, Status> {
        Ok(Response::new(guestpb::GuestHealthResponse {
            features: vec![
                files::FEATURE_FILES_AS_USER.to_string(),
                "attach-input".to_string(),
            ],
        }))
    }

    type ExecStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::ExecOutput, Status>>;

    async fn exec(
        &self,
        req: Request<tonic::Streaming<guestpb::ExecInput>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let rx = exec::run(req.into_inner()).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn upload_file(
        &self,
        req: Request<tonic::Streaming<guestpb::FileChunk>>,
    ) -> Result<Response<guestpb::UploadResult>, Status> {
        Ok(Response::new(files::upload(req.into_inner()).await?))
    }

    type DownloadFileStream =
        tokio_stream::wrappers::ReceiverStream<Result<guestpb::FileChunk, Status>>;

    async fn download_file(
        &self,
        req: Request<guestpb::DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let req = req.into_inner();
        let rx = files::download(req.path, &req.user).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type WatchStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::WatchEvent, Status>>;

    async fn watch(
        &self,
        req: Request<guestpb::WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = req.into_inner();
        let interval = std::time::Duration::from_millis(if req.interval_ms == 0 {
            500
        } else {
            req.interval_ms.max(50) as u64
        });
        let rx = files::watch(req.path, req.is_recursive, interval, &req.user).await?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn list_dir(
        &self,
        req: Request<guestpb::ListDirRequest>,
    ) -> Result<Response<guestpb::ListDirResponse>, Status> {
        let req = req.into_inner();
        Ok(Response::new(files::list_dir(&req.path, &req.user).await?))
    }

    async fn list_commands(
        &self,
        _req: Request<guestpb::ListCommandsRequest>,
    ) -> Result<Response<guestpb::ListCommandsResponse>, Status> {
        Ok(Response::new(commands::list()))
    }

    async fn get_command(
        &self,
        req: Request<guestpb::GetCommandRequest>,
    ) -> Result<Response<guestpb::CommandInfo>, Status> {
        Ok(Response::new(commands::get(&req.into_inner().command_id)?))
    }

    type AttachCommandStream =
        tokio_stream::wrappers::ReceiverStream<Result<guestpb::ExecOutput, Status>>;

    async fn attach_command(
        &self,
        req: Request<guestpb::AttachCommandRequest>,
    ) -> Result<Response<Self::AttachCommandStream>, Status> {
        let rx = commands::attach(&req.into_inner().command_id, 0)?;
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    type AttachStream = tokio_stream::wrappers::ReceiverStream<Result<guestpb::ExecOutput, Status>>;

    async fn attach(
        &self,
        req: Request<tonic::Streaming<guestpb::AttachInput>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        use guestpb::attach_input::Input as Attach;
        use guestpb::exec_input::Input as Exec;
        use tokio_stream::StreamExt as _;

        let mut inbound = req.into_inner();
        let Some(Attach::Start(start)) = inbound.next().await.transpose()?.and_then(|m| m.input)
        else {
            return Err(Status::invalid_argument(
                "first Attach message must be Start",
            ));
        };
        let rx = commands::attach(&start.command_id, start.from_offset)?;
        // Looked up on the first input rather than now: following a command
        // that has finished is fine, and only feeding it is not.
        let id = start.command_id;
        tokio::spawn(async move {
            let mut input = None;
            while let Some(Ok(msg)) = inbound.next().await {
                let translated = match msg.input {
                    Some(Attach::Stdin(bytes)) => Exec::Stdin(bytes),
                    Some(Attach::Resize(size)) => Exec::Resize(size),
                    Some(Attach::Signal(signal)) => Exec::Signal(signal),
                    Some(Attach::IsStdinEof(eof)) => Exec::IsStdinEof(eof),
                    Some(Attach::Start(_)) | None => continue,
                };
                if input.is_none() {
                    match commands::input(&id) {
                        Ok(tx) => input = Some(tx),
                        Err(err) => {
                            tracing::debug!(%err, "input for a command that takes none");
                            return;
                        }
                    }
                }
                let msg = guestpb::ExecInput {
                    input: Some(translated),
                };
                // Waits for room rather than dropping: this task carries only
                // input, so a slow child holds up nobody's output.
                if let Some(tx) = &input
                    && tx.send(msg).await.is_err()
                {
                    return;
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn prune_commands(
        &self,
        _req: Request<guestpb::PruneCommandsRequest>,
    ) -> Result<Response<guestpb::PruneCommandsResponse>, Status> {
        Ok(Response::new(
            tokio::task::spawn_blocking(commands::prune)
                .await
                .map_err(|err| Status::internal(format!("pruning did not run: {err}")))?,
        ))
    }

    async fn signal_command(
        &self,
        req: Request<guestpb::SignalCommandRequest>,
    ) -> Result<Response<guestpb::SignalCommandResponse>, Status> {
        let req = req.into_inner();
        commands::signal(&req.command_id, req.signal)?;
        Ok(Response::new(guestpb::SignalCommandResponse {}))
    }

    async fn create_user(
        &self,
        req: Request<guestpb::CreateUserRequest>,
    ) -> Result<Response<guestpb::CreateUserResponse>, Status> {
        Ok(Response::new(
            users::create_user(&req.into_inner().name).await?,
        ))
    }

    async fn create_group(
        &self,
        req: Request<guestpb::CreateGroupRequest>,
    ) -> Result<Response<guestpb::CreateGroupResponse>, Status> {
        Ok(Response::new(
            users::create_group(&req.into_inner().name).await?,
        ))
    }

    async fn add_user_to_group(
        &self,
        req: Request<guestpb::GroupMembership>,
    ) -> Result<Response<guestpb::GroupMembershipResponse>, Status> {
        let req = req.into_inner();
        users::add_to_group(&req.user, &req.group).await?;
        Ok(Response::new(guestpb::GroupMembershipResponse {}))
    }

    async fn remove_user_from_group(
        &self,
        req: Request<guestpb::GroupMembership>,
    ) -> Result<Response<guestpb::GroupMembershipResponse>, Status> {
        let req = req.into_inner();
        users::remove_from_group(&req.user, &req.group).await?;
        Ok(Response::new(guestpb::GroupMembershipResponse {}))
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
        "burrow-guest listening on vsock"
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
        .add_service(GuestServer::new(AgentService))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let is_init = std::process::id() == 1;
    let is_reexec = std::env::var_os(REEXEC_MARK).is_some();

    // The agent's stdout is the guest's serial console, which Firecracker
    // emulates a byte at a time: every log line costs milliseconds of guest
    // time and shows up directly in boot and resume latency. Default to
    // `warn`; `RUST_LOG=info` turns the detail back on when debugging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    if is_init && !is_reexec {
        // Pivot into the writable overlay before mounting anything else, so
        // the pseudo-filesystems land inside the final root.
        init::setup_writable_root();
        if let Err(err) = init::mount_essentials() {
            tracing::error!(%err, "failed to mount essential filesystems");
        }
        init::write_resolv_conf();
        // The kernel brought the interface up over IPv4; v6 has no equivalent
        // boot argument the kernel understands, so burrow passes its own and
        // the address is added here.
        if let Some((address, prefix, gateway)) = init::boot_ipv6() {
            if let Err(err) = netconf::add_ipv6(address, prefix, gateway).await {
                tracing::warn!(%address, %err, "could not add the guest's IPv6 address");
            } else {
                tracing::debug!(%address, prefix, "IPv6 configured");
            }
        }
    }
    let is_systemd = is_init && systemd::is_requested();
    if is_systemd && is_reexec {
        systemd::adopt();
    }
    // Exec depends on the reaper for exit statuses, so it runs even when the
    // agent is not PID 1 (development outside a microVM).
    reaper::spawn();

    // Established before any snapshot is taken, so a restored clone does not
    // pay for it on the critical path of a warm create.
    netconf::prepare().await;
    if is_reexec {
        commands::restore(COMMANDS_STATE);
        tracing::warn!(
            version = VERSION,
            digest = self_digest(),
            "agent upgraded in place"
        );
    }
    if is_systemd && !is_reexec {
        systemd::start();
    }

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
