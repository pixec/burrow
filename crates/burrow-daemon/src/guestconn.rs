//! Connecting to a sandbox's guest agent.
//!
//! The agent speaks gRPC over vsock, so the tonic channel is built on a custom
//! connector that dials the guest's vsock, whichever transport its hypervisor
//! gives it, instead of TCP. The URI is a required placeholder that nothing
//! ever resolves.

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::guest_client::GuestClient;
use burrow_vmm::GuestAddr;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::sandbox::RunningSandbox;

/// vsock port the agent listens on inside the guest.
pub const AGENT_PORT: u32 = 1024;

/// Builds an agent client for the guest at `guest`.
///
/// Channels must not be held across a pause/resume: the underlying vsock
/// connection dies with the snapshot. Reconnect after every resume.
///
/// `timeout` bounds every unary call the client makes, which is what keeps a
/// guest that accepts the connection and then goes quiet from parking the task
/// that called it for the life of the node. See [`connect_timed`] for why it
/// does not bound the streaming ones.
pub async fn connect(
    guest: GuestAddr,
    timeout: std::time::Duration,
) -> anyhow::Result<GuestClient<Channel>> {
    connect_timed(guest, timeout)
        .await
        .map(|(client, _)| client)
}

/// Connects, and says when the guest's vsock listener accepted.
///
/// That instant is guest wake; the gRPC HTTP/2 handshake that follows it is
/// not, and conflating the two hides whether a slow create is the hypervisor's
/// fault or the agent's.
///
/// The deadline is tonic's per-request one, which bounds the wait for a
/// response *head* rather than the body that follows it. That is the boundary
/// we want: a handshake or a health check that never answers fails, while an
/// exec, a log watch or a download goes on streaming for as long as the caller
/// wants it to. Streams need their own deadline where the daemon, rather than
/// a caller, is waiting on one.
///
/// What a stream does get is a check that the guest is still there: HTTP/2
/// pings while any call is open, failing the call when one goes unanswered for
/// `timeout`. A vsock connection can die without either end hearing of it,
/// when the VM under it is replaced or its VMM wedges, and an exec on one would
/// otherwise wait for output that can never come. Idle channels are not
/// pinged, so a guest nobody is using is not woken to answer.
async fn connect_timed(
    guest: GuestAddr,
    timeout: std::time::Duration,
) -> anyhow::Result<(GuestClient<Channel>, Option<std::time::Instant>)> {
    let accepted: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>> =
        std::sync::Arc::default();
    let recorder = accepted.clone();
    let channel = Endpoint::try_from("http://vsock.invalid")?
        .timeout(timeout)
        .http2_keep_alive_interval(timeout)
        .keep_alive_timeout(timeout)
        .connect_with_connector(service_fn(move |_: Uri| {
            let guest = guest.clone();
            let recorder = recorder.clone();
            async move {
                let stream = guest.connect(AGENT_PORT).await?;
                *recorder.lock().unwrap() = Some(std::time::Instant::now());
                Ok::<_, burrow_vmm::Error>(TokioIo::new(stream))
            }
        }))
        .await?;
    let at = *accepted.lock().unwrap();
    Ok((GuestClient::new(channel), at))
}

/// Connects as soon as the guest's agent accepts, or gives up.
///
/// The successful attempt *is* the connection, so a warm create pays one vsock
/// handshake rather than probing with a throwaway one first. The poll interval
/// is short because a guest waking from a snapshot takes tens of milliseconds.
pub async fn connect_when_ready(
    guest: GuestAddr,
    timeout: std::time::Duration,
) -> anyhow::Result<(GuestClient<Channel>, Option<std::time::Instant>)> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match connect_timed(guest.clone(), timeout).await {
            Ok(ready) => return Ok(ready),
            Err(err) if std::time::Instant::now() >= deadline => {
                return Err(err.context(format!("agent did not accept within {timeout:?}")));
            }
            Err(_) => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

/// Fresh entropy and the host clock, for the guest to apply on handshake.
pub fn handshake_request(restored: bool) -> burrow_proto::guest::v1::HandshakeRequest {
    handshake_with_network(restored, None)
}

/// Handshake carrying the address the guest should adopt.
///
/// Required for a sandbox restored from a shared warm snapshot: it wakes with
/// the snapshot's address, which belongs to no one, and only the host knows
/// which lease is actually its own.
pub fn handshake_with_network(
    restored: bool,
    network: Option<burrow_proto::guest::v1::NetworkConfig>,
) -> burrow_proto::guest::v1::HandshakeRequest {
    handshake_full(restored, network, String::new(), Vec::new(), Vec::new())
}

/// Handshake carrying the inspection CA as well.
///
/// Sent only to a sandbox that opted in: installing it elsewhere would let the
/// proxy impersonate any host to a sandbox that never agreed to that. The
/// bundles are the ones the image names in its environment; the guest installs
/// into the system store either way.
pub fn handshake_full(
    restored: bool,
    network: Option<burrow_proto::guest::v1::NetworkConfig>,
    inspection_ca_pem: String,
    extra_trust_bundles: Vec<burrow_proto::guest::v1::TrustBundle>,
    volumes: Vec<burrow_proto::guest::v1::VolumeMount>,
) -> burrow_proto::guest::v1::HandshakeRequest {
    burrow_proto::guest::v1::HandshakeRequest {
        inspection_ca_pem,
        extra_trust_bundles,
        entropy: fresh_entropy(),
        host_time_unix_nanos: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
        is_restored: restored,
        network,
        volumes,
    }
}

/// 32 bytes from the host CSPRNG. Every restored clone must get a *different*
/// seed, otherwise they all inherit the snapshot's RNG state.
fn fresh_entropy() -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; 32];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => buf,
        Err(err) => {
            tracing::error!(%err, "cannot read host entropy; guest rng will not diverge");
            Vec::new()
        }
    }
}

/// What a command run to completion left behind.
pub struct Finished {
    pub exit_code: i32,
    /// stdout and stderr interleaved as they arrived.
    pub output: Vec<u8>,
}

/// Runs a command in a sandbox and waits for it, as the node's own lifecycle
/// work does for Kit hooks.
pub async fn run_to_completion(
    sandbox: &RunningSandbox,
    start: guestpb::ExecStart,
) -> Result<Finished, Status> {
    let mut agent = sandbox.agent().await?;
    let begin = guestpb::ExecInput {
        input: Some(guestpb::exec_input::Input::Start(start)),
    };
    let mut stream = agent
        .exec(tokio_stream::iter(vec![begin]))
        .await?
        .into_inner();
    let mut finished = Finished {
        exit_code: -1,
        output: Vec::new(),
    };
    while let Some(msg) = stream.next().await {
        match msg?.output {
            Some(guestpb::exec_output::Output::Stdout(bytes))
            | Some(guestpb::exec_output::Output::Stderr(bytes)) => finished.output.extend(bytes),
            Some(guestpb::exec_output::Output::ExitCode(code)) => finished.exit_code = code,
            _ => {}
        }
    }
    Ok(finished)
}

/// Starts a command and returns once the agent has registered it, leaving it
/// to run. The agent keeps a command alive after the stream that started it
/// is gone, which is what makes a workload's entrypoint survive this call.
pub async fn spawn_detached(
    sandbox: &RunningSandbox,
    start: guestpb::ExecStart,
) -> Result<String, Status> {
    let mut agent = sandbox.agent().await?;
    let begin = guestpb::ExecInput {
        input: Some(guestpb::exec_input::Input::Start(start)),
    };
    // The sender side stays open and parked, so the agent sees no stdin EOF
    // and no hangup until this task is dropped along with the stream.
    let (tx, rx) = tokio::sync::mpsc::channel::<guestpb::ExecInput>(1);
    tx.send(begin)
        .await
        .map_err(|_| Status::internal("exec stream closed"))?;
    let mut stream = agent
        .exec(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await?
        .into_inner();
    let mut command_id = String::new();
    while let Some(msg) = stream.next().await {
        match msg?.output {
            Some(guestpb::exec_output::Output::CommandId(id)) => {
                command_id = id;
                break;
            }
            Some(guestpb::exec_output::Output::ExitCode(code)) => {
                return Err(Status::internal(format!(
                    "command exited with status {code} before it was registered"
                )));
            }
            _ => {}
        }
    }
    tokio::spawn(async move {
        let _keep = tx;
        while let Some(Ok(_)) = stream.next().await {}
    });
    Ok(command_id)
}

/// Writes a small file into a sandbox.
pub async fn upload(
    sandbox: &RunningSandbox,
    path: &str,
    content: &[u8],
    mode: u32,
    owner: &str,
    skip_existing: bool,
) -> Result<(), Status> {
    let mut agent = sandbox.agent().await?;
    let first = guestpb::FileChunk {
        path: path.to_string(),
        mode,
        data: content.to_vec(),
        owner: owner.to_string(),
        is_existing_skipped: skip_existing,
        user: String::new(),
    };
    agent.upload_file(tokio_stream::iter(vec![first])).await?;
    Ok(())
}

/// The agent binary this node ships, for upgrading guests that run another.
#[derive(Debug, Clone)]
pub struct GuestUpgrade {
    pub path: std::path::PathBuf,
    /// SHA-256 of `path`, lowercase hex.
    pub digest: String,
}

/// Handshakes, and brings the guest's agent up to this node's if it differs.
///
/// A guest reports the digest of the agent it runs. One that matches, or that
/// predates reporting, is left alone. One that differs is sent the node's
/// binary; it re-executes itself as PID 1, so the connection drops and this
/// reconnects and handshakes the new agent, which is the client handed back.
/// A guest that cannot upgrade right now, because a command is running, is
/// logged and left on the old agent until its next handshake.
pub async fn handshake_upgrading(
    mut agent: GuestClient<Channel>,
    guest: GuestAddr,
    request: guestpb::HandshakeRequest,
    upgrade: Option<&GuestUpgrade>,
    timeout: std::time::Duration,
) -> Result<(GuestClient<Channel>, guestpb::HandshakeResponse), tonic::Status> {
    let response = agent.handshake(request.clone()).await?.into_inner();
    let Some(upgrade) = upgrade else {
        return Ok((agent, response));
    };
    // An agent that reports no digest was built before in-place upgrades and
    // cannot be upgraded; the template it came from has to be imported again.
    if response.agent_digest.is_empty() {
        return Err(tonic::Status::failed_precondition(format!(
            "the guest runs agent {}, which predates in-place upgrades; import its \
             template again",
            response.agent_version
        )));
    }
    if response.agent_digest == upgrade.digest {
        return Ok((agent, response));
    }
    // The digest sent is of the bytes read now, not the one hashed at
    // startup: the binary on disk may have been replaced since, and the guest
    // verifies what it receives against what it is told.
    let bytes = tokio::fs::read(&upgrade.path).await.map_err(|err| {
        tonic::Status::internal(format!("reading {}: {err}", upgrade.path.display()))
    })?;
    let digest = {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&bytes))
    };
    if digest == response.agent_digest {
        return Ok((agent, response));
    }
    tracing::info!(
        from = response.agent_version,
        "guest runs another agent build; upgrading it"
    );
    let chunks = bytes
        .chunks(256 * 1024)
        .map(|chunk| guestpb::UpgradeChunk {
            data: chunk.to_vec(),
            digest: digest.clone(),
        })
        .collect::<Vec<_>>();
    let started = std::time::Instant::now();
    // A guest with a command running cannot be upgraded until it is idle,
    // because the command's pipes live in the agent's process; that guest is
    // upgraded on its next handshake. Any other refusal is an error.
    let restarting = match agent.upgrade(tokio_stream::iter(chunks)).await {
        Ok(resp) => resp.into_inner().is_restarting,
        Err(err) if err.code() == tonic::Code::FailedPrecondition => {
            tracing::warn!(%err, "guest agent busy; upgrading it on its next handshake");
            return Ok((agent, response));
        }
        Err(err) => return Err(err),
    };
    if !restarting {
        return Ok((agent, response));
    }
    drop(agent);
    // The old agent answers and then re-executes, and how long that takes
    // is the guest's business, so a reconnect can still land on the old
    // process and be cut off as it is replaced. The new agent is the one
    // reporting the digest it was sent, so connecting and handshaking is
    // repeated until that is who answers.
    let deadline = std::time::Instant::now() + timeout;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let attempt = async {
            let (mut agent, _) = connect_when_ready(guest.clone(), timeout)
                .await
                .map_err(|err| tonic::Status::internal(format!("upgraded agent: {err}")))?;
            let response = agent.handshake(request.clone()).await?.into_inner();
            Ok::<_, tonic::Status>((agent, response))
        };
        match attempt.await {
            Ok((agent, response)) if response.agent_digest == digest => {
                tracing::info!(
                    version = response.agent_version,
                    took_ms = started.elapsed().as_millis() as u64,
                    "guest agent upgraded"
                );
                return Ok((agent, response));
            }
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => continue,
            Ok((_, response)) => {
                return Err(tonic::Status::internal(format!(
                    "the guest agent did not come back as the new build: it reports {}",
                    response.agent_digest
                )));
            }
            Err(err) => return Err(err),
        }
    }
}
