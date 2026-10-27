//! Connecting to a sandbox's guest agent.
//!
//! The agent speaks gRPC over vsock, so the tonic channel is built on a custom
//! connector that performs Firecracker's hybrid-vsock handshake instead of
//! dialing TCP. The URI is a required placeholder that nothing ever resolves.

use std::path::PathBuf;

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use burrow_proto::guest::v1 as guestpb;
use burrow_proto::guest::v1::guest_client::GuestClient;
use tokio_stream::StreamExt;
use tonic::Status;

use crate::sandbox::RunningSandbox;

/// vsock port the agent listens on inside the guest.
pub const AGENT_PORT: u32 = 1024;

/// Builds an agent client for the VM whose vsock UDS is at `uds_path`.
///
/// Channels must not be held across a pause/resume: the underlying vsock
/// connection dies with the snapshot. Reconnect after every resume.
///
/// `timeout` bounds every unary call the client makes, which is what keeps a
/// guest that accepts the connection and then goes quiet from parking the task
/// that called it for the life of the node. See [`connect_timed`] for why it
/// does not bound the streaming ones.
pub async fn connect(
    uds_path: PathBuf,
    timeout: std::time::Duration,
) -> anyhow::Result<GuestClient<Channel>> {
    connect_timed(uds_path, timeout)
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
async fn connect_timed(
    uds_path: PathBuf,
    timeout: std::time::Duration,
) -> anyhow::Result<(GuestClient<Channel>, Option<std::time::Instant>)> {
    let accepted: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>> =
        std::sync::Arc::default();
    let recorder = accepted.clone();
    let channel = Endpoint::try_from("http://vsock.invalid")?
        .timeout(timeout)
        .connect_with_connector(service_fn(move |_: Uri| {
            let uds_path = uds_path.clone();
            let recorder = recorder.clone();
            async move {
                let stream = burrow_firecracker::vsock::connect(&uds_path, AGENT_PORT).await?;
                *recorder.lock().unwrap() = Some(std::time::Instant::now());
                Ok::<_, burrow_firecracker::VmmError>(TokioIo::new(stream))
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
    uds_path: PathBuf,
    timeout: std::time::Duration,
) -> anyhow::Result<(GuestClient<Channel>, Option<std::time::Instant>)> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match connect_timed(uds_path.clone(), timeout).await {
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
    };
    agent.upload_file(tokio_stream::iter(vec![first])).await?;
    Ok(())
}
