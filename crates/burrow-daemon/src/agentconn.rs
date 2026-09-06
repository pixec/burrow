//! Connecting to a sandbox's guest agent.
//!
//! The agent speaks gRPC over vsock, so the tonic channel is built on a custom
//! connector that performs Firecracker's hybrid-vsock handshake instead of
//! dialing TCP. The URI is a required placeholder that nothing ever resolves.

use std::path::PathBuf;

use hyper_util::rt::TokioIo;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use burrow_proto::agent::v1::agent_client::AgentClient;

/// vsock port the agent listens on inside the guest.
pub const AGENT_PORT: u32 = 1024;

/// Builds an agent client for the VM whose vsock UDS is at `uds_path`.
///
/// Channels must not be held across a pause/resume: the underlying vsock
/// connection dies with the snapshot. Reconnect after every resume.
pub async fn connect(uds_path: PathBuf) -> anyhow::Result<AgentClient<Channel>> {
    connect_timed(uds_path).await.map(|(client, _)| client)
}

/// Connects, and says when the guest's vsock listener accepted.
///
/// That instant is guest wake; the gRPC HTTP/2 handshake that follows it is
/// not, and conflating the two hides whether a slow create is the hypervisor's
/// fault or the agent's.
async fn connect_timed(
    uds_path: PathBuf,
) -> anyhow::Result<(AgentClient<Channel>, Option<std::time::Instant>)> {
    let accepted: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>> =
        std::sync::Arc::default();
    let recorder = accepted.clone();
    let channel = Endpoint::try_from("http://vsock.invalid")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let uds_path = uds_path.clone();
            let recorder = recorder.clone();
            async move {
                let stream = burrow_vmm::vsock::connect(&uds_path, AGENT_PORT).await?;
                *recorder.lock().unwrap() = Some(std::time::Instant::now());
                Ok::<_, burrow_vmm::VmmError>(TokioIo::new(stream))
            }
        }))
        .await?;
    let at = *accepted.lock().unwrap();
    Ok((AgentClient::new(channel), at))
}

/// Connects as soon as the guest's agent accepts, or gives up.
///
/// The successful attempt *is* the connection, so a warm create pays one vsock
/// handshake rather than probing with a throwaway one first. The poll interval
/// is short because a guest waking from a snapshot takes tens of milliseconds.
pub async fn connect_when_ready(
    uds_path: PathBuf,
    timeout: std::time::Duration,
) -> anyhow::Result<(AgentClient<Channel>, Option<std::time::Instant>)> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match connect_timed(uds_path.clone()).await {
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
pub fn handshake_request(restored: bool) -> burrow_proto::agent::v1::HandshakeRequest {
    handshake_with_network(restored, None)
}

/// Handshake carrying the address the guest should adopt.
///
/// Required for a sandbox restored from a shared warm snapshot: it wakes with
/// the snapshot's address, which belongs to no one, and only the host knows
/// which lease is actually its own.
pub fn handshake_with_network(
    restored: bool,
    network: Option<burrow_proto::agent::v1::NetworkConfig>,
) -> burrow_proto::agent::v1::HandshakeRequest {
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
    network: Option<burrow_proto::agent::v1::NetworkConfig>,
    inspection_ca_pem: String,
    extra_trust_bundles: Vec<burrow_proto::agent::v1::TrustBundle>,
    volumes: Vec<burrow_proto::agent::v1::VolumeMount>,
) -> burrow_proto::agent::v1::HandshakeRequest {
    burrow_proto::agent::v1::HandshakeRequest {
        inspection_ca_pem,
        extra_trust_bundles,
        entropy: fresh_entropy(),
        host_time_unix_nanos: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
        restored,
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
