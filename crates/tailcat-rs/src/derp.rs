//! A DERP relay client.
//!
//! DERP is a TCP (normally TLS) connection to a relay that carries packets
//! between node keys. A client upgrades an HTTP request to the DERP
//! protocol, learns the relay's key, proves its own with a NaCl box, and
//! then exchanges length-prefixed frames. Tailcat uses one relay: the
//! region in the server's address. Everything a client sends before it has
//! found a direct path, and everything if it never does, goes through here.
//!
//! The client reconnects on its own. A dropped relay connection costs a few
//! seconds of relayed traffic, not the tunnel, since the same node key
//! reattaches to the same relay.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf,
    WriteHalf,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::derpmap::{DerpNode, DerpRegion};
use crate::error::{Error, Result};
use crate::key::{KEY_LEN, NodePrivate, NodePublic};

const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
const PROTOCOL_VERSION: u32 = 2;
pub const MAX_PACKET_SIZE: usize = 64 << 10;
const MAX_INFO_LEN: usize = 1 << 20;
const FRAME_HEADER_LEN: usize = 5;

const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const FRAME_HEALTH: u8 = 0x14;
const FRAME_RESTARTING: u8 = 0x15;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// The relay sends a keep-alive every minute; twice that with nothing at
/// all means the connection is dead even if the socket has not noticed.
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
const SEND_QUEUE: usize = 256;

const HTTPS_PORT: u16 = 443;
/// What `derper --dev` listens on without TLS.
const DEV_HTTP_PORT: u16 = 3340;

#[derive(Clone, Debug)]
pub struct Options {
    /// Speak plain HTTP to the relay, as `derper --dev` expects. Never for
    /// a real relay: the node key exchange is authenticated by the box, but
    /// the relay's identity is only TLS.
    pub plaintext_http: bool,
    /// Announced to the relay; some relays refuse app names they know to be
    /// abusive.
    pub app_name: String,
}

/// One packet the relay delivered, and who sent it.
#[derive(Debug)]
pub struct Packet {
    pub src: NodePublic,
    pub data: Vec<u8>,
}

/// A handle to a relay connection that is maintained in the background.
pub struct DerpClient {
    frames: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
}

impl DerpClient {
    /// Starts connecting to `region` and keeps the connection up until the
    /// client is dropped or the event receiver is closed.
    pub fn connect(
        region: DerpRegion,
        key: NodePrivate,
        opts: Options,
    ) -> (DerpClient, mpsc::Receiver<Packet>) {
        let (frames_tx, frames_rx) = mpsc::channel(SEND_QUEUE);
        let (packets_tx, packets_rx) = mpsc::channel(SEND_QUEUE);
        let task = tokio::spawn(run(region, key, opts, packets_tx, frames_rx));
        (
            DerpClient {
                frames: frames_tx,
                task,
            },
            packets_rx,
        )
    }

    /// Queues `pkt` for `dst`. Delivery is best effort, as on any relay: a
    /// full queue or a disconnected relay drops the packet, and so does the
    /// relay if `dst` is not connected to it.
    pub fn send(&self, dst: &NodePublic, pkt: &[u8]) -> bool {
        if pkt.len() > MAX_PACKET_SIZE {
            return false;
        }
        let mut body = Vec::with_capacity(KEY_LEN + pkt.len());
        body.extend_from_slice(dst.as_bytes());
        body.extend_from_slice(pkt);
        self.frames
            .try_send(frame(FRAME_SEND_PACKET, &body))
            .is_ok()
    }
}

impl Drop for DerpClient {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn frame(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    f.push(typ);
    f.extend_from_slice(&(body.len() as u32).to_be_bytes());
    f.extend_from_slice(body);
    f
}

type Stream = Box<dyn Io + Send>;
type Reader = BufReader<ReadHalf<Stream>>;
type Writer = WriteHalf<Stream>;

trait Io: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> Io for T {}

async fn run(
    region: DerpRegion,
    key: NodePrivate,
    opts: Options,
    packets: mpsc::Sender<Packet>,
    mut frames: mpsc::Receiver<Vec<u8>>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_once(&region, &key, &opts).await {
            Ok((reader, writer, node)) => {
                tracing::info!(region = region.region_id, node, "derp connected");
                backoff = Duration::from_secs(1);
                let err = session(reader, writer, &mut frames, &packets).await;
                tracing::warn!(region = region.region_id, %err, "derp connection lost");
            }
            Err(err) => {
                tracing::warn!(region = region.region_id, %err, "derp connect failed");
            }
        }
        if packets.is_closed() {
            return;
        }
        // Anything queued while disconnected is stale by the time the relay
        // is back: WireGuard retransmits and disco re-probes on their own.
        let sleep = tokio::time::sleep(backoff);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                Some(_) = frames.recv() => {}
            }
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn session(
    mut reader: Reader,
    mut writer: Writer,
    frames: &mut mpsc::Receiver<Vec<u8>>,
    packets: &mpsc::Sender<Packet>,
) -> Error {
    loop {
        tokio::select! {
            frame = frames.recv() => {
                let Some(frame) = frame else { return Error::Closed };
                if let Err(err) = writer.write_all(&frame).await {
                    return err.into();
                }
            }
            read = tokio::time::timeout(READ_TIMEOUT, read_frame(&mut reader, MAX_PACKET_SIZE + KEY_LEN)) => {
                let (typ, body) = match read {
                    Ok(Ok(f)) => f,
                    Ok(Err(err)) => return err.into(),
                    Err(_) => return Error::Derp("no frames for 120s".into()),
                };
                match typ {
                    FRAME_RECV_PACKET => {
                        if body.len() < KEY_LEN {
                            return Error::Derp("short RecvPacket frame".into());
                        }
                        let src = NodePublic::from_slice(&body[..KEY_LEN]).unwrap();
                        let data = body[KEY_LEN..].to_vec();
                        if packets.send(Packet { src, data }).await.is_err() {
                            return Error::Closed;
                        }
                    }
                    FRAME_PING => {
                        if let Err(err) = writer.write_all(&frame(FRAME_PONG, &body)).await {
                            return err.into();
                        }
                    }
                    FRAME_PEER_GONE => {
                        if let Some(peer) = NodePublic::from_slice(body.get(..KEY_LEN).unwrap_or(&[])) {
                            tracing::debug!(peer = %peer.short(), "relay reports peer gone");
                        }
                    }
                    FRAME_HEALTH => {
                        tracing::warn!(problem = %String::from_utf8_lossy(&body), "derp health");
                    }
                    FRAME_RESTARTING => {
                        return Error::Derp("relay restarting".into());
                    }
                    FRAME_KEEP_ALIVE => {}
                    _ => {}
                }
            }
        }
    }
}

async fn read_frame(reader: &mut Reader, max: usize) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > max {
        return Err(std::io::Error::other(format!(
            "frame of {len} bytes exceeds limit of {max}"
        )));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok((hdr[0], body))
}

#[derive(Serialize)]
struct ClientInfo {
    version: u32,
    #[serde(rename = "CanAckPings")]
    can_ack_pings: bool,
    #[serde(rename = "AppName")]
    app_name: String,
}

#[derive(Deserialize)]
struct ServerInfo {}

async fn connect_once(
    region: &DerpRegion,
    key: &NodePrivate,
    opts: &Options,
) -> Result<(Reader, Writer, String)> {
    let mut last_err = Error::Derp(format!("region {} has no DERP nodes", region.region_id));
    for node in region.nodes.iter().filter(|n| !n.stun_only) {
        match connect_node(node, key, opts).await {
            Ok((r, w)) => return Ok((r, w, node.host_name.clone())),
            Err(err) => {
                tracing::debug!(node = node.host_name, %err, "derp node failed");
                last_err = err;
            }
        }
    }
    Err(last_err)
}

fn port_of(node: &DerpNode, opts: &Options) -> u16 {
    match u16::try_from(node.derp_port) {
        Ok(p) if p != 0 => p,
        _ if opts.plaintext_http => DEV_HTTP_PORT,
        _ => HTTPS_PORT,
    }
}

async fn dial(node: &DerpNode, port: u16) -> Result<TcpStream> {
    let mut targets: Vec<String> = node
        .ip_addrs()
        .into_iter()
        .map(|ip| std::net::SocketAddr::new(ip, port).to_string())
        .collect();
    if targets.is_empty() {
        targets.push(format!("{}:{port}", node.host_name));
    }
    let mut last_err = Error::Derp(format!("no address for {}", node.host_name));
    for target in targets {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&target)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(err)) => last_err = Error::Derp(format!("dial {target}: {err}")),
            Err(_) => last_err = Error::Derp(format!("dial {target}: timed out")),
        }
    }
    Err(last_err)
}

fn tls_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    if insecure {
        return Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        );
    }
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Accepts any certificate. Only for nodes flagged `InsecureForTests`,
/// which is how a test's self-signed relay gets used.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn connect_node(
    node: &DerpNode,
    key: &NodePrivate,
    opts: &Options,
) -> Result<(Reader, Writer)> {
    let port = port_of(node, opts);
    let tcp = dial(node, port).await?;
    let stream: Stream = if opts.plaintext_http {
        Box::new(tcp)
    } else {
        let name = ServerName::try_from(node.host_name.clone())
            .map_err(|err| Error::Derp(format!("bad host name {:?}: {err}", node.host_name)))?;
        let connector = tokio_rustls::TlsConnector::from(tls_config(node.insecure_for_tests));
        Box::new(
            connector
                .connect(name, tcp)
                .await
                .map_err(|err| Error::Derp(format!("tls to {}: {err}", node.host_name)))?,
        )
    };
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);

    let default_port = if opts.plaintext_http {
        DEV_HTTP_PORT
    } else {
        HTTPS_PORT
    };
    let host = if port == default_port {
        node.host_name.clone()
    } else {
        format!("{}:{port}", node.host_name)
    };
    wr.write_all(
        format!(
            "GET /derp HTTP/1.1\r\nHost: {host}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;

    let mut status = String::new();
    rd.read_line(&mut status).await?;
    if !status.starts_with("HTTP/1.1 101") {
        return Err(Error::Derp(format!(
            "upgrade refused: {}",
            status.trim_end()
        )));
    }
    loop {
        let mut line = String::new();
        if rd.read_line(&mut line).await? == 0 {
            return Err(Error::Derp("connection closed in upgrade response".into()));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let (typ, body) = read_frame(&mut rd, 1 << 10).await?;
    if typ != FRAME_SERVER_KEY
        || body.len() < MAGIC.len() + KEY_LEN
        || &body[..MAGIC.len()] != MAGIC
    {
        return Err(Error::Derp("invalid server greeting".into()));
    }
    let server_key = NodePublic::from_slice(&body[MAGIC.len()..MAGIC.len() + KEY_LEN]).unwrap();

    let info = serde_json::to_vec(&ClientInfo {
        version: PROTOCOL_VERSION,
        can_ack_pings: true,
        app_name: opts.app_name.clone(),
    })
    .expect("static struct serialises");
    let mut client_info = key.public().as_bytes().to_vec();
    client_info.extend(key.seal_to(&server_key, &info));
    wr.write_all(&frame(FRAME_CLIENT_INFO, &client_info))
        .await?;

    let (typ, body) = read_frame(&mut rd, MAX_INFO_LEN + 24).await?;
    if typ != FRAME_SERVER_INFO {
        return Err(Error::Derp(format!(
            "expected ServerInfo, got frame 0x{typ:02x}"
        )));
    }
    let opened = key
        .open_from(&server_key, &body)
        .ok_or_else(|| Error::Derp("failed to open ServerInfo box".into()))?;
    serde_json::from_slice::<ServerInfo>(&opened)
        .map_err(|err| Error::Derp(format!("invalid ServerInfo: {err}")))?;
    Ok((rd, wr))
}
