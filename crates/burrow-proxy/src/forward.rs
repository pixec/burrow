//! Sending an inspected request to an endpoint the operator controls.
//!
//! A forward is what a rule does to a request that has already passed every
//! check: instead of going to the origin the sandbox named, it goes to a URL
//! the operator runs, carrying the method, path, query, headers and body it was
//! written with. That is how a domain gets restricted to a set of paths no
//! allowlist could express.
//!
//! A forwarded request is not signed. It carries the shared secret configured
//! on the rule as `burrow-forwarded-secret`, held on the node and never in any
//! guest, so seeing it proves only that the request came from a node holding
//! the rule: it names no sandbox and binds nothing to the request's contents.
//! The `burrow-forwarded-*` headers are the node's claims, believable exactly
//! as far as the node is, so the endpoint must not be given authority a node
//! compromise should not also grant.
//!
//! An `https://` endpoint is dialled through the same verified TLS client the
//! inspected upstream leg uses, against the same public roots. Verification is
//! mandatory and nothing retries in plaintext. An `http://` endpoint carries
//! the secret in clear text, which is legitimate only where the node alone can
//! reach the endpoint.
//!
//! Every header in the reserved prefix is stripped from the sandbox's request
//! before the node's own are set, so a guest cannot forge any of it.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use crate::policy;

/// Prefix for everything the node says about a forwarded request.
///
/// Burrow's own rather than a copy of another vendor's: a header that looks
/// like somebody else's would invite an endpoint to trust it as if it were.
pub const PREFIX: &str = "burrow-forwarded-";

/// Largest request body forwarded.
///
/// A forward changes which connection the body goes down, so it is buffered
/// rather than streamed, and a buffer on a policy path needs a ceiling. A
/// request over this is refused rather than truncated, since a body the
/// endpoint reads as shorter than it was written is a desync.
pub const MAX_BODY: u64 = 8 * 1024 * 1024;

/// Where the request was going before the rule claimed it.
pub struct Origin<'a> {
    pub host: &'a str,
    pub scheme: &'a str,
    pub port: u16,
    /// Path and query as the request wrote them.
    pub target: &'a str,
    pub sandbox_id: &'a str,
}

/// What the endpoint answered. The body is still arriving.
pub struct Answer {
    pub status: ::http::StatusCode,
    pub headers: ::http::HeaderMap,
    pub body: ::hyper::body::Incoming,
}

/// Hop-by-hop fields, plus the two the forward leg frames for itself.
///
/// None of these describe the request; they describe the connection it arrived
/// on, and carrying them onto a different connection is how two hops end up
/// disagreeing about where a body ends.
fn is_connection_header(name: &str) -> bool {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    ];
    HOP_BY_HOP.iter().any(|hop| name.eq_ignore_ascii_case(hop))
}

/// Sends one request to the endpoint a rule names.
///
/// `headers` are the sandbox's own, and are copied through except for the
/// connection's own fields and anything already claiming the reserved prefix.
pub async fn send(
    forward: &policy::Forward,
    method: &str,
    headers: &[(String, String)],
    body: Bytes,
    origin: Origin<'_>,
) -> Result<Answer, String> {
    let target = if origin.target.starts_with('/') {
        origin.target
    } else {
        "/"
    };
    // Origin-form, with the endpoint named in `Host`. The low-level client
    // writes the target exactly as it is given, so this is where the shape of
    // the request line is decided.
    let uri = format!("{}{}", forward.target.prefix, target);
    let authority = match forward.target.port {
        port if port == forward.target.scheme.default_port() => forward.target.host.clone(),
        port => format!("{}:{port}", forward.target.host),
    };

    let method = ::http::Method::from_bytes(method.as_bytes())
        .map_err(|_| "request method is not a token".to_string())?;
    let mut request = ::http::Request::builder()
        .method(method)
        .uri(&uri)
        .header(::http::header::HOST, &authority)
        .body(Full::new(body))
        .map_err(|err| format!("building the forwarded request: {err}"))?;

    let out = request.headers_mut();
    for (name, value) in headers {
        if is_connection_header(name) || name.to_ascii_lowercase().starts_with(PREFIX) {
            continue;
        }
        let (Ok(name), Ok(value)) = (
            ::http::HeaderName::from_bytes(name.as_bytes()),
            ::http::HeaderValue::from_str(value),
        ) else {
            return Err("request carries a header that cannot be forwarded".into());
        };
        out.append(name, value);
    }
    // Set after the copy, so nothing the guest sent can survive under one of
    // these names.
    let stamped = [
        ("host", origin.host.to_string()),
        ("scheme", origin.scheme.to_string()),
        ("port", origin.port.to_string()),
        ("path", origin.target.to_string()),
        ("sandbox", origin.sandbox_id.to_string()),
    ];
    for (suffix, value) in stamped {
        let name = ::http::HeaderName::from_bytes(format!("{PREFIX}{suffix}").as_bytes())
            .map_err(|_| "forwarded header name is not a token".to_string())?;
        let value = ::http::HeaderValue::from_str(&value)
            .map_err(|_| format!("{PREFIX}{suffix} would not be a header value"))?;
        out.insert(name, value);
    }
    if !forward.secret.is_empty() {
        let value = ::http::HeaderValue::from_str(&forward.secret)
            .map_err(|_| "the forward secret is not a header value".to_string())?;
        out.insert(
            ::http::HeaderName::from_static("burrow-forwarded-secret"),
            value,
        );
    }

    let stream =
        tokio::net::TcpStream::connect((forward.target.host.as_str(), forward.target.port))
            .await
            .map_err(|err| format!("connecting to the forward endpoint: {err}"))?;

    match forward.target.scheme {
        policy::ForwardScheme::Http => exchange(stream, request).await,
        policy::ForwardScheme::Https => {
            // The same verified client the inspected upstream leg uses, so
            // the endpoint is held to exactly the anchors an origin is. A
            // handshake that does not verify ends the request: a plaintext
            // retry would put the secret on the wire verification exists to
            // keep it off.
            let name = rustls::pki_types::ServerName::try_from(forward.target.host.clone())
                .map_err(|_| {
                    format!(
                        "{} is not a usable server name for a forward endpoint",
                        forward.target.host
                    )
                })?;
            let tls = tokio_rustls::TlsConnector::from(crate::inspect::verified_client(vec![
                b"http/1.1".to_vec(),
            ]))
            .connect(name, stream)
            .await
            .map_err(|err| format!("tls handshake with the forward endpoint failed: {err}"))?;
            exchange(tls, request).await
        }
    }
}

/// Sends one already-built request down an established connection.
///
/// Generic over the transport so the plaintext and TLS legs run the same code:
/// what differs between them is the handshake, and nothing after it.
async fn exchange<S>(stream: S, request: ::http::Request<Full<Bytes>>) -> Result<Answer, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) =
        ::hyper::client::conn::http1::handshake(::hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|err| format!("handshaking with the forward endpoint: {err}"))?;
    // The connection has to be driven for the response and its body to arrive.
    // It ends when the sender is dropped and the body is done with.
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("the forward endpoint did not answer: {err}"))?;
    let (parts, body) = response.into_parts();
    Ok(Answer {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

/// Reads a forwarded response's body, one frame at a time.
///
/// Responses are streamed rather than buffered: they are the direction that
/// carries a download, and nothing on the policy path needs to see them whole.
pub async fn next_chunk(body: &mut ::hyper::body::Incoming) -> Result<Option<Bytes>, String> {
    loop {
        let Some(frame) = body.frame().await else {
            return Ok(None);
        };
        let frame = frame.map_err(|err| format!("reading the forwarded response: {err}"))?;
        match frame.into_data() {
            Ok(data) => return Ok(Some(data)),
            // Trailers, which nothing downstream of here frames for.
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::inspect::{Authority, Protocol};

    /// A forward endpoint on loopback, and the request head it received.
    struct Endpoint {
        port: u16,
        seen: tokio::sync::oneshot::Receiver<String>,
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow-fwd-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Adds one authority to the anchors the forward leg verifies against.
    ///
    /// The test's endpoint is on loopback, so no public authority will sign for
    /// it; this is the only reason the crate's tests can dial one at all.
    fn trust(authority: &Authority) {
        let mut pem = authority.certificate_pem().as_bytes();
        for der in rustls_pemfile::certs(&mut pem) {
            crate::inspect::trust_in_tests(der.unwrap());
        }
    }

    /// Reads one request head and answers `200`, whatever carried it.
    async fn answer_once<S>(mut io: S, tx: tokio::sync::oneshot::Sender<String>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while io.read_exact(&mut byte).await.is_ok() {
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = io
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await;
        let _ = io.flush().await;
        let _ = tx.send(String::from_utf8_lossy(&head).into_owned());
        // Held open long enough for the client to read the answer off it.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    /// A TLS endpoint presenting a leaf `authority` signed.
    async fn tls_endpoint(authority: &Authority) -> Endpoint {
        let config = authority
            .server_config("127.0.0.1", Protocol::Http11)
            .unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, seen) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(tls) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await else {
                return;
            };
            answer_once(tls, tx).await;
        });
        Endpoint { port, seen }
    }

    /// A plaintext endpoint, which is still a supported deployment.
    async fn plain_endpoint() -> Endpoint {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, seen) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            answer_once(stream, tx).await;
        });
        Endpoint { port, seen }
    }

    fn rule(url: &str) -> policy::Forward {
        policy::Forward {
            target: policy::ForwardTarget::parse(url).unwrap(),
            url: url.to_string(),
            secret: "shared-secret".into(),
        }
    }

    /// The sandbox's own headers, including two it has no business setting.
    fn guest_headers() -> Vec<(String, String)> {
        vec![
            ("Content-Type".into(), "application/json".into()),
            ("burrow-forwarded-sandbox".into(), "somebody-else".into()),
            ("Burrow-Forwarded-Secret".into(), "guessed".into()),
        ]
    }

    fn origin() -> Origin<'static> {
        Origin {
            host: "api.example.com",
            scheme: "https",
            port: 443,
            target: "/v1/users?a=1",
            sandbox_id: "sbx-1",
        }
    }

    /// Header names are written lowercase on the wire; values are not touched.
    fn assert_provenance(seen: &str) {
        let lower = seen.to_ascii_lowercase();
        assert!(
            lower.starts_with("post /inspect/v1/users?a=1 http/1.1\r\n"),
            "{seen}"
        );
        for expected in [
            "burrow-forwarded-host: api.example.com",
            "burrow-forwarded-scheme: https",
            "burrow-forwarded-port: 443",
            "burrow-forwarded-path: /v1/users?a=1",
            "burrow-forwarded-sandbox: sbx-1",
            "burrow-forwarded-secret: shared-secret",
            "content-type: application/json",
        ] {
            assert!(lower.contains(expected), "missing {expected:?} in {seen}");
        }
        // A guest cannot claim to be another sandbox or to hold the secret.
        assert!(!lower.contains("somebody-else"), "{seen}");
        assert!(!lower.contains("guessed"), "{seen}");
    }

    #[tokio::test]
    async fn an_https_endpoint_is_reached_over_verified_tls_and_told_where_the_request_came_from() {
        let dir = scratch("https-verified");
        let authority = Authority::load_or_create(&dir).unwrap();
        trust(&authority);
        let endpoint = tls_endpoint(&authority).await;

        let forward = rule(&format!("https://127.0.0.1:{}/inspect", endpoint.port));
        let answer = send(
            &forward,
            "POST",
            &guest_headers(),
            Bytes::from_static(b"{}"),
            origin(),
        )
        .await
        .unwrap();
        assert_eq!(answer.status, ::http::StatusCode::OK);
        assert_provenance(&endpoint.seen.await.unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A certificate that does not verify ends the request. There is no
    /// plaintext retry: retrying would put the secret on the wire that the
    /// verification exists to keep it off.
    #[tokio::test]
    async fn an_endpoint_that_does_not_verify_fails_instead_of_falling_back() {
        let dir = scratch("https-untrusted");
        // Generated and never trusted, so its leaf chains to nothing the
        // forward leg accepts.
        let authority = Authority::load_or_create(&dir).unwrap();
        let mut endpoint = tls_endpoint(&authority).await;

        let forward = rule(&format!("https://127.0.0.1:{}/inspect", endpoint.port));
        let Err(err) = send(
            &forward,
            "POST",
            &guest_headers(),
            Bytes::from_static(b"{}"),
            origin(),
        )
        .await
        else {
            panic!("an unverifiable endpoint must not be forwarded to");
        };
        assert!(
            err.contains("tls handshake with the forward endpoint failed"),
            "{err}"
        );
        // Nothing reached the endpoint, in the clear or otherwise.
        assert!(endpoint.seen.try_recv().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node-local endpoint stays a supported deployment.
    #[tokio::test]
    async fn an_http_endpoint_still_receives_the_same_request() {
        let endpoint = plain_endpoint().await;
        let forward = rule(&format!("http://127.0.0.1:{}/inspect", endpoint.port));
        let answer = send(
            &forward,
            "POST",
            &guest_headers(),
            Bytes::from_static(b"{}"),
            origin(),
        )
        .await
        .unwrap();
        assert_eq!(answer.status, ::http::StatusCode::OK);
        assert_provenance(&endpoint.seen.await.unwrap());
    }

    #[test]
    fn the_connections_own_headers_are_not_carried_onto_another_one() {
        for name in [
            "Connection",
            "transfer-encoding",
            "Content-Length",
            "Host",
            "Upgrade",
            "TE",
        ] {
            assert!(is_connection_header(name), "{name} is hop-by-hop");
        }
        assert!(!is_connection_header("Authorization"));
        assert!(!is_connection_header("content-type"));
    }
}
