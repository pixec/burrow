//! Relaying HTTP/2 inside an inspected session, under the same policy.
//!
//! HTTP/2 puts the host in a `:authority` pseudo-header compressed with HPACK,
//! spread over a HEADERS frame and any number of CONTINUATION frames. Refusing
//! to speak it downgrades every client that wanted it; speaking it unchecked
//! would make h2 the way around the allowlist, the fronting check and the
//! credential broker at once. So the same decisions are made here as in
//! [`crate::http`]:
//!
//! - the host named inside the session is checked against the allowlist *and*
//!   against the name the session was opened for, which closes domain fronting;
//! - anything two hops could read differently is refused rather than
//!   interpreted: a `:authority` and a `Host` that disagree, two `Host`
//!   headers, a `Content-Length` that is not digits or that the body does not
//!   match;
//! - brokered credentials replace whatever the client sent under the same name,
//!   so guest code can neither read them back nor forge them.
//!
//! Framing and HPACK are the `h2` crate's, deliberately. CONTINUATION floods,
//! HPACK bombs and unbounded header lists are the failure modes of a
//! hand-rolled decoder, and this is a policy path.
//!
//! Multiplexing is the one structural difference from HTTP/1.1: several
//! requests share a connection, so policy is evaluated per stream, each stream
//! produces its own audit record, and a refused stream is answered `403`
//! without disturbing the others. Only a connection that is itself unusable
//! ends the whole session.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

use crate::inspect;
use crate::policy;

/// Largest decoded header list accepted, in either direction.
///
/// On the *decoded* size, because that is what the policy path holds: HPACK
/// expands, and a few hundred bytes on the wire can name megabytes of headers.
/// Matches the HTTP/1.1 relay's head limit, so neither protocol is the lenient
/// way in.
const MAX_HEADER_LIST: u32 = 16 * 1024;

/// Streams a sandbox may have open at once on one connection.
///
/// Each one is a task holding an upstream stream and its buffers, and a sandbox
/// can open them far faster than it uses them. Multiplexing must not turn one
/// accepted connection into unbounded fan-out.
const MAX_CONCURRENT_STREAMS: u32 = 64;

/// Streams the peer may open and immediately reset before the connection is
/// dropped.
///
/// The rapid-reset pattern (CVE-2023-44487): a reset stream has still cost a
/// policy evaluation and an upstream stream, and cancelling does not refund
/// either. Beyond this the connection is not one worth serving.
const MAX_PENDING_ACCEPT_RESET: usize = 32;

/// Bytes buffered per stream in the direction the proxy writes. Bounded so a
/// peer that stops reading cannot make the proxy hold the difference.
const MAX_SEND_BUFFER: usize = 256 * 1024;

/// How long the streams already in flight are given to finish once the
/// connection has stopped accepting new ones. A stream that neither completes
/// nor fails must not hold the connection's task forever.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What one stream did, for its own audit record.
///
/// Per stream and not per connection: the requests multiplexed onto one
/// connection each name their own host and each get their own decision, so a
/// single record per connection could only report one of them.
pub struct StreamOutcome {
    /// The host the request named, as it named it. Present even on a refusal:
    /// which host was refused is the useful part of the record.
    pub host: Option<String>,
    pub allowed: bool,
    pub reason: String,
    pub sent: u64,
    pub received: u64,
}

/// The per-connection policy every stream on it is judged against.
struct Session {
    /// The name the TLS session was opened for. Every stream must name it.
    opened_for: String,
    allowed: Vec<String>,
    /// The same rules the HTTP/1.1 relay applies, evaluated per stream. h2 must
    /// not be the way around a rule, so nothing here is a weaker check.
    rules: Vec<policy::Rule>,
    sandbox_id: String,
}

/// One stream's request as a matcher sees it.
///
/// Built to the same shape the HTTP/1.1 relay builds, from `:method` and
/// `:path` split at its `?`. A request that matched under one protocol and not
/// the other would be a rule with a hole in it.
fn facts(parts: &::http::request::Parts) -> (String, String, Vec<(String, String)>) {
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or_default().to_string();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|text| (name.as_str().to_string(), text.to_string()))
        })
        .collect();
    (path, query, headers)
}

/// What a request head says, once it has passed every check.
#[derive(Debug, PartialEq, Eq)]
pub struct Checked {
    /// The host the request names, normalised the same way the HTTP/1.1 relay
    /// normalises a `Host` header.
    pub host: String,
    /// The body length the request declared, if it declared one.
    pub content_length: Option<u64>,
}

/// Checks one request's head against policy.
///
/// The HTTP/2 counterpart of the relay's `check_request`: a host is extracted,
/// everything ambiguous about it is refused, and the survivor is matched
/// against the allowlist and the name the session was opened for.
///
/// Not re-checked here because `h2` has already refused it as a stream-level
/// `PROTOCOL_ERROR`: a pseudo-header repeated, appearing after an ordinary
/// header, or outside the six defined ones; a missing `:method`, `:scheme` or
/// `:path`; a `:status` on a request; an uppercase header name; a
/// connection-specific header; and a `TE` naming anything but `trailers`.
pub fn check_request(
    parts: &::http::request::Parts,
    allowed: &[String],
    opened_for: &str,
) -> Result<Checked, String> {
    // CONNECT would turn the stream into a tunnel, and a tunnel is exactly what
    // the policy path cannot see into. Extended CONNECT cannot arrive at all:
    // the server side never enables it, so a `:protocol` pseudo-header is only
    // legal on a CONNECT, which is refused here.
    if parts.method == ::http::Method::CONNECT {
        return Err("CONNECT is not relayed inside an inspected session".into());
    }
    // The session was opened as https and the origin is being spoken to as
    // https. A request naming another scheme is asking the origin to treat it
    // as something none of the outer checks were made against.
    if parts.uri.scheme_str() != Some("https") {
        return Err("request does not name the https scheme".into());
    }

    // `:authority` is the HTTP/2 spelling of the host, and it is authoritative:
    // a server that sees both is required to route on this one.
    let authority = match parts.uri.authority() {
        Some(authority) => match crate::http::parse_host_value(authority.as_str()) {
            Some(host) => Some(host),
            // Userinfo, a non-numeric port, an embedded slash: all names some
            // other parser might resolve differently.
            None => return Err("malformed :authority".into()),
        },
        None => None,
    };

    let mut header_host = None;
    let mut hosts = 0usize;
    for value in parts.headers.get_all(::http::header::HOST) {
        hosts += 1;
        // Two Host headers is a routing disagreement waiting to happen: the
        // allowlist checks one, the server answers the other.
        if hosts > 1 {
            return Err("more than one Host header".into());
        }
        let text = value.to_str().map_err(|_| "malformed Host header")?;
        header_host = Some(crate::http::parse_host_value(text).ok_or("malformed Host header")?);
    }

    let host = match (authority, header_host) {
        // Both present and naming different hosts: one of the two hops routes
        // on each, and which one is not something to guess at.
        (Some(authority), Some(header)) if !authority.eq_ignore_ascii_case(&header) => {
            return Err(":authority and Host name different hosts".into());
        }
        (Some(authority), _) => authority,
        (None, Some(header)) => header,
        // Nothing names a destination, so nothing can be checked against one.
        (None, None) => return Err("request names neither :authority nor Host".into()),
    };

    // Digits only, and one value: a length the origin's own HTTP/1 backend
    // would read differently from the length the frames actually carry is the
    // HTTP/2 spelling of request smuggling.
    let mut content_length: Option<u64> = None;
    for value in parts.headers.get_all(::http::header::CONTENT_LENGTH) {
        let text = value.to_str().map_err(|_| "malformed Content-Length")?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err("malformed Content-Length".into());
        }
        let parsed = text
            .parse::<u64>()
            .map_err(|_| "malformed Content-Length")?;
        if content_length.is_some_and(|existing| existing != parsed) {
            return Err("conflicting Content-Length headers".into());
        }
        content_length = Some(parsed);
    }

    inspect::inner_host_allowed(opened_for, &host, allowed)
        .map_err(|reason| format!("{reason} ({host})"))?;
    Ok(Checked {
        host,
        content_length,
    })
}

/// Sets the credentials the policy brokers for this request's host.
///
/// Every value the client sent under one of those names is removed first, not
/// just the first, so guest code can neither read the credential back out of
/// its own request nor send a value of its own that survives.
pub fn inject_headers(
    headers: &mut ::http::HeaderMap,
    injections: &[(&str, &str)],
) -> Result<(), String> {
    for (name, value) in injections {
        // A name is a token and a value is visible ASCII; `http`'s parsers
        // enforce both. A name beginning with `:` would be a pseudo-header,
        // which this must never be able to forge, and it fails the same check.
        let name = ::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "injected header name is not a token".to_string())?;
        let value = ::http::HeaderValue::from_str(value)
            .map_err(|_| "injected header value is not a header value".to_string())?;
        headers.remove(&name);
        headers.append(name, value);
    }
    Ok(())
}

/// Relays one inspected HTTP/2 connection.
///
/// `client` is the session with the sandbox, `upstream` the one with the
/// origin; both are already TLS and both negotiated `h2`, so there is no
/// protocol translation anywhere here.
///
/// Each accepted stream is audited through `audit` and the returned totals are
/// deliberately zero: the bytes belong to the streams that moved them, and
/// counting them twice would make the log's own arithmetic wrong.
pub(crate) async fn relay<C, U>(
    client: C,
    upstream: U,
    opened_for: &str,
    allowed: &[String],
    rules: &[policy::Rule],
    sandbox_id: &str,
    audit: Arc<dyn Fn(StreamOutcome) + Send + Sync>,
) -> Result<crate::Relayed, String>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let session = Arc::new(Session {
        opened_for: opened_for.to_string(),
        allowed: allowed.to_vec(),
        rules: rules.to_vec(),
        sandbox_id: sandbox_id.to_string(),
    });

    let (sender, connection) = ::h2::client::Builder::new()
        .max_header_list_size(MAX_HEADER_LIST)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_send_buffer_size(MAX_SEND_BUFFER)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESET)
        // Server push would deliver responses to requests no sandbox made, and
        // therefore to requests nothing checked. Never enabled.
        .enable_push(false)
        .handshake::<U, Bytes>(upstream)
        .await
        .map_err(|err| format!("http/2 handshake with the server failed: {err}"))?;
    // The upstream connection has to be driven for any stream on it to make
    // progress. It ends when the last sender is dropped, which is when this
    // function returns.
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut server = ::h2::server::Builder::new()
        .max_header_list_size(MAX_HEADER_LIST)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_send_buffer_size(MAX_SEND_BUFFER)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESET)
        .handshake(client)
        .await
        .map_err(|err| format!("http/2 handshake with the sandbox failed: {err}"))?;

    let streams = Arc::new(AtomicU64::new(0));
    let refused = Arc::new(AtomicU64::new(0));
    let mut running = tokio::task::JoinSet::new();
    let mut failure = None;

    loop {
        // Accepting is also what drives the sandbox's side of every stream
        // already running, so this is polled for as long as any of them live.
        let accepted = match server.accept().await {
            Some(Ok(accepted)) => accepted,
            // A stream-level error never arrives here: `h2` resets that stream
            // and keeps the connection. What does arrive is a connection the
            // proxy can no longer frame, which nothing further can be relayed
            // on.
            Some(Err(err)) => {
                failure = Some(format!("http/2 connection from the sandbox failed: {err}"));
                break;
            }
            None => break,
        };

        let (request, respond) = accepted;
        let session = Arc::clone(&session);
        let sender = sender.clone();
        let audit = Arc::clone(&audit);
        let streams = Arc::clone(&streams);
        let refused = Arc::clone(&refused);
        running.spawn(async move {
            let outcome = serve_stream(request, respond, sender, session).await;
            streams.fetch_add(1, Ordering::Relaxed);
            if !outcome.allowed {
                refused.fetch_add(1, Ordering::Relaxed);
            }
            audit(outcome);
        });
        // Finished streams are reaped as new ones arrive so a long-lived
        // connection does not accumulate their handles.
        while running.try_join_next().is_some() {}
    }

    // The streams still in flight are given a bounded chance to finish, so
    // their audit records are written rather than lost with the task.
    let drain = async { while running.join_next().await.is_some() {} };
    if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_err() {
        running.shutdown().await;
    }
    drop(sender);
    driver.abort();

    let streams = streams.load(Ordering::Relaxed);
    let refused = refused.load(Ordering::Relaxed);
    Ok(crate::Relayed {
        // Zero, because every stream reported its own bytes.
        sent: 0,
        received: 0,
        refusal: failure,
        note: Some(format!(
            "allowed (inspected, http/2: {streams} streams, {refused} refused)"
        )),
    })
}

/// Checks one stream, forwards it if it passes, and answers it either way.
async fn serve_stream(
    request: ::http::Request<::h2::RecvStream>,
    mut respond: ::h2::server::SendResponse<Bytes>,
    sender: ::h2::client::SendRequest<Bytes>,
    session: Arc<Session>,
) -> StreamOutcome {
    let (parts, mut body) = request.into_parts();
    // Recorded as the request named it, so a refusal says which host was asked
    // for rather than only that one was.
    let named = parts
        .uri
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            parts
                .headers
                .get(::http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });

    let checked = match check_request(&parts, &session.allowed, &session.opened_for) {
        Ok(checked) => checked,
        Err(reason) => {
            refuse(&mut respond);
            return StreamOutcome {
                host: named,
                allowed: false,
                reason,
                sent: 0,
                received: 0,
            };
        }
    };

    let (path, query, headers) = facts(&parts);
    let request = policy::Request {
        method: parts.method.as_str(),
        path: &path,
        query: &query,
        headers: &headers,
    };
    // Matching nothing is not a refusal: the stream is forwarded exactly as it
    // was written.
    let action = crate::select_rule(&session.rules, &checked.host, &request).cloned();

    if let Some(policy::Action::Refuse(reason)) = &action {
        refuse(&mut respond);
        return StreamOutcome {
            host: named,
            allowed: false,
            reason: reason.clone(),
            sent: 0,
            received: 0,
        };
    }
    if let Some(policy::Action::Forward(forward)) = &action {
        let target = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| path.clone());
        return forward_stream(
            forward,
            parts.method.as_str(),
            &headers,
            &target,
            &checked.host,
            &session.sandbox_id,
            body,
            respond,
        )
        .await;
    }

    let mut outbound = ::http::Request::from_parts(parts, ());
    if let Some(policy::Action::SetHeaders(headers)) = &action {
        let set: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        if let Err(reason) = inject_headers(outbound.headers_mut(), &set) {
            refuse(&mut respond);
            return StreamOutcome {
                host: named,
                allowed: false,
                reason,
                sent: 0,
                received: 0,
            };
        }
    }

    let end_of_stream = body.is_end_stream();
    let mut sender = match sender.ready().await {
        Ok(sender) => sender,
        Err(err) => {
            refuse(&mut respond);
            return StreamOutcome {
                host: named,
                allowed: false,
                reason: format!("the server would not accept another stream: {err}"),
                sent: 0,
                received: 0,
            };
        }
    };
    let (response, mut request_body) = match sender.send_request(outbound, end_of_stream) {
        Ok(pair) => pair,
        Err(err) => {
            refuse(&mut respond);
            return StreamOutcome {
                host: named,
                allowed: false,
                reason: format!("forwarding a request: {err}"),
                sent: 0,
                received: 0,
            };
        }
    };

    // Both directions run together. Pumping the request to completion first
    // would deadlock against any origin that answers before it has read the
    // whole body, which is most of them for a large upload.
    let forwarding = async {
        if end_of_stream {
            return Ok(0);
        }
        let moved =
            forward_request_body(&mut body, &mut request_body, checked.content_length).await;
        if moved.is_err() {
            // The origin must not be left holding a request the proxy stopped
            // believing in halfway through.
            request_body.send_reset(::h2::Reason::CANCEL);
        }
        moved
    };
    let answering = async {
        let response = response
            .await
            .map_err(|err| format!("the server did not answer: {err}"))?;
        let (parts, mut received) = response.into_parts();
        let end = received.is_end_stream();
        let mut send = respond
            .send_response(::http::Response::from_parts(parts, ()), end)
            .map_err(|err| format!("answering the sandbox: {err}"))?;
        if end {
            return Ok(0);
        }
        forward_response_body(&mut received, &mut send).await
    };
    let (sent, received) = tokio::join!(forwarding, answering);

    let refusal = sent.as_ref().err().or(received.as_ref().err()).cloned();
    StreamOutcome {
        host: Some(checked.host),
        allowed: refusal.is_none(),
        reason: refusal.unwrap_or_else(|| "allowed (inspected)".to_string()),
        sent: sent.unwrap_or(0),
        received: received.unwrap_or(0),
    }
}

/// Sends one stream to the endpoint a rule names and answers it from there.
///
/// The origin the sandbox asked for never sees the request. Its connection is
/// already open, since the protocol had to be negotiated before any stream
/// could be read, but nothing is written on it for this stream.
#[allow(clippy::too_many_arguments)]
async fn forward_stream(
    forward: &policy::Forward,
    method: &str,
    headers: &[(String, String)],
    target: &str,
    host: &str,
    sandbox_id: &str,
    mut body: ::h2::RecvStream,
    mut respond: ::h2::server::SendResponse<Bytes>,
) -> StreamOutcome {
    let refused = |respond: &mut ::h2::server::SendResponse<Bytes>, reason: String, sent: u64| {
        refuse(respond);
        StreamOutcome {
            host: Some(host.to_string()),
            allowed: false,
            reason,
            sent,
            received: 0,
        }
    };

    // A forwarded request changes connections, so its body is held rather than
    // streamed. Bounded for the same reason the HTTP/1.1 path bounds it.
    let mut collected: Vec<u8> = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(err) => {
                return refused(
                    &mut respond,
                    format!("reading a request body: {err}"),
                    collected.len() as u64,
                );
            }
        };
        if collected.len() as u64 + chunk.len() as u64 > crate::forward::MAX_BODY {
            return refused(
                &mut respond,
                format!(
                    "a forwarded request body is at most {} bytes",
                    crate::forward::MAX_BODY
                ),
                collected.len() as u64,
            );
        }
        let len = chunk.len();
        collected.extend_from_slice(&chunk);
        if let Err(err) = body.flow_control().release_capacity(len) {
            return refused(
                &mut respond,
                format!("reading a request body: {err}"),
                collected.len() as u64,
            );
        }
    }
    let sent = collected.len() as u64;

    let answer = crate::forward::send(
        forward,
        method,
        headers,
        Bytes::from(collected),
        crate::forward::Origin {
            host,
            scheme: "https",
            port: 443,
            target,
            sandbox_id,
        },
    )
    .await;
    let mut answer = match answer {
        Ok(answer) => answer,
        Err(reason) => return refused(&mut respond, reason, sent),
    };

    let mut response = ::http::Response::new(());
    *response.status_mut() = answer.status;
    for (name, value) in answer.headers.iter() {
        // Connection-specific fields have no meaning in HTTP/2, and sending one
        // is a protocol error rather than a curiosity.
        if is_connection_specific(name.as_str()) {
            continue;
        }
        response.headers_mut().append(name.clone(), value.clone());
    }
    let mut send = match respond.send_response(response, false) {
        Ok(send) => send,
        Err(err) => {
            return refused(&mut respond, format!("answering the sandbox: {err}"), sent);
        }
    };

    let mut received = 0u64;
    loop {
        match crate::forward::next_chunk(&mut answer.body).await {
            Ok(Some(chunk)) => {
                received += chunk.len() as u64;
                if let Err(reason) = send_data(&mut send, chunk).await {
                    return StreamOutcome {
                        host: Some(host.to_string()),
                        allowed: false,
                        reason,
                        sent,
                        received,
                    };
                }
            }
            Ok(None) => break,
            Err(reason) => {
                send.send_reset(::h2::Reason::INTERNAL_ERROR);
                return StreamOutcome {
                    host: Some(host.to_string()),
                    allowed: false,
                    reason,
                    sent,
                    received,
                };
            }
        }
    }
    let _ = send.send_data(Bytes::new(), true);

    StreamOutcome {
        host: Some(host.to_string()),
        allowed: true,
        reason: format!("forwarded to {}", forward.url),
        sent,
        received,
    }
}

/// Fields that describe a connection rather than a message. HTTP/2 has its own
/// mechanisms for every one of them and forbids them all on the wire.
fn is_connection_specific(name: &str) -> bool {
    const NAMES: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ];
    NAMES.iter().any(|entry| name.eq_ignore_ascii_case(entry))
}

/// Answers one stream with a refusal.
///
/// A refusal is a stream-level event: the other requests multiplexed onto this
/// connection were checked on their own and are none of this one's business.
fn refuse(respond: &mut ::h2::server::SendResponse<Bytes>) {
    let mut response = ::http::Response::new(());
    *response.status_mut() = ::http::StatusCode::FORBIDDEN;
    if respond.send_response(response, true).is_err() {
        respond.send_reset(::h2::Reason::REFUSED_STREAM);
    }
}

/// Forwards a request body, holding it to the length it declared.
async fn forward_request_body(
    from: &mut ::h2::RecvStream,
    to: &mut ::h2::SendStream<Bytes>,
    declared: Option<u64>,
) -> Result<u64, String> {
    let mut moved = 0u64;
    while let Some(chunk) = from.data().await {
        let chunk = chunk.map_err(|err| format!("reading a request body: {err}"))?;
        let len = chunk.len();
        moved += len as u64;
        // A body that outruns its own Content-Length is a desync waiting for
        // whatever HTTP/1 hop sits behind the origin. `h2` checks this too;
        // it is checked here as well because the length is what the origin's
        // own backend will frame on, and that must never depend on a check
        // somebody else owns.
        if declared.is_some_and(|declared| moved > declared) {
            return Err("request body is longer than its Content-Length".into());
        }
        send_data(to, chunk).await?;
        from.flow_control()
            .release_capacity(len)
            .map_err(|err| format!("reading a request body: {err}"))?;
    }
    // Request trailers are not forwarded. Nothing checks them, and a trailer
    // naming a header the broker had just replaced is a way to put the guest's
    // own value back on a request that was already approved.
    if from
        .trailers()
        .await
        .map_err(|err| format!("reading a request body: {err}"))?
        .is_some()
    {
        return Err("request trailers are not relayed".into());
    }
    if declared.is_some_and(|declared| declared != moved) {
        return Err("request body is shorter than its Content-Length".into());
    }
    to.send_data(Bytes::new(), true)
        .map_err(|err| format!("forwarding a request body: {err}"))?;
    Ok(moved)
}

/// Forwards a response body, trailers included.
///
/// Responses are not policed, policy being about where a request goes, so the
/// origin's trailers are passed through as the origin sent them.
async fn forward_response_body(
    from: &mut ::h2::RecvStream,
    to: &mut ::h2::SendStream<Bytes>,
) -> Result<u64, String> {
    let mut moved = 0u64;
    while let Some(chunk) = from.data().await {
        let chunk = chunk.map_err(|err| format!("reading a response: {err}"))?;
        let len = chunk.len();
        moved += len as u64;
        send_data(to, chunk).await?;
        from.flow_control()
            .release_capacity(len)
            .map_err(|err| format!("reading a response: {err}"))?;
    }
    match from
        .trailers()
        .await
        .map_err(|err| format!("reading a response: {err}"))?
    {
        Some(trailers) => to
            .send_trailers(trailers)
            .map_err(|err| format!("answering the sandbox: {err}"))?,
        None => to
            .send_data(Bytes::new(), true)
            .map_err(|err| format!("answering the sandbox: {err}"))?,
    }
    Ok(moved)
}

/// Writes one chunk, waiting for the flow-control capacity to carry it.
///
/// Waiting rather than buffering is what keeps a fast sender from making the
/// proxy hold the difference between the two sides.
async fn send_data(to: &mut ::h2::SendStream<Bytes>, mut data: Bytes) -> Result<(), String> {
    while !data.is_empty() {
        to.reserve_capacity(data.len());
        let available = std::future::poll_fn(|cx| to.poll_capacity(cx))
            .await
            .ok_or_else(|| "the stream closed before its body was forwarded".to_string())?
            .map_err(|err| format!("forwarding a body: {err}"))?;
        let take = available.min(data.len());
        if take == 0 {
            continue;
        }
        let chunk = data.split_to(take);
        to.send_data(chunk, false)
            .map_err(|err| format!("forwarding a body: {err}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec!["api.example.com".to_string(), "other.example".to_string()]
    }

    fn request(uri: &str) -> ::http::request::Builder {
        ::http::Request::builder().uri(uri).method("GET")
    }

    fn parts(builder: ::http::request::Builder) -> ::http::request::Parts {
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn an_allowed_authority_passes() {
        let checked = check_request(
            &parts(request("https://api.example.com/v1")),
            &allowed(),
            "api.example.com",
        )
        .unwrap();
        assert_eq!(checked.host, "api.example.com");
        assert_eq!(checked.content_length, None);
    }

    /// The case the whole feature exists for, in its HTTP/2 spelling: the
    /// session was opened for one allowed name and the stream names another.
    #[test]
    fn an_authority_that_is_not_the_session_name_is_refused() {
        let refusal = check_request(
            &parts(request("https://other.example/v1")),
            &allowed(),
            "api.example.com",
        )
        .unwrap_err();
        assert!(refusal.contains("does not match the name the session was opened for"));

        let refusal = check_request(
            &parts(request("https://evil.example/v1")),
            &allowed(),
            "api.example.com",
        )
        .unwrap_err();
        assert!(refusal.contains("not in the allowlist"));
    }

    #[test]
    fn a_port_and_a_case_difference_do_not_change_the_host() {
        assert_eq!(
            check_request(
                &parts(request("https://API.example.com:8443/v1")),
                &allowed(),
                "api.example.com",
            )
            .unwrap()
            .host,
            "API.example.com"
        );
    }

    /// The HTTP/2 fronting move: an allowlisted `:authority` with the real
    /// destination in a `Host` the origin might route on instead.
    #[test]
    fn an_authority_and_a_host_that_disagree_are_refused() {
        let refusal = check_request(
            &parts(request("https://api.example.com/v1").header("host", "evil.example")),
            &allowed(),
            "api.example.com",
        )
        .unwrap_err();
        assert_eq!(refusal, ":authority and Host name different hosts");

        // Agreeing is fine, port and case included.
        assert!(
            check_request(
                &parts(request("https://api.example.com/v1").header("host", "API.example.com:443")),
                &allowed(),
                "api.example.com",
            )
            .is_ok()
        );
    }

    #[test]
    fn a_host_header_stands_in_for_a_missing_authority() {
        let mut request = ::http::Request::new(());
        *request.method_mut() = ::http::Method::GET;
        *request.uri_mut() = "/v1".parse().unwrap();
        request
            .headers_mut()
            .insert("host", "api.example.com".parse().unwrap());
        // Without an authority there is no scheme either, which is refused on
        // its own: a stream that names neither is not one to route.
        let refusal =
            check_request(&request.into_parts().0, &allowed(), "api.example.com").unwrap_err();
        assert_eq!(refusal, "request does not name the https scheme");
    }

    #[test]
    fn two_host_headers_are_refused() {
        let mut builder = request("https://api.example.com/v1");
        builder = builder.header("host", "api.example.com");
        builder = builder.header("host", "evil.example");
        let refusal = check_request(&parts(builder), &allowed(), "api.example.com").unwrap_err();
        assert_eq!(refusal, "more than one Host header");
    }

    #[test]
    fn a_request_naming_no_host_at_all_is_refused() {
        let mut request = ::http::Request::new(());
        *request.method_mut() = ::http::Method::GET;
        *request.uri_mut() = "/v1".parse().unwrap();
        assert!(check_request(&request.into_parts().0, &allowed(), "api.example.com").is_err());
    }

    #[test]
    fn connect_and_other_schemes_are_refused() {
        let connect = ::http::Request::builder()
            .method("CONNECT")
            .uri("https://api.example.com/")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(
            check_request(&connect, &allowed(), "api.example.com").unwrap_err(),
            "CONNECT is not relayed inside an inspected session"
        );

        let plaintext = parts(request("http://api.example.com/v1"));
        assert_eq!(
            check_request(&plaintext, &allowed(), "api.example.com").unwrap_err(),
            "request does not name the https scheme"
        );
    }

    /// The same strictness the HTTP/1.1 relay applies: a length only one of the
    /// two hops will accept is a desync.
    #[test]
    fn a_malformed_or_conflicting_content_length_is_refused() {
        let refused = |value: &str| {
            check_request(
                &parts(request("https://api.example.com/v1").header("content-length", value)),
                &allowed(),
                "api.example.com",
            )
            .is_err()
        };
        assert!(refused("+41"));
        assert!(refused("0x29"));
        assert!(refused("41, 41"));
        assert!(refused(""));

        let mut builder = request("https://api.example.com/v1");
        builder = builder.header("content-length", "5");
        builder = builder.header("content-length", "9");
        assert_eq!(
            check_request(&parts(builder), &allowed(), "api.example.com").unwrap_err(),
            "conflicting Content-Length headers"
        );

        assert_eq!(
            check_request(
                &parts(request("https://api.example.com/v1").header("content-length", "41")),
                &allowed(),
                "api.example.com",
            )
            .unwrap()
            .content_length,
            Some(41)
        );
    }

    /// The point of brokering: the guest's own value never reaches the server.
    #[test]
    fn an_injected_header_replaces_every_value_the_client_sent() {
        let mut headers = ::http::HeaderMap::new();
        headers.append("authorization", "Bearer forged".parse().unwrap());
        headers.append("authorization", "Bearer also-forged".parse().unwrap());
        headers.append("accept", "*/*".parse().unwrap());

        inject_headers(&mut headers, &[("Authorization", "Bearer real")]).unwrap();

        let values: Vec<_> = headers.get_all("authorization").iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "Bearer real");
        assert_eq!(headers.get("accept").unwrap(), "*/*");
    }

    /// A pseudo-header must never be forgeable through an injection rule, and
    /// neither must a value carrying a line break.
    #[test]
    fn an_injection_that_could_forge_a_field_is_refused() {
        let mut headers = ::http::HeaderMap::new();
        assert!(inject_headers(&mut headers, &[(":authority", "evil.example")]).is_err());
        assert!(inject_headers(&mut headers, &[("X-K", "v\r\nX-Evil: 1")]).is_err());
        assert!(inject_headers(&mut headers, &[("X K", "v")]).is_err());
        assert!(inject_headers(&mut headers, &[("", "v")]).is_err());
        assert!(headers.is_empty());
    }
    //
    // A real HTTP/2 client on one side and a real HTTP/2 origin on the other,
    // with the relay between them: the checks above are only worth what the
    // wiring around them enforces.

    use tokio::io::DuplexStream;
    use tokio::sync::mpsc;

    const PIPE: usize = 64 * 1024;

    fn rule(domain: &str, name: &str, value: &str) -> policy::Rule {
        policy::Rule {
            domain: domain.into(),
            matcher: None,
            action: policy::Action::SetHeaders(vec![(name.to_string(), value.to_string())]),
        }
    }

    /// The same rule, narrowed to the requests a matcher selects.
    fn matched(
        domain: &str,
        name: &str,
        value: &str,
        matcher: policy::RequestMatch,
    ) -> policy::Rule {
        policy::Rule {
            domain: domain.into(),
            matcher: Some(matcher),
            action: policy::Action::SetHeaders(vec![(name.to_string(), value.to_string())]),
        }
    }

    /// A minimal origin: records the head of everything it is asked for, drains
    /// the body, and answers `200` with two bytes.
    async fn origin(io: DuplexStream, seen: mpsc::UnboundedSender<::http::request::Parts>) {
        let Ok(mut server) = ::h2::server::handshake(io).await else {
            return;
        };
        while let Some(Ok((request, mut respond))) = server.accept().await {
            let seen = seen.clone();
            // Each stream is served in its own task, because `accept` is also
            // what drives the connection: draining a body inline would stop the
            // frames that body arrives in from ever being read.
            tokio::spawn(async move {
                let (parts, mut body) = request.into_parts();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                let _ = seen.send(parts);
                let Ok(mut send) = respond.send_response(::http::Response::new(()), false) else {
                    return;
                };
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
            });
        }
    }

    /// Wires a client duplex and an origin duplex to a relay pinned to
    /// `api.example.com`, and returns the halves the test drives.
    fn harness(
        rules: Vec<policy::Rule>,
    ) -> (
        DuplexStream,
        mpsc::UnboundedReceiver<::http::request::Parts>,
        mpsc::UnboundedReceiver<StreamOutcome>,
    ) {
        let (client, relay_client) = tokio::io::duplex(PIPE);
        let (relay_upstream, server) = tokio::io::duplex(PIPE);
        let (seen_tx, seen_rx) = mpsc::unbounded_channel();
        let (audit_tx, audit_rx) = mpsc::unbounded_channel();

        tokio::spawn(origin(server, seen_tx));
        tokio::spawn(async move {
            let audit = Arc::new(move |outcome: StreamOutcome| {
                let _ = audit_tx.send(outcome);
            }) as Arc<dyn Fn(StreamOutcome) + Send + Sync>;
            relay(
                relay_client,
                relay_upstream,
                "api.example.com",
                &allowed(),
                &rules,
                "sbx",
                audit,
            )
            .await
        });
        (client, seen_rx, audit_rx)
    }

    /// Starts an HTTP/2 client on `io` and drives its connection.
    async fn connect(io: DuplexStream) -> ::h2::client::SendRequest<Bytes> {
        let (sender, connection) = ::h2::client::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender.ready().await.unwrap()
    }

    #[tokio::test]
    async fn a_stream_to_the_session_host_is_forwarded_and_carries_the_credential() {
        let (client, mut seen, mut audited) = harness(vec![rule(
            "api.example.com",
            "Authorization",
            "Bearer real",
        )]);
        let mut sender = connect(client).await;

        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/v1")
            .header("authorization", "Bearer forged")
            .header("accept", "*/*")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);

        let forwarded = seen
            .recv()
            .await
            .expect("the origin should see the request");
        assert_eq!(
            forwarded.uri.authority().map(|a| a.as_str()),
            Some("api.example.com")
        );
        // The guest's own value never reaches the server, and only one survives.
        let credentials: Vec<_> = forwarded.headers.get_all("authorization").iter().collect();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0], "Bearer real");
        assert_eq!(forwarded.headers.get("accept").unwrap(), "*/*");

        let outcome = audited.recv().await.unwrap();
        assert!(outcome.allowed, "{}", outcome.reason);
        assert_eq!(outcome.host.as_deref(), Some("api.example.com"));
    }

    /// h2 must not be the way around a matcher: the same rule selects the same
    /// requests it would have on the HTTP/1.1 path.
    #[tokio::test]
    async fn a_matcher_narrows_which_streams_carry_the_credential() {
        let matcher = policy::RequestMatch {
            path: Some(policy::Match::compile(policy::MatchOp::StartsWith, "/v1/").unwrap()),
            methods: vec!["GET".into()],
            query: vec![(
                "tenant".into(),
                policy::Match::compile(policy::MatchOp::Exact, "acme").unwrap(),
            )],
            ..Default::default()
        };
        let (client, mut seen, _audited) = harness(vec![matched(
            "api.example.com",
            "Authorization",
            "Bearer real",
            matcher,
        )]);
        let mut sender = connect(client).await;

        let get = |uri: &str| {
            ::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(())
                .unwrap()
        };
        let (selected, _) = sender
            .send_request(get("https://api.example.com/v1/users?tenant=acme"), true)
            .unwrap();
        assert_eq!(selected.await.unwrap().status(), 200);
        let mut sender = sender.ready().await.unwrap();
        // Same path, wrong query: selected by nothing, and still allowed.
        let (other, _) = sender
            .send_request(get("https://api.example.com/v1/users?tenant=other"), true)
            .unwrap();
        assert_eq!(other.await.unwrap().status(), 200);

        let first = seen.recv().await.unwrap();
        assert_eq!(first.headers.get("authorization").unwrap(), "Bearer real");
        let second = seen.recv().await.unwrap();
        assert!(second.headers.get("authorization").is_none());
    }

    /// The forwarding case in its HTTP/2 spelling: the stream reaches the
    /// operator's endpoint stamped with where it came from, and the origin
    /// never sees it.
    #[tokio::test]
    async fn a_forwarded_stream_reaches_the_endpoint_and_not_the_origin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = socket.read(&mut buf).await.unwrap();
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            socket
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nX-Gate: yes\r\n\r\nok")
                .await
                .unwrap();
            String::from_utf8_lossy(&head).into_owned()
        });

        let url = format!("http://127.0.0.1:{port}/gate");
        let (client, mut seen, mut audited) = harness(vec![policy::Rule {
            domain: "api.example.com".into(),
            matcher: None,
            action: policy::Action::Forward(policy::Forward {
                target: policy::ForwardTarget::parse(&url).unwrap(),
                url: url.clone(),
                secret: "shared".into(),
            }),
        }]);
        let mut sender = connect(client).await;

        let request = ::http::Request::builder()
            .method("POST")
            .uri("https://api.example.com/v1/users?a=1")
            .body(())
            .unwrap();
        let (response, mut body) = sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"hello"), true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers().get("x-gate").unwrap(), "yes");

        let head = endpoint.await.unwrap();
        assert!(
            head.starts_with("POST /gate/v1/users?a=1 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.contains("burrow-forwarded-host: api.example.com\r\n"),
            "{head}"
        );
        assert!(head.contains("burrow-forwarded-sandbox: sbx\r\n"));
        assert!(head.contains("burrow-forwarded-secret: shared\r\n"));

        assert!(seen.try_recv().is_err(), "nothing may reach the origin");
        let outcome = audited.recv().await.unwrap();
        assert!(outcome.allowed, "{}", outcome.reason);
        assert_eq!(outcome.reason, format!("forwarded to {url}"));
        assert_eq!(outcome.sent, 5);
        assert_eq!(outcome.received, 2);
    }

    /// Fronting in its HTTP/2 spelling, plus the multiplexing property that
    /// goes with it: refusing one stream must not disturb the others.
    #[tokio::test]
    async fn a_stream_naming_another_host_is_refused_without_ending_the_connection() {
        let (client, mut seen, mut audited) = harness(Vec::new());
        let mut sender = connect(client).await;

        // `other.example` is allowlisted, but this session was opened for
        // `api.example.com`.
        let fronting = ::http::Request::builder()
            .method("GET")
            .uri("https://other.example/v1")
            .body(())
            .unwrap();
        let (fronted, _) = sender.send_request(fronting, true).unwrap();
        assert_eq!(fronted.await.unwrap().status(), 403);

        let refusal = audited.recv().await.unwrap();
        assert!(!refusal.allowed);
        assert!(
            refusal
                .reason
                .contains("does not match the name the session was opened for"),
            "{}",
            refusal.reason
        );
        assert_eq!(refusal.host.as_deref(), Some("other.example"));

        // The connection is still usable, and the refused stream never reached
        // the origin.
        let mut sender = sender.ready().await.unwrap();
        let allowed = ::http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/v1")
            .body(())
            .unwrap();
        let (answer, _) = sender.send_request(allowed, true).unwrap();
        assert_eq!(answer.await.unwrap().status(), 200);

        let forwarded = seen.recv().await.unwrap();
        assert_eq!(
            forwarded.uri.authority().map(|a| a.as_str()),
            Some("api.example.com")
        );
        assert!(seen.try_recv().is_err(), "only one stream may be forwarded");
        assert!(audited.recv().await.unwrap().allowed);
    }

    #[tokio::test]
    async fn a_host_header_disagreeing_with_the_authority_is_refused() {
        let (client, mut seen, mut audited) = harness(Vec::new());
        let mut sender = connect(client).await;

        let request = ::http::Request::builder()
            .method("GET")
            .uri("https://api.example.com/v1")
            .header("host", "evil.example")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        assert_eq!(response.await.unwrap().status(), 403);

        let refusal = audited.recv().await.unwrap();
        assert!(!refusal.allowed);
        assert_eq!(refusal.reason, ":authority and Host name different hosts");
        assert!(seen.try_recv().is_err(), "nothing may reach the origin");
    }

    /// A body that does not match the length it declared is what an HTTP/1 hop
    /// behind the origin would read as the start of a second request.
    #[tokio::test]
    async fn a_body_shorter_than_its_content_length_is_refused() {
        let (client, _seen, mut audited) = harness(Vec::new());
        let mut sender = connect(client).await;

        let request = ::http::Request::builder()
            .method("POST")
            .uri("https://api.example.com/v1")
            .header("content-length", "5")
            .body(())
            .unwrap();
        let (_response, mut body) = sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"hi"), true).unwrap();

        let outcome = audited.recv().await.unwrap();
        // `h2` rejects the mismatch as it reads the body, and the check in
        // `forward_request_body` is the backstop for the same disagreement
        // arriving some other way. Either way the stream is refused and
        // recorded, which is the property that matters.
        assert!(!outcome.allowed, "{}", outcome.reason);
    }

    #[tokio::test]
    async fn a_body_matching_its_content_length_is_forwarded() {
        let (client, mut seen, mut audited) = harness(Vec::new());
        let mut sender = connect(client).await;

        let request = ::http::Request::builder()
            .method("POST")
            .uri("https://api.example.com/v1")
            .header("content-length", "5")
            .body(())
            .unwrap();
        let (response, mut body) = sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"hello"), true).unwrap();
        assert_eq!(response.await.unwrap().status(), 200);

        assert!(seen.recv().await.is_some());
        let outcome = audited.recv().await.unwrap();
        assert!(outcome.allowed, "{}", outcome.reason);
        assert_eq!(outcome.sent, 5);
        assert_eq!(outcome.received, 2);
    }

    // A HEADERS frame is assembled by hand below because no client library will
    // produce the malformed ones: a duplicated pseudo-header and a pseudo-header
    // after an ordinary one are exactly what a client is written not to send.

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    /// One HPACK literal field, never indexed, with both name and value as
    /// plain text.
    fn literal(name: &str, value: &str) -> Vec<u8> {
        let mut out = vec![0x00];
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        out.push(value.len() as u8);
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut out = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Sends `fields` as a HEADERS frame on stream 1 and reports whether the
    /// relay reset the stream or tore the connection down.
    async fn raw_stream(fields: Vec<u8>) -> (bool, bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut client, mut seen, _audited) = harness(Vec::new());
        let mut opening = PREFACE.to_vec();
        opening.extend_from_slice(&frame(0x4, 0, 0, &[])); // SETTINGS
        // HEADERS, END_STREAM | END_HEADERS.
        opening.extend_from_slice(&frame(0x1, 0x5, 1, &fields));
        client.write_all(&opening).await.unwrap();

        let mut reset = false;
        let mut buf = [0u8; 4096];
        let mut pending = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !reset && tokio::time::Instant::now() < deadline {
            let Ok(Ok(read)) = tokio::time::timeout_at(deadline, client.read(&mut buf)).await
            else {
                break;
            };
            if read == 0 {
                break;
            }
            pending.extend_from_slice(&buf[..read]);
            let mut at = 0;
            while pending.len() >= at + 9 {
                let len =
                    u32::from_be_bytes([0, pending[at], pending[at + 1], pending[at + 2]]) as usize;
                let kind = pending[at + 3];
                if pending.len() < at + 9 + len {
                    break;
                }
                // RST_STREAM, or a GOAWAY that ends everything.
                if kind == 0x3 || kind == 0x7 {
                    reset = true;
                }
                at += 9 + len;
            }
            pending.drain(..at);
        }
        (reset, seen.try_recv().is_ok())
    }

    /// The control for the three below: the same hand-built frame, well formed,
    /// is relayed and not reset, so a reset in those means the malformation was
    /// caught rather than the harness rejecting everything.
    #[tokio::test]
    async fn a_well_formed_raw_stream_is_relayed() {
        let mut fields = literal(":method", "GET");
        fields.extend(literal(":scheme", "https"));
        fields.extend(literal(":path", "/v1"));
        fields.extend(literal(":authority", "api.example.com"));

        let (reset, forwarded) = raw_stream(fields).await;
        assert!(!reset, "a well-formed stream must not be reset");
        assert!(forwarded, "it must reach the origin");
    }

    /// A repeated pseudo-header is two answers to "where is this going", and
    /// which one a server picks is not something to guess at.
    #[tokio::test]
    async fn a_duplicated_pseudo_header_is_refused() {
        let mut fields = literal(":method", "GET");
        fields.extend(literal(":scheme", "https"));
        fields.extend(literal(":path", "/v1"));
        fields.extend(literal(":authority", "api.example.com"));
        fields.extend(literal(":authority", "evil.example"));

        let (reset, forwarded) = raw_stream(fields).await;
        assert!(reset, "a duplicated pseudo-header must not be relayed");
        assert!(!forwarded, "nothing may reach the origin");
    }

    /// A pseudo-header after an ordinary one is the same disagreement, spelled
    /// as an ordering trick.
    #[tokio::test]
    async fn a_pseudo_header_after_a_regular_header_is_refused() {
        let mut fields = literal(":method", "GET");
        fields.extend(literal(":scheme", "https"));
        fields.extend(literal(":path", "/v1"));
        fields.extend(literal("accept", "*/*"));
        fields.extend(literal(":authority", "api.example.com"));

        let (reset, forwarded) = raw_stream(fields).await;
        assert!(reset, "a trailing pseudo-header must not be relayed");
        assert!(!forwarded, "nothing may reach the origin");
    }

    /// A connection-specific header has no meaning in HTTP/2 and is how an
    /// HTTP/1 hop behind the origin gets a second, unchecked request.
    #[tokio::test]
    async fn a_connection_specific_header_is_refused() {
        let mut fields = literal(":method", "GET");
        fields.extend(literal(":scheme", "https"));
        fields.extend(literal(":path", "/v1"));
        fields.extend(literal(":authority", "api.example.com"));
        fields.extend(literal("transfer-encoding", "chunked"));

        let (reset, forwarded) = raw_stream(fields).await;
        assert!(reset, "a connection-specific header must not be relayed");
        assert!(!forwarded, "nothing may reach the origin");
    }
}
