//! What an edge router agrees on with the rest of the fleet: the hostname, the
//! head, and the wire format of a forwarded connection.
//!
//! A node's edge serves `<port>-<sandbox-id>.<domain>` for the sandboxes it
//! holds. Hostname parsing, the request-head rewrite, trusted proxies and the
//! bounds live here rather than in the daemon because the rewrite is what keeps
//! a guest's idea of its caller honest, and because the hostname a caller is
//! handed and the hostname a router parses must not be able to disagree.
//!
//! A forwarded connection has a wire format of its own. Its sender has to say
//! which sandbox and which port, and prove it is allowed to ask, so it opens
//! with one line before any of the client's own bytes:
//!
//! ```text
//! BURROW/1 <token> <sandbox-id> <port>\n
//! ```
//!
//! It lives here rather than in either daemon because both ends must agree on
//! it exactly, and a format defined twice is a format that drifts.

use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct Prelude<'a> {
    pub token: &'a str,
    pub sandbox_id: &'a str,
    pub port: u16,
}

impl<'a> Prelude<'a> {
    pub fn parse(line: &'a str) -> Option<Self> {
        let mut parts = line.trim_end_matches(['\r', '\n']).split(' ');
        if parts.next()? != "BURROW/1" {
            return None;
        }
        let token = parts.next()?;
        let sandbox_id = parts.next()?;
        let port: u16 = parts.next()?.parse().ok()?;
        // Extra fields mean a version mismatch, not something to guess at.
        if parts.next().is_some() || sandbox_id.is_empty() || port == 0 {
            return None;
        }
        Some(Self {
            // "-" stands in for no token, because the prelude is
            // space-separated and an empty field would be invisible.
            token: if token == "-" { "" } else { token },
            sandbox_id,
            port,
        })
    }
}

/// Writes the prelude a forwarder sends. Kept here so both ends share one
/// definition of the format.
pub fn prelude_line(token: Option<&str>, sandbox_id: &str, port: u16) -> String {
    let token = match token {
        Some(token) if !token.is_empty() => token,
        _ => "-",
    };
    format!("BURROW/1 {token} {sandbox_id} {port}\n")
}

/// The URL a published guest port answers on through the edge.
///
/// The mirror of the hostname the router parses, here so the two cannot
/// disagree about the shape. The port leads because a sandbox id may contain
/// dashes.
///
/// `None` without a domain, which is also the answer for a node running no
/// edge: there is no name to hand a caller, and guessing one would send them
/// somewhere that does not resolve. The listen port is carried because an edge
/// is not always on 80.
pub fn sandbox_url(
    domain: &str,
    listen_port: u16,
    sandbox_id: &str,
    guest_port: u32,
) -> Option<String> {
    let domain = domain.trim_matches('.');
    if domain.is_empty() || sandbox_id.is_empty() || guest_port == 0 {
        return None;
    }
    let host = format!("{guest_port}-{sandbox_id}.{domain}").to_ascii_lowercase();
    Some(match listen_port {
        80 => format!("http://{host}/"),
        port => format!("http://{host}:{port}/"),
    })
}

/// Cap on the request head read while looking for `Host`.
///
/// Real request heads are well under this. A client that sends a megabyte of
/// headers without ending them is not one to keep buffering for.
pub const MAX_HEAD: usize = 16 * 1024;

/// A client that connects and sends nothing holds a socket for nothing.
pub const HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long a guest has to say whether it accepts an upgrade.
///
/// Longer than [`HEAD_TIMEOUT`], because this one waits on an application
/// rather than on a client that has already connected. Nothing else on the
/// forwarded path waits for a response at all.
pub const UPGRADE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Longest chain honoured from a trusted proxy, before the edge's own peer is
/// appended. A chain is caller-supplied even when the caller is trusted, so it
/// is bounded rather than believed to be short.
const MAX_FORWARDED_HOPS: usize = 16;

/// Headers an edge is authoritative for.
///
/// Whatever a client sent under these names is removed before the edge sets its
/// own. Removing *every* occurrence matters: header names may repeat, and one
/// left behind is a forged address a guest cannot tell from a real one.
const FORWARDING_HEADERS: [&str; 5] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
];

/// Headers that describe the hop rather than the request.
///
/// Dropped and replaced by the edge's own `Connection`. A connection is routed
/// to a sandbox by the first request on it, so how long it lives is the edge's
/// decision and not the client's.
const HOP_HEADERS: [&str; 3] = ["connection", "keep-alive", "proxy-connection"];

/// What a hostname names.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub sandbox_id: String,
    pub port: u16,
}

impl Target {
    /// Parses `<port>-<sandbox-id>` out of a Host header.
    ///
    /// The port comes first because a sandbox id may itself contain dashes, so
    /// it has to be whatever remains.
    pub fn parse(host: &str, domain: &str) -> Option<Self> {
        // Strip the port the client connected on; it is not the guest's.
        let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
        let host = host.trim_end_matches('.').to_ascii_lowercase();

        let domain = domain.trim_start_matches('.').trim_end_matches('.');
        let label = if domain.is_empty() {
            host.as_str()
        } else {
            host.strip_suffix(domain)?.strip_suffix('.')?
        };

        let (port, sandbox_id) = label.split_once('-')?;
        let port: u16 = port.parse().ok()?;
        if port == 0 || sandbox_id.is_empty() {
            return None;
        }
        Some(Self {
            sandbox_id: sandbox_id.to_string(),
            port,
        })
    }
}

/// A connection an edge may forward: where it goes, and the head to replay.
pub struct Forward {
    pub target: Target,
    /// The client's own bytes, with the edge's forwarding headers in place of
    /// anything the client claimed about itself.
    pub head: Vec<u8>,
    pub exchange: Exchange,
}

/// What a forwarded connection may still carry after its head.
///
/// A connection is routed by its first request, so it carries that one request
/// and nothing else: a second request on it would be delivered to the sandbox
/// the first one named, whatever hostname it carried.
#[derive(Debug, PartialEq, Eq)]
pub struct Exchange {
    /// Bytes of request body the client may still send. `0` for a request with
    /// no body, the `Content-Length` where there is one, and [`u64::MAX`] where
    /// the framing does not give a number. Anything past a body is a second
    /// request and is not the guest's to see.
    pub body: u64,
    /// The client asked to leave HTTP behind, and the head forwarded says so.
    /// A `101` is then one request that never ends, rather than a second one,
    /// which is the only case where this connection outlives a response.
    pub upgrade: bool,
}

/// What [`route`] made of a connection.
pub enum Routed {
    Forward(Forward),
    /// Answered by the edge itself, never by a guest.
    Refused {
        status: u16,
        message: &'static str,
    },
}

/// Reads a request head and decides where it goes, without touching a sandbox.
///
/// Everything both routers do before they differ: the head is read under a
/// bound and a timeout, the `Host` is validated as a hostname rather than
/// trusted to be one, the target is parsed out of it, and the head is rewritten
/// to carry the edge's own account of the client.
///
/// The rewrite happens before either caller resolves anything, so a head that
/// cannot be forwarded does not first wake a suspended sandbox.
pub async fn route<S: AsyncRead + Unpin>(
    stream: &mut S,
    peer: IpAddr,
    domain: &str,
    trusted_proxies: &[Cidr],
) -> std::io::Result<Routed> {
    let head = tokio::time::timeout(HEAD_TIMEOUT, read_head(stream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no request head"))??;

    let Some(host) = host_header(&head) else {
        return Ok(refused(400, "no Host header"));
    };
    // The host is echoed back out in a header of the edge's own, so it is held
    // to a hostname's characters rather than trusted to be one. A bare CR
    // inside it would otherwise be a header the client got to write.
    let Some(host) = clean_host(&host) else {
        return Ok(refused(400, "malformed Host header"));
    };
    let Some(target) = Target::parse(&host, domain) else {
        return Ok(refused(404, "hostname does not name a sandbox"));
    };
    let peer = peer.to_canonical();
    let trusted = trusted_proxies.iter().any(|cidr| cidr.contains(peer));
    let (head, exchange) = match rewrite_head(&head, peer, &host, trusted) {
        Ok(rewritten) => rewritten,
        Err(message) => return Ok(refused(400, message)),
    };
    Ok(Routed::Forward(Forward {
        target,
        head,
        exchange,
    }))
}

fn refused(status: u16, message: &'static str) -> Routed {
    Routed::Refused { status, message }
}

/// A trusted upstream, as a single address or a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn contains(&self, addr: IpAddr) -> bool {
        // Canonical on both sides, so a v4 client arriving on a dual-stack
        // listener as `::ffff:10.0.0.1` matches a `10.0.0.0/8` proxy.
        let (network, addr) = (self.addr, addr.to_canonical());
        match (network, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                masked_eq(&network.octets(), &addr.octets(), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                masked_eq(&network.octets(), &addr.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Whether two addresses agree on their first `prefix` bits.
fn masked_eq(network: &[u8], addr: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    if network[..whole] != addr[..whole] {
        return false;
    }
    match prefix % 8 {
        0 => true,
        bits => {
            let mask = 0xffu8 << (8 - bits);
            network[whole] & mask == addr[whole] & mask
        }
    }
}

/// Parses `--edge-trusted-proxy`: an address, or an address and a prefix.
///
/// A bare address is a host route. Anything else (whitespace, `+24`, a prefix
/// wider than the family) is refused rather than interpreted: the value decides
/// whose claim about a client address is believed.
pub fn parse_trusted_proxy(value: &str) -> Option<Cidr> {
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, len)) => {
            // `str::parse` accepts a leading `+`; a prefix length is digits.
            if len.is_empty() || !len.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            (addr, Some(len.parse::<u8>().ok()?))
        }
        None => (value, None),
    };
    let addr = addr.parse::<IpAddr>().ok()?.to_canonical();
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(bits);
    if prefix > bits {
        return None;
    }
    Some(Cidr { addr, prefix })
}

/// Rewrites the head so it carries the edge's account of the client, and only
/// the edge's, and so the exchange it opens is a single request.
///
/// Returns the reason instead when the head cannot be forwarded: a result that
/// would not fit in `MAX_HEAD`, since a truncated head is a request the guest
/// would answer wrongly, and framing two hops could read differently, since
/// that is how a second request hides inside a first one's body.
///
/// `host` must already be validated; it is written back out as a header value.
fn rewrite_head(
    head: &[u8],
    peer: IpAddr,
    host: &str,
    trusted: bool,
) -> Result<(Vec<u8>, Exchange), &'static str> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let request_line = trim_cr(lines.next().ok_or("empty request head")?);

    let mut kept: Vec<&[u8]> = Vec::new();
    let mut chain: Vec<IpAddr> = Vec::new();
    let mut proto: Option<String> = None;
    let mut forwarded_host: Option<String> = None;
    let mut lengths: Vec<String> = Vec::new();
    let mut encoded = false;
    let mut asked_upgrade = false;
    let mut names_protocol = false;
    // A continuation line belongs to the header above it, so a dropped header
    // takes its obs-fold with it rather than leaving the value behind.
    let mut dropping = false;

    for line in lines {
        let line = trim_cr(line);
        // The blank line ends the head; nothing after it was ever the edge's.
        if line.is_empty() {
            break;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if !dropping {
                kept.push(line);
            }
            continue;
        }
        let Some((name, value)) = split_header(line) else {
            // Not a header at all. It is the guest's problem, not the edge's.
            dropping = false;
            kept.push(line);
            continue;
        };
        match name.as_str() {
            "content-length" => lengths.push(value.clone()),
            "transfer-encoding" => encoded = true,
            "upgrade" => names_protocol = true,
            "connection" => asked_upgrade |= has_token(&value, "upgrade"),
            _ => {}
        }
        dropping =
            FORWARDING_HEADERS.contains(&name.as_str()) || HOP_HEADERS.contains(&name.as_str());
        if !dropping {
            kept.push(line);
            continue;
        }
        if !trusted || HOP_HEADERS.contains(&name.as_str()) {
            continue;
        }
        // The peer is an operator's proxy, so what it says about the client is
        // the only account of the client there is. Still parsed rather than
        // copied: the proxy's own upstream is not trusted.
        match name.as_str() {
            "x-forwarded-for" => chain.extend(parse_chain(&value)),
            "x-forwarded-proto" => proto = proto.or_else(|| clean_proto(&value)),
            "x-forwarded-host" => forwarded_host = forwarded_host.or_else(|| clean_host(&value)),
            _ => {}
        }
    }

    chain.truncate(MAX_FORWARDED_HOPS);
    chain.push(peer);
    // An edge only ever speaks plaintext, so anything else is what a trusted
    // proxy terminated on the client's behalf.
    let proto = proto.as_deref().unwrap_or("http");
    let host = forwarded_host.as_deref().unwrap_or(host);

    let mut elements: Vec<String> = chain
        .iter()
        .map(|addr| format!("for={}", forwarded_node(*addr)))
        .collect();
    // The parameters describe the hop the edge itself accepted, so they belong
    // on its element, which is the last one.
    if let Some(last) = elements.last_mut() {
        last.push_str(&format!(";proto={proto};host=\"{host}\""));
    }
    let addresses: Vec<String> = chain.iter().map(IpAddr::to_string).collect();

    let mut out = Vec::with_capacity(head.len() + 256);
    let mut push = |line: &[u8]| {
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    };
    push(request_line);
    for line in kept {
        push(line);
    }
    push(format!("Forwarded: {}", elements.join(", ")).as_bytes());
    push(format!("X-Forwarded-For: {}", addresses.join(", ")).as_bytes());
    push(format!("X-Forwarded-Proto: {proto}").as_bytes());
    push(format!("X-Forwarded-Host: {host}").as_bytes());
    // One request per connection. The connection was routed by this request's
    // hostname, so a guest that answered and kept it open would be handed
    // whatever came next, which may be another tenant's request. `close` is
    // what makes the guest end it, and the guest ending it is what ends the
    // splice.
    //
    // An upgrade is the exception, and is the client's own ask rather than
    // anything the edge adds: a `101` is one request that never ends.
    let upgrade = asked_upgrade && names_protocol;
    push(if upgrade {
        b"Connection: upgrade"
    } else {
        b"Connection: close"
    });
    push(b"");

    if out.len() > MAX_HEAD {
        return Err("request head too large");
    }
    let body = body_length(&lengths, encoded).ok_or("ambiguous request framing")?;
    Ok((out, Exchange { body, upgrade }))
}

/// How many bytes of body the head says follow it.
///
/// `None` where two hops could read the framing differently, which is refused
/// rather than guessed at: the guess decides where this request ends and where
/// a second one, meant for another sandbox, would begin.
fn body_length(lengths: &[String], encoded: bool) -> Option<u64> {
    if encoded {
        // The length is in the body the edge does not read. Both framings at
        // once is the classic desync and is not forwarded.
        return lengths.is_empty().then_some(u64::MAX);
    }
    match lengths {
        [] => Some(0),
        // Digits only: `+1` and `0x10` are lengths one hop would take and the
        // other would refuse.
        [only] => only
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| only.parse().ok())
            .flatten(),
        _ => None,
    }
}

/// Whether a comma-separated header value lists `token`.
fn has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|entry| entry.trim().eq_ignore_ascii_case(token))
}

/// An RFC 7239 node identifier. IPv6 has to be bracketed, and brackets have to
/// be quoted.
fn forwarded_node(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) => format!("\"[{addr}]\""),
    }
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Splits a header line into a lowercased name and its value.
fn split_header(line: &[u8]) -> Option<(String, String)> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    let name = String::from_utf8_lossy(&line[..colon])
        .trim()
        .to_ascii_lowercase();
    let value = String::from_utf8_lossy(&line[colon + 1..])
        .trim()
        .to_string();
    Some((name, value))
}

/// The addresses in an `X-Forwarded-For` chain, in order.
///
/// Entries that are not addresses (obfuscated identifiers, `unknown`, junk)
/// are dropped, so the header the edge emits is one a guest can parse without
/// deciding what to believe.
fn parse_chain(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            let entry = entry
                .strip_prefix('[')
                .and_then(|entry| entry.split(']').next())
                .unwrap_or(entry);
            entry.parse::<IpAddr>().ok().map(|addr| addr.to_canonical())
        })
        .collect()
}

/// A hostname an edge is willing to write into a header value.
///
/// Deliberately narrow: letters, digits, and the punctuation a host and port
/// need. A control character here would be a header break the client got to
/// choose.
fn clean_host(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 255 {
        return None;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-_:[]".contains(&byte))
        .then(|| value.to_string())
}

/// The two schemes a proxy in front of an edge can have terminated.
fn clean_proto(value: &str) -> Option<String> {
    match value.to_ascii_lowercase().as_str() {
        "http" => Some("http".into()),
        "https" => Some("https".into()),
        _ => None,
    }
}

/// Reads until the end of the request head, returning the bytes consumed.
///
/// They are returned rather than discarded because they belong to the guest:
/// the edge only borrowed them long enough to read `Host`.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the request head ended",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            return Ok(head);
        }
        if head.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    }
}

/// Reads a guest's response head and reports the status it carries.
///
/// Read only where the client asked to upgrade: whether the guest agreed is
/// what says whether the connection may carry anything more. A status that does
/// not parse is not an agreement, so it reports `0` rather than failing.
pub async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<(Vec<u8>, u16)> {
    let head = tokio::time::timeout(UPGRADE_TIMEOUT, read_head(stream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no response head"))??;
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    Ok((head, status))
}

/// Extracts the `Host` header from a request head.
fn host_header(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    text.lines()
        // The request line has no colon, so it filters itself out. The header
        // name is case-insensitive.
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Answers the client directly, for the cases that never reach a sandbox.
pub async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    message: &str,
) -> std::io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         content-type: text/plain\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_names_the_port_then_the_sandbox() {
        assert_eq!(
            sandbox_url("sandbox.example.com", 80, "sbx_abc", 8000).unwrap(),
            "http://8000-sbx_abc.sandbox.example.com/"
        );
    }

    /// The edge is not always on 80, and a URL that omits its port goes
    /// nowhere.
    #[test]
    fn a_non_default_listen_port_is_carried() {
        assert_eq!(
            sandbox_url(".sandbox.local.", 7080, "sbx_abc", 3000).unwrap(),
            "http://3000-sbx_abc.sandbox.local:7080/"
        );
    }

    /// Every URL this produces round-trips through the router's own parser,
    /// which is the only thing that makes it a real address.
    #[test]
    fn a_url_is_one_the_router_would_accept() {
        let url = sandbox_url("sandbox.local", 7080, "my-sandbox-1", 80).unwrap();
        let host = url.trim_start_matches("http://").trim_end_matches('/');
        assert_eq!(host, "80-my-sandbox-1.sandbox.local:7080");
    }

    #[test]
    fn without_a_domain_there_is_no_url_to_hand_back() {
        assert!(sandbox_url("", 80, "sbx_abc", 8000).is_none());
        assert!(sandbox_url(".", 80, "sbx_abc", 8000).is_none());
        assert!(sandbox_url("sandbox.local", 80, "", 8000).is_none());
        assert!(sandbox_url("sandbox.local", 80, "sbx_abc", 0).is_none());
    }

    #[test]
    fn a_prelude_round_trips() {
        let line = prelude_line(Some("secret"), "sbx_abc", 8000);
        let parsed = Prelude::parse(&line).expect("should parse");
        assert_eq!(parsed.token, "secret");
        assert_eq!(parsed.sandbox_id, "sbx_abc");
        assert_eq!(parsed.port, 8000);
    }

    #[test]
    fn a_missing_token_round_trips_as_empty() {
        let line = prelude_line(None, "sbx_abc", 80);
        let parsed = Prelude::parse(&line).expect("should parse");
        assert_eq!(parsed.token, "");
        assert_eq!(parsed.sandbox_id, "sbx_abc");
    }

    #[test]
    fn malformed_preludes_are_refused() {
        for bad in [
            "",
            "BURROW/1",
            "BURROW/1 tok",
            "BURROW/1 tok sbx_a",
            "BURROW/2 tok sbx_a 80",
            "GET / HTTP/1.1",
            "BURROW/1 tok sbx_a notaport",
            "BURROW/1 tok sbx_a 0",
            "BURROW/1 tok  80",
            "BURROW/1 tok sbx_a 80 extra",
            "BURROW/1 tok sbx_a 99999",
        ] {
            assert!(Prelude::parse(bad).is_none(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn a_trailing_carriage_return_is_tolerated() {
        let parsed = Prelude::parse("BURROW/1 tok sbx_a 80\r\n").expect("should parse");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.sandbox_id, "sbx_a");
    }

    #[test]
    fn a_hostname_names_a_port_and_a_sandbox() {
        let target = Target::parse("8000-sbx_abc.sandbox.example.com", ".sandbox.example.com")
            .expect("should parse");
        assert_eq!(target.port, 8000);
        assert_eq!(target.sandbox_id, "sbx_abc");
    }

    /// A browser sends the port it connected on; it is not the guest's.
    #[test]
    fn the_clients_own_port_is_ignored() {
        let target = Target::parse("3000-sbx_abc.edge.local:8080", "edge.local").unwrap();
        assert_eq!(target.port, 3000);
        assert_eq!(target.sandbox_id, "sbx_abc");
    }

    #[test]
    fn hostnames_are_case_insensitive_and_tolerate_a_trailing_dot() {
        let target = Target::parse("8000-SBX_ABC.Edge.Local.", "edge.local").unwrap();
        assert_eq!(target.sandbox_id, "sbx_abc");
    }

    /// A sandbox id may contain dashes, which is why the port leads.
    #[test]
    fn a_sandbox_id_containing_dashes_survives() {
        let target = Target::parse("80-my-sandbox-1.edge.local", "edge.local").unwrap();
        assert_eq!(target.port, 80);
        assert_eq!(target.sandbox_id, "my-sandbox-1");
    }

    #[test]
    fn a_hostname_outside_the_domain_is_refused() {
        assert!(Target::parse("8000-sbx_abc.evil.example.com", "edge.local").is_none());
        assert!(Target::parse("edge.local", "edge.local").is_none());
    }

    #[test]
    fn nonsense_hostnames_are_refused() {
        for host in [
            "",
            "sbx_abc.edge.local",
            "-sbx_abc.edge.local",
            "8000-.edge.local",
            "notaport-sbx_abc.edge.local",
            "0-sbx_abc.edge.local",
            "99999-sbx_abc.edge.local",
        ] {
            assert!(
                Target::parse(host, "edge.local").is_none(),
                "{host:?} should not parse"
            );
        }
    }

    #[test]
    fn an_empty_domain_accepts_a_bare_label() {
        let target = Target::parse("8000-sbx_abc", "").unwrap();
        assert_eq!(target.sandbox_id, "sbx_abc");
    }

    #[test]
    fn the_host_header_is_found_regardless_of_case_or_position() {
        let head = b"GET /path HTTP/1.1\r\nUser-Agent: x\r\nHOST:  8000-sbx_a.edge.local  \r\n\r\n";
        assert_eq!(host_header(head).as_deref(), Some("8000-sbx_a.edge.local"));
    }

    #[test]
    fn a_request_without_a_host_yields_nothing() {
        assert_eq!(host_header(b"GET / HTTP/1.0\r\n\r\n"), None);
        assert_eq!(host_header(b"GET / HTTP/1.1\r\nHost:  \r\n\r\n"), None);
        assert_eq!(host_header(b""), None);
    }

    fn rewrite(head: &[u8], peer: &str, trusted: bool) -> Result<(String, Exchange), &'static str> {
        let (head, exchange) = rewrite_head(
            head,
            peer.parse::<IpAddr>().unwrap().to_canonical(),
            "8000-sbx_a.edge.local",
            trusted,
        )?;
        Ok((
            String::from_utf8(head).expect("rewritten head stays utf-8"),
            exchange,
        ))
    }

    fn rewritten(head: &[u8], peer: &str, trusted: bool) -> String {
        rewrite(head, peer, trusted).expect("should rewrite").0
    }

    /// Every header the edge emits, lowercased, in order.
    fn header(head: &str, name: &str) -> Vec<String> {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_string())
            .collect()
    }

    /// The whole point: what a client claims about itself is not evidence.
    #[test]
    fn a_forged_chain_from_an_untrusted_peer_is_replaced() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
              X-Forwarded-For: 9.9.9.9\r\nX-Real-IP: 9.9.9.9\r\n\
              Forwarded: for=9.9.9.9\r\n\r\n",
            "203.0.113.7",
            false,
        );
        assert_eq!(header(&head, "x-forwarded-for"), ["203.0.113.7"]);
        assert!(!head.contains("9.9.9.9"), "{head}");
        // Nothing is put back under a name the edge does not set itself.
        assert!(header(&head, "x-real-ip").is_empty());
    }

    /// A name may repeat, and an obs-fold hides a value on a line of its own.
    /// One occurrence left behind is the entire bug.
    #[test]
    fn every_occurrence_is_removed_including_its_continuation() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
              x-forwarded-for: 9.9.9.9\r\nUser-Agent: curl\r\n\
              X-FORWARDED-FOR: 8.8.8.8\r\n\
              forwarded: for=1.1.1.1,\r\n\tfor=2.2.2.2\r\n\
              X-Forwarded-Host: evil.example.com\r\n\
              X-Forwarded-Proto: https\r\n\r\n",
            "203.0.113.7",
            false,
        );
        for forged in [
            "9.9.9.9",
            "8.8.8.8",
            "1.1.1.1",
            "2.2.2.2",
            "evil.example.com",
        ] {
            assert!(!head.contains(forged), "{forged} survived:\n{head}");
        }
        assert_eq!(header(&head, "x-forwarded-for"), ["203.0.113.7"]);
        assert_eq!(header(&head, "x-forwarded-proto"), ["http"]);
        assert_eq!(header(&head, "x-forwarded-host"), ["8000-sbx_a.edge.local"]);
        // Headers that are not the edge's business are untouched.
        assert_eq!(header(&head, "user-agent"), ["curl"]);
        assert_eq!(header(&head, "host"), ["8000-sbx_a.edge.local"]);
    }

    /// Behind a proxy the peer is the proxy, so the chain is the only account
    /// of the client there is, and the edge's own hop is appended to it.
    #[test]
    fn a_trusted_proxys_chain_is_appended_to() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
              X-Forwarded-For: 198.51.100.4, 203.0.113.9\r\n\
              X-Forwarded-Proto: https\r\nX-Forwarded-Host: app.example.com\r\n\r\n",
            "10.0.0.2",
            true,
        );
        assert_eq!(
            header(&head, "x-forwarded-for"),
            ["198.51.100.4, 203.0.113.9, 10.0.0.2"]
        );
        // What the client actually reached, which the edge itself cannot see.
        assert_eq!(header(&head, "x-forwarded-proto"), ["https"]);
        assert_eq!(header(&head, "x-forwarded-host"), ["app.example.com"]);
        assert_eq!(
            header(&head, "forwarded"),
            [
                "for=198.51.100.4, for=203.0.113.9, for=10.0.0.2;proto=https;host=\"app.example.com\""
            ]
        );
    }

    /// Trust is per-peer, not per-header: the same request from anyone else is
    /// a forgery.
    #[test]
    fn trust_belongs_to_the_peer_not_the_header() {
        let request = b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
                        X-Forwarded-For: 198.51.100.4\r\n\r\n";
        let untrusted = rewritten(request, "10.0.0.2", false);
        assert_eq!(header(&untrusted, "x-forwarded-for"), ["10.0.0.2"]);
    }

    /// Junk in a trusted proxy's chain is dropped: the proxy is trusted, the
    /// hop in front of it is not.
    #[test]
    fn only_addresses_survive_a_trusted_chain() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
              X-Forwarded-For: unknown, _hidden, 198.51.100.4, <script>\r\n\r\n",
            "10.0.0.2",
            true,
        );
        assert_eq!(header(&head, "x-forwarded-for"), ["198.51.100.4, 10.0.0.2"]);
    }

    #[test]
    fn an_ipv6_peer_is_rendered_the_way_rfc_7239_wants() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\r\n",
            "2001:db8::1",
            false,
        );
        assert_eq!(
            header(&head, "forwarded"),
            ["for=\"[2001:db8::1]\";proto=http;host=\"8000-sbx_a.edge.local\""]
        );
        assert_eq!(header(&head, "x-forwarded-for"), ["2001:db8::1"]);
    }

    /// A v4 client on a dual-stack listener arrives mapped; a guest should see
    /// the address the client would recognise.
    #[test]
    fn a_mapped_v4_peer_is_reported_as_v4() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\r\n",
            "::ffff:203.0.113.7",
            false,
        );
        assert_eq!(header(&head, "x-forwarded-for"), ["203.0.113.7"]);
    }

    #[test]
    fn the_rewritten_head_still_ends_at_the_blank_line() {
        let head = rewritten(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\r\n",
            "203.0.113.7",
            false,
        );
        assert!(head.ends_with("\r\n\r\n"), "{head:?}");
        assert!(head.starts_with("GET / HTTP/1.1\r\n"));
    }

    /// Truncating a head would hand the guest a request it would answer
    /// wrongly, so a head that no longer fits is refused instead.
    #[test]
    fn a_head_that_would_outgrow_the_cap_is_refused() {
        let filler = "x".repeat(MAX_HEAD - 64);
        let head =
            format!("GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\nX-Pad: {filler}\r\n\r\n");
        assert_eq!(
            rewrite(head.as_bytes(), "203.0.113.7", false).unwrap_err(),
            "request head too large"
        );
    }

    /// The bug this exists to prevent: a connection is routed by its first
    /// request, so the guest is told to end it after answering. What a client
    /// asked for about the connection is not the client's to decide.
    #[test]
    fn a_forwarded_request_is_the_only_one_its_connection_carries() {
        let (head, exchange) = rewrite(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
              Connection: keep-alive\r\nKeep-Alive: timeout=60\r\n\
              Proxy-Connection: keep-alive\r\n\r\n",
            "203.0.113.7",
            false,
        )
        .unwrap();
        assert_eq!(header(&head, "connection"), ["close"]);
        assert!(header(&head, "keep-alive").is_empty(), "{head}");
        assert!(header(&head, "proxy-connection").is_empty(), "{head}");
        assert!(!exchange.upgrade);
        assert_eq!(exchange.body, 0);
    }

    /// An upgrade is the one exchange that legitimately outlives its response,
    /// so the token the guest needs to see survives.
    #[test]
    fn an_upgrade_keeps_the_connection_it_asked_for() {
        let (head, exchange) = rewrite(
            b"GET /ws HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\
              Connection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n",
            "203.0.113.7",
            false,
        )
        .unwrap();
        assert_eq!(header(&head, "connection"), ["upgrade"]);
        assert_eq!(header(&head, "upgrade"), ["websocket"]);
        assert!(exchange.upgrade);
    }

    /// `Upgrade` alone is a hop-by-hop hint, not an ask. Treating it as one
    /// would hand a connection a way to stay open without a `101`.
    #[test]
    fn an_upgrade_header_without_the_token_is_not_an_upgrade() {
        let (head, exchange) = rewrite(
            b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\nUpgrade: websocket\r\n\r\n",
            "203.0.113.7",
            false,
        )
        .unwrap();
        assert_eq!(header(&head, "connection"), ["close"]);
        assert!(!exchange.upgrade);
    }

    /// The body is the only thing the client may still send, so how long it is
    /// is what says where a second request would have begun.
    #[test]
    fn the_framing_says_how_much_of_the_client_is_still_the_request() {
        let body = |extra: &str| {
            let head = format!("POST / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n{extra}\r\n");
            rewrite(head.as_bytes(), "203.0.113.7", false).map(|(_, exchange)| exchange.body)
        };
        assert_eq!(body("Content-Length: 12\r\n"), Ok(12));
        assert_eq!(body("Content-Length: 0\r\n"), Ok(0));
        // Chunked has no number in the head, and the edge does not read chunks.
        assert_eq!(body("Transfer-Encoding: chunked\r\n"), Ok(u64::MAX));
        // Framings two hops could read differently are refused, not guessed.
        for ambiguous in [
            "Content-Length: +12\r\n",
            "Content-Length: 0x0c\r\n",
            "Content-Length: \r\n",
            "Content-Length: 12\r\nContent-Length: 34\r\n",
            "Content-Length: 12\r\nTransfer-Encoding: chunked\r\n",
        ] {
            assert_eq!(
                body(ambiguous),
                Err("ambiguous request framing"),
                "{ambiguous}"
            );
        }
    }

    #[test]
    fn a_host_that_could_forge_a_header_is_refused() {
        assert!(clean_host("8000-sbx_a.edge.local:8080").is_some());
        assert!(clean_host("a\rX-Forwarded-For: 9.9.9.9").is_none());
        assert!(clean_host("a b").is_none());
        assert!(clean_host("").is_none());
    }

    #[test]
    fn a_trusted_proxy_is_an_address_or_a_network() {
        let host = parse_trusted_proxy("10.0.0.2").unwrap();
        assert!(host.contains("10.0.0.2".parse().unwrap()));
        assert!(!host.contains("10.0.0.3".parse().unwrap()));

        let net = parse_trusted_proxy("10.0.0.0/24").unwrap();
        assert!(net.contains("10.0.0.255".parse().unwrap()));
        assert!(!net.contains("10.0.1.1".parse().unwrap()));
        // A mapped v4 peer is the same peer.
        assert!(net.contains("::ffff:10.0.0.5".parse().unwrap()));

        let six = parse_trusted_proxy("2001:db8::/32").unwrap();
        assert!(six.contains("2001:db8::1".parse().unwrap()));
        assert!(!six.contains("2001:db9::1".parse().unwrap()));
        // Families do not cross.
        assert!(!six.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn a_malformed_trusted_proxy_is_refused_rather_than_guessed() {
        for entry in [
            "",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.0/8/8",
            " 10.0.0.1",
            "example.com",
        ] {
            assert!(
                parse_trusted_proxy(entry).is_none(),
                "{entry:?} should not parse"
            );
        }
    }

    #[tokio::test]
    async fn the_head_is_read_whole_and_handed_on() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let request = b"GET / HTTP/1.1\r\nHost: 8000-sbx_a.edge.local\r\n\r\nBODY";

        tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client.write_all(request).await.unwrap();
            // Held open so the reader is not racing a close.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let (mut server, _) = listener.accept().await.unwrap();
        let head = read_head(&mut server).await.unwrap();
        assert!(
            head.ends_with(b"\r\n\r\n"),
            "head must stop at the blank line"
        );
        assert!(
            !head.ends_with(b"BODY"),
            "the body belongs to the guest, not the edge"
        );
        assert_eq!(host_header(&head).as_deref(), Some("8000-sbx_a.edge.local"));
    }

    /// The refusals are the edge's own answers, so both routers give the same
    /// one for the same bad request.
    #[tokio::test]
    async fn a_request_that_names_nothing_is_refused_before_any_lookup() {
        for (request, status) in [
            (&b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n"[..], 400u16),
            (
                &b"GET / HTTP/1.1\r\nHost: evil.example.com\r\n\r\n"[..],
                404,
            ),
        ] {
            let mut stream = std::io::Cursor::new(request.to_vec());
            let routed = route(
                &mut stream,
                "203.0.113.7".parse().unwrap(),
                "edge.local",
                &[],
            )
            .await
            .expect("a complete head is readable");
            match routed {
                Routed::Refused { status: got, .. } => assert_eq!(got, status),
                Routed::Forward(_) => panic!("{request:?} should not route"),
            }
        }
    }
}
