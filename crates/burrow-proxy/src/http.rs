//! Relaying HTTP while checking every request, not just the first.
//!
//! Peeking at the opening bytes and splicing the rest is fine for a protocol
//! that stays pointed at one place. HTTP does not: keep-alive carries many
//! requests down one connection, each naming its own host, so checking only
//! the first lets a sandbox ask an allowed server for anything else it fronts,
//! which on a CDN is most of the internet.
//!
//! The relay therefore follows request boundaries: read a head, check it,
//! forward it, step over exactly as much body as the framing says, repeat.
//! Anything unparseable ends the connection rather than being guessed at.
//!
//! The parsing is stricter than a server's would be, because every place
//! burrow and the upstream server could read the same bytes differently is a
//! place a second, unchecked request can be smuggled through. Obsolete line
//! folding, a `Content-Length` of `+41`, `chunked` buried in a list of codings
//! and two `Host` headers are all refused rather than interpreted.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Longest request head accepted. Real ones are far smaller; a client that
/// never ends its headers is not one to keep buffering for.
const MAX_HEAD: usize = 16 * 1024;

/// Longest chunk-size or trailer line accepted.
const MAX_LINE: usize = 1024;

/// Working buffer for one direction of one connection. Small, because there
/// is one per relayed connection and they exist to avoid a syscall per byte,
/// not to hold whole bodies.
const BUFFER: usize = 8 * 1024;

/// How long a relayed connection may sit without a byte moving before it is
/// dropped. Long enough for a slow upstream or a polling client, short enough
/// that abandoned connections do not accumulate.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// What the framing says follows a request's headers.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Body {
    /// No body: no `Content-Length`, no chunked encoding.
    None,
    /// Exactly this many bytes.
    Fixed(u64),
    /// Chunked, terminated by a zero-length chunk.
    Chunked,
}

/// Everything policy and framing need from a request head.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestHead {
    /// The `Host` header with any port removed, if there was exactly one.
    pub host: Option<String>,
    /// The method, as written. Compared case-sensitively wherever it is used,
    /// which is what RFC 9110 says a method is.
    pub method: String,
    /// The request target, as written: `/v1/x?a=1` in the ordinary case.
    pub target: String,
    /// Every header, in the order they arrived, names as spelled. Bounded by
    /// [`MAX_HEAD`], which is what bounds the work a matcher does over them.
    pub headers: Vec<(String, String)>,
    pub framing: Body,
    /// The client asked to stop speaking HTTP: the `Connection` header lists
    /// the `upgrade` token. An `Upgrade` header alone is *not* enough, being a
    /// hop-by-hop hint; treating it as a licence to tunnel would make the
    /// allowlist decorative.
    pub upgrade: bool,
}

/// Parses and validates a request head.
///
/// Every return of `Err` here ends the connection with an audited reason. The
/// rule throughout is that anything two hops could read differently is
/// malformed, not ambiguous.
pub fn parse_head(head: &str) -> Result<RequestHead, &'static str> {
    // The head must be CRLF-framed. A head terminated by bare LFs is one that
    // burrow and the upstream server may disagree about, so it is refused
    // rather than normalised.
    let Some((block, _)) = head.split_once("\r\n\r\n") else {
        return Err("request head is not CRLF-terminated");
    };

    let mut lines = block.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Err("empty request head");
    };
    if request_line.is_empty() || starts_with_space(request_line) {
        return Err("malformed request line");
    }
    if has_stray_control(request_line) {
        return Err("stray control character in the request line");
    }
    // `method SP target SP version`, exactly. A request line with any other
    // number of parts is one two hops could split differently.
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed request line");
    };
    if method.is_empty() || !method.bytes().all(is_tchar) || !version.starts_with("HTTP/") {
        return Err("malformed request line");
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut lengths = 0usize;
    let mut transfer_encodings: Vec<String> = Vec::new();
    let mut hosts = 0usize;
    let mut host = None;
    let mut upgrade = false;

    for line in lines {
        if line.is_empty() {
            return Err("blank line inside a request head");
        }
        // Obsolete line folding: upstream reads this as a continuation of the
        // header before it, a proxy that trims it reads it as a header of its
        // own. That disagreement is exactly a smuggled Content-Length.
        if starts_with_space(line) {
            return Err("obsolete line folding in a request head");
        }
        if has_stray_control(line) {
            return Err("stray control character in a request head");
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("header line without a colon");
        };
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err("malformed header name");
        }
        let value = trim_ows(value);
        headers.push((name.to_string(), value.to_string()));

        if name.eq_ignore_ascii_case("content-length") {
            lengths += 1;
            // Digits only: `+41`, ` 41`, `41, 41` and `0x29` are all things a
            // second parser might read differently.
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("malformed Content-Length");
            }
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "malformed Content-Length")?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err("conflicting Content-Length headers");
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            // A comma-separated list, and repeated headers extend the same
            // list, so `chunked` twice is two codings rather than one.
            for coding in value.split(',') {
                transfer_encodings.push(trim_ows(coding).to_ascii_lowercase());
            }
        } else if name.eq_ignore_ascii_case("host") {
            hosts += 1;
            // Two Host headers is a routing disagreement waiting to happen:
            // the allowlist checks one, the server answers the other.
            if hosts > 1 {
                return Err("more than one Host header");
            }
            host = parse_host_value(value);
            if host.is_none() {
                return Err("malformed Host header");
            }
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|token| trim_ows(token).eq_ignore_ascii_case("upgrade"))
        {
            upgrade = true;
        }
    }

    let chunked = if transfer_encodings.is_empty() {
        false
    } else {
        // `chunked` must be the final coding, and burrow relays no others: it
        // has to know where the body ends, and it cannot know that for a
        // coding it does not implement.
        if transfer_encodings.last().map(String::as_str) != Some("chunked") {
            return Err("Transfer-Encoding does not end in chunked");
        }
        if transfer_encodings.len() != 1 {
            return Err("unsupported Transfer-Encoding");
        }
        true
    };
    if chunked && lengths > 0 {
        // Both present: the two hops could disagree about where this request
        // ends and the next begins, which is exactly how a second, unchecked
        // request gets smuggled through.
        return Err("both Transfer-Encoding and Content-Length");
    }

    let framing = if chunked {
        Body::Chunked
    } else {
        match content_length {
            Some(0) | None => Body::None,
            Some(len) => Body::Fixed(len),
        }
    };
    Ok(RequestHead {
        host,
        method: method.to_string(),
        target: target.to_string(),
        headers,
        framing,
        upgrade,
    })
}

impl RequestHead {
    /// The target split into its path and its query string.
    ///
    /// An absolute-form target (`http://host/x`) has its origin stripped, so
    /// the two forms of the same request match the same rule. A target that is
    /// neither has no query.
    pub fn path_and_query(&self) -> (&str, &str) {
        let target = match self.target.split_once("://") {
            Some((_, rest)) => match rest.find('/') {
                Some(at) => &rest[at..],
                None => "/",
            },
            None => self.target.as_str(),
        };
        match target.split_once('?') {
            Some((path, query)) => (path, query),
            None => (target, ""),
        }
    }

    /// The target, in origin-form (`/x?a=1`), whichever form it was written
    /// in.
    pub fn origin_form(&self) -> String {
        let (path, query) = self.path_and_query();
        if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        }
    }

    /// This request as a matcher sees it.
    pub fn facts(&self) -> crate::policy::Request<'_> {
        let (path, query) = self.path_and_query();
        crate::policy::Request {
            method: &self.method,
            path,
            query,
            headers: &self.headers,
        }
    }
}

/// Rewrites a request head so `injections` are the headers the server sees.
///
/// Any header the client sent under one of those names is removed first, so
/// code in the sandbox can neither read the credential back out of its own
/// request nor send a value of its own that survives. Called only on a head
/// [`parse_head`] has already accepted, which is what makes the CRLF framing
/// below safe to assume.
pub fn inject_headers(head: &[u8], injections: &[(&str, &str)]) -> Result<Vec<u8>, &'static str> {
    if injections.is_empty() {
        return Ok(head.to_vec());
    }
    let text = std::str::from_utf8(head).map_err(|_| "request head is not text")?;
    let Some((block, rest)) = text.split_once("\r\n\r\n") else {
        return Err("request head is not CRLF-terminated");
    };
    // A name or value carrying CR, LF or NUL would append lines of its own: a
    // request smuggled by the policy rather than by the guest. Validated at the
    // API door as well; refused here because this is where it would land.
    for (name, value) in injections {
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err("injected header name is not a token");
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err("injected header value contains a line break");
        }
    }

    let mut out = String::with_capacity(text.len() + 64);
    for (index, line) in block.split("\r\n").enumerate() {
        // The request line has no name to compare and is always kept.
        let replaced = index > 0
            && line.split_once(':').is_some_and(|(name, _)| {
                injections
                    .iter()
                    .any(|(injected, _)| name.eq_ignore_ascii_case(injected))
            });
        if replaced {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    for (name, value) in injections {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.push_str(rest);
    Ok(out.into_bytes())
}

/// The host named by an absolute-form request target (`GET http://host/x
/// HTTP/1.1`), if the target is in that form.
///
/// `None` for origin-form (`/x`), `*`, and anything else not starting with a
/// scheme: those name no host of their own and are left to the `Host` header.
/// `Some(None)` for an absolute-form target whose authority is missing,
/// carries userinfo, or is otherwise unparseable: malformed rather than
/// merely unmatched, since a request that gets this far is going somewhere.
///
/// A recipient that honours absolute-form (a CDN edge, any gateway fronting
/// more than one name) routes on this authority, not on `Host`, so the two
/// must be reconciled before the allowlist check on `Host` means anything.
pub(crate) fn target_authority(target: &str) -> Option<Option<String>> {
    let rest = if let Some(rest) = strip_scheme(target, "http://") {
        rest
    } else if let Some(rest) = strip_scheme(target, "https://") {
        rest
    } else {
        return None;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(parse_host_value(&rest[..authority_end]))
}

fn strip_scheme<'a>(target: &'a str, scheme: &str) -> Option<&'a str> {
    (target.len() >= scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme))
        .then(|| &target[scheme.len()..])
}

/// Rewrites an absolute-form request line to origin-form, keeping the method
/// and version untouched.
///
/// Called only once the target's authority has been checked against `Host`
/// ([`target_authority`]): forwarding the absolute-form target verbatim would
/// still hand the upstream a second, unchecked place to route on even after
/// the two are confirmed to agree.
pub fn normalize_absolute_target(head: &[u8], origin_form: &str) -> Result<Vec<u8>, &'static str> {
    let text = std::str::from_utf8(head).map_err(|_| "request head is not text")?;
    let Some((request_line, rest)) = text.split_once("\r\n") else {
        return Err("malformed request head");
    };
    let mut parts = request_line.splitn(3, ' ');
    let (Some(method), Some(_old_target), Some(version)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed request line");
    };
    let mut out = String::with_capacity(text.len());
    out.push_str(method);
    out.push(' ');
    out.push_str(origin_form);
    out.push(' ');
    out.push_str(version);
    out.push_str("\r\n");
    out.push_str(rest);
    Ok(out.into_bytes())
}

/// The host a `Host` header names, with any port removed.
///
/// `None` for anything that is not one host and an optional numeric port.
///
/// Shared with the HTTP/2 path, which normalises `:authority` the same way: a
/// name the two protocols read differently would be a name only one of them
/// checks.
pub(crate) fn parse_host_value(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let host = match value.strip_prefix('[') {
        // A bracketed IPv6 literal: the colons inside the brackets are part of
        // the address, and only a colon after the `]` is a port.
        Some(rest) => {
            let end = rest.find(']')?;
            let after = &rest[end + 1..];
            if !after.is_empty() && !is_port_suffix(after) {
                return None;
            }
            rest[..end].to_string()
        }
        None => match value.rsplit_once(':') {
            Some((name, port)) => {
                if name.contains(':')
                    || port.is_empty()
                    || !port.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                name.to_string()
            }
            None => value.to_string(),
        },
    };
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b <= b' ' || matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#' | 0x7f))
    {
        return None;
    }
    Some(host)
}

fn is_port_suffix(text: &str) -> bool {
    text.strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

fn starts_with_space(line: &str) -> bool {
    line.starts_with(' ') || line.starts_with('\t')
}

/// A CR or LF surviving the split on `\r\n`, or a NUL: a lone one of either is
/// a line boundary to somebody.
fn has_stray_control(line: &str) -> bool {
    line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Optional whitespace around a header value is SP and HTAB, and nothing else.
fn trim_ows(value: &str) -> &str {
    value.trim_matches(|c| c == ' ' || c == '\t')
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

/// A reader with a buffer the relay owns.
///
/// One buffer serves head parsing, chunk framing and body forwarding, so bytes
/// read while looking for the end of a head are still there when the body is
/// forwarded and nothing is lost at the boundary between the two.
pub struct Buffered<R> {
    inner: R,
    buf: Box<[u8]>,
    start: usize,
    end: usize,
}

impl<R: AsyncRead + Unpin> Buffered<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0u8; BUFFER].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// Reads more from the peer. `Ok(0)` means it closed.
    async fn fill(&mut self) -> Result<usize, String> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.end == self.buf.len() {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let read = tokio::time::timeout(IDLE_TIMEOUT, self.inner.read(&mut self.buf[self.end..]))
            .await
            .map_err(|_| "the connection went idle".to_string())?
            .map_err(|err| format!("reading from the connection: {err}"))?;
        self.end += read;
        Ok(read)
    }

    /// Reads one head, up to and including the blank line.
    ///
    /// `None` means the peer closed cleanly with nothing buffered, which is how
    /// a keep-alive connection normally ends. A read *error* is never that: it
    /// is reported, so a connection torn down mid-flight is not audited as a
    /// tidy close.
    pub async fn read_head(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut head = Vec::new();
        loop {
            if self.start == self.end && self.fill().await? == 0 {
                return if head.is_empty() {
                    Ok(None)
                } else {
                    Err("connection closed mid-request".into())
                };
            }

            let mut consumed = 0;
            let mut complete = false;
            for &byte in self.available() {
                head.push(byte);
                consumed += 1;
                if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
                    complete = true;
                    break;
                }
                if head.len() > MAX_HEAD {
                    break;
                }
            }
            self.consume(consumed);
            if complete {
                return Ok(Some(head));
            }
            if head.len() > MAX_HEAD {
                return Err("request head is too large".into());
            }
        }
    }

    fn consume(&mut self, n: usize) {
        self.start = (self.start + n).min(self.end);
    }

    async fn read_line(&mut self) -> Result<Vec<u8>, String> {
        let mut line = Vec::new();
        loop {
            if self.start == self.end && self.fill().await? == 0 {
                return Err("chunked body ended early".into());
            }
            let mut consumed = 0;
            let mut complete = false;
            for &byte in self.available() {
                line.push(byte);
                consumed += 1;
                if byte == b'\n' {
                    complete = true;
                    break;
                }
                if line.len() > MAX_LINE {
                    break;
                }
            }
            self.consume(consumed);
            if complete {
                return Ok(line);
            }
            if line.len() > MAX_LINE {
                return Err("chunk header is too long".into());
            }
        }
    }

    /// Copies a request body of known framing onward.
    pub async fn forward_body<W>(&mut self, to: &mut W, body: &Body) -> Result<u64, String>
    where
        W: AsyncWrite + Unpin,
    {
        match body {
            Body::None => Ok(0),
            Body::Fixed(len) => self.copy_exact(to, *len).await,
            Body::Chunked => self.copy_chunked(to).await,
        }
    }

    /// Reads a request body whole, decoded, up to `limit` bytes.
    ///
    /// The one place a body is held rather than stepped over: a request that
    /// changes connections cannot be streamed from one to the other, and a
    /// buffer on a policy path needs a ceiling. Chunked bodies are decoded
    /// here, unlike [`Self::forward_body`], which relays their framing verbatim
    /// because the far side is another HTTP/1.1 hop.
    pub async fn read_body_whole(&mut self, body: &Body, limit: u64) -> Result<Vec<u8>, String> {
        let too_large = || format!("a body of more than {limit} bytes is not relayed here");
        match body {
            Body::None => Ok(Vec::new()),
            Body::Fixed(len) => {
                if *len > limit {
                    return Err(too_large());
                }
                let mut out = Vec::with_capacity(*len as usize);
                self.copy_exact(&mut out, *len).await?;
                Ok(out)
            }
            Body::Chunked => {
                let mut out = Vec::new();
                loop {
                    let line = self.read_line().await?;
                    let text = String::from_utf8_lossy(&line);
                    let size_text = text.trim_end().split(';').next().unwrap_or("").trim();
                    if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err("malformed chunk size".into());
                    }
                    let size =
                        u64::from_str_radix(size_text, 16).map_err(|_| "malformed chunk size")?;
                    if size == 0 {
                        // Trailers, then a final blank line. Nothing checks a
                        // trailer, so none of them are carried onward.
                        loop {
                            let trailer = self.read_line().await?;
                            if trailer == b"\r\n" || trailer == b"\n" {
                                return Ok(out);
                            }
                        }
                    }
                    if out.len() as u64 + size > limit {
                        return Err(too_large());
                    }
                    self.copy_exact(&mut out, size).await?;
                    // The CRLF that follows every chunk's data.
                    self.read_line().await?;
                }
            }
        }
    }

    /// Copies everything left on this side onward, until it closes or goes
    /// idle.
    ///
    /// Used where there is nothing further to parse: the response direction,
    /// and both directions of a connection that has left HTTP behind. The idle
    /// timeout is what terminates it, since a peer that neither sends nor
    /// closes must not hold a relay open forever.
    pub async fn copy_all<W>(&mut self, to: &mut W) -> u64
    where
        W: AsyncWrite + Unpin,
    {
        let mut moved = 0;
        loop {
            if self.start == self.end && !matches!(self.fill().await, Ok(n) if n > 0) {
                break;
            }
            let take = self.end - self.start;
            if to.write_all(&self.buf[self.start..self.end]).await.is_err() {
                break;
            }
            self.start += take;
            moved += take as u64;
        }
        moved
    }

    async fn copy_exact<W>(&mut self, to: &mut W, mut left: u64) -> Result<u64, String>
    where
        W: AsyncWrite + Unpin,
    {
        let total = left;
        while left > 0 {
            if self.start == self.end && self.fill().await? == 0 {
                return Err("request body ended early".into());
            }
            let take = (self.end - self.start).min(left as usize);
            to.write_all(&self.buf[self.start..self.start + take])
                .await
                .map_err(|err| format!("forwarding a request body: {err}"))?;
            self.start += take;
            left -= take as u64;
        }
        Ok(total)
    }

    /// Copies a chunked body, chunk by chunk, up to and including the
    /// terminator.
    ///
    /// The sizes are parsed rather than streamed blindly: they say where this
    /// request ends, and so where the next one, which also needs checking,
    /// begins.
    async fn copy_chunked<W>(&mut self, to: &mut W) -> Result<u64, String>
    where
        W: AsyncWrite + Unpin,
    {
        let mut moved = 0;
        loop {
            let line = self.read_line().await?;
            moved += line.len() as u64;
            to.write_all(&line)
                .await
                .map_err(|err| format!("forwarding a chunk header: {err}"))?;

            let text = String::from_utf8_lossy(&line);
            let size_text = text.trim_end().split(';').next().unwrap_or("").trim();
            if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("malformed chunk size".into());
            }
            let size = u64::from_str_radix(size_text, 16).map_err(|_| "malformed chunk size")?;

            if size == 0 {
                // Trailers, then a final blank line.
                loop {
                    let trailer = self.read_line().await?;
                    moved += trailer.len() as u64;
                    to.write_all(&trailer)
                        .await
                        .map_err(|err| format!("forwarding a trailer: {err}"))?;
                    if trailer == b"\r\n" || trailer == b"\n" {
                        return Ok(moved);
                    }
                }
            }

            moved += self.copy_exact(to, size).await?;
            // The CRLF that follows every chunk's data.
            let terminator = self.read_line().await?;
            moved += terminator.len() as u64;
            to.write_all(&terminator)
                .await
                .map_err(|err| format!("forwarding a chunk terminator: {err}"))?;
        }
    }
}

// Buffered bytes belong to the stream, so a Buffered reader *is* the stream:
// handing the inner reader to a blind copy would drop whatever is already
// held. Reading through this drains the buffer first.
impl<R: AsyncRead + Unpin> AsyncRead for Buffered<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.start < this.end {
            let take = (this.end - this.start).min(dst.remaining());
            dst.put_slice(&this.buf[this.start..this.start + take]);
            this.start += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, dst)
    }
}

/// Reads a response head from upstream and reports the status it carries.
///
/// Only the status matters here: it is what says whether the server agreed to
/// leave HTTP behind. Everything else is forwarded verbatim.
pub async fn read_response_head<R: AsyncRead + Unpin>(
    from: &mut Buffered<R>,
) -> Result<(Vec<u8>, u16), String> {
    let Some(head) = from.read_head().await? else {
        return Err("upstream closed before answering".into());
    };
    let text = String::from_utf8_lossy(&head);
    let status = text
        .split("\r\n")
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("malformed response status line")?;
    Ok((head, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(extra: &str) -> String {
        format!("GET / HTTP/1.1\r\nHost: example.com\r\n{extra}\r\n")
    }

    fn body_framing(head: &str) -> Result<Body, &'static str> {
        parse_head(head).map(|parsed| parsed.framing)
    }

    #[test]
    fn a_plain_get_has_no_body() {
        assert_eq!(body_framing(&head("")), Ok(Body::None));
    }

    #[test]
    fn content_length_is_read() {
        assert_eq!(
            body_framing(&head("Content-Length: 42\r\n")),
            Ok(Body::Fixed(42))
        );
        // Zero-length is the same as no body for framing purposes.
        assert_eq!(body_framing(&head("Content-Length: 0\r\n")), Ok(Body::None));
    }

    /// A length only one of the two hops will accept is a desync, so only
    /// digits count as a length.
    #[test]
    fn a_signed_or_padded_content_length_is_refused() {
        assert!(body_framing(&head("Content-Length: +41\r\n")).is_err());
        assert!(body_framing(&head("Content-Length: -1\r\n")).is_err());
        assert!(body_framing(&head("Content-Length: 0x29\r\n")).is_err());
        assert!(body_framing(&head("Content-Length: 41, 41\r\n")).is_err());
        assert!(body_framing(&head("Content-Length: \r\n")).is_err());
        // OWS around the value is still OWS.
        assert_eq!(
            body_framing(&head("Content-Length:\t41 \r\n")),
            Ok(Body::Fixed(41))
        );
    }

    #[test]
    fn chunked_is_recognised_case_insensitively() {
        assert_eq!(
            body_framing(&head("Transfer-Encoding: Chunked\r\n")),
            Ok(Body::Chunked)
        );
    }

    /// Sending both is the classic way to make two hops disagree about where a
    /// request ends, and a second unchecked request begins.
    #[test]
    fn both_framings_at_once_is_refused() {
        assert!(
            body_framing(&head("Transfer-Encoding: chunked\r\nContent-Length: 5\r\n")).is_err()
        );
    }

    #[test]
    fn conflicting_content_lengths_are_refused() {
        assert!(body_framing(&head("Content-Length: 5\r\nContent-Length: 9\r\n")).is_err());
        // Repeating the same value is harmless.
        assert_eq!(
            body_framing(&head("Content-Length: 5\r\nContent-Length: 5\r\n")),
            Ok(Body::Fixed(5))
        );
    }

    #[test]
    fn a_malformed_length_is_refused_rather_than_ignored() {
        assert!(body_framing(&head("Content-Length: not-a-number\r\n")).is_err());
    }

    #[test]
    fn an_unknown_transfer_encoding_is_refused() {
        assert!(body_framing(&head("Transfer-Encoding: gzip\r\n")).is_err());
    }

    /// `chunked` is only framing burrow can follow when it is the whole list
    /// and comes last; anything else is a coding it cannot step over.
    #[test]
    fn transfer_encoding_is_read_as_a_token_list() {
        assert!(body_framing(&head("Transfer-Encoding: gzip, chunked\r\n")).is_err());
        assert!(body_framing(&head("Transfer-Encoding: chunked, gzip\r\n")).is_err());
        // The substring trick: a coding merely *containing* the word.
        assert!(body_framing(&head("Transfer-Encoding: xchunked\r\n")).is_err());
        assert!(body_framing(&head("Transfer-Encoding: chunkedx\r\n")).is_err());
        // Repeated headers extend one list, so this is chunked twice.
        assert!(
            body_framing(&head(
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"
            ))
            .is_err()
        );
    }

    /// A folded line is a header to a proxy that trims names and a continuation
    /// to the server behind it. That disagreement is the smuggling.
    #[test]
    fn obsolete_line_folding_is_refused() {
        assert!(body_framing(&head(" Content-Length: 41\r\n")).is_err());
        assert!(body_framing(&head("\tContent-Length: 41\r\n")).is_err());
        assert!(body_framing(&head("Content-Length : 41\r\n")).is_err());
        assert!(body_framing(&head("Content Length: 41\r\n")).is_err());
    }

    #[test]
    fn a_header_line_without_a_colon_is_malformed() {
        assert!(body_framing(&head("nonsense\r\n")).is_err());
    }

    #[test]
    fn a_head_that_is_not_crlf_framed_is_refused() {
        assert!(parse_head("GET / HTTP/1.1\nHost: example.com\n\n").is_err());
    }

    #[test]
    fn duplicate_host_headers_are_refused() {
        assert!(
            body_framing("GET / HTTP/1.1\r\nHost: allowed.example\r\nHost: evil.example\r\n\r\n")
                .is_err()
        );
    }

    #[test]
    fn the_host_is_read_without_its_port() {
        assert_eq!(
            parse_head("GET / HTTP/1.1\r\nHost: pypi.org:8080\r\n\r\n")
                .unwrap()
                .host
                .as_deref(),
            Some("pypi.org")
        );
    }

    /// The colons in an IPv6 literal are the address, not a port.
    #[test]
    fn a_bracketed_ipv6_host_is_not_mangled() {
        assert_eq!(
            parse_head("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n")
                .unwrap()
                .host
                .as_deref(),
            Some("::1")
        );
        assert_eq!(
            parse_head("GET / HTTP/1.1\r\nHost: [2001:db8::5]:8443\r\n\r\n")
                .unwrap()
                .host
                .as_deref(),
            Some("2001:db8::5")
        );
        assert!(parse_head("GET / HTTP/1.1\r\nHost: [::1]junk\r\n\r\n").is_err());
        assert!(parse_head("GET / HTTP/1.1\r\nHost: a:b:c\r\n\r\n").is_err());
    }

    /// An `Upgrade` header alone is a hint; only the `upgrade` token in
    /// `Connection` is a request to leave HTTP.
    #[test]
    fn only_the_connection_token_marks_an_upgrade() {
        assert!(!parse_head(&head("Upgrade: websocket\r\n")).unwrap().upgrade);
        assert!(
            parse_head(&head("Upgrade: websocket\r\nConnection: Upgrade\r\n"))
                .unwrap()
                .upgrade
        );
        assert!(
            parse_head(&head("Connection: keep-alive, Upgrade\r\n"))
                .unwrap()
                .upgrade
        );
        // A token that merely contains the word is not the token.
        assert!(
            !parse_head(&head("Connection: upgrades\r\n"))
                .unwrap()
                .upgrade
        );
    }

    /// The desync the old code allowed: an Upgrade header used to win over
    /// framing entirely, so this body was never stepped over.
    #[test]
    fn an_upgrade_does_not_override_the_body_framing() {
        let parsed = parse_head(&head(
            "Upgrade: x\r\nConnection: upgrade\r\nContent-Length: 100\r\n",
        ))
        .unwrap();
        assert_eq!(parsed.framing, Body::Fixed(100));
        assert!(parsed.upgrade);
    }

    /// The point of brokering: the guest's own value never reaches the server,
    /// so code inside the sandbox cannot spoof the credential either.
    #[test]
    fn an_injected_header_replaces_whatever_the_client_sent() {
        let head =
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\nauthorization: Bearer forged\r\n\r\n";
        let rewritten = inject_headers(head, &[("Authorization", "Bearer real")]).unwrap();
        let text = String::from_utf8(rewritten).unwrap();

        assert!(!text.contains("forged"));
        assert_eq!(text.matches("uthorization").count(), 1);
        assert!(text.contains("Authorization: Bearer real\r\n"));
        assert!(text.contains("Host: api.example.com\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        // Still a head the strict parser accepts, which is what keeps the
        // relay's framing intact.
        assert!(parse_head(&text).is_ok());
    }

    #[test]
    fn injecting_nothing_leaves_the_head_byte_identical() {
        let head = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(inject_headers(head, &[]).unwrap(), head.to_vec());
    }

    /// A value carrying a line break would smuggle a header, or a whole
    /// request, of its own.
    #[test]
    fn a_header_that_would_forge_lines_is_refused() {
        let head = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert!(inject_headers(head, &[("X-K", "v\r\nX-Evil: 1")]).is_err());
        assert!(inject_headers(head, &[("X-K", "v\nX-Evil: 1")]).is_err());
        assert!(inject_headers(head, &[("X K", "v")]).is_err());
        assert!(inject_headers(head, &[("", "v")]).is_err());
    }

    #[tokio::test]
    async fn heads_are_read_one_request_at_a_time() {
        let stream = b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: b\r\n\r\n";
        let mut reader = Buffered::new(std::io::Cursor::new(stream.to_vec()));

        let first = reader.read_head().await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&first).contains("/a"));
        let second = reader.read_head().await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&second).contains("/b"));
        assert!(reader.read_head().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_fixed_body_is_stepped_over_exactly() {
        let mut reader = Buffered::new(std::io::Cursor::new(b"hello!GET /next".to_vec()));
        let mut out = Vec::new();
        let moved = reader
            .forward_body(&mut out, &Body::Fixed(6))
            .await
            .unwrap();
        assert_eq!(moved, 6);
        assert_eq!(out, b"hello!");

        // The stream is left exactly at the next request, including the bytes
        // the buffer had already read past.
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, b"GET /next");
    }

    #[tokio::test]
    async fn a_chunked_body_is_stepped_over_exactly() {
        let body = "5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\nGET /next";
        let mut reader = Buffered::new(std::io::Cursor::new(body.as_bytes().to_vec()));
        let mut out = Vec::new();
        reader.forward_body(&mut out, &Body::Chunked).await.unwrap();

        // Forwarded verbatim, framing included.
        assert_eq!(
            String::from_utf8_lossy(&out),
            "5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n"
        );
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, b"GET /next", "the next request must be left intact");
    }

    #[tokio::test]
    async fn a_truncated_body_is_an_error_not_a_silent_desync() {
        let mut reader = Buffered::new(std::io::Cursor::new(b"only-four".to_vec()));
        let mut out = Vec::new();
        assert!(
            reader
                .forward_body(&mut out, &Body::Fixed(100))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_response_status_is_read_back() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nrest";
        let mut reader = Buffered::new(std::io::Cursor::new(response.to_vec()));
        let (head, status) = read_response_head(&mut reader).await.unwrap();
        assert_eq!(status, 101);
        assert!(head.ends_with(b"\r\n\r\n"));

        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, b"rest");
    }

    #[test]
    fn origin_form_targets_have_no_authority() {
        assert_eq!(target_authority("/v1/x?a=1"), None);
        assert_eq!(target_authority("*"), None);
    }

    #[test]
    fn absolute_form_authority_is_extracted() {
        assert_eq!(
            target_authority("http://example.com/x"),
            Some(Some("example.com".to_string()))
        );
        // The scheme is matched case-insensitively; the host itself is
        // returned as written, exactly like `parse_host_value` for `Host`.
        // Callers compare the two with `eq_ignore_ascii_case`, not here.
        assert_eq!(
            target_authority("HTTPS://Example.COM:443/x?a=1"),
            Some(Some("Example.COM".to_string()))
        );
        assert_eq!(
            target_authority("http://[::1]:8080/x"),
            Some(Some("::1".to_string()))
        );
    }

    /// Userinfo in the authority is exactly the kind of thing a browser
    /// would never send but a hostile guest might, to try to slip an
    /// authority a naive comparison reads differently.
    #[test]
    fn userinfo_in_the_authority_is_malformed() {
        assert_eq!(target_authority("http://user@evil.example/x"), Some(None));
        assert_eq!(
            target_authority("http://user:pass@evil.example/x"),
            Some(None)
        );
    }

    #[test]
    fn absolute_form_is_rewritten_to_origin_form() {
        let head = b"GET http://example.com/x?a=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let rewritten = normalize_absolute_target(head, "/x?a=1").unwrap();
        assert_eq!(
            rewritten,
            b"GET /x?a=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
    }

    #[test]
    fn absolute_form_target_is_stripped_for_matching() {
        let parsed = parse_head("GET http://example.com/x?a=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(parsed.origin_form(), "/x?a=1");
    }
}
