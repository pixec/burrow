//! Extracting the requested hostname from the first bytes of a connection.
//!
//! The proxy needs to know where a connection is *going* before it decides
//! whether to allow it, without terminating TLS. For HTTPS that means reading
//! the SNI extension out of the ClientHello; for plaintext HTTP, the Host
//! header. Both are readable from the client's first flight, so the decision
//! happens before a single byte reaches the destination.

/// A slice reader that never panics on truncated input.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Skips a block prefixed with a 1-byte length.
    fn skip_u8_prefixed(&mut self) -> Option<()> {
        let len = self.u8()? as usize;
        self.take(len).map(|_| ())
    }

    fn skip_u16_prefixed(&mut self) -> Option<()> {
        let len = self.u16()? as usize;
        self.take(len).map(|_| ())
    }
}

/// Extension id for Encrypted Client Hello (RFC 9180 / draft-ietf-tls-esni).
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_ALPN: u16 = 0x0010;

/// How many protocol names are read out of an ALPN extension.
///
/// Only `h2` and `http/1.1` are ever acted on, and a hello listing hundreds of
/// names is not one worth allocating for.
const MAX_ALPN_ENTRIES: usize = 16;

/// What a ClientHello says about where it is going.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// The name in the server_name extension, if any.
    pub server_name: Option<String>,
    /// Whether the real destination is encrypted inside the handshake.
    ///
    /// With ECH the visible `server_name` is a cover name, often the
    /// provider's own, and the name actually asked for is sealed in this
    /// extension. An allowlist containing the cover name would wave through a
    /// connection to anywhere the provider hosts.
    pub encrypted_client_hello: bool,
    /// The protocols the client offered in ALPN, in the order it listed them.
    ///
    /// An inspected session negotiates upstream with exactly this offer, so
    /// the protocol the origin picks is one the sandbox was willing to speak.
    /// Empty means the client offered none, which is HTTP/1.1 by default and
    /// never a licence to pick something it did not ask for.
    pub alpn: Vec<String>,
}

/// Parses a TLS ClientHello for everything policy needs from it.
///
/// Returns `None` for anything that is not a well-formed ClientHello. Callers
/// must treat that as "unknown destination", never as "allowed".
pub fn parse_client_hello(buf: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(buf);

    // TLS record header: handshake type, version, length.
    if r.u8()? != 0x16 {
        return None;
    }
    r.u16()?; // legacy record version
    r.u16()?; // record length

    // Handshake header: ClientHello, 3-byte length.
    if r.u8()? != 0x01 {
        return None;
    }
    r.take(3)?;

    r.u16()?; // client version
    r.take(32)?; // random
    r.skip_u8_prefixed()?; // session id
    r.skip_u16_prefixed()?; // cipher suites
    r.skip_u8_prefixed()?; // compression methods

    let extensions_len = r.u16()? as usize;
    let end = r.pos + extensions_len;

    // Every extension is walked rather than stopping at the first server_name:
    // ECH can appear after it, and missing it would mean trusting a cover name.
    let mut hello = ClientHello::default();
    while r.pos < end {
        let ext_type = r.u16()?;
        let ext_len = r.u16()? as usize;
        let body = r.take(ext_len)?;

        match ext_type {
            EXT_ENCRYPTED_CLIENT_HELLO => hello.encrypted_client_hello = true,
            EXT_SERVER_NAME => {
                // server_name extension: list length, then entries of
                // (type, length, name). Only host_name (type 0) is defined.
                let mut names = Reader::new(body);
                names.u16()?; // server_name_list length
                while let Some(name_type) = names.u8() {
                    let Some(len) = names.u16() else { break };
                    let Some(value) = names.take(len as usize) else {
                        break;
                    };
                    if name_type == 0 {
                        hello.server_name = String::from_utf8(value.to_vec()).ok();
                        break;
                    }
                }
            }
            EXT_ALPN => {
                // A 2-byte list length, then entries of (1-byte length, name).
                let mut names = Reader::new(body);
                names.u16()?; // protocol name list length
                while let Some(len) = names.u8() {
                    let Some(value) = names.take(len as usize) else {
                        break;
                    };
                    // A name that is not text is not one of the two protocols
                    // the proxy relays, so it is dropped rather than guessed at.
                    if let Ok(name) = std::str::from_utf8(value) {
                        hello.alpn.push(name.to_string());
                    }
                    if hello.alpn.len() >= MAX_ALPN_ENTRIES {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    Some(hello)
}

/// Parses the Host header from the start of an HTTP/1.x request.
///
/// The same strict parser the relay enforces with, so a head the two read
/// differently cannot be checked against the allowlist while the server routes
/// elsewhere. Anything malformed is `None`, which callers must treat as
/// "unknown destination", never as "allowed".
pub fn parse_http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    crate::http::parse_head(text).ok()?.host
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_sni(buf: &[u8]) -> Option<String> {
        parse_client_hello(buf)?.server_name
    }

    /// Builds a minimal but structurally valid ClientHello for `host`.
    fn client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
        sni.push(0); // host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        let len = body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn reads_sni_from_a_client_hello() {
        assert_eq!(
            parse_sni(&client_hello("pypi.org")).as_deref(),
            Some("pypi.org")
        );
    }

    #[test]
    fn truncated_input_returns_none_rather_than_panicking() {
        let full = client_hello("example.com");
        for cut in 0..full.len() {
            // The property that matters: never panic, never invent a name.
            let _ = parse_sni(&full[..cut]);
        }
        assert_eq!(parse_sni(&[]), None);
        assert_eq!(parse_sni(&[0x16, 0x03]), None);
    }

    #[test]
    fn non_tls_input_is_not_a_client_hello() {
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
    }

    #[test]
    fn reads_host_header_and_strips_the_port() {
        let req = b"GET /simple/ HTTP/1.1\r\nHost: pypi.org:8080\r\nAccept: */*\r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("pypi.org"));
    }

    #[test]
    fn host_header_match_is_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nhOsT:  example.com \r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("example.com"));
    }

    /// Checking the first Host while the server routes on the last is a way to
    /// reach anything the allowlisted server fronts.
    #[test]
    fn two_host_headers_name_no_host_at_all() {
        let req = b"GET / HTTP/1.1\r\nHost: allowed.example\r\nHost: evil.example\r\n\r\n";
        assert_eq!(parse_http_host(req), None);
    }

    /// A colonless line used to abort the search; a valid Host after it was
    /// silently missed. Now the head is simply malformed either way.
    #[test]
    fn a_malformed_head_names_no_host() {
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\nnonsense\r\nHost: example.com\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\n Host: example.com\r\n\r\n"),
            None
        );
        // An incomplete head is not yet a request.
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            None
        );
    }

    #[test]
    fn a_bracketed_ipv6_host_keeps_its_address() {
        let req = b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("::1"));
    }

    /// A ClientHello carrying ECH presents a cover name; treating that as the
    /// destination would let it front for anywhere the provider hosts.
    #[test]
    fn ech_is_reported_alongside_the_cover_name() {
        let hello = client_hello_with(&[
            (0x0000, server_name_extension("cover.example.com")),
            (0xfe0d, vec![0xAB, 0xCD]),
        ]);
        let parsed = parse_client_hello(&hello).expect("should parse");
        assert_eq!(parsed.server_name.as_deref(), Some("cover.example.com"));
        assert!(
            parsed.encrypted_client_hello,
            "ECH must be reported, not ignored"
        );
    }

    /// ECH can appear after server_name, so parsing must not stop at the name.
    #[test]
    fn ech_after_the_server_name_is_still_seen() {
        let hello = client_hello_with(&[
            (0x0000, server_name_extension("cover.example.com")),
            (0x002b, vec![0x02, 0x03, 0x04]),
            (0xfe0d, vec![0x01]),
        ]);
        assert!(parse_client_hello(&hello).unwrap().encrypted_client_hello);
    }

    #[test]
    fn an_ordinary_client_hello_is_not_flagged() {
        let hello = client_hello_with(&[(0x0000, server_name_extension("example.com"))]);
        let parsed = parse_client_hello(&hello).unwrap();
        assert_eq!(parsed.server_name.as_deref(), Some("example.com"));
        assert!(!parsed.encrypted_client_hello);
    }

    /// What the sandbox offered is what an inspected session may negotiate
    /// upstream, so it has to be read exactly and in order.
    #[test]
    fn alpn_is_read_in_the_order_it_was_offered() {
        let mut body = Vec::new();
        for name in ["h2", "http/1.1"] {
            body.push(name.len() as u8);
            body.extend_from_slice(name.as_bytes());
        }
        let mut ext = (body.len() as u16).to_be_bytes().to_vec();
        ext.extend_from_slice(&body);

        let hello = client_hello_with(&[
            (0x0000, server_name_extension("example.com")),
            (0x0010, ext),
        ]);
        let parsed = parse_client_hello(&hello).unwrap();
        assert_eq!(parsed.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    /// A hello with no ALPN offers nothing, which is HTTP/1.1 by default and
    /// never a licence to pick something the client did not ask for.
    #[test]
    fn a_hello_without_alpn_offers_nothing() {
        let hello = client_hello_with(&[(0x0000, server_name_extension("example.com"))]);
        assert!(parse_client_hello(&hello).unwrap().alpn.is_empty());
    }

    /// A hello with only ECH and no cover name still has to be recognised as
    /// hiding its destination.
    #[test]
    fn ech_without_a_server_name_is_still_flagged() {
        let hello = client_hello_with(&[(0xfe0d, vec![0x01, 0x02])]);
        let parsed = parse_client_hello(&hello).unwrap();
        assert_eq!(parsed.server_name, None);
        assert!(parsed.encrypted_client_hello);
    }

    fn server_name_extension(name: &str) -> Vec<u8> {
        let mut entry = vec![0u8];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut ext = (entry.len() as u16).to_be_bytes().to_vec();
        ext.extend_from_slice(&entry);
        ext
    }

    /// Builds a ClientHello carrying the given extensions verbatim.
    fn client_hello_with(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut ext_block = Vec::new();
        for (kind, body) in extensions {
            ext_block.extend_from_slice(&kind.to_be_bytes());
            ext_block.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext_block.extend_from_slice(body);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // empty session id
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression methods
        body.push(0);
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
