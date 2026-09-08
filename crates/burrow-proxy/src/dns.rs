//! A forwarding DNS resolver that records what sandboxes look up.
//!
//! Without this, guests query a public resolver directly and burrow never sees
//! it: a sandbox's DNS traffic is the clearest signal of what it is *trying*
//! to reach, including the lookups whose connections the proxy later refuses.
//!
//! Queries are forwarded verbatim rather than parsed and rebuilt. Only the
//! question name is decoded, for the log; EDNS, DNSSEC and unusual record types
//! pass through untouched, so this cannot become a source of resolution bugs.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::audit::{AuditLog, EgressEvent};
use crate::policy::PolicyTable;

/// Bounded well above a normal query; anything larger is not something to
/// forward blindly.
const MAX_PACKET: usize = 4096;
/// Receive buffer for an upstream answer.
///
/// The whole 16-bit DNS length, because a `recv` on a UDP socket discards
/// whatever does not fit and reports only what did. A smaller buffer would cut
/// a large answer, a fat TXT set or a DNSSEC-signed response, down to a packet
/// handed to the guest with no TC bit set, which is a resolver claiming to
/// have answered completely. There is no TCP fallback to recover with either:
/// the firewall opens UDP/53 to the resolver and nothing else.
const MAX_ANSWER: usize = 65_535;
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Queries being forwarded at once, across every sandbox.
///
/// Each forward holds an ephemeral UDP socket for up to [`UPSTREAM_TIMEOUT`],
/// so the ceiling on file descriptors is this number and not the rate at which
/// sandboxes can send datagrams. Without it a sandbox emitting queries in a
/// loop exhausts the process's descriptors, which takes the proxy and the
/// resolver down for every sandbox on the node.
const MAX_INFLIGHT_FORWARDS: usize = 256;

/// Sustained queries per second one sandbox may forward, and the burst it may
/// do it in.
///
/// A token bucket rather than a flat cap: resolution is bursty, a page load or
/// a package install fans out to dozens of names at once, and refusing those
/// would break ordinary work. What it stops is the *sustained* flood, which is
/// the shape of both a descriptor exhaustion attempt and of using the question
/// name as an exfiltration channel.
const QUERIES_PER_SECOND: f64 = 32.0;
const QUERY_BURST: f64 = 128.0;
/// Buckets kept for sources that have gone quiet, before they are forgotten.
///
/// Addresses are recycled between sandboxes, so an entry per address ever seen
/// would grow without bound on a busy node.
const BUCKET_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// What one source has spent of its query budget.
struct Bucket {
    tokens: f64,
    last: std::time::Instant,
    /// Queries dropped since the last warning, so a flood produces a log line
    /// occasionally rather than one per datagram.
    dropped: u64,
}

/// The resolver's share of the node, split so one sandbox cannot spend it all.
#[derive(Default)]
struct Limits {
    buckets: std::sync::Mutex<std::collections::HashMap<Ipv4Addr, Bucket>>,
}

impl Limits {
    /// Whether `source` may forward one more query now.
    fn allow(&self, source: Ipv4Addr) -> bool {
        let now = std::time::Instant::now();
        let mut buckets = self.buckets.lock().unwrap();

        // Pruned here rather than on a timer: the map is only ever touched
        // from this path, and a sandbox that stopped asking has nothing worth
        // remembering.
        if buckets.len() > 1024 {
            buckets.retain(|_, bucket| now.duration_since(bucket.last) < BUCKET_IDLE);
        }

        let bucket = buckets.entry(source).or_insert(Bucket {
            tokens: QUERY_BURST,
            last: now,
            dropped: 0,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * QUERIES_PER_SECOND).min(QUERY_BURST);

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return true;
        }
        bucket.dropped += 1;
        // Dropped without a reply and without an audit record: a record per
        // over-limit query would be a second flood, through the audit queue,
        // evicting the records of every other sandbox on the node. The count
        // is what an operator needs, and it is logged.
        if bucket.dropped.is_power_of_two() {
            tracing::warn!(
                %source,
                dropped = bucket.dropped,
                "dns queries dropped: source is over its rate limit"
            );
        }
        false
    }
}

pub struct Resolver {
    pub policies: Arc<PolicyTable>,
    pub audit: AuditLog,
    /// Where queries are forwarded, e.g. `1.1.1.1:53`.
    pub upstream: SocketAddr,
    /// Answers are recorded here so the proxy can check that a connection's
    /// destination is one this sandbox was actually given for that name.
    pub resolutions: Arc<crate::Resolutions>,
    /// Private-network names, answered here rather than forwarded.
    pub directory: Arc<crate::directory::Directory>,
}

impl Resolver {
    /// Serves until the socket fails.
    pub async fn serve(self: Arc<Self>, socket: UdpSocket) {
        let socket = Arc::new(socket);
        // Received into the full datagram size so that an oversized query is
        // seen to be oversized rather than silently cut down to something that
        // parses differently here than it would upstream.
        let mut buf = vec![0u8; MAX_ANSWER];
        let limits = Arc::new(Limits::default());
        let forwards = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_FORWARDS));

        loop {
            let (len, from) = match socket.recv_from(&mut buf).await {
                Ok(received) => received,
                Err(err) => {
                    tracing::warn!(%err, "dns receive failed");
                    continue;
                }
            };
            if len > MAX_PACKET {
                tracing::debug!(%from, len, "dropping an oversized dns query");
                continue;
            }

            let query = buf[..len].to_vec();
            let resolver = Arc::clone(&self);
            let socket = Arc::clone(&socket);
            let limits = Arc::clone(&limits);
            let forwards = Arc::clone(&forwards);
            // Each query is independent; a slow upstream must not stall the
            // whole resolver.
            tokio::spawn(async move {
                resolver
                    .handle(query, from, socket, &limits, &forwards)
                    .await;
            });
        }
    }

    async fn handle(
        &self,
        query: Vec<u8>,
        from: SocketAddr,
        socket: Arc<UdpSocket>,
        limits: &Limits,
        forwards: &Arc<tokio::sync::Semaphore>,
    ) {
        let name = parse_question(&query);
        let source_ip = match from.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => return,
        };
        // Before anything is parsed, logged or recorded, so a flood costs this
        // one lookup and nothing downstream of it.
        if !limits.allow(source_ip) {
            return;
        }
        // `.internal` is burrow's zone, answered from the directory and never
        // forwarded: a name that leaked upstream would both fail and tell a
        // public resolver what the fleet is called.
        let internal = crate::directory::is_internal(&name);

        // Anything else leaves the node, which makes it egress and the
        // allowlist's business. Forwarding regardless of policy would hand
        // every sandbox, one with no network included, a channel out through
        // the question name itself.
        let (policy, decision) = self.policies.may_resolve(source_ip, &name);
        let sandbox_id = policy.map(|p| p.sandbox_id).unwrap_or_default();

        let mut refusal = None;
        let answer = if internal {
            Some(self.answer_internal(&query, source_ip, &name))
        } else if decision.allowed() {
            self.forward(&query, forwards).await
        } else {
            // REFUSED rather than a forged NXDOMAIN: the name may well exist,
            // and saying so is the honest answer to "you may not ask".
            refusal = Some(decision.reason());
            Some(rcode_response(&query, RCODE_REFUSED))
        };

        // Pin before replying: the client may connect the instant it has the
        // answer, and an unpinned destination is refused.
        if let Some(answer) = &answer
            && refusal.is_none()
            && !name.is_empty()
        {
            let (addresses, ttl) = crate::resolutions::parse_answers(answer);
            self.resolutions.record(source_ip, &name, addresses, ttl);
        }

        self.audit.record(EgressEvent {
            at: crate::now_rfc3339(),
            sandbox_id,
            source_ip: source_ip.to_string(),
            destination: if internal {
                "directory".to_string()
            } else if refusal.is_some() {
                "refused".to_string()
            } else {
                self.upstream.to_string()
            },
            host: if name.is_empty() {
                None
            } else {
                Some(name.clone())
            },
            port: 53,
            // A lookup is not a connection: resolving a name is recorded, but
            // whether the sandbox may *reach* it is still the proxy's call.
            allowed: answer.is_some() && refusal.is_none(),
            reason: match (&answer, internal, refusal) {
                (_, _, Some(reason)) => format!("dns query refused: {reason}"),
                (Some(_), true, None) => "internal dns query".into(),
                (Some(_), false, None) => "dns query".into(),
                (None, _, None) => "dns upstream failed".into(),
            },
            bytes_sent: query.len() as u64,
            bytes_received: answer.as_ref().map(|a| a.len() as u64).unwrap_or(0),
            dropped_records: 0,
        });

        if let Some(answer) = answer
            && let Err(err) = socket.send_to(&answer, from).await
        {
            tracing::debug!(%err, "dns reply failed");
        }
    }

    /// Builds the reply for a name in burrow's own zone.
    ///
    /// A name the caller may not see is answered `NXDOMAIN`, identically to one
    /// that does not exist: whether a private network has a member called
    /// `db` is not something an outsider should be able to probe.
    fn answer_internal(&self, query: &[u8], client: Ipv4Addr, name: &str) -> Vec<u8> {
        match self.directory.resolve(client, name) {
            Some(address) => a_record_response(query, address),
            None => rcode_response(query, RCODE_NXDOMAIN),
        }
    }

    async fn forward(
        &self,
        query: &[u8],
        forwards: &Arc<tokio::sync::Semaphore>,
    ) -> Option<Vec<u8>> {
        // One descriptor per in-flight forward, held for up to
        // `UPSTREAM_TIMEOUT`. Claimed without waiting: a query that has to
        // queue for a slot has already lost the client's patience, and the
        // caller records the refusal as an upstream failure, which is what it
        // is.
        let Ok(_slot) = forwards.try_acquire() else {
            tracing::warn!("dns forward refused: too many queries already in flight");
            return None;
        };

        // An ephemeral socket per query keeps replies unambiguous. It is
        // `connect`ed to the upstream so the kernel drops any datagram from a
        // different source outright, and every datagram that does get through
        // is still checked against the query's transaction id and question:
        // an off-path attacker who can reach this port would otherwise only
        // need to win a timing race, not spoof the upstream's address, to
        // plant an answer of their choosing (which becomes a pin).
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .await
            .ok()?;
        socket.connect(self.upstream).await.ok()?;
        socket.send(query).await.ok()?;

        let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
        // The full datagram size: see [`MAX_ANSWER`]. A short buffer would
        // hand the guest a truncated answer with no TC bit and no TCP to fall
        // back to.
        let mut buf = vec![0u8; MAX_ANSWER];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let len = tokio::time::timeout(remaining, socket.recv(&mut buf))
                .await
                .ok()?
                .ok()?;
            let candidate = &buf[..len];
            if answers_query(query, candidate) {
                return Some(candidate.to_vec());
            }
            // Not this query's answer (stale reply, or a forged/off-path
            // datagram that connect() above couldn't filter by address alone
            // on some platforms). Keep waiting for the real one.
            tracing::debug!("dns forward: ignoring reply that does not match the query");
        }
    }
}

/// Whether `reply` looks like the upstream's answer to `query`: same
/// transaction id, the QR bit set, and the same question (name, qtype,
/// qclass). This is what stands between a forged UDP datagram and a pinned
/// answer, so it checks the whole question rather than just the id.
fn answers_query(query: &[u8], reply: &[u8]) -> bool {
    if query.len() < 12 || reply.len() < 12 {
        return false;
    }
    if reply[0] != query[0] || reply[1] != query[1] {
        return false; // transaction id
    }
    if reply[2] & 0x80 == 0 {
        return false; // QR must be a response
    }
    let Some(q_end) = question_end(query) else {
        return false;
    };
    let Some(r_end) = question_end(reply) else {
        return false;
    };
    query[12..q_end] == reply[12..r_end]
}

/// How long a client may cache an internal name.
///
/// Short, because these move: a sandbox that is recreated gets a new address,
/// and a peer holding a stale one would fail rather than reconnect.
const INTERNAL_TTL_SECS: u32 = 30;

const RCODE_NXDOMAIN: u8 = 3;
/// The answer to a name this sandbox's policy does not let it ask about.
const RCODE_REFUSED: u8 = 5;

/// Copies a query's header and question into a reply, with the response and
/// recursion-available bits set.
fn reply_skeleton(query: &[u8]) -> Option<Vec<u8>> {
    // Header plus at least a root question.
    if query.len() < 13 {
        return None;
    }
    let question_end = question_end(query)?;
    let mut reply = query[..question_end].to_vec();
    reply[2] = 0x81; // QR=1, RD copied as set by the client
    reply[3] = 0x80; // RA=1, RCODE=0
    reply[6] = 0;
    reply[7] = 0; // ANCOUNT
    reply[8] = 0;
    reply[9] = 0; // NSCOUNT
    reply[10] = 0;
    reply[11] = 0; // ARCOUNT
    Some(reply)
}

/// Offset just past the first question, or `None` if it is malformed.
fn question_end(packet: &[u8]) -> Option<usize> {
    let mut pos = 12;
    loop {
        let &len = packet.get(pos)?;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        pos += 1 + len as usize;
    }
    // QTYPE + QCLASS
    let end = pos + 4;
    (end <= packet.len()).then_some(end)
}

/// A reply carrying one A record for the question that was asked.
fn a_record_response(query: &[u8], address: Ipv4Addr) -> Vec<u8> {
    let Some(mut reply) = reply_skeleton(query) else {
        return rcode_response(query, RCODE_NXDOMAIN);
    };
    reply[7] = 1; // ANCOUNT = 1

    // The answer's name is a pointer back to the question's, at offset 12.
    reply.extend_from_slice(&[0xc0, 0x0c]);
    reply.extend_from_slice(&[0, 1]); // TYPE = A
    reply.extend_from_slice(&[0, 1]); // CLASS = IN
    reply.extend_from_slice(&INTERNAL_TTL_SECS.to_be_bytes());
    reply.extend_from_slice(&[0, 4]); // RDLENGTH
    reply.extend_from_slice(&address.octets());
    reply
}

/// A reply carrying only a response code.
fn rcode_response(query: &[u8], rcode: u8) -> Vec<u8> {
    match reply_skeleton(query) {
        Some(mut reply) => {
            reply[3] = 0x80 | (rcode & 0x0f);
            reply
        }
        // Too malformed to answer in kind; echo the header with the code set.
        None => {
            let mut reply = query.to_vec();
            reply.resize(12, 0);
            reply[2] = 0x81;
            reply[3] = 0x80 | (rcode & 0x0f);
            reply[4..12].fill(0);
            reply
        }
    }
}

/// Decodes the QNAME of the first question, for logging.
///
/// Returns an empty string for anything malformed: this is used for a log
/// line, so a strange packet should not cost a resolution.
fn parse_question(packet: &[u8]) -> String {
    // Header is 12 bytes; QDCOUNT must be non-zero for a question to exist.
    if packet.len() < 13 || u16::from_be_bytes([packet[4], packet[5]]) == 0 {
        return String::new();
    }

    let mut labels = Vec::new();
    let mut pos = 12;
    loop {
        let Some(&len) = packet.get(pos) else {
            return String::new();
        };
        if len == 0 {
            break;
        }
        // Compression pointers cannot appear in a question's QNAME; refusing
        // them avoids following offsets into arbitrary parts of the packet.
        if len & 0xc0 != 0 {
            return String::new();
        }
        let start = pos + 1;
        let end = start + len as usize;
        let Some(label) = packet.get(start..end) else {
            return String::new();
        };
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos = end;
    }
    labels.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_for(name: &str) -> Vec<u8> {
        let mut packet = vec![0u8; 12];
        packet[5] = 1; // QDCOUNT = 1
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        packet
    }

    #[test]
    fn reads_the_question_name() {
        assert_eq!(
            parse_question(&query_for("files.pythonhosted.org")),
            "files.pythonhosted.org"
        );
        assert_eq!(parse_question(&query_for("example.com")), "example.com");
    }

    #[test]
    fn malformed_packets_do_not_panic() {
        let full = query_for("example.com");
        for cut in 0..full.len() {
            let _ = parse_question(&full[..cut]);
        }
        assert_eq!(parse_question(&[]), "");
        assert_eq!(parse_question(&[0u8; 12]), "");
    }

    #[test]
    fn compression_pointers_in_a_question_are_refused() {
        let mut packet = vec![0u8; 12];
        packet[5] = 1;
        // 0xc0 marks a pointer, which has no place in a QNAME.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        assert_eq!(parse_question(&packet), "");
    }

    /// The reply must be a well-formed DNS answer, not merely non-empty: a
    /// guest resolver will silently ignore anything it cannot parse.
    #[test]
    fn an_internal_name_gets_a_parseable_a_record() {
        let query = query_for("beta.team.internal");
        let reply = a_record_response(&query, Ipv4Addr::new(10, 99, 0, 10));

        assert_eq!(&reply[0..2], &query[0..2], "transaction id must be echoed");
        assert_eq!(reply[2] & 0x80, 0x80, "QR bit must be set");
        assert_eq!(reply[3] & 0x0f, 0, "RCODE must be NOERROR");
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 1, "QDCOUNT");
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1, "ANCOUNT");

        // The question is echoed verbatim, then the answer follows.
        let answer_at = question_end(&query).unwrap();
        assert_eq!(&reply[12..answer_at], &query[12..answer_at]);
        assert_eq!(&reply[answer_at..answer_at + 2], &[0xc0, 0x0c]);
        assert_eq!(&reply[answer_at + 2..answer_at + 4], &[0, 1]); // A
        assert_eq!(&reply[answer_at + 4..answer_at + 6], &[0, 1]); // IN
        assert_eq!(&reply[answer_at + 10..answer_at + 12], &[0, 4]); // RDLENGTH
        assert_eq!(&reply[answer_at + 12..], &[10, 99, 0, 10]);
    }

    #[test]
    fn a_reply_with_the_wrong_transaction_id_is_rejected() {
        let query = query_for("example.com");
        let mut forged = query.clone();
        forged[2] |= 0x80; // pretend to be a response
        forged[0] ^= 0xff; // wrong transaction id
        assert!(!answers_query(&query, &forged));
    }

    #[test]
    fn a_reply_to_a_different_question_is_rejected() {
        let query = query_for("example.com");
        let mut forged = query_for("evil.example");
        forged[0] = query[0];
        forged[1] = query[1];
        forged[2] |= 0x80;
        assert!(!answers_query(&query, &forged));
    }

    #[test]
    fn a_reply_without_the_qr_bit_is_rejected() {
        // Same id and question, but never marked as a response (e.g. an
        // echoed query rather than an answer).
        let query = query_for("example.com");
        assert!(!answers_query(&query, &query));
    }

    #[test]
    fn a_matching_reply_is_accepted() {
        let query = query_for("example.com");
        let reply = a_record_response(&query, Ipv4Addr::new(93, 184, 216, 34));
        assert!(answers_query(&query, &reply));
    }

    /// The parser burrow already has must be able to read back what it wrote.
    #[test]
    fn the_generated_answer_round_trips_through_the_pin_parser() {
        let query = query_for("beta.team.internal");
        let reply = a_record_response(&query, Ipv4Addr::new(10, 99, 0, 10));
        let (addresses, ttl) = crate::resolutions::parse_answers(&reply);
        assert_eq!(addresses, vec![Ipv4Addr::new(10, 99, 0, 10)]);
        assert_eq!(ttl.as_secs(), INTERNAL_TTL_SECS as u64);
    }

    #[test]
    fn a_name_the_caller_may_not_see_is_nxdomain() {
        let query = query_for("beta.team.internal");
        let reply = rcode_response(&query, RCODE_NXDOMAIN);
        assert_eq!(reply[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0, "no answers");
    }

    /// A lookup the policy does not permit is answered, not forwarded: the
    /// question name never reaches an upstream resolver.
    #[test]
    fn a_query_outside_the_policy_is_answered_refused() {
        let query = query_for("secret.exfil.example");
        let reply = rcode_response(&query, RCODE_REFUSED);
        assert_eq!(reply[3] & 0x0f, RCODE_REFUSED);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0, "no answers");
        assert_eq!(&reply[0..2], &query[0..2], "transaction id must be echoed");
    }

    #[test]
    fn a_malformed_query_still_produces_a_reply_rather_than_a_panic() {
        let full = query_for("beta.team.internal");
        for cut in 0..full.len() {
            let reply = rcode_response(&full[..cut], RCODE_NXDOMAIN);
            assert!(reply.len() >= 12);
            let _ = a_record_response(&full[..cut], Ipv4Addr::LOCALHOST);
        }
    }

    #[test]
    fn the_question_boundary_is_found_correctly() {
        let query = query_for("a.b.internal");
        // 12 header + (1+1)+(1+1)+(1+8) labels + 1 root + 4 = 30
        assert_eq!(question_end(&query), Some(query.len()));
        assert_eq!(question_end(&[0u8; 12]), None);
    }

    /// A sandbox emitting queries in a loop would otherwise exhaust the
    /// process's descriptors, taking the resolver down for every sandbox on
    /// the node. The burst is generous but finite, and it is its own.
    #[test]
    fn one_source_can_burst_but_not_flood() {
        let limits = Limits::default();
        let noisy = Ipv4Addr::new(10, 99, 0, 6);
        let quiet = Ipv4Addr::new(10, 99, 0, 10);

        for n in 0..QUERY_BURST as usize {
            assert!(limits.allow(noisy), "query {n} is within the burst");
        }
        assert!(!limits.allow(noisy), "the burst must be finite");
        // The neighbour's budget is untouched, which is the point of keying
        // this by source at all.
        assert!(limits.allow(quiet));
    }

    /// The bucket refills, or a sandbox that burst once would be refused for
    /// the rest of its life.
    #[test]
    fn a_spent_budget_refills_over_time() {
        let limits = Limits::default();
        let source = Ipv4Addr::new(10, 99, 0, 6);
        for _ in 0..QUERY_BURST as usize {
            assert!(limits.allow(source));
        }
        assert!(!limits.allow(source));

        // Rewind the bucket's clock rather than sleeping: one second of
        // refill is QUERIES_PER_SECOND more queries.
        {
            let mut buckets = limits.buckets.lock().unwrap();
            let bucket = buckets.get_mut(&source).unwrap();
            bucket.last -= std::time::Duration::from_secs(1);
        }
        for n in 0..QUERIES_PER_SECOND as usize {
            assert!(limits.allow(source), "refilled query {n}");
        }
        assert!(!limits.allow(source), "refill must not exceed the rate");
    }

    /// Addresses are recycled, so a bucket per address ever seen would grow
    /// without bound on a long-lived node.
    #[test]
    fn buckets_for_sources_that_went_quiet_are_forgotten() {
        let limits = Limits::default();
        for n in 0..1200u32 {
            limits.allow(Ipv4Addr::from(n.to_be_bytes()));
        }
        {
            // Age every bucket past the idle window, then touch one more
            // source to trigger the prune.
            let mut buckets = limits.buckets.lock().unwrap();
            for bucket in buckets.values_mut() {
                bucket.last -= BUCKET_IDLE * 2;
            }
        }
        limits.allow(Ipv4Addr::new(10, 99, 0, 6));
        let buckets = limits.buckets.lock().unwrap();
        assert_eq!(
            buckets.len(),
            1,
            "only the live source should still have a bucket"
        );
    }
}
