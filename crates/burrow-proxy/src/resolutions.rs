//! DNS pinning: which addresses a sandbox was actually told a name resolves to.
//!
//! The proxy decides on the hostname a client claims, the TLS SNI or the HTTP
//! Host header, but connects to the address the client chose. Nothing ties the
//! two together, so a sandbox could open a connection to any address at all and
//! label it with an allowed hostname, which points straight at the cloud
//! metadata service.
//!
//! Burrow runs the resolver its sandboxes use, so it knows which addresses it
//! handed out for which name. A connection is allowed only to an address this
//! sandbox was told that name resolves to.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Floor on how long a pin is kept, regardless of the record's TTL.
///
/// Clients cache aggressively and connect well after the lookup; a
/// short-TTL record would otherwise expire between the two and break a
/// legitimate request.
const MIN_PIN: Duration = Duration::from_secs(60);
/// Ceiling, so a hostile TTL cannot make a pin permanent.
const MAX_PIN: Duration = Duration::from_secs(3600);
/// Distinct names pinned per sandbox, bounding memory against a sandbox that
/// resolves endlessly.
const MAX_NAMES_PER_SANDBOX: usize = 1024;

struct Pin {
    addresses: Vec<IpAddr>,
    expires: Instant,
}

/// Per-sandbox record of what the resolver answered.
#[derive(Default)]
pub struct Resolutions {
    /// sandbox id -> hostname -> pin
    ///
    /// Keyed by the sandbox rather than by the address it arrived from: a
    /// sandbox has one address per family, and a name resolved over one and
    /// connected to over the other is the same sandbox keeping the same
    /// promise. Keying by address made every dual-stack lookup miss.
    by_sandbox: RwLock<HashMap<String, HashMap<String, Pin>>>,
}

impl Resolutions {
    /// Records the addresses `sandbox_id` was told `host` resolves to.
    pub fn record(&self, sandbox_id: &str, host: &str, addresses: Vec<IpAddr>, ttl: Duration) {
        if sandbox_id.is_empty() || host.is_empty() || addresses.is_empty() {
            return;
        }
        let lifetime = ttl.clamp(MIN_PIN, MAX_PIN);
        let mut table = self.by_sandbox.write().unwrap();
        let names = table.entry(sandbox_id.to_string()).or_default();

        if names.len() >= MAX_NAMES_PER_SANDBOX {
            let now = Instant::now();
            names.retain(|_, pin| pin.expires > now);
            // Still full of live entries: refuse to grow rather than evict
            // something a legitimate request may be about to use.
            if names.len() >= MAX_NAMES_PER_SANDBOX {
                return;
            }
        }

        names.insert(
            host.trim_end_matches('.').to_ascii_lowercase(),
            Pin {
                addresses,
                expires: Instant::now() + lifetime,
            },
        );
    }

    /// Whether `sandbox_id` was told `host` resolves to `address`.
    pub fn is_pinned(&self, sandbox_id: &str, host: &str, address: IpAddr) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let table = self.by_sandbox.read().unwrap();
        table
            .get(sandbox_id)
            .and_then(|names| names.get(&host))
            .is_some_and(|pin| pin.expires > Instant::now() && pin.addresses.contains(&address))
    }

    /// Drops pins for every sandbox that no longer exists.
    ///
    /// Without this a deleted sandbox's promises sit in the table forever, and
    /// the table grows without bound over the lifetime of the daemon.
    pub fn retain_live(&self, live: &std::collections::HashSet<String>) {
        self.by_sandbox
            .write()
            .unwrap()
            .retain(|sandbox_id, _| live.contains(sandbox_id));
    }
}

/// The addresses burrow's own control plane answers on, which no sandbox may
/// reach through the proxy.
///
/// The firewall denies these to every sandbox at the IP layer (see
/// `burrow-net`'s `firewall::render_with`), but the proxy is a hole through
/// that: it runs on the host, outside the sandbox chain, and opens the
/// upstream connection with its own source address. A name resolving to the
/// orchestrator's API or a node's edge router would otherwise be reachable
/// through the proxy even though a packet addressed there directly is dropped,
/// and reaching either means creating, deleting or exec'ing into sandboxes
/// this one shares nothing with.
///
/// Unlike [`is_forbidden_destination`], these are this deployment's own
/// addresses, so the daemon supplies them and keeps the set in step with what
/// it renders into the ruleset.
#[derive(Debug, Default)]
pub struct DeniedAddresses {
    addresses: RwLock<std::collections::HashSet<IpAddr>>,
}

impl DeniedAddresses {
    /// Replaces the set wholesale, the way the ruleset is re-rendered
    /// wholesale: an address that has stopped being control plane stops being
    /// denied, and one that has started is denied from the next connection on.
    pub fn replace(&self, addresses: impl IntoIterator<Item = IpAddr>) {
        *self.addresses.write().unwrap() = addresses.into_iter().collect();
    }

    /// Checked against the unmapped address, so a control plane cannot be
    /// reached by asking for it in the other family's notation.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.addresses
            .read()
            .unwrap()
            .contains(&crate::policy::unmap(address))
    }
}

/// Addresses the proxy will never connect to on a sandbox's behalf.
///
/// Independent of pinning, because a name can legitimately resolve into these
/// ranges: `169.254.169.254` is the cloud metadata service, and reaching it
/// hands the host's own instance credentials to the sandbox. Loopback and
/// private ranges are the rest of the classic SSRF surface, the proxy running
/// on the host so that "localhost" to it is the host, not the guest.
pub fn is_forbidden_destination(address: IpAddr) -> bool {
    // Unmapped first, always. `::ffff:169.254.169.254` is the cloud metadata
    // endpoint and every v4 predicate below answers `false` for it while it
    // is still wearing a v6 shape.
    match crate::policy::unmap(address) {
        IpAddr::V4(address) => forbidden_v4(address),
        IpAddr::V6(address) => forbidden_v6(address),
    }
}

fn forbidden_v4(address: Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_link_local()
        || address.is_private()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_unspecified()
        // 100.64.0.0/10, carrier-grade NAT, used by some metadata endpoints.
        || matches!(address.octets(), [100, b, _, _] if (64..128).contains(&b))
}

/// The v6 counterparts, plus the two ways a v4 address can arrive dressed as
/// a v6 one. `::ffff:…` is handled by unmapping before this is reached; the
/// NAT64 well-known prefix is handled here, because the embedded address is
/// what the packet actually reaches.
fn forbidden_v6(address: Ipv6Addr) -> bool {
    if let Some(embedded) = nat64_embedded(address) {
        return forbidden_v4(embedded);
    }
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        // fe80::/10, link-local, which is where a v6 metadata service lives.
        || (address.segments()[0] & 0xffc0) == 0xfe80
        // fc00::/7, unique local, burrow's own sandbox range included.
        || (address.segments()[0] & 0xfe00) == 0xfc00
        // The IPv4-compatible form, deprecated but still parsed by resolvers.
        || matches!(address.segments(), [0, 0, 0, 0, 0, 0, _, _] if !address.is_unspecified())
}

/// The IPv4 address inside a `64:ff9b::/96` destination, if it is one.
fn nat64_embedded(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = address.segments();
    (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0)
        .then(|| Ipv4Addr::from(((s[6] as u32) << 16) | s[7] as u32))
}

/// Extracts the A records from a DNS response, with the smallest TTL seen.
///
/// Only A records are collected; anything else is skipped without
/// interpretation. A malformed packet yields nothing rather than an error: the
/// answer is forwarded to the client either way, so failing to pin costs a
/// later denial rather than a broken lookup.
pub fn parse_answers(packet: &[u8]) -> (Vec<IpAddr>, Duration) {
    let mut addresses = Vec::new();
    let mut min_ttl = u32::MAX;

    let Some(header) = packet.get(..12) else {
        return (addresses, MIN_PIN);
    };
    let questions = u16::from_be_bytes([header[4], header[5]]);
    let answers = u16::from_be_bytes([header[6], header[7]]);

    let mut pos = 12;
    for _ in 0..questions {
        let Some(next) = skip_name(packet, pos) else {
            return (addresses, MIN_PIN);
        };
        // QTYPE and QCLASS.
        pos = next + 4;
    }

    for _ in 0..answers {
        let Some(after_name) = skip_name(packet, pos) else {
            break;
        };
        let Some(fields) = packet.get(after_name..after_name + 10) else {
            break;
        };
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        let record_type = u16::from_be_bytes([fields[0], fields[1]]);
        let ttl = u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]);
        let rdlength = u16::from_be_bytes([fields[8], fields[9]]) as usize;
        let rdata_start = after_name + 10;

        let Some(rdata) = packet.get(rdata_start..rdata_start + rdlength) else {
            break;
        };
        // Type 1 is A and type 28 is AAAA; each has a fixed rdata length.
        // An AAAA that is not pinned here is an address the proxy will refuse
        // to dial, so parsing both is what makes v6 destinations reachable at
        // all rather than merely resolvable.
        match (record_type, rdlength) {
            (1, 4) => {
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
                min_ttl = min_ttl.min(ttl);
            }
            (28, 16) => {
                let octets: [u8; 16] = rdata.try_into().expect("checked length");
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                min_ttl = min_ttl.min(ttl);
            }
            _ => {}
        }
        pos = rdata_start + rdlength;
    }

    let ttl = if min_ttl == u32::MAX {
        MIN_PIN
    } else {
        Duration::from_secs(min_ttl as u64)
    };
    (addresses, ttl)
}

/// Returns the offset just past a name, following at most one compression
/// pointer level's worth of jumps before giving up.
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    // A name is at most 255 bytes; this bounds a malicious pointer loop.
    for _ in 0..255 {
        let len = *packet.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // A pointer is two bytes and always ends the name.
            packet.get(pos + 1)?;
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A control-plane address on a public range is exactly what the fixed
    /// SSRF list cannot cover, so the daemon supplies the set and re-supplies
    /// it wholesale the way the ruleset is re-rendered.
    #[test]
    fn the_control_plane_set_is_replaced_wholesale() {
        let orchestrator = IpAddr::from([172, 18, 0, 4]);
        let edge = IpAddr::from([203, 0, 113, 9]);
        assert!(!is_forbidden_destination(edge));

        let denied = DeniedAddresses::default();
        assert!(!denied.contains(orchestrator));
        denied.replace([orchestrator, edge]);
        assert!(denied.contains(orchestrator) && denied.contains(edge));

        // An address that stopped being control plane stops being denied, the
        // same way a re-render drops the rule that named it.
        denied.replace([edge]);
        assert!(!denied.contains(orchestrator));
        assert!(denied.contains(edge));
    }

    fn response(host: &str, addresses: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut packet = vec![0u8; 12];
        packet[5] = 1; // QDCOUNT
        packet[7] = addresses.len() as u8; // ANCOUNT

        for label in host.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A QCLASS=IN

        for address in addresses {
            packet.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
            packet.extend_from_slice(&1u16.to_be_bytes()); // TYPE=A
            packet.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
            packet.extend_from_slice(&ttl.to_be_bytes());
            packet.extend_from_slice(&4u16.to_be_bytes());
            packet.extend_from_slice(&address.octets());
        }
        packet
    }

    #[test]
    fn reads_a_records_and_the_smallest_ttl() {
        let a = Ipv4Addr::new(93, 184, 215, 14);
        let b = Ipv4Addr::new(93, 184, 215, 15);
        let (addresses, ttl) = parse_answers(&response("example.com", &[a, b], 300));
        assert_eq!(addresses, vec![IpAddr::V4(a), IpAddr::V4(b)]);
        assert_eq!(ttl, Duration::from_secs(300));
    }

    /// An AAAA answer has to be pinned like an A one. A destination the
    /// resolver handed out but never recorded is one the proxy refuses to
    /// dial, so skipping these would make every v6 name unreachable while
    /// looking like a resolution problem.
    #[test]
    fn reads_aaaa_records_too() {
        let mut packet = vec![0u8; 12];
        packet[5] = 1;
        packet[7] = 1;
        for label in "example.com".split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 28, 0, 1]);
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&[0, 28, 0, 1]);
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&16u16.to_be_bytes());
        let address: Ipv6Addr = "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().unwrap();
        packet.extend_from_slice(&address.octets());

        let (addresses, ttl) = parse_answers(&packet);
        assert_eq!(addresses, vec![IpAddr::V6(address)]);
        assert_eq!(ttl, Duration::from_secs(60));
    }

    /// The trap this whole family split exists to avoid: the metadata
    /// endpoint and the private ranges wearing a v6 shape. Every v4
    /// predicate answers `false` for these until they are unmapped.
    #[test]
    fn a_mapped_or_nat64_address_is_still_forbidden() {
        for hidden in [
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b::10.0.0.1",
        ] {
            let address: IpAddr = hidden.parse().unwrap();
            assert!(
                is_forbidden_destination(address),
                "{hidden} must be refused"
            );
        }
        // And the v6 ranges in their own right.
        for forbidden in ["::1", "fe80::1", "fd99:b070:0:1::2", "ff02::1", "::"] {
            let address: IpAddr = forbidden.parse().unwrap();
            assert!(is_forbidden_destination(address), "{forbidden}");
        }
        // A public v6 address is still reachable.
        let public: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(!is_forbidden_destination(public));
    }

    #[test]
    fn malformed_responses_yield_nothing_rather_than_panicking() {
        let full = response("example.com", &[Ipv4Addr::new(1, 2, 3, 4)], 60);
        for cut in 0..full.len() {
            let _ = parse_answers(&full[..cut]);
        }
        assert!(parse_answers(&[]).0.is_empty());
    }

    #[test]
    fn a_pointer_loop_does_not_hang() {
        // A name pointing at itself would spin a naive parser forever.
        let mut packet = vec![0u8; 12];
        packet[5] = 1;
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c]);
        let _ = parse_answers(&packet);
    }

    #[test]
    fn a_connection_is_allowed_only_to_an_address_this_sandbox_was_given() {
        let table = Resolutions::default();
        let allowed = IpAddr::from([93, 184, 215, 14]);
        let attacker = IpAddr::from([34, 223, 124, 45]);

        table.record(
            "sb-1",
            "example.com",
            vec![allowed],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned("sb-1", "example.com", allowed));
        // A name it was told does not authorise an address it was not.
        assert!(!table.is_pinned("sb-1", "example.com", attacker));
    }

    #[test]
    fn a_deleted_sandbox_does_not_leave_its_pins_behind() {
        let table = Resolutions::default();
        let target = IpAddr::from([93, 184, 215, 14]);
        table.record(
            "sb-1",
            "example.com",
            vec![target],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned("sb-1", "example.com", target));

        table.retain_live(&std::collections::HashSet::new());
        assert!(!table.is_pinned("sb-1", "example.com", target));
    }

    #[test]
    fn one_sandbox_cannot_use_anothers_resolution() {
        let table = Resolutions::default();
        let address = IpAddr::from([93, 184, 215, 14]);
        table.record(
            "sb-1",
            "example.com",
            vec![address],
            Duration::from_secs(300),
        );
        assert!(!table.is_pinned("sb-2", "example.com", address));
    }

    #[test]
    fn a_name_resolved_over_one_family_is_pinned_for_the_other() {
        // The guest resolves over IPv4 and connects over IPv6. Both are the
        // same sandbox, so the promise holds across the families.
        let table = Resolutions::default();
        let address = "2606:4700::1".parse::<IpAddr>().unwrap();
        table.record(
            "sb-1",
            "example.com",
            vec![address],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned("sb-1", "example.com", address));
    }

    #[test]
    fn pins_are_case_and_trailing_dot_insensitive() {
        let table = Resolutions::default();
        let address = IpAddr::from([93, 184, 215, 14]);
        table.record(
            "sb-1",
            "Example.COM.",
            vec![address],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned("sb-1", "example.com", address));
    }

    #[test]
    fn an_unresolved_name_pins_nothing() {
        let table = Resolutions::default();
        assert!(!table.is_pinned("sb-1", "example.com", IpAddr::from([1, 2, 3, 4])));
    }

    #[test]
    fn metadata_and_internal_ranges_are_refused() {
        // The reason this exists: a name that resolves here would otherwise
        // pass pinning and hand over the host's cloud credentials.
        assert!(is_forbidden_destination(IpAddr::from([169, 254, 169, 254])));
        assert!(is_forbidden_destination(IpAddr::from([127, 0, 0, 1])));
        assert!(is_forbidden_destination(IpAddr::from([10, 0, 0, 1])));
        assert!(is_forbidden_destination(IpAddr::from([192, 168, 1, 1])));
        assert!(is_forbidden_destination(IpAddr::from([172, 16, 0, 1])));
        assert!(is_forbidden_destination(IpAddr::from([100, 100, 0, 1])));
        assert!(!is_forbidden_destination(IpAddr::from([93, 184, 215, 14])));
        assert!(!is_forbidden_destination(IpAddr::from([8, 8, 8, 8])));
    }
}
