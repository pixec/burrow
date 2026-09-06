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
use std::net::Ipv4Addr;
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
    addresses: Vec<Ipv4Addr>,
    expires: Instant,
}

/// Per-sandbox record of what the resolver answered.
#[derive(Default)]
pub struct Resolutions {
    /// sandbox address -> hostname -> pin
    by_sandbox: RwLock<HashMap<Ipv4Addr, HashMap<String, Pin>>>,
}

impl Resolutions {
    /// Records the addresses returned to `client` for `host`.
    pub fn record(&self, client: Ipv4Addr, host: &str, addresses: Vec<Ipv4Addr>, ttl: Duration) {
        if host.is_empty() || addresses.is_empty() {
            return;
        }
        let lifetime = ttl.clamp(MIN_PIN, MAX_PIN);
        let mut table = self.by_sandbox.write().unwrap();
        let names = table.entry(client).or_default();

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

    /// Whether `client` was told `host` resolves to `address`.
    pub fn is_pinned(&self, client: Ipv4Addr, host: &str, address: Ipv4Addr) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let table = self.by_sandbox.read().unwrap();
        table
            .get(&client)
            .and_then(|names| names.get(&host))
            .is_some_and(|pin| pin.expires > Instant::now() && pin.addresses.contains(&address))
    }

    /// Drops pins for every address that is no longer a live sandbox.
    ///
    /// Leases are recycled: a deleted sandbox's address is handed to the next
    /// one created. Without this the new sandbox inherits the old one's
    /// resolutions and may reach hosts it never looked up, which silently stops
    /// the pin check being a check.
    pub fn retain_live(&self, live: &std::collections::HashSet<Ipv4Addr>) {
        self.by_sandbox
            .write()
            .unwrap()
            .retain(|address, _| live.contains(address));
    }
}

/// Addresses the proxy will never connect to on a sandbox's behalf.
///
/// Independent of pinning, because a name can legitimately resolve into these
/// ranges: `169.254.169.254` is the cloud metadata service, and reaching it
/// hands the host's own instance credentials to the sandbox. Loopback and
/// private ranges are the rest of the classic SSRF surface, the proxy running
/// on the host so that "localhost" to it is the host, not the guest.
pub fn is_forbidden_destination(address: Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_link_local()
        || address.is_private()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_unspecified()
        // 100.64.0.0/10, carrier-grade NAT, used by some metadata endpoints.
        || matches!(address.octets(), [100, b, _, _] if (64..128).contains(&b))
}

/// Extracts the A records from a DNS response, with the smallest TTL seen.
///
/// Only A records are collected; anything else is skipped without
/// interpretation. A malformed packet yields nothing rather than an error: the
/// answer is forwarded to the client either way, so failing to pin costs a
/// later denial rather than a broken lookup.
pub fn parse_answers(packet: &[u8]) -> (Vec<Ipv4Addr>, Duration) {
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
        // Type 1 is A; rdata is exactly four bytes of address.
        if record_type == 1 && rdlength == 4 {
            addresses.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            min_ttl = min_ttl.min(ttl);
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
        assert_eq!(addresses, vec![a, b]);
        assert_eq!(ttl, Duration::from_secs(300));
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
        let client = Ipv4Addr::new(10, 99, 0, 6);
        let allowed = Ipv4Addr::new(93, 184, 215, 14);
        let attacker = Ipv4Addr::new(34, 223, 124, 45);

        table.record(
            client,
            "example.com",
            vec![allowed],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned(client, "example.com", allowed));
        // A name it was told does not authorise an address it was not.
        assert!(!table.is_pinned(client, "example.com", attacker));
    }

    #[test]
    fn a_recycled_address_does_not_inherit_the_previous_sandboxs_pins() {
        let table = Resolutions::default();
        let recycled = Ipv4Addr::new(10, 99, 0, 6);
        let target = Ipv4Addr::new(93, 184, 215, 14);
        table.record(
            recycled,
            "example.com",
            vec![target],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned(recycled, "example.com", target));

        // The sandbox is deleted and its lease returns to the pool.
        table.retain_live(&std::collections::HashSet::new());
        assert!(!table.is_pinned(recycled, "example.com", target));
    }

    #[test]
    fn one_sandbox_cannot_use_anothers_resolution() {
        let table = Resolutions::default();
        let (a, b) = (Ipv4Addr::new(10, 99, 0, 6), Ipv4Addr::new(10, 99, 0, 10));
        let address = Ipv4Addr::new(93, 184, 215, 14);
        table.record(a, "example.com", vec![address], Duration::from_secs(300));
        assert!(!table.is_pinned(b, "example.com", address));
    }

    #[test]
    fn pins_are_case_and_trailing_dot_insensitive() {
        let table = Resolutions::default();
        let client = Ipv4Addr::new(10, 99, 0, 6);
        let address = Ipv4Addr::new(93, 184, 215, 14);
        table.record(
            client,
            "Example.COM.",
            vec![address],
            Duration::from_secs(300),
        );
        assert!(table.is_pinned(client, "example.com", address));
    }

    #[test]
    fn an_unresolved_name_pins_nothing() {
        let table = Resolutions::default();
        let client = Ipv4Addr::new(10, 99, 0, 6);
        assert!(!table.is_pinned(client, "example.com", Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn metadata_and_internal_ranges_are_refused() {
        // The reason this exists: a name that resolves here would otherwise
        // pass pinning and hand over the host's cloud credentials.
        assert!(is_forbidden_destination(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(is_forbidden_destination(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_forbidden_destination(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_forbidden_destination(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_forbidden_destination(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_forbidden_destination(Ipv4Addr::new(100, 100, 0, 1)));
        assert!(!is_forbidden_destination(Ipv4Addr::new(93, 184, 215, 14)));
        assert!(!is_forbidden_destination(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
