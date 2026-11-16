//! The audit records of what the sandbox chains drop on their own: deny_cidrs,
//! deny_ports, the control plane, IPv6 and the chains' closing drops, read
//! from NFLOG and written beside the proxy's and the resolver's.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::sync::RwLock;

use burrow_net::firewall::{self, Mode};

/// How often drops past the log's rate are counted into the audit log.
const SUPPRESSED_EVERY: std::time::Duration = std::time::Duration::from_secs(10);

/// The sandbox behind each tap, as the last render named them, and the
/// suppressed count last reported for each tap.
#[derive(Default)]
pub struct Owners {
    taps: RwLock<HashMap<String, Owner>>,
    seen: tokio::sync::Mutex<HashMap<String, u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub sandbox_id: String,
    pub mode: Mode,
}

impl Owners {
    /// Takes the taps `rules` name, returning each tap that no longer
    /// belongs to the sandbox it did, with that sandbox.
    pub fn replace(&self, rules: &[firewall::SandboxRules]) -> Vec<(String, Owner)> {
        let taps: HashMap<String, Owner> = rules
            .iter()
            .map(|rule| {
                (
                    rule.tap.clone(),
                    Owner {
                        sandbox_id: rule.sandbox_id.clone(),
                        mode: rule.mode,
                    },
                )
            })
            .collect();
        let previous = std::mem::replace(&mut *self.taps.write().unwrap(), taps.clone());
        let mut gone: Vec<(String, Owner)> = previous
            .into_iter()
            .filter(|(tap, owner)| taps.get(tap) != Some(owner))
            .collect();
        gone.sort_by(|a, b| a.0.cmp(&b.0));
        gone
    }

    fn get(&self, tap: &str) -> Option<Owner> {
        self.taps.read().unwrap().get(tap).cloned()
    }
}

/// The audit record for one drop, between interfaces `indev` and `outdev`.
/// A packet from a sandbox's tap is that sandbox's; failing that, a packet
/// to one is a refused inbound one. Neither, and it is no sandbox's here.
pub fn event(
    owners: &Owners,
    drop: &burrow_net::nflog::Drop,
    indev: &str,
    outdev: &str,
) -> Option<burrow_proxy::EgressEvent> {
    let (owner, is_inbound) = match (owners.get(indev), owners.get(outdev)) {
        (Some(owner), _) => (owner, false),
        (None, Some(owner)) => (owner, true),
        (None, None) => return None,
    };
    let reason = drop
        .refusal
        .reason(owner.mode, drop.destination.is_ipv6(), is_inbound);
    Some(burrow_proxy::EgressEvent {
        at_ms: burrow_proxy::unix_now_ms(),
        sandbox_id: owner.sandbox_id,
        source_ip: drop.source.to_string(),
        destination: std::net::SocketAddr::new(drop.destination, drop.port).to_string(),
        host: None,
        port: drop.port,
        is_allowed: false,
        reason: format!("{reason} ({})", drop.protocol),
        bytes_sent: 0,
        bytes_received: 0,
        dropped_records: 0,
    })
}

/// The record saying how many of a sandbox's drops were past the log's rate.
pub fn suppressed_event(owner: Owner, count: u64) -> burrow_proxy::EgressEvent {
    burrow_proxy::EgressEvent {
        at_ms: burrow_proxy::unix_now_ms(),
        sandbox_id: owner.sandbox_id,
        source_ip: String::new(),
        destination: "firewall".into(),
        host: None,
        port: 0,
        is_allowed: false,
        reason: format!(
            "{count} more packets were dropped past the audit rate limit and not recorded one by one"
        ),
        bytes_sent: 0,
        bytes_received: 0,
        dropped_records: 0,
    }
}

/// Each tap's count in `nft -j list set` output, or `None` for output that
/// is not a listing of the set.
pub fn parse_suppressed(json: &str) -> Option<HashMap<String, u64>> {
    let value = serde_json::from_str::<serde_json::Value>(json).ok()?;
    let set = value["nftables"]
        .as_array()?
        .iter()
        .find(|entry| entry["set"].is_object())?;
    Some(
        set["set"]["elem"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|elem| {
                let elem = &elem["elem"];
                Some((
                    elem["val"].as_str()?.to_owned(),
                    elem["counter"]["packets"].as_u64()?,
                ))
            })
            .collect(),
    )
}

/// What each tap counted since `seen`, which is moved on. A tap counting
/// less than before timed out of the set and started again.
pub fn suppressed_since(
    seen: &mut HashMap<String, u64>,
    now: HashMap<String, u64>,
) -> Vec<(String, u64)> {
    let mut grown: Vec<_> = now
        .iter()
        .filter_map(|(tap, &count)| {
            let before = seen.get(tap).copied().unwrap_or(0);
            let added = if count >= before {
                count - before
            } else {
                count
            };
            (added > 0).then(|| (tap.clone(), added))
        })
        .collect();
    grown.sort();
    *seen = now;
    grown
}

/// The suppressed counts the kernel holds now, or `None` when they cannot
/// be read.
#[cfg(target_os = "linux")]
async fn read_suppressed() -> Option<HashMap<String, u64>> {
    let output = tokio::process::Command::new("nft")
        .args([
            "-j",
            "list",
            "set",
            "inet",
            "burrow",
            firewall::DROP_SUPPRESSED_SET,
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_suppressed(&String::from_utf8_lossy(&output.stdout))
}

/// Reports what each tap suppressed since the last report.
#[cfg(target_os = "linux")]
async fn report_suppressed(manager: &crate::sandbox::SandboxManager, owners: &Owners) {
    let mut seen = owners.seen.lock().await;
    let Some(now) = read_suppressed().await else {
        return;
    };
    for (tap, count) in suppressed_since(&mut seen, now) {
        if let Some(owner) = owners.get(&tap) {
            manager.audit(suppressed_event(owner, count));
        }
    }
}

/// Settles the taps a render took from their sandboxes: what each suppressed
/// since the last report goes on its old sandbox's record, and its rate and
/// count are removed, so a sandbox given the tap next starts with neither.
#[cfg(target_os = "linux")]
pub async fn retire(manager: &crate::sandbox::SandboxManager, gone: Vec<(String, Owner)>) {
    let owners = manager.drop_owners();
    let mut seen = owners.seen.lock().await;
    let now = read_suppressed().await.unwrap_or_default();
    for (tap, owner) in gone {
        let before = seen.remove(&tap).unwrap_or(0);
        let count = now.get(&tap).copied().unwrap_or(0);
        let added = if count >= before {
            count - before
        } else {
            count
        };
        if added > 0 {
            manager.audit(suppressed_event(owner, added));
        }
        for set in [firewall::DROP_RATE_SET, firewall::DROP_SUPPRESSED_SET] {
            let _ = tokio::process::Command::new("nft")
                .args(["delete", "element", "inet", "burrow", set])
                .arg(format!("{{ \"{tap}\" }}"))
                .output()
                .await;
        }
    }
}

/// Whether this kernel and nft can log the sandbox chains' drops, and the
/// socket they arrive on when they can. Warned about once when they cannot;
/// the drops are enforced either way.
#[cfg(target_os = "linux")]
pub async fn open() -> Option<burrow_net::nflog::Socket> {
    if let Err(err) = firewall::apply(&firewall::drop_log_probe()).await {
        tracing::warn!(
            %err,
            "nftables cannot log drops to NFLOG here; the firewall still drops what the policy \
             denies, but those drops are not in the audit log"
        );
        return None;
    }
    if let Err(err) = firewall::apply(firewall::DROP_LOG_PROBE_CLEANUP).await {
        tracing::warn!(%err, "could not remove the drop log probe table");
    }
    match burrow_net::nflog::Socket::open(firewall::DROP_LOG_GROUP) {
        Ok(socket) => Some(socket),
        Err(err) => {
            tracing::warn!(
                %err,
                group = firewall::DROP_LOG_GROUP,
                "cannot read NFLOG; the firewall still drops what the policy denies, but those \
                 drops are not in the audit log"
            );
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn interface_name(index: u32) -> String {
    if index == 0 {
        return String::new();
    }
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: if_indextoname writes at most IF_NAMESIZE bytes into `buf`.
    let name = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if name.is_null() {
        return String::new();
    }
    // SAFETY: on success `buf` holds a NUL-terminated name.
    unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Reads drops off `socket` into the audit log, and counts what the rate
/// left out, for as long as the node runs.
#[cfg(target_os = "linux")]
pub fn spawn(manager: crate::sandbox::SandboxManager, socket: burrow_net::nflog::Socket) {
    let (arrived, mut arrivals) = tokio::sync::mpsc::channel::<burrow_proxy::EgressEvent>(1024);
    let owners = manager.drop_owners();
    std::thread::Builder::new()
        .name("burrow-droplog".into())
        .spawn(move || {
            let mut buf = vec![0u8; 1 << 16];
            let mut drops = Vec::new();
            let mut overruns: u64 = 0;
            loop {
                let read = match socket.recv(&mut buf) {
                    Ok(read) => read,
                    Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => {
                        overruns += 1;
                        if overruns.is_power_of_two() {
                            tracing::warn!(
                                overruns,
                                "the NFLOG socket overflowed; some logged drops were lost"
                            );
                        }
                        continue;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        tracing::error!(%err, "reading NFLOG failed; firewall drops are no longer audited");
                        return;
                    }
                };
                drops.clear();
                burrow_net::nflog::parse(&buf[..read], &mut drops);
                for drop in &drops {
                    let indev = interface_name(drop.indev);
                    let outdev = interface_name(drop.outdev);
                    if let Some(event) = event(&owners, drop, &indev, &outdev)
                        && arrived.blocking_send(event).is_err()
                    {
                        return;
                    }
                }
            }
        })
        .expect("spawning the drop log reader");
    let recorder = manager.clone();
    tokio::spawn(async move {
        while let Some(event) = arrivals.recv().await {
            recorder.audit(event);
        }
    });
    tokio::spawn(async move {
        let owners = manager.drop_owners();
        let mut interval = tokio::time::interval(SUPPRESSED_EVERY);
        loop {
            interval.tick().await;
            report_suppressed(&manager, &owners).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use burrow_net::firewall::Refusal;

    fn owners() -> Owners {
        let owners = Owners::default();
        owners.taps.write().unwrap().insert(
            "bt3".into(),
            Owner {
                sandbox_id: "sbx_a".into(),
                mode: Mode::Allowlist,
            },
        );
        owners
    }

    fn drop(refusal: Refusal, destination: &str, port: u16) -> burrow_net::nflog::Drop {
        burrow_net::nflog::Drop {
            refusal,
            indev: 0,
            outdev: 0,
            source: "10.99.0.6".parse().unwrap(),
            destination: destination.parse().unwrap(),
            protocol: "tcp".into(),
            port,
        }
    }

    #[test]
    fn a_drop_from_a_tap_is_its_sandboxes_refusal() {
        let event = event(
            &owners(),
            &drop(Refusal::Range, "192.0.2.9", 443),
            "bt3",
            "eth0",
        )
        .unwrap();
        assert_eq!(event.sandbox_id, "sbx_a");
        assert_eq!(event.destination, "192.0.2.9:443");
        assert_eq!(event.port, 443);
        assert!(!event.is_allowed);
        assert_eq!(event.reason, "destination is in a denied range (tcp)");
    }

    #[test]
    fn the_closing_drop_is_worded_for_the_sandboxes_mode_and_direction() {
        let owners = owners();
        let egress = event(
            &owners,
            &drop(Refusal::Unmatched, "192.0.2.9", 22),
            "bt3",
            "eth0",
        )
        .unwrap();
        assert_eq!(egress.reason, "destination not in allowlist (tcp)");
        let v6 = event(
            &owners,
            &drop(Refusal::Unmatched, "2001:db8::1", 22),
            "bt3",
            "eth0",
        )
        .unwrap();
        assert_eq!(v6.reason, "ipv6 egress is open mode only (tcp)");
        let inbound = event(
            &owners,
            &drop(Refusal::Unmatched, "10.99.0.6", 22),
            "eth0",
            "bt3",
        )
        .unwrap();
        assert_eq!(inbound.sandbox_id, "sbx_a");
        assert_eq!(inbound.reason, "no rule admits this inbound traffic (tcp)");
        assert!(
            event(
                &owners,
                &drop(Refusal::Unmatched, "10.0.0.1", 22),
                "eth0",
                "eth1"
            )
            .is_none()
        );
    }

    #[test]
    fn suppressed_counts_are_read_from_nft_json_and_reported_once() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.0.6"}}, {"set": {"family": "inet",
            "name": "audit_suppressed", "table": "burrow", "elem": [
            {"elem": {"val": "bt3", "counter": {"packets": 45, "bytes": 1350}}},
            {"elem": {"val": "bt4", "counter": {"packets": 0, "bytes": 0}}}]}}]}"#;
        let tap = "bt3".to_string();
        let mut seen = HashMap::new();
        let read = |json: &str| parse_suppressed(json).unwrap();
        assert_eq!(suppressed_since(&mut seen, read(json)), [(tap.clone(), 45)]);
        assert!(suppressed_since(&mut seen, read(json)).is_empty());
        let grown = json.replace("\"packets\": 45", "\"packets\": 50");
        assert_eq!(
            suppressed_since(&mut seen, read(&grown)),
            [(tap.clone(), 5)]
        );
        let restarted = json.replace("\"packets\": 45", "\"packets\": 3");
        assert_eq!(suppressed_since(&mut seen, read(&restarted)), [(tap, 3)]);
    }

    /// An unreadable listing is not an empty one: taken as empty, it would
    /// forget every count, and the next listing would report them all again.
    #[test]
    fn an_unreadable_listing_reads_as_nothing_rather_than_empty() {
        assert_eq!(parse_suppressed("not json"), None);
        assert_eq!(parse_suppressed(r#"{"nftables": []}"#), None);
        let empty = r#"{"nftables": [{"set": {"name": "audit_suppressed"}}]}"#;
        assert_eq!(parse_suppressed(empty), Some(HashMap::new()));
    }

    #[test]
    fn a_tap_taken_from_its_sandbox_is_returned_with_it() {
        let rule = |tap: &str, id: &str| firewall::SandboxRules {
            sandbox_id: id.into(),
            tap: tap.into(),
            host_ip: "10.99.0.5".parse().unwrap(),
            guest_ip: "10.99.0.6".parse().unwrap(),
            host_ip6: "fd99::1".parse().unwrap(),
            guest_ip6: "fd99::2".parse().unwrap(),
            pool: Default::default(),
            mode: Mode::Open,
            allow_cidrs: vec![],
            deny_cidrs: vec![],
            deny_ports: vec![],
            is_ipv6_denied: false,
            allow_ports: vec![],
            peers: vec![],
            ports: vec![],
            inspected: None,
            public: Default::default(),
        };
        let owners = Owners::default();
        assert!(
            owners
                .replace(&[rule("bt1", "sbx_a"), rule("bt2", "sbx_b")])
                .is_empty()
        );
        let gone = owners.replace(&[rule("bt1", "sbx_c")]);
        let ids: Vec<(&str, &str)> = gone
            .iter()
            .map(|(tap, owner)| (tap.as_str(), owner.sandbox_id.as_str()))
            .collect();
        assert_eq!(ids, [("bt1", "sbx_a"), ("bt2", "sbx_b")]);
        assert_eq!(owners.get("bt1").unwrap().sandbox_id, "sbx_c");
    }
}
